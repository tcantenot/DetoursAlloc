#include <Windows.h>
#include <detours.h>
#include <DbgHelp.h>
#include <algorithm>
#include <cstdint>
#include <mutex>


#define LOG_MAX_LEN 512

#define LOG(...) \
	do { \
		char _LogFmtBuffer_[LOG_MAX_LEN]; \
		snprintf(_LogFmtBuffer_, LOG_MAX_LEN, __VA_ARGS__); \
		OutputDebugString(_LogFmtBuffer_); OutputDebugString("\n");\
		puts(_LogFmtBuffer_); \
	} while(0)

#define LOG_BREAK(...) \
	LOG(__VA_ARGS__); \
	__debugbreak()

void HumanReadableByteCount(char str[256], size_t bytes)
{
	const int32_t exponent = bytes > 0 ? static_cast<int32_t>(log10(bytes) / log10(1024)) : 0;
	snprintf(str, 256, "%.3f%c%s", bytes / pow(1024.f, exponent), "BKMGTPE"[exponent], exponent > 0 ? "B" : "");
}

// https://github.com/microsoft/Detours/wiki/DetourAttach
inline LONG CheckDetourAttach(LONG err)
{
	switch(err)
	{
		case ERROR_INVALID_BLOCK:		LOG_BREAK("ERROR_INVALID_BLOCK: The function referenced is too small to be detoured."); break;
		case ERROR_INVALID_HANDLE:		LOG_BREAK("ERROR_INVALID_HANDLE: The ppPointer parameter is null or points to a null pointer."); break;
		case ERROR_INVALID_OPERATION:	LOG_BREAK("ERROR_INVALID_OPERATION: No pending transaction exists."); break;
		case ERROR_NOT_ENOUGH_MEMORY:	LOG_BREAK("ERROR_NOT_ENOUGH_MEMORY: Not enough memory exists to complete the operation."); break;
		case NO_ERROR: break;
		default: __debugbreak(); break; // Unreachable
	}
	return err;
}

// https://github.com/microsoft/Detours/wiki/DetourDetach
inline LONG CheckDetourDetach(LONG err)
{
	switch(err)
	{
		case ERROR_INVALID_BLOCK:		LOG_BREAK("ERROR_INVALID_BLOCK: The function to be detached was too small to be detoured."); break;
		case ERROR_INVALID_HANDLE:		LOG_BREAK("ERROR_INVALID_HANDLE: The ppPointer parameter is null or references a null address."); break;
		case ERROR_INVALID_OPERATION:	LOG_BREAK("ERROR_INVALID_OPERATION: No pending transaction exists."); break;
		case ERROR_NOT_ENOUGH_MEMORY:	LOG_BREAK("ERROR_NOT_ENOUGH_MEMORY: Not enough memory to complete the operation."); break;
		case NO_ERROR: break;
		default: __debugbreak(); break; // Unreachable
	}
	return err;
}

// https://github.com/microsoft/Detours/wiki/DetourTransactionCommit
inline LONG CheckDetourTransactionCommit(LONG err)
{
	switch(err)
	{
		case ERROR_INVALID_DATA:		LOG_BREAK("ERROR_INVALID_DATA: Target function was changed by third party between steps of the transaction."); break;
		case ERROR_INVALID_OPERATION:	LOG_BREAK("ERROR_INVALID_OPERATION: No pending transaction exists."); break;
		case NO_ERROR: break;
		default: CheckDetourAttach(err); break;
	}
	return err;
}


#define CALLSTACK_MAX_FRAMES 32

using CallstackFrames	= void*[CALLSTACK_MAX_FRAMES];
using CallstackHash		= ULONG;

struct CallstackFrameInfo
{
	char const * frameName = nullptr; // /!\ Can be nullptr if resolve fails
	char const * filename  = nullptr; // /!\ Can be nullptr if resolve fails
	uint16_t lineNumber = 0;
	uint16_t frameIndex = 0;
};

class DbgHelper
{
	public:
		static DbgHelper & Instance()
		{
			static DbgHelper s_instance;
			return s_instance;
		}

		static bool Initialize() { return Instance().init(); }

		static uint16_t GetCallstack(CallstackFrames & callstackFrames, CallstackHash * callstackHash = nullptr)
		{
			return RtlCaptureStackBackTrace(0, CALLSTACK_MAX_FRAMES, callstackFrames, callstackHash);
		}

		using CallstackWalker = void(*)(CallstackFrameInfo const & info, void * userdata);

		static void WalkCallstack(CallstackFrames const & callstackFrames, uint16_t frameStart, uint16_t frameCount, CallstackWalker walker, void * userdata = nullptr)
		{
			const HANDLE process = Instance().m_process;

			if(!process) return;

			std::lock_guard<std::mutex> lockDbgHelp(Instance().m_mutex);

			const size_t MaxNameLen = 255;
			SYMBOL_INFO* symInfo  = (SYMBOL_INFO*) alloca(sizeof(SYMBOL_INFO) + (MaxNameLen + 1) * sizeof(TCHAR));
			symInfo->SizeOfStruct = sizeof(SYMBOL_INFO);
			symInfo->MaxNameLen   = MaxNameLen;

			IMAGEHLP_LINE64 lineInfo;
			lineInfo.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

			DWORD64 symDisplacement = 0;

			CallstackFrameInfo callstackFrameInfo;
			for(uint16_t i = frameStart; i < frameCount; ++i)
			{
				const DWORD64 address = (DWORD64)callstackFrames[i];

				callstackFrameInfo.frameName	= nullptr;
				callstackFrameInfo.frameIndex	= i;
				callstackFrameInfo.filename		= nullptr;
				callstackFrameInfo.lineNumber	= 0;

				if(SymFromAddr(process, address, &symDisplacement, symInfo))
				{
					callstackFrameInfo.frameName = symInfo->Name;

					DWORD displacement = 0;
					if(SymGetLineFromAddr64(process, address, &displacement, &lineInfo))
					{
						callstackFrameInfo.filename = lineInfo.FileName;
						callstackFrameInfo.lineNumber = static_cast<uint16_t>(lineInfo.LineNumber);
					}
				}

				walker(callstackFrameInfo, userdata);
			}
		}

		static void PrintStackTrace()
		{
			CallstackFrames callstackFrames;
			const uint16_t callstackFrameCount = GetCallstack(callstackFrames);

			WalkCallstack(callstackFrames, 0, callstackFrameCount,
				[](CallstackFrameInfo const & info, void *)
				{
					LOG("  %s(%d): %s", 
						info.filename ? info.filename : "<Unknown file>",
						uint32_t(info.lineNumber),
						info.frameName ? info.frameName : "<Unknown frame>"
					);
				}
			);
		}

	private:
		DbgHelper()	{ }

		~DbgHelper()
		{
			if(m_process)
				SymCleanup(m_process);
		}

		bool init()
		{
			std::lock_guard<std::mutex> lockDbgHelp(Instance().m_mutex);

			if(!m_bInitialized)
			{
				SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_INCLUDE_32BIT_MODULES | SYMOPT_UNDNAME);
				m_process = GetCurrentProcess();
				m_bInitialized = SymInitialize(m_process, nullptr, TRUE);
			}

			return m_bInitialized;
		}

	private:
		HANDLE m_process	= nullptr;
		std::mutex m_mutex	= { };
		bool m_bInitialized = false;
};

struct CallstackEntry
{
	CallstackFrames frames;
	size_t hitCount		= 0;
	size_t accValue		= 0;
	uint16_t frameCount = 0;
};

class ValueTracker
{
	public:
		ValueTracker(size_t maxCallstackCount): m_maxCallstackCount(maxCallstackCount)
		{
			DbgHelper::Initialize();

			m_allocCallstackHashes = static_cast<CallstackHash *>(malloc(maxCallstackCount * sizeof(CallstackHash)));
			if(!m_allocCallstackHashes)
			{
				LOG("ValueTracker: failed to allocate m_allocCallstackHashes");
				m_bInitialized = false;
				return;
			}
			
			m_allocCallstacks = static_cast<CallstackEntry *>(malloc(maxCallstackCount * sizeof(CallstackEntry)));
			if(!m_allocCallstacks)
			{
				LOG("ValueTracker: failed to allocate m_allocCallstacks");
				free(m_allocCallstackHashes);
				m_allocCallstackHashes = nullptr;
				m_bInitialized = false;
				return;
			}
			m_bInitialized = true;
		}

		~ValueTracker()
		{
			free(m_allocCallstackHashes);
			free(m_allocCallstacks);
		}

		CallstackHash registerAllocCallstack(size_t value)
		{
			++m_totalHitCount;
			m_totalAccValue += value;

			if(!m_bInitialized) return 0;
			if(m_callstackCount == m_maxCallstackCount)
			{
				LOG("Maximum number of tracked callstacks reached");
				return 0;
			}

			std::lock_guard<std::mutex> lock(m_mutex);

			CallstackHash  & callstackHash  = m_allocCallstackHashes[m_callstackCount];
			CallstackEntry & callstackEntry = m_allocCallstacks[m_callstackCount];
			callstackEntry.frameCount = DbgHelper::GetCallstack(callstackEntry.frames, &callstackHash);

			// Try to find the callstack in the currently registered callstacks:
			// Note: this is O(n). Could be O(1) with a fixed-size hashmap...
			size_t idx;
			for(idx = 0; idx < m_callstackCount &&(callstackHash != m_allocCallstackHashes[idx]); ++idx);

			if(idx < m_callstackCount)
			{
				m_allocCallstacks[idx].hitCount++;
				m_allocCallstacks[idx].accValue += value;
			}
			else
			{
				callstackEntry.hitCount = 1;
				callstackEntry.accValue = value;
				m_callstackCount++;
			}

			return callstackHash;
		}

		size_t getAllocCallstackCount() const { return m_callstackCount; }
		size_t getTotalHitCount()		const { return m_totalHitCount; }
		size_t getTotalAccValue()		const { return m_totalAccValue; }

		void printAllocCallstacks() const
		{
			printAllocCallstacks(m_maxCallstackCount);
		}

		void printAllocCallstacks(size_t numCallstackToDisplay) const
		{
			if(!m_bInitialized) return;

			char fmtBuffer[256];
			HumanReadableByteCount(fmtBuffer, m_totalAccValue);

			LOG("\n=====================\n");
			LOG("Callstack count: %zd", m_callstackCount);
			LOG("Total allocation count: %zd", m_totalHitCount);
			LOG("Total allocation size:  %s (%zdB)\n\n", fmtBuffer, m_totalAccValue);

			size_t totalValue = 0;

			const auto PrintCallstack = [&](size_t idx, CallstackHash callstackHash, CallstackEntry const & entry)
			{
				totalValue += entry.accValue;
				
				HumanReadableByteCount(fmtBuffer, entry.accValue);
				float invTotalAllocSizePercent = 100.f / m_totalAccValue;
				
				LOG("Callstack #%zd [%#010x] (%zd hit%s) (%s %.4f%%, cumulated %.4f%%) ",
					idx, callstackHash, entry.hitCount, entry.hitCount > 1 ? "s" : "",
					fmtBuffer, float(entry.accValue) * invTotalAllocSizePercent,
					float(totalValue) * invTotalAllocSizePercent
				);

				DbgHelper::WalkCallstack(entry.frames, 2, entry.frameCount,
					[](CallstackFrameInfo const & info, void *)
					{
						LOG("  %s(%d): %s", 
							info.filename ? info.filename : "<Unknown file>",
							uint32_t(info.lineNumber),
							info.frameName ? info.frameName : "<Unknown frame>"
						);
					}
				);

				LOG("");
			};

			const size_t maxDisplayedCallstackCount = std::min<size_t>(m_callstackCount, numCallstackToDisplay);
			size_t * sortedCallstacks = static_cast<size_t*>(alloca(m_callstackCount * sizeof(size_t)));
			if(sortedCallstacks)
			{
				for(uint16_t i = 0; i < m_callstackCount; sortedCallstacks[i++] = i);

				std::sort(sortedCallstacks, sortedCallstacks + m_callstackCount,
					[this](size_t lhs, size_t rhs)
					{
						return m_allocCallstacks[lhs].accValue > m_allocCallstacks[rhs].accValue;
					}
				);

				for(size_t i = 0; i < maxDisplayedCallstackCount; ++i)
				{
					size_t sortedIdx = sortedCallstacks[i];
					PrintCallstack(i, m_allocCallstackHashes[sortedIdx], m_allocCallstacks[sortedIdx]);
				}
			}
			else
			{
				for(size_t i = 0; i < maxDisplayedCallstackCount; ++i)
					PrintCallstack(i, m_allocCallstackHashes[i], m_allocCallstacks[i]);
			}
		}


	private:
		std::mutex m_mutex;
		CallstackHash  * m_allocCallstackHashes = nullptr;
		CallstackEntry * m_allocCallstacks = nullptr;
		size_t m_callstackCount = 0;
		const size_t m_maxCallstackCount = 0;
		size_t m_totalHitCount = 0;
		size_t m_totalAccValue = 0;
		bool m_bInitialized = false;
};

ValueTracker s_MemAllocTracker(4096);

// NtAllocateVirtualMemory /////////////////////////////////////////////////////

// https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/ntifs/nf-ntifs-ntallocatevirtualmemory
// https://www.tophertimzen.com/resources/cs407/slides/week03_01-MemoryInternals.html#slide33

#ifndef NTSTATUS
#define NTSTATUS LONG
#endif

typedef NTSYSCALLAPI NTSTATUS NTALLOCATEVIRTUALMEMORY(
	_In_        HANDLE ProcessHandle,
	_Inout_     PVOID *BaseAddress,
	_In_        ULONG_PTR ZeroBits,
	_Inout_     PSIZE_T RegionSize,
	_In_        ULONG AllocationType,
	_In_        ULONG Protect
);

typedef NTALLOCATEVIRTUALMEMORY * NtAllocateVirtualMemoryFuncPtr;

NtAllocateVirtualMemoryFuncPtr RealNtAllocateVirtualMemory = nullptr;


NTSTATUS NTAPI DetouredNtAllocateVirtualMemory(
	_In_        HANDLE ProcessHandle,
	_Inout_     PVOID *BaseAddress,
	_In_        ULONG_PTR ZeroBits,
	_Inout_     PSIZE_T RegionSize,
	_In_        ULONG AllocationType,
	_In_        ULONG Protect
)
{
	NTSTATUS status = RealNtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

	if(AllocationType & (MEM_COMMIT|MEM_PHYSICAL))
	{
		const size_t byteSize = RegionSize ? *RegionSize : 0;
		s_MemAllocTracker.registerAllocCallstack(byteSize);
	}

	return status;
}


BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    if(DetourIsHelperProcess()) { return TRUE; }

	if(dwReason == DLL_PROCESS_ATTACH)
	{
		DetourRestoreAfterWith();

		LOG(" DLLs:");
		for(HMODULE hModule = NULL;(hModule = DetourEnumerateModules(hModule)) != NULL;)
		{
			CHAR szName[MAX_PATH] = {0};
			GetModuleFileNameA(hModule, szName, sizeof(szName) - 1);
			LOG("  0x%p: %s",(void*)hModule, szName);
		}

		HINSTANCE hinstStub = GetModuleHandle("ntdll.dll");
		RealNtAllocateVirtualMemory = (NtAllocateVirtualMemoryFuncPtr)GetProcAddress(hinstStub, "NtAllocateVirtualMemory");

		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());

		CheckDetourAttach(DetourAttach(&(PVOID&)RealNtAllocateVirtualMemory, DetouredNtAllocateVirtualMemory));

		CheckDetourTransactionCommit(DetourTransactionCommit());
	}
	else if(dwReason == DLL_PROCESS_DETACH)
	{
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		
		CheckDetourDetach(DetourDetach(&(PVOID&)RealNtAllocateVirtualMemory, DetouredNtAllocateVirtualMemory));

		CheckDetourTransactionCommit(DetourTransactionCommit());

		s_MemAllocTracker.printAllocCallstacks(10);
	}

    return TRUE;
}
