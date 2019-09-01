project(DetoursAlloc)

set(DETOURS_ALLOC_SOURCES
    # .def file for the dll exports
    src/DetoursAlloc.def
    # The patches
    src/DetoursAlloc.cpp
)

set(DETOURS_ALLOC_HEADERS

)

add_library(DetoursAlloc 
    SHARED # We want to create a detours dll
    ${DETOURS_ALLOC_SOURCES} ${DETOURS_ALLOC_HEADERS}
)
target_include_directories(DetoursAlloc PRIVATE include)

target_link_libraries(DetoursAlloc
    PRIVATE
        Shlwapi.lib
		DbgHelp.lib
        Detours::Detours
)

target_compile_definitions(DetoursAlloc
    PRIVATE
        # For faster build
        -DWIN32_LEAN_AND_MEAN
        -DNOCOMM
        # To remove annoying stuff
        -DNOMINMAX
		-D_CRT_SECURE_NO_WARNINGS
)
