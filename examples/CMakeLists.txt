include_directories(
    .
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_BINARY_DIR}
)

set( CMAKE_C_FLAGS "-ggdb -Wall -O0" )

function(example_prog name)
    set( SOURCES ${PROJECT_SOURCE_DIR}/examples/${name}.c )
    add_executable( ${name} ${SOURCES} )
    target_link_libraries( ${name} libsecpolicy_static )
endfunction()

function(example name)
    example_prog(${name}-server)
    example_prog(${name}-client)
endfunction()

example(challenge)
example_prog(basic-server)
