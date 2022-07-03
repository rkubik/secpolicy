include_directories(
    .
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/src
    ${PROJECT_BINARY_DIR}
)
add_compile_options("-std=c++17" "-O0" "-ggdb")

function(addTest name)
    add_executable(${name} ${name}.cpp)
    target_link_libraries("${name}" libsecpolicy_static)
    add_test(NAME "${name}" COMMAND "${name}")
endfunction()

addTest(PermsTest)
addTest(UidTest)
addTest(GidTest)
addTest(CallbackTest)
addTest(UserTest)
addTest(GroupTest)
addTest(ProgramTest)
addTest(ChallengeTest)
addTest(CredsTest)
