cmake_minimum_required(VERSION 3.16)

project(hash_verifier_gui_cpp LANGUAGES CXX)

add_executable(hash_verifier_gui WIN32 main.cpp)

target_compile_features(hash_verifier_gui PRIVATE cxx_std_17)

target_compile_definitions(hash_verifier_gui PRIVATE UNICODE _UNICODE)

if (MINGW)
    target_compile_options(hash_verifier_gui PRIVATE -municode)
    target_link_options(hash_verifier_gui PRIVATE -municode)
endif()

target_link_libraries(hash_verifier_gui PRIVATE bcrypt comdlg32)

if (EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/exe_security_agent.cpp")
    add_executable(exe_security_agent exe_security_agent.cpp)
    target_compile_features(exe_security_agent PRIVATE cxx_std_17)
    target_compile_definitions(exe_security_agent PRIVATE UNICODE _UNICODE)

    if (MINGW)
        target_compile_options(exe_security_agent PRIVATE -municode)
        target_link_options(exe_security_agent PRIVATE -municode)
    endif()

    target_link_libraries(exe_security_agent PRIVATE bcrypt wintrust crypt32)
endif()
