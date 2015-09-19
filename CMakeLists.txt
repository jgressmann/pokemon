project(pokemon)
cmake_minimum_required(VERSION 2.8)


include(${CMAKE_ROOT}/Modules/FindPkgConfig.cmake)

pkg_check_modules(LUA51 REQUIRED lua5.1)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(STATUS "64 bit arch")
    set(M64 1)
else()
    message(STATUS "32 bit arch")
    set(M32 1)
endif()

if(CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wall -fno-rtti")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
endif(CMAKE_COMPILER_IS_GNUCXX)

set(LIBPOKEMONSRC
    src/pokemon.cpp
    src/pokemon.h
    src/json.c
    src/json.h
    src/buffer.c
    src/buffer.h
)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    execute_process(COMMAND uname -a OUTPUT_VARIABLE ARCH)
    add_definitions(
        -D_GNU_SOURCE
        -D_LARGEFILE64_SOURCE
        -D_FILE_OFFSET_BITS=64
        -DPOKEMON_LINUX)

    if(CMAKE_COMPILER_IS_GNUCXX)
        if(M64)
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64")
            #set(CMAKE_LD_FLAGS "${CMAKE_LD_FLAGS} -m64")
            if("${ARCH}" MATCHES "x86_64")
                set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcx16")
                set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcx16")
                #set(CMAKE_LD_FLAGS "${CMAKE_LD_FLAGS} -mcx16")
            endif()
        else()
            set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32")
        endif()
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pthread")
        set(CMAKE_LD_FLAGS "${CMAKE_LD_FLAGS} -pthread")
    endif(CMAKE_COMPILER_IS_GNUCXX)

    set(LIBPOKEMONSRC
        ${LIBPOKEMONSRC}
        src/linux.c
        src/linux.h
    )
endif()

add_library(pokemon-static STATIC ${LIBPOKEMONSRC})
target_link_libraries(pokemon-static ${LUA51_LIBRARIES} ${POKEMON_EXTRA_LIBS})
target_include_directories(pokemon-static PUBLIC ${LUA51_INCLUDE_DIRS})
set_target_properties(pokemon-static PROPERTIES OUTPUT_NAME pokemon)

add_library(pokemon-shared SHARED ${LIBPOKEMONSRC})
target_link_libraries(pokemon-shared ${LUA51_LIBRARIES} ${POKEMON_EXTRA_LIBS})
target_include_directories(pokemon-shared PUBLIC ${LUA51_INCLUDE_DIRS})
set_target_properties(pokemon-shared PROPERTIES OUTPUT_NAME pokemon)

add_executable(test src/test.cpp)
target_link_libraries(test pokemon-shared)