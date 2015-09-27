project(pokemon)
cmake_minimum_required(VERSION 2.8)


include(${CMAKE_ROOT}/Modules/FindPkgConfig.cmake)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(STATUS "64 bit arch")
    set(M64 1)
else()
    message(STATUS "32 bit arch")
    set(M32 1)
endif()

if(CMAKE_COMPILER_IS_GNUCXX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pipe -fPIC -std=c++11 -Wall -fno-rtti")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pipe -fPIC -Wall")
endif(CMAKE_COMPILER_IS_GNUCXX)

set(LIBPOKEMONSRC
    src/pokemon.cpp
    src/pokemon.h
    src/json.c
    src/json.h
    src/buffer.c
    src/buffer.h
    src/platform.h
)



# Set this to 1 to print messages sent to /received from QtCreator
# to stderr
add_definitions(-DPOKEMON_DEBUG_MESSAGES=0)

# Uncomment this to disable the debugger stub
#add_definitions(-DPOKEMON_NDEBUG)

if(CMAKE_SYSTEM_NAME MATCHES "Linux")
    pkg_check_modules(LUA51 REQUIRED lua5.1)
    set(LUA_INCLUDE_DIRS ${LUA51_INCLUDE_DIRS})
    set(LUA_LIBRARIES ${LUA51_LIBRARIES})
    #set(LUA_INCLUDE_DIRS /home/jean/lua-5.2.4/src)
    #set(LUA_LIBRARIES /home/jean/lua-5.2/lib/liblua.a -ldl)
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
            if("${ARCH}" MATCHES "x86_64")
                set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mcx16")
                set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -mcx16")
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
    )
elseif(CMAKE_SYSTEM_NAME MATCHES "Windows")
    add_definitions(
        -D_CRT_SECURE_NO_WARNINGS
        -DPOKEMON_WINDOWS)

    set(LIBPOKEMONSRC
        ${LIBPOKEMONSRC}
        src/windows.c
    )
endif()

add_library(pokemon STATIC ${LIBPOKEMONSRC})
target_link_libraries(pokemon ${LUA_LIBRARIES} ${POKEMON_EXTRA_LIBS})
target_include_directories(pokemon PUBLIC ${LUA_INCLUDE_DIRS})

if(POKEMON_EXAMPLE)
    add_executable(pokemon-example example.cpp)
    target_link_libraries(pokemon-example pokemon)
    target_include_directories(pokemon-example PRIVATE src)
    add_definitions(-DPOKEMON_LUA_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
endif()
