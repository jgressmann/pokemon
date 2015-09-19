#include <cstdio>
#include <cstdlib>

extern "C" {
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
}


#if defined(_WIN32) || defined(_WIN64)
#   include <windows.h>
#   define sleep(x) Sleep((DWORD)(x*1000))
#else
#   include <unistd.h>
#endif


#include "pokemon.h"

static
int
xSleep(lua_State* L) {
    luaD_push_location(L, __FILE__, __LINE__);
    sleep(lua_tointeger(L, 1));
    luaD_pop_location(L);
    return 0;
}

using namespace std;

int
main(int argc, char** argv) {

    // set up pokemon
    int error = luaD_setup(&argc, argv);

    if (error) {
        fprintf(stderr, "Pokemon setup error %d\n", error);
        return error;
    }

    // create Lua state and register packages
    lua_State* L = lua_open();
    luaL_openlibs(L);

    // register a global C function with name 'sleep'
    lua_pushcfunction(L, xSleep);
    lua_setglobal(L, "sleep");

    // register Lua state with the debugger
    luaD_register(L);

    // register inline Lua code with the deugger
    luaD_push_location(L, __FILE__, __LINE__ + 2);
    error = luaL_loadstring(L,
        "dofile(\"/home/jean/build/pokemon/debug/lua.js\")"
    );

    if (error) {
        fprintf(stderr, "lua_loadstring error %d\n", error);
    } else {
        error =  lua_pcall(L, 0, LUA_MULTRET, 0);
        if (error) {
            const char* errorMessage = lua_tostring(L, 1);
            fprintf(stderr, "%s\n", errorMessage);
        }
    }

    // unregister Lua state from the debugger
    luaD_unregister(L);

    // tear down pokemon
    luaD_teardown();

    return error;
}
