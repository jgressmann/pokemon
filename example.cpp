#include <cstdio>
#include <cstdlib>
#include <cassert>
#include <cstring>

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


using namespace std;

// Sleep function exported to Lua
static
int
Zzzzz(lua_State* L) {
    (void)luaD_push_location(L, __FILE__, __LINE__);
    sleep(lua_tointeger(L, 1));
    (void)luaD_pop_location(L);
    return 0;
}

static int s_Line = -1;
static
int
ResolveLocation( lua_State* L,
                 const lua_Debug* dbg,
                 const char** filePath,
                 int* line) {
    assert(L);
    assert(dbg);
    assert(filePath);
    assert(line);

    if (dbg->source && strcmp(dbg->source, "EXAMPLE") == 0) {
        *filePath = __FILE__;
        *line = s_Line;
        return PKMN_LC_RESOLVED;
    }

    return PKMN_LC_FALLBACK;
}

int
main(int argc, char** argv) {

    // set up pokemon
    int error = luaD_setup(&argc, argv);

    if (error) {
        fprintf(stderr, "Pokemon setup error %d\n", error);
        return error;
    }

    // set location resolve callback
    (void)luaD_set_location_callback(ResolveLocation);

    // create Lua state and register packages
#if LUA_VERSION_NUM >= 502
    lua_State* L = luaL_newstate();
#else
    lua_State* L = lua_open();
#endif

    // setup default libraries
    luaL_openlibs(L);

    // register a global C function with name 'sleep'
    lua_pushcfunction(L, Zzzzz);
    lua_setglobal(L, "sleep");

    // register Lua state with the debugger
    (void)luaD_register(L);

    // register inline Lua code with the debugger
    const char LuaCode[] = "dofile(\"" POKEMON_LUA_SOURCE_DIR  "/example.lua\")"; s_Line = __LINE__ + 1;

    // load inline code
    error = luaL_loadbuffer(L, LuaCode, sizeof(LuaCode) - 1, "EXAMPLE");

    if (error) {
        fprintf(stderr, "luaL_loadbuffer error %d\n", error);
    } else {
        error =  lua_pcall(L, 0, LUA_MULTRET, 0);
        if (error) {
            const char* errorMessage = lua_tostring(L, 1);
            fprintf(stderr, "%s\n", errorMessage);
        }
    }

    // unregister Lua state from the debugger
    (void)luaD_unregister(L);

    // destroy Lua state
    lua_close(L);

    // tear down pokemon
    luaD_teardown();

    return error;
}
