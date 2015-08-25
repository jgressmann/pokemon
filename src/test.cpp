#include <cstdio>
#include <cstdlib>
#include <unistd.h>

extern "C" {
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
}

#include "pokemon.h"

static
int
Sleep(lua_State* L) {
    luaD_push_location(L, __FILE__, __LINE__);
    /*
    lua_Debug dbg;
    for (int i = 0 ; lua_getstack(L, i, &dbg);++i) {
           lua_getinfo(L,"nSu", &dbg);
           fprintf(stdout, "%02d %s(", i, dbg.name);
           int locals = 0;
           const char* name;
           for (int j = 1; (name = lua_getlocal(L, &dbg, j)) != NULL; ++j, ++locals) {
               const char* value = lua_tostring(L, -1);
               if (j > 1) {
                   fprintf(stdout, ", ");
               }
               fprintf(stdout, "%s=%s", name, value);
               lua_pop(L, 1);
           }

           fprintf(stdout, ")\n");
           fflush(stdout);

    }
    */

    sleep(lua_tointeger(L, 1));
    luaD_pop_location(L);
    return 0;
}


int
main(int argc, char** argv) {

    int error = luaD_setup(&argc, argv);

    if (error) {
        fprintf(stderr, "Pokemon setup error %d\n", error);
        return error;
    }

    lua_State* L = lua_open();
    luaL_openlibs(L);

    lua_pushcfunction(L, Sleep);
    lua_setglobal(L, "sleep");


    luaD_register(L);

    //(luaL_loadstring(L, str) || lua_pcall(L, 0, LUA_MULTRET, 0))
    //luaD_push_location(L, __FILE__, __LINE__ + 2);
    error = luaL_loadstring(L,
//"function foo(s)\n"
//"   print(\"Hello world!\")\n"
//"   sleep(s)\n"
//"end\n"
//"while true do\n"
//"   foo(1)\n"
//"end\n");
"dofile(\"/home/jean/lua.js\")");

    if (!error) {
        error =  lua_pcall(L, 0, LUA_MULTRET, 0);
        if (error) {
            const char* errorMessage = lua_tostring(L, 1);
            fprintf(stderr, "%s\n", errorMessage);
        }
    }


    luaD_unregister(L);

    luaD_teardown();
    return error;

}
