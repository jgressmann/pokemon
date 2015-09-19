/* For copyright information see the LICENSE file */

#ifndef POKEMON_H
#define POKEMON_H

#ifdef __cplusplus
extern "C" {
#endif

/* From lua.h */
typedef struct lua_State lua_State;

#define PKMN_E_NONE                      0
#define PKMN_E_NOT_INITIALIZED          -1
#define PKMN_E_OUT_OF_RESOURCES         -2
#define PKMN_E_INVALID_PARAM            -3
#define PKMN_E_ALREADY_REGISTERED       -4
#define PKMN_E_CHECK_SYSTEM_ERROR       -5
#define PKMN_E_NOT_REGISTERED           -6

int
luaD_setup(int* argc, char** argv);

void
luaD_teardown();

int
luaD_register(lua_State* L);

int
luaD_unregister(lua_State* L);

int
luaD_push_location(lua_State* L, const char* filePath, int line);

int
luaD_pop_location(lua_State* L);

#ifdef __cplusplus
}
#endif
#endif // POKEMON_H
