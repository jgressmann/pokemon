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

#ifdef POKEMON_NDEBUG

#define luaD_setup(...) PKMN_E_NONE
#define luaD_teardown(...)
#define luaD_register(...) PKMN_E_NONE
#define luaD_unregister(...) PKMN_E_NONE
#define luaD_push_location(...) PKMN_E_NONE
#define luaD_pop_location(...) PKMN_E_NONE
#define luaD_select(...) PKMN_E_NONE

#else

#define luaD_setup(...) pokemon_setup(__VA_ARGS__)
#define luaD_teardown(...) pokemon_teardown(__VA_ARGS__)
#define luaD_register(...) pokemon_register(__VA_ARGS__)
#define luaD_unregister(...) pokemon_unregister(__VA_ARGS__)
#define luaD_push_location(...) pokemon_push_location(__VA_ARGS__)
#define luaD_pop_location(...) pokemon_pop_location(__VA_ARGS__)
#define luaD_select(...) pokemon_select(__VA_ARGS__)

int
pokemon_setup(int* argc, char** argv);

void
pokemon_teardown();

int
pokemon_register(lua_State* L);

int
pokemon_unregister(lua_State* L);

int
pokemon_push_location(lua_State* L, const char* filePath, int line);

int
pokemon_pop_location(lua_State* L);

int
pokemon_select(lua_State* L);


#endif

#ifdef __cplusplus
}
#endif

#endif // POKEMON_H
