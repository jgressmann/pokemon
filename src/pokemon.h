/* For copyright information see the LICENSE file */

#ifndef POKEMON_H
#define POKEMON_H

#ifdef __cplusplus
extern "C" {
#endif

/* From lua.h */
typedef struct lua_State lua_State;
struct lua_Debug;

/* Pokemon error codes */
#define PKMN_E_NONE                      0
#define PKMN_E_NOT_INITIALIZED          -1
#define PKMN_E_OUT_OF_RESOURCES         -2
#define PKMN_E_INVALID_PARAM            -3
#define PKMN_E_ALREADY_REGISTERED       -4
#define PKMN_E_CHECK_SYSTEM_ERROR       -5
#define PKMN_E_NOT_REGISTERED           -6

/* Pokemon location resolve callback */
typedef int (*pokemon_location_callback_t)(
    lua_State* L,
    const lua_Debug* dbg,
    const char** filePath,
    int* line);

/* Possible location callback results */
#define PKMN_LC_NONE                    0 /* No location could be resolved */
#define PKMN_LC_FALLBACK                1 /* Perform default location resolution */
#define PKMN_LC_RESOLVED                2 /* Location resolved */


#ifdef POKEMON_NDEBUG

#define luaD_setup(...) PKMN_E_NONE
#define luaD_teardown(...)
#define luaD_register(...) PKMN_E_NONE
#define luaD_unregister(...) PKMN_E_NONE
#define luaD_push_location(...) PKMN_E_NONE
#define luaD_pop_location(...) PKMN_E_NONE
#define luaD_select(...) PKMN_E_NONE
#define luaD_set_location_callback(...) PKMN_E_NONE

#else

#define luaD_setup(...) pokemon_setup(__VA_ARGS__)
#define luaD_teardown(...) pokemon_teardown(__VA_ARGS__)
#define luaD_register(...) pokemon_register(__VA_ARGS__)
#define luaD_unregister(...) pokemon_unregister(__VA_ARGS__)
#define luaD_push_location(...) pokemon_push_location(__VA_ARGS__)
#define luaD_pop_location(...) pokemon_pop_location(__VA_ARGS__)
#define luaD_select(...) pokemon_select(__VA_ARGS__)
#define luaD_set_location_callback(...) pokemon_set_location_callback(__VA_ARGS__)

/* Setup pokemon library
 *
 * Call this once before any other pokemon function.
 * */
int
pokemon_setup(int* argc, char** argv);

/* Teardown pokemon library
 *
 * Call this once when you are finished using pokemon.
 * */
void
pokemon_teardown();

/* Register a Lua state with the debugger
 *
 * This permits to debug the Lua state once it's
 * selected.
 * */
int
pokemon_register(lua_State* L);

/* Unregister a Lua state with the debugger */
int
pokemon_unregister(lua_State* L);

/* Push a location (file, line) on the location stack
 *
 * This permits to break in code for which no
 * file is known to Lua.
 * */
int
pokemon_push_location(lua_State* L, const char* filePath, int line);

/* Pop a location off the location stack
 * */
int
pokemon_pop_location(lua_State* L);

/* Select the Lua state for the debugger
 *
 * Only the selected Lua state is visible
 * in the debugger
 * */
int
pokemon_select(lua_State* L);

/* Set the function to call when pokemon needs to resolve a location
 *
 * Set to NULL to use default location resolution.
 * If you set this to non-NULL your function must return one
 * of the PKMN_LC_* values and if the location is resolved, set filePath
 * and line to a (absolute file) path that can be opened by the debugger.
 * */
int
pokemon_set_location_callback(pokemon_location_callback_t callback);


#endif

#ifdef __cplusplus
}
#endif

#endif // POKEMON_H
