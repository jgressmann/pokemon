/* For copyright information see the LICENSE file */

#include "pokemon.h"
#include "json.h"
#include "buffer.h"
#include "platform.h"

extern "C" {
#include <lua.h>
#include <lauxlib.h>
}

#include <stdint.h>
#include <inttypes.h>

#include <cstdio>
#include <cctype>
#include <cstring>
#include <thread>
#include <atomic>
#include <unordered_map>
#include <mutex>
#include <condition_variable>
#include <vector>
#include <deque>
#include <cassert>
#include <tuple>
#include <cstdarg>
#include <functional>
#include <algorithm>
#include <cstdarg>
#include <memory>

#ifdef POKEMON_LINUX
#   include <arpa/inet.h>
#endif

#ifdef POKEMON_WINDOWS
#   include <Winsock2.h>
#   define snprintf _snprintf
#endif

#define POKEMON_UNUSED(x) (void)x
#define POKEMON_DEBUG_MESSAGES 1
#define POKEMON_PTR_TO_STRING(p, name) \
    char __PtrBuffer[sizeof(void*)*3]; \
    snprintf(__PtrBuffer, sizeof(__PtrBuffer), sizeof(void*) == 4 ? ("0x%08" PRIxPTR) : ("0x%016" PRIxPTR), (uintptr_t)p); \
    const char* const name = __PtrBuffer


#if LUA_VERSION_NUM >= 502
#   define lua_objlen lua_rawlen
#endif

namespace
{
static const char POKEMONTABLE[] = "__PKMNT";
static const char METATABLE[] = "__metatable";
static const char ADDRESS[] = "__address";

inline
bool
IsReservedKey(const char* key)
{
    return  strcmp(METATABLE, key) == 0 ||
            strcmp(ADDRESS, key) == 0;
}

inline
int
HandleToLuaIndex(int x) {
    return x;
}

const int GlobalTableHandle = 1;

enum {
    Pokemon_Locations = 1,
    Pokemon_Handles,
    Pokemon_RefObjects,
    Pokemon_Count = Pokemon_Handles
};

void
GetPokemonTables(lua_State* L, ...) {
    const int before = lua_gettop(L);
    lua_getglobal(L, POKEMONTABLE);
    assert(lua_type(L, -1) == LUA_TTABLE);

    va_list val;
    va_start(val, L);

    int tables = 0;

    for (int tableId = va_arg(val, int); tableId; tableId = va_arg(val, int), ++tables) {
        lua_rawgeti(L, -1, tableId);
        assert(lua_type(L, -1) == LUA_TTABLE);
        lua_insert(L, -2);
    }
    va_end(val);

    lua_pop(L, 1); // pokemon table

    const int after = lua_gettop(L);
    assert(before + tables == after);
    POKEMON_UNUSED(before);
    POKEMON_UNUSED(after);
}

inline
void
GetPokemonTable(lua_State* L, int tableId) {
    GetPokemonTables(L, tableId, 0);
}

const int ValueHandleOffset = 1 << 16;

inline
bool
IsValueHandle(int x) {
    return x <= -1;
}

inline
bool
IsObjectHandle(int x) {
    return !IsValueHandle(x);
}

class LuaPopGuard
{
public:
    ~LuaPopGuard() {
        lua_pop(m_LuaState, m_Count);
    }

    LuaPopGuard(lua_State* L, int count) {
        m_LuaState = L;
        m_Count = count;
    }
private:
    lua_State* m_LuaState;
    int m_Count;
};

void LuaHook(lua_State* L, lua_Debug* d);
void Send(buffer* buffer);
buffer* MakeV8ResponseResponseHeader();
buffer* EndV8DebuggerResponse(buffer* buffer);

struct JsonValueDeleter {
    void operator()(json_value* p) {
        json_value_free(p);
    }
};

struct BufferDeleter {
    void operator()(buffer* p) {
        buf_free(p);
    }
};

typedef std::unique_ptr<json_value, JsonValueDeleter> JsonPtr;
typedef std::unique_ptr<buffer, BufferDeleter> BufferPtr;


// Based on code (C) 2011 Joseph A. Adams (joeyadams3.14159@gmail.com)
bool
Utf8WriteChar(buffer* buf, unsigned unicode)
{
    if (!buf_reserve(buf, 4)) {
        return false;
    }
    assert(unicode <= 0x10FFFF && !(unicode >= 0xD800 && unicode <= 0xDFFF));

    if (unicode <= 0x7F) {
        /* U+0000..U+007F */
        switch (unicode) {
        case '"':
        case '\\':
        case '/':
            *buf->end++ = '\\';
            *buf->end++ = unicode;
            break;
        case '\n':
            *buf->end++ = '\\';
            *buf->end++ = 'n';
            break;
        case '\r':
            *buf->end++ = '\\';
            *buf->end++ = 'r';
            break;
        case '\f':
            *buf->end++ = '\\';
            *buf->end++ = 'f';
            break;
        case '\t':
            *buf->end++ = '\\';
            *buf->end++ = 't';
            break;
        default:
            *buf->end++ = unicode;
            break;
        }
    } else if (unicode <= 0x7FF) {
        /* U+0080..U+07FF */
        *buf->end++ = 0xC0 | unicode >> 6;
        *buf->end++ = 0x80 | (unicode & 0x3F);
    } else if (unicode <= 0xFFFF) {
        /* U+0800..U+FFFF */
        *buf->end++ = 0xE0 | unicode >> 12;
        *buf->end++ = 0x80 | (unicode >> 6 & 0x3F);
        *buf->end++ = 0x80 | (unicode & 0x3F);
    } else {
        /* U+10000..U+10FFFF */
        *buf->end++ = 0xF0 | unicode >> 18;
        *buf->end++ = 0x80 | (unicode >> 12 & 0x3F);
        *buf->end++ = 0x80 | (unicode >> 6 & 0x3F);
        *buf->end++ = 0x80 | (unicode & 0x3F);
    }

    return true;
}


static
json_value*
GetKey(json_value* obj, const char* key) {
    assert(obj);
    if (obj->type != json_object) {
        return nullptr;
    }

    for (size_t i = 0; i < obj->u.object.length; ++i) {
        if (strcmp(key, obj->u.object.values[i].name) == 0) {
            return obj->u.object.values[i].value;
        }
    }

    return nullptr;
}

static
bool
Get(json_value* obj, const char* key, int64_t& result) {
    auto value = GetKey(obj, key);
    if (value && value->type == json_integer) {
        result = value->u.integer;
        return true;
    }
    return false;
}

//static
//bool
//Get(json_value* obj, const char* key, bool& result) {
//    auto value = GetKey(obj, key);
//    if (value && value->type == json_boolean) {
//        result = value->u.boolean != 0;
//        return true;
//    }
//    return false;
//}

//static
//bool
//Get(json_value* obj, const char* key, std::string& result) {
//    auto value = GetKey(obj, key);
//    if (value && value->type == json_string) {
//        result.assign(value->u.string.ptr, value->u.string.ptr + value->u.string.length);
//        return true;
//    }
//    return false;
//}

template<typename T>
static
bool
Get(json_value* obj, const char* key,  T*& ptr, size_t& len) {
    auto value = GetKey(obj, key);
    if (value && value->type == json_string) {
        ptr = value->u.string.ptr;
        len = value->u.string.length;
        return true;
    }
    return false;
}


//int
//GetPayloadChars(buffer *buf, const char *fmt, ...) {
//    assert(buf);
//    assert(fmt);
//    assert(*fmt);

//    va_list args;
//    va_start (args, fmt);
//    auto chars = vsnprintf(NULL, 0, fmt, args);
//    va_end (args);
//    return chars;
//}

template<typename T>
bool
Patch4Net(buffer *buf, unsigned char*& p, T t) {
    if (p + 4 > buf->end) {
        return false;
    }

    uint32_t x = static_cast<uint32_t>(t);
    x = htonl(x);
    *p++ = (x >> 0) & 0xff;
    *p++ = (x >> 8) & 0xff;
    *p++ = (x >> 16) & 0xff;
    *p++ = (x >> 24) & 0xff;

    return true;
}

template<typename T>
bool
Write4Net(buffer *buf, T t) {
    if (!buf_reserve(buf, 4)) {
        return false;
    }

    uint32_t x = static_cast<uint32_t>(t);
    x = htonl(x);
    *buf->end++ = (x >> 0) & 0xff;
    *buf->end++ = (x >> 8) & 0xff;
    *buf->end++ = (x >> 16) & 0xff;
    *buf->end++ = (x >> 24) & 0xff;

    return true;
}

bool
WriteRaw(buffer *buf, const char *fmt, ...) {
    assert(buf);
    assert(fmt);
    assert(*fmt);

    va_list args;
    va_start (args, fmt);
    auto chars = vsnprintf(NULL, 0, fmt, args);
    va_end (args);
    if (chars >= 0) {
        if (buf_reserve(buf, chars + 1)) {
            va_start (args, fmt);
            vsnprintf((char*)buf->end, chars + 1, fmt, args);
            va_end (args);
            buf->end += chars;
        } else {
            chars = -1;
        }
    }

    return chars >= 0;
}


bool
WritePayload(buffer *buf, const char *fmt, ...) {
    assert(buf);
    assert(fmt);
    assert(*fmt);

    va_list args;
    va_start (args, fmt);
    auto chars = vsnprintf(NULL, 0, fmt, args);
    va_end (args);
    if (chars >= 0) {
        if (buf_reserve(buf, chars + 5)) {
            Write4Net(buf, chars);
            va_start (args, fmt);
            vsnprintf((char*)buf->end, chars + 1, fmt, args);
            va_end (args);
            buf->end += chars;
        } else {
            chars = -1;
        }
    }

    return chars >= 0;
}

bool
GetLocation(lua_State* L, const lua_Debug& dbg, BufferPtr& buffer, const char*& filePath, int& line) {
    const int before = lua_gettop(L);
    bool result = true;
    line = dbg.currentline;
    filePath = "";
    if (dbg.source[0] == '@') {
        filePath = dbg.source + 1;
    } else {
        GetPokemonTable(L, Pokemon_Locations);
        int pops = 1;
        lua_rawgeti(L, -1, 1);
        ++pops;
        const int entries = (int)lua_tointeger(L, -1);
        if (entries) { // possible no one pushed a location
            lua_rawgeti(L, -2, entries + 1);
            ++pops;
            size_t len;
            const char* location = lua_tolstring(L, -1, &len);
            const char* colon = strchr(location, ':');
            assert(colon);
            const size_t filePathLen = len - (colon - location) - 1;
            buffer.reset(buf_alloc(filePathLen + 1));
            if (buffer.get()) {
                memcpy(buffer->beg, colon + 1, filePathLen);
                buffer->beg[filePathLen] = 0;
                filePath = (char*)buffer->beg;
                if (line <= 0) {
                    line = 1;
                }
                line += strtol(location, NULL, 10);
            } else {
                result = false;
            }
        }
        lua_pop(L, pops);
    }

    const int after = lua_gettop(L);
    assert(before == after);
    POKEMON_UNUSED(before);
    POKEMON_UNUSED(after);

    return result;
}

enum {
    Cmd_Unknown = -1,
    Cmd_Version,
    Cmd_Continue,
    Cmd_Backtrace,
    Cmd_Frame,
    Cmd_Evaluate,
    Cmd_Scope,
    Cmd_Lookup,
    Cmd_SetBreakpoint,
    Cmd_ClearBreakpoint,
};

enum {
    Type_Unknown = -1,
    Type_Request,
};

enum {
    Step_Count,
    Step_In,
    Step_Out,

    // [count:x|level:16:breakpoint hit:1|step:2]
    Breakpoint_Hit_Shift = 2,
    Breakpoint_Hit_Bits = 1,
    Level_Bits = 16,
    Level_Shift = Breakpoint_Hit_Shift + Breakpoint_Hit_Bits,
    Step_Count_Bits = 13,
    Step_Count_Shift = Level_Shift + Level_Bits
};

struct Breakpoint {
    Breakpoint* Next;
    std::string Regex;
    std::string Condition;
    int Line;
    int Id;
    int IgnoreCount;
    bool Enabled;
    bool Hit;
    volatile bool Dead;
};

struct LuaValue {
    int Type;
    int Handle;
    union {
        lua_Number Number;
        buffer* String;
    } Data;

    ~LuaValue();
    LuaValue() = delete;
    LuaValue(int handle);
    LuaValue(int handle, lua_Number n);
    LuaValue(int handle, bool b);
    LuaValue(int handle, const char* str, size_t len);
    LuaValue(LuaValue&& other);
    LuaValue(const LuaValue&);
    LuaValue& operator=(const LuaValue&) = delete;
    static LuaValue fromStack(lua_State* L, int index, int handle);
};


struct DebuggerState {
    lua_State* L;
    JsonPtr CurrentMessage;
    int64_t OutputSequence;
    bool Running;
    int m_NextValueHandle;
    int m_Frame;
    std::atomic<int> m_Step;
    std::mutex m_Lock;
    std::condition_variable m_Resume;
    BufferPtr m_JsonString;
    BufferPtr m_LuaStepFilePathBuffer;
    int m_LastLine;
    int m_Level;

//    std::vector<std::string> m_Stack;


    std::vector<int> m_HandlesToExpose;
    std::vector<bool> m_ExposedObjects;
    std::vector<bool> m_ExposedValues;
    typedef std::unordered_map<int, LuaValue> ValueTable;

    ValueTable m_Values;
    std::atomic<Breakpoint*> m_Breakpoints;
    int m_NextBreakpointId;
    std::vector<int> m_Hits;
    std::string m_LastFile;

    ~DebuggerState() {
        Uninit();
        for (auto* bp = m_Breakpoints.load(std::memory_order_relaxed); bp; ) {
            auto x = bp;
            bp = bp->Next;
            delete x;
        }
    }
    DebuggerState(lua_State* l) {
        m_Breakpoints = nullptr;
        L = l;
        Running = false;

        m_NextValueHandle = ValueHandleOffset;
        m_Frame = -1;
        m_LastLine = -1;
        m_Level = 0;
        OutputSequence = 0;
        m_NextBreakpointId = 0;
        m_Step.store(-1 << Step_Count_Shift | Step_Count);
    }
public:
    void Init();
    void Uninit();
    void Connect();
    void Disconnect();
    void ProcessLuaStep(lua_Debug* dbg);
    buffer* ProcessRequest(buffer* response, JsonPtr&& json);
    void Break();
    void Resume();
    void Lock() { m_Lock.lock();}
    void Unlock() { m_Lock.unlock();}
    void ResetHandleTables();
private:
    void GetStep(int& count, int& action, int& breakpointHit, int& level) const;
    bool Unbreak();
    JsonPtr PopRequest();
    int64_t GetInputSequenceNumber();
    int GetType();
    std::tuple<int, json_value*> GetCommand();
    static int GetCommand(const char* str);
    bool ProcessContinue(buffer* response, int64_t seq, json_value* args);
    bool ProcessBacktrace(buffer* response, int64_t seq, json_value* args);
    bool ProcessFrame(buffer* response, int64_t seq, json_value* args);
    bool ProcessEvaluate(buffer* response, int64_t seq, json_value* args);
    bool ProcessScope(buffer* response, int64_t seq, json_value* args);
    bool ProcessLookup(buffer* response, int64_t seq, json_value* args);
    bool ProcessSetBreakpoint(buffer* response, int64_t seq, json_value* args);
    bool ProcessClearBreakpoint(buffer* response, int64_t seq, json_value* args);
    void Mnemonize();
    int Mnemonize(
        int index,
        int handleTableIndex,
        int refTableIndex,
        int globalTableIndex,
        const char* name,
        size_t len);

    bool GetJsonString(const char* str, size_t len);
    bool WriteObject(buffer* response, int handle, int handleTableIndex, int refTableIndex);
    bool WriteValue(buffer* response, int handle);
    bool WriteRefs(buffer* response);
    bool WriteRefs(buffer* response, int handleTableIndex, int refTableIndex);
    int GetThis(lua_Debug& dbg);
    void KillBreakpoints();
    void PruneDeadBreakpoints();
};

LuaValue::~LuaValue() {
    if (LUA_TSTRING == (int)Type) {
        buf_free(Data.String);
    }
}

LuaValue::LuaValue(LuaValue&& other) {
    memcpy(this, &other, sizeof(*this));
    other.Type = LUA_TNIL;
}

LuaValue::LuaValue(const LuaValue& other) {
    memcpy(this, &other, sizeof(other));

    if (Type == LUA_TSTRING) {
        buffer*& buf = Data.String;
        const size_t len = buf_used(buf);
        buf = buf_alloc(len + 1);
        if (!buf) {
            throw std::bad_alloc();
        }

        memcpy(buf->beg, other.Data.String->beg, len + 1);
        buf->end = buf->beg + len;
    }
}

LuaValue::LuaValue(int handle)
    : Type(LUA_TNIL)
    , Handle(handle)
{
}

LuaValue::LuaValue(int handle, lua_Number n)
    : Type(LUA_TNUMBER)
    , Handle(handle)
{

    Data.Number = n;
}

LuaValue::LuaValue(int handle, bool b)
    : Type(LUA_TBOOLEAN)
    , Handle(handle)
{
    Data.Number = b ? 1 : 0;
}

LuaValue::LuaValue(int handle, const char* str, size_t len)
    : Type(LUA_TSTRING)
    , Handle(handle)
{
    buffer*& buf = Data.String;
    buf = buf_alloc(len + 1);
    if (!buf) {
        throw std::bad_alloc();
    }

    memcpy(buf->beg, str, len);
    buf->end = buf->beg + len;
    *(buf->end) = 0;
    assert(buf_used(buf) == len);
}

LuaValue
LuaValue::fromStack(lua_State* L, int index, int handle) {
    const auto type = lua_type(L, index);
    switch (type) {
    case LUA_TBOOLEAN:
        return LuaValue(handle, lua_toboolean(L, index) != 0);
    case LUA_TNUMBER:
        return LuaValue(handle, lua_tonumber(L, index));
    case LUA_TSTRING: {
        lua_pushvalue(L, index);
        size_t len;
        const char* str = lua_tolstring(L, -1, &len);
        LuaPopGuard g(L, 1);
        return LuaValue(handle, str, len);
    } break;
    case LUA_TNIL:
        return LuaValue(handle);
    default:
        throw std::exception();
    }
}


void
DebuggerState::Init() {
    m_LastLine = -1;
    m_Level = 0;
#if LUA_VERSION_NUM >= 502
    lua_sethook(L, LuaHook, LUA_HOOKCALL | LUA_HOOKCOUNT | LUA_HOOKLINE | LUA_HOOKRET | LUA_HOOKTAILCALL, 1);
#else
    lua_sethook(L, LuaHook, LUA_HOOKCALL | LUA_HOOKCOUNT | LUA_HOOKLINE | LUA_HOOKRET | LUA_HOOKTAILRET, 1);
#endif
}

void
DebuggerState::Uninit() {
    lua_sethook(L, LuaHook, 0, 0);
}


int
DebuggerState::GetThis(lua_Debug& dbg) {
    return m_NextValueHandle--;


    const bool isC = strcmp("C", dbg.what) == 0;
    if (isC) {
        return -1;
    }

    return GlobalTableHandle;
    /*
    const char* name = lua_getlocal(L, &dbg, 1);
    if (name) {
        LuaPopGuard g(L, 1);
        if (strcmp(name, "self") == 0 && lua_istable(L, -1)) {
            auto ptr = lua_topointer(L, -1);
            auto it = m_References.find(ptr);
            assert(it != m_References.end());
            return it->second.Handle;
        }
    }

    return -1;
    */
}

bool
DebuggerState::GetJsonString(const char* str, size_t len) {
    if (!m_JsonString) {
        buffer* b = buf_alloc(len);
        if (!b) {
            return false;
        }
        m_JsonString.reset(b);
    }

    buffer* buf = m_JsonString.get();
    buf_clear(buf);

    for (size_t i = 0; i < len; ++i) {
        if (!Utf8WriteChar(buf, str[i])) {
            return false;
        }
    }

    if (!buf_reserve(buf, 1)) {
        return false;
    }

    // zero terminate but don't increase size
    *buf->end = 0;

    return true;
}

int
DebuggerState::Mnemonize(int index, int handleTableIndex, int refTableIndex, int globalTableIndex, const char* name, size_t nameLen) {
    assert(index > 0);
    assert(handleTableIndex > 0);
    assert(refTableIndex > 0);
    assert(globalTableIndex > 0);

    int handle = 0;

    const int type = lua_type(L, index);
    switch (type) {
    case LUA_TTABLE:
    case LUA_TFUNCTION:
    case LUA_TLIGHTUSERDATA:
    case LUA_TUSERDATA:
    case LUA_TTHREAD: {
        lua_pushvalue(L, index);
        lua_rawget(L, refTableIndex);
        handle = (int)lua_tointeger(L, -1);
        lua_pop(L, 1);
        const bool seen = handle >= GlobalTableHandle;
        if (!seen) {
            assert(!lua_rawequal(L, index, handleTableIndex));
            assert(!lua_rawequal(L, index, refTableIndex));
            // store (handle, value) in handle table
            lua_pushvalue(L, index);
            const int handleTableLen = (int)lua_objlen(L, handleTableIndex);
            handle = handleTableLen + 1;
            assert(IsObjectHandle(handle));
            lua_rawseti(L, handleTableIndex, handle);
            // store (value, handle) in ref obj table
            lua_pushvalue(L, index);
            lua_pushinteger(L, handle);
            lua_rawset(L, refTableIndex);
            if (lua_getmetatable(L, index)) {
                Mnemonize(lua_gettop(L), handleTableIndex, refTableIndex, globalTableIndex, METATABLE, sizeof(METATABLE) - 1);
                lua_pop(L, 1);
            }
            if (type == LUA_TTABLE) {
                const bool isGlobalTable = lua_rawequal(L, globalTableIndex, index) != 0;
                lua_pushnil(L);  /* first key */
                while (lua_next(L, index) != 0) {
                    lua_pushvalue(L, -2);
                    size_t keyLen;
                    const char* key = lua_tolstring(L, -1, &keyLen);
                    if (isGlobalTable && strcmp(key, POKEMONTABLE) == 0) {
                        // skip
                    } else {
                        Mnemonize(lua_gettop(L)-1, handleTableIndex, refTableIndex, globalTableIndex, key, keyLen);
                    }
                    lua_pop(L, 2); // pop value, name
                }
            }
        }
    } break;
    default: {
        //NMEMONIZE;
    } break;
    }

    return handle;
}

void
DebuggerState::Mnemonize() {
    const int topBefore = lua_gettop(L);

    m_Values.clear();
    //m_NextValueHandle = ValueHandleOffset;
    m_NextValueHandle = -1;

    lua_getglobal(L, POKEMONTABLE);
    lua_rawgeti(L, -1, Pokemon_Handles);
    lua_rawgeti(L, -2, Pokemon_RefObjects);
    // clear self
    lua_pushnil(L);
    lua_setglobal(L, POKEMONTABLE);
    lua_getglobal(L, "_G");
    const int globalTableIndex = lua_gettop(L);
    const int refTableIndex = globalTableIndex-1;
    const int handleTableIndex = refTableIndex-1;

    Mnemonize(globalTableIndex, handleTableIndex, refTableIndex, globalTableIndex, "_G", 2);

    lua_pop(L, 1); // global table
    lua_pop(L, 1); // ref table
    lua_pop(L, 1); // handle table

    lua_setglobal(L, POKEMONTABLE);

    const int topAfter = lua_gettop(L);
    assert(topBefore == topAfter);
    POKEMON_UNUSED(topBefore);
    POKEMON_UNUSED(topAfter);
}

void
DebuggerState::GetStep(int& count, int& action, int& breakpointHit, int& level) const {
    int value = m_Step.load();
    action = value & ((1 << Breakpoint_Hit_Shift)-1);
    breakpointHit = (value >> Breakpoint_Hit_Shift) & ((1 << Breakpoint_Hit_Bits)-1);
    level = (value >> Level_Shift) & ((1 << Level_Bits)-1);
    count = value / (1 << Step_Count_Shift);
}

bool
DebuggerState::Unbreak() {

    PruneDeadBreakpoints();

    int count, action, breakpointHit, level;
    GetStep(count, action, breakpointHit, level);
    if (breakpointHit) {
        return false;
    }

    //return action == Step_Count && count == -1;
    return true;
}

void
DebuggerState::Break() {
    m_Step.store(0);
}

void
DebuggerState::Resume() {
    m_Step.store(-1 << Step_Count_Shift | Step_Count);
    m_Resume.notify_all();
}

int64_t
DebuggerState::GetInputSequenceNumber() {
    assert(CurrentMessage);

    int64_t result = -1;
    if (Get(CurrentMessage.get(), "seq", result)) {
        return result;
    }
    return -1;
}

int
DebuggerState::GetType() {
    assert(CurrentMessage);

    const char* ptr;
    size_t len;
    if (Get(CurrentMessage.get(), "type", ptr, len)) {
        if (strcmp(ptr, "request") == 0) {
            return Type_Request;
        }
    }
    return Type_Unknown;
}

std::tuple<int, json_value*>
DebuggerState::GetCommand() {
    assert(CurrentMessage);

    const char* ptr;
    size_t len;
    if (Get(CurrentMessage.get(), "command", ptr, len)) {
        auto cmd = GetCommand(ptr);
        if (cmd != Cmd_Unknown) {
            auto args = GetKey(CurrentMessage.get(), "arguments");
            if (args && args->type == json_object) {
                return std::make_tuple(cmd, args);
            }
            return std::make_tuple(cmd, static_cast<json_value*>(nullptr));
        }
    }
    return std::make_tuple(Cmd_Unknown, static_cast<json_value*>(nullptr));
}

int
DebuggerState::GetCommand(const char* str) {
    if (strcmp("continue", str) == 0) {
        return Cmd_Continue;
    }
    if (strcmp("version", str) == 0) {
        return Cmd_Version;
    }
    if (strcmp("backtrace", str) == 0) {
        return Cmd_Backtrace;
    }
    if (strcmp("frame", str) == 0) {
        return Cmd_Frame;
    }
    if (strcmp("evaluate", str) == 0) {
        return Cmd_Evaluate;
    }
    if (strcmp("scope", str) == 0) {
        return Cmd_Scope;
    }
    if (strcmp("lookup", str) == 0) {
        return Cmd_Lookup;
    }
    if (strcmp("setbreakpoint", str) == 0) {
        return Cmd_SetBreakpoint;
    }
    if (strcmp("clearbreakpoint", str) == 0) {
        return Cmd_ClearBreakpoint;
    }


    return Cmd_Unknown;
}

void
DebuggerState::ProcessLuaStep(lua_Debug* dbg) {
    assert(dbg);

    auto stop = false;
    const char* filePath = "";
    int line = -1;

    switch (dbg->event) {
    case LUA_HOOKCALL:
        ++m_Level;
        break;
    case LUA_HOOKRET:
        --m_Level;
        break;
    }


    /*
    ++m_LastLine ;

    int spaces = 0;
    char buf[256];
    if (m_Stack.empty()) {
        for (int frame = 0; lua_getstack(L, frame, dbg); ++frame, spaces += 2) {
            if (!lua_getinfo(L, "lnS", dbg)) {
                break;
            }

            const bool isMain = strcmp("main", dbg->what) == 0;
            const bool isC = !isMain && strcmp("C", dbg->what) == 0;

            if (!dbg->name) {
                if (isC) {
                    dbg->name = "C";
                } else {
                    dbg->name = "Lua entry";
                }
            }

            GetLocation(L, *dbg, m_LuaStepFilePathBuffer, filePath, line);

            snprintf(buf, sizeof(buf), "%20s %3s %6s %s(%d)", dbg->name, "", dbg->what, filePath, line);

            m_Stack.emplace_back(buf);
        }

        std::reverse(m_Stack.begin(), m_Stack.end());
    }

    switch (dbg->event) {
    default:
        m_Stack.pop_back();
    case LUA_HOOKCALL: {
        if (!lua_getinfo(L, "lnS", dbg)) {
            break;
        }

        const bool isMain = strcmp("main", dbg->what) == 0;
        const bool isC = !isMain && strcmp("C", dbg->what) == 0;

        if (!dbg->name) {
            if (isC) {
                dbg->name = "C";
            } else {
                dbg->name = "Lua entry";
            }
        }

        GetLocation(L, *dbg, m_LuaStepFilePathBuffer, filePath, line);

        snprintf(buf, sizeof(buf), "%20s %3s %6s %s(%d)", dbg->name, "", dbg->what, filePath, line);

        m_Stack.emplace_back(buf);
    } break;
    case LUA_HOOKRET:
        m_Stack.pop_back();
        break;
    }


    for (size_t i = 0; i < m_Stack.size(); ++i) {
        fprintf(stderr, "%04d %s\n", m_LastLine, m_Stack[m_Stack.size()-1 - i].c_str());
    }

    fprintf(stderr, "\n");
    */

//    for (int frame = 0; lua_getstack(L, frame, dbg); ++frame, spaces += 2) {
//        if (!lua_getinfo(L, "lnS", dbg)) {
//            break;
//        }

//        const bool isMain = strcmp("main", dbg->what) == 0;
//        const bool isC = !isMain && strcmp("C", dbg->what) == 0;

//        if (!dbg->name) {
//            if (isC) {
//                dbg->name = "C";
//            } else {
//                dbg->name = "Lua entry";
//            }
//        }

//        GetLocation(L, *dbg, m_LuaStepFilePathBuffer, filePath, line);

//        fprintf(stderr, "%04d %20s %3s %6s %s(%d)\n", m_LastLine, dbg->name, dbg->event == LUA_HOOKCALL ? "IN" : "OUT", dbg->what, filePath, line);

//    }


//    fprintf(stderr, "\n");

//    return;



    if (!lua_getinfo(L, "lnS", dbg)) {
        return;
    }

    if (!GetLocation(L, *dbg, m_LuaStepFilePathBuffer, filePath, line)) {
        return;
    }

    if (line > 0 &&
        m_LastLine == line &&
        m_LastFile.length() > 0 &&
        *filePath &&
        m_LastFile == filePath) {
        return; // rets from calls
    }

    m_LastLine = line;
    m_LastFile = filePath;

    if (line <= 0 || !*filePath) {
        return;
    }

    int count, action, breakPointHit, level;
    GetStep(count, action, breakPointHit, level);
    assert(!breakPointHit);




    m_Hits.clear();

    for (auto* pBp = m_Breakpoints.load(); pBp; pBp = pBp->Next) {
        auto& bp = *pBp;

        bp.Hit = false;

        if (!bp.Enabled || bp.Dead) {
            continue;
        }

        if (bp.Condition.length()) {
            if (0 == luaL_loadstring(L, bp.Condition.c_str())) {
                if (0 == lua_pcall(L, 0, 1, 0)) {
                    bp.Hit = lua_toboolean(L, -1) != 0;
                }
                lua_pop(L, 1);
            }
        }

        if (!bp.Hit) {
            if (line == bp.Line) {
                //hit = std::regex_match(filePath, filePath + strlen(filePath), bp.Regex);
                bp.Hit = strstr(filePath, bp.Regex.c_str()) != nullptr;
            }
        }

        if (bp.Hit && bp.IgnoreCount > 0) {
            bp.Hit = false;
            --bp.IgnoreCount;
            continue;
        }

        if (bp.Hit) {
            m_Hits.push_back(bp.Id);
            breakPointHit = 1;
        }
    }

    if (breakPointHit) {
        m_Step.store(count << Step_Count_Shift | level << Level_Shift | breakPointHit << Breakpoint_Hit_Shift | action);
        stop |= true;
    }

    switch (action) {
    case Step_Count: {
        if (m_Level <= level) {
            if (count >= 0) {
                if (count > 0) {
                    m_Step.store((count - 1) << Step_Count_Shift | level << Level_Shift | breakPointHit << Breakpoint_Hit_Shift | Step_Count);
                } else {
                    m_Step.store((-1 << Step_Count_Shift) | (1 << Breakpoint_Hit_Shift) | Step_Count);
                    stop = true;
                }
            }
        }
    } break;
    case Step_In:
        if (m_Level > level) {
            m_Step.store(-1 << Step_Count_Shift | 1 << Breakpoint_Hit_Shift | Step_Count);
            stop = true;
        } else {
            m_Step.store(-1 << Step_Count_Shift | 1 << Breakpoint_Hit_Shift | Step_Count);
            stop = true;
        }
        break;
    case Step_Out:
        if (m_Level < level) {
            m_Step.store(-1 << Step_Count_Shift | 1 << Breakpoint_Hit_Shift | Step_Count);
            stop = true;
        }
        break;
    }

    if (stop) {
        BufferPtr event(MakeV8ResponseResponseHeader());
        if (event) {

            if (GetJsonString(filePath, strlen(filePath))) {
                const size_t offset = buf_used(event.get());
                if (Write4Net(event.get(), 0) && // sizeof following string
                        WriteRaw(event.get(),
                                 "{\"seq\":%" PRId64 ",\"type\":\"event\",\"event\":\"break\",\"body\":{"
                                 "\"invocationText\":\"%s\",\"sourceLine\":%d,\"sourceColumn\":1,\"sourceLineText\":\"%s\","
                                 "\"script\":{\"name\":\"%s\",\"breakpoints\":[",
                                 OutputSequence++, dbg->name, line, dbg->name, m_JsonString->beg)) {


                    for (size_t i = 0; i < m_Hits.size(); ++i) {
                        if (i > 0) {
                            WriteRaw(event.get(), ",");
                        }
                        WriteRaw(event.get(), "%d", m_Hits[i]);
                    }

                    if (WriteRaw(event.get(), "]}}}")) {
                        uint32_t size = buf_used(event.get()) - offset - 4;
                        unsigned char* p = event->beg + offset;
                        Patch4Net(event.get(), p, size);

                        if (EndV8DebuggerResponse(event.get())) {
                            Send(event.release());

                        }
                    }

                }
            }
        }

        std::unique_lock<std::mutex> uniqueLock(m_Lock);
        Running = false;
        m_Frame = -1;
        Mnemonize();
        m_Resume.wait(uniqueLock, [this] { return Unbreak();});
        Running = true;

    }
}

buffer*
DebuggerState::ProcessRequest(buffer* response, JsonPtr&& json) {
    BufferPtr buf(response);
    ::std::lock_guard<std::mutex> g(m_Lock);
    CurrentMessage.swap(json);

    int64_t seq = GetInputSequenceNumber();
    if (seq < 0) {
        return nullptr;
    }

    int type = GetType();
    if (type != Type_Request) {
        return nullptr;
    }

    m_HandlesToExpose.clear();

    auto cmd = GetCommand();

    bool result = false;
    const int before = lua_gettop(L);

    switch (std::get<0>(cmd)) {
    case Cmd_Version:
        result = WritePayload(response,
"{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
"\"command\":\"version\",\"success\":true,\"running\":%s,\"body\":{\"V8Version\":\"%s\"}}",
                   OutputSequence++, seq, (Running ? "true" : "false"), LUA_VERSION);
        break;
    case Cmd_Continue: {
        result = ProcessContinue(response, seq, std::get<1>(cmd));
    } break;
    case Cmd_Backtrace: {
        result = ProcessBacktrace(response, seq, std::get<1>(cmd));
    } break;
    case Cmd_Frame: {
        result = ProcessFrame(response, seq, std::get<1>(cmd));
    } break;
    case Cmd_Evaluate: {
        result = ProcessEvaluate(response, seq, std::get<1>(cmd));
    } break;
    case Cmd_Scope: {
        result = ProcessScope(response, seq, std::get<1>(cmd));
    } break;
    case Cmd_Lookup: {
        result = ProcessLookup(response, seq, std::get<1>(cmd));
    } break;
    case Cmd_SetBreakpoint: {
        result = ProcessSetBreakpoint(response, seq, std::get<1>(cmd));
    } break;
    case Cmd_ClearBreakpoint: {
        result = ProcessClearBreakpoint(response, seq, std::get<1>(cmd));
    } break;
    default:
        result = false;
        break;
    }

    const int after = lua_gettop(L);
    assert(before == after);
    POKEMON_UNUSED(before);
    POKEMON_UNUSED(after);

    if (!result) {
        return nullptr;
    }

    return buf.release();
}

bool
DebuggerState::WriteRefs(buffer* response, int handleTableIndex, int refTableIndex) {
    m_ExposedObjects.clear();
    m_ExposedValues.clear();
    // serialize refs
    bool first = true;
    while (!m_HandlesToExpose.empty()) {
        auto handle = m_HandlesToExpose.back();
        m_HandlesToExpose.pop_back();
        assert(handle != 0);
        if (IsObjectHandle(handle)) {
            if ((size_t)handle >= m_ExposedObjects.size()) {
                m_ExposedObjects.resize(handle + 1);
            }
            if (!m_ExposedObjects[handle]) {
                m_ExposedObjects[handle] = true;
                assert(handle >= GlobalTableHandle);

                if (!first) {
                    if (!WriteRaw(response, ",")) {
                        return false;
                    }
                }

                if (!WriteObject(response, handle, handleTableIndex, refTableIndex)) {
                    return false;
                }
            }
        } else {
            const size_t index = -handle + 1;
            if ((size_t)index >= m_ExposedValues.size()) {
                m_ExposedValues.resize(index + 1);
            }
            if (!m_ExposedValues[index]) {
                 m_ExposedValues[index] = true;
                if (!first) {
                    if (!WriteRaw(response, ",")) {
                        return false;
                    }
                }

                if (!WriteValue(response, handle)) {
                    return false;
                }
            }
        }

        first = false;
    }

    return true;
}
bool
DebuggerState::WriteRefs(buffer* response) {
    const int before = lua_gettop(L);
    GetPokemonTables(L, Pokemon_Handles, Pokemon_RefObjects, 0);

    bool result = WriteRefs(response, lua_gettop(L)-1, lua_gettop(L));

    lua_pop(L, 2);
    const int after = lua_gettop(L);
    assert(before == after);
    POKEMON_UNUSED(before);
    POKEMON_UNUSED(after);

    return result;
}

bool
DebuggerState::WriteValue(buffer* response, int handle) {
    auto it = m_Values.find(handle);
    if (it == m_Values.end()) {
        if (!WriteRaw(response, "{\"handle\":%d,\"type\":\"undefined\"}", handle)) {
            return false;
        }
    } else {
        assert(it != m_Values.end());
        const auto& value = it->second;
        assert(handle == value.Handle);

        switch (value.Type) {
        default:
            assert(false);
            return false;
            break;
        case LUA_TNIL: {
            if (!WriteRaw(response, "{\"handle\":%d,\"type\":\"null\"}", value.Handle)) {
                return false;
            }
        } break;
        case LUA_TBOOLEAN: {
            if (!WriteRaw(response, "{\"handle\":%d,\"type\":\"boolean\",\"value\":%s}", value.Handle, value.Data.Number > 0 ? "true" : "false")) {
                return false;
            }
        } break;
        case LUA_TNUMBER: {
            const lua_Number& n = value.Data.Number;
            if (n != n) { // nan?
                if (!WriteRaw(response, "{\"handle\":%d,\"type\":\"string\",\"value\":\"NaN\"}", value.Handle)) {
                    return false;
                }
            } else {
                if (n == std::numeric_limits<lua_Number>::infinity()) {
                    if (!WriteRaw(response, "{\"handle\":%d,\"type\":\"string\",\"value\":\"inf\"}", value.Handle)) {
                        return false;
                    }
                } else {
                    if (!WriteRaw(response, "{\"handle\":%d,\"type\":\"number\",\"value\":%f}", value.Handle, n)) {
                        return false;
                    }
                }
            }
        } break;
        case LUA_TSTRING: {
            // buf_used returns 0, wtf?
            if (!GetJsonString((const char*)value.Data.String->beg, strlen((char*)value.Data.String->beg))) {
                return false;
            }
            if (!WriteRaw(response, "{\"handle\":%d,\"type\":\"string\",\"value\":\"%s\"}", value.Handle, m_JsonString->beg)) {
                return false;
            }
        } break;
        }
    }

    return true;
}

bool
DebuggerState::WriteObject(buffer* buf, int handle, int handleTableIndex, int refTableIndex) {
    assert(handle >= GlobalTableHandle);
    assert(handleTableIndex > 0);
    assert(refTableIndex > 0);

    lua_rawgeti(L, handleTableIndex, HandleToLuaIndex(handle));
    const int typeOnStack = lua_type(L, -1);
    if (typeOnStack == LUA_TNIL) {
        lua_pop(L, 1);
        if (!WriteRaw(buf, "{\"handle\":%d,\"type\":\"null\"}", handle)) {
            return false;
        }
    } else {
        LuaPopGuard g(L, 1);
        const int index = lua_gettop(L);
        switch (typeOnStack) {
        default:
            assert(false);
            return false;
            break;
        case LUA_TFUNCTION:
        case LUA_TTABLE:
        case LUA_TUSERDATA:
        case LUA_TTHREAD:
        case LUA_TLIGHTUSERDATA: {
            auto ptr = lua_topointer(L, index);
            POKEMON_PTR_TO_STRING(ptr, strPtr);
            switch (typeOnStack) {
            case LUA_TFUNCTION: {
                int addressHandle = m_NextValueHandle--;
                m_Values.insert(std::make_pair(std::move(addressHandle), std::move(LuaValue(addressHandle, strPtr, strlen(strPtr)))));
                m_HandlesToExpose.emplace_back(addressHandle);

                if (!WriteRaw(buf, "{\"handle\":%d,\"type\":\"function\",\"name\":\"\",\"properties\":[{\"ref\":%d,\"name\":\"%s\"}]}", handle, addressHandle, ADDRESS)) {
                    return false;
                }
            } break;
            default: {
                int metaTableHandle = 0;
                if (lua_getmetatable(L, index)) {
                    lua_rawget(L, refTableIndex);
                    metaTableHandle = (int)lua_tointeger(L, -1);
                    lua_pop(L, 1);
                }
                const bool hasMetatable = metaTableHandle >= GlobalTableHandle;


                if (!WriteRaw(buf,
    "{\"handle\":%d,\"type\":\"object\",\"properties\":[",
                              handle)) {
                    return false;
                }
                bool firstMember = true;
                if (hasMetatable) {
                    m_HandlesToExpose.push_back(metaTableHandle);

                    firstMember = false;
                    if (!WriteRaw(buf, "{\"ref\":%d,\"name\":\"%s\"}", metaTableHandle, METATABLE)) {
                        return false;
                    }
                }

                if (!firstMember) {
                    if (!WriteRaw(buf, ",")) {
                        return false;
                    }
                }

                int addressHandle = m_NextValueHandle--;
                m_Values.insert(std::make_pair(std::move(addressHandle), std::move(LuaValue(addressHandle, strPtr, strlen(strPtr)))));
                m_HandlesToExpose.emplace_back(addressHandle);

                if (!WriteRaw(buf, "{\"ref\":%d,\"name\":\"%s\"}", addressHandle, ADDRESS)) {
                    return false;
                }
                firstMember = false;
                const char* className = "Object";
                switch (typeOnStack) {
                case LUA_TUSERDATA:
                case LUA_TTHREAD:
                case LUA_TLIGHTUSERDATA:
                    break; // fix me
                case LUA_TTABLE: {

                    assert(!lua_rawequal(L, index, handleTableIndex));
                    assert(!lua_rawequal(L, index, refTableIndex));
                    lua_pushnil(L);  /* first key */
                    while (lua_next(L, index) != 0) {
                        const int valueType = lua_type(L, -1);
                        POKEMON_UNUSED(valueType);
                        lua_pushvalue(L, -2);
                        size_t len;
                        const char* key = lua_tolstring(L, -1, &len);
                        if (handle == GlobalTableHandle && strcmp(POKEMONTABLE, key) == 0) {
                            lua_pop(L, 2);
                            continue;
                        }
                        if (!GetJsonString(key, len)) {
                            lua_pop(L, 3);
                            return false;
                        }
                        lua_pop(L, 1); // name copy

                        if (!firstMember) {
                            if (!WriteRaw(buf, ",")) {
                                lua_pop(L, 2);
                                return false;
                            }
                        }

                        lua_pushvalue(L, -1);
                        lua_rawget(L, refTableIndex);
                        int subhandle = (int)lua_tointeger(L, -1);
                        lua_pop(L, 1);

                        if (subhandle == 0) {
                            subhandle = m_NextValueHandle--;
                            assert(IsValueHandle(subhandle));
                            m_Values.insert(std::make_pair(std::move(subhandle), std::move(LuaValue::fromStack(L, -1, subhandle))));
                        }

                        // FIXME: is there a way to not always expose evertying?
                        m_HandlesToExpose.push_back(subhandle);

                        assert(subhandle != 0);

                        if (!WriteRaw(buf, "{\"ref\":%d,\"name\":\"%s\"}", subhandle, m_JsonString->beg)) {
                            lua_pop(L, 2);
                            return false;
                        }

                        firstMember = false;
                        lua_pop(L, 1); // value;
                    }
                } break;
                }
                if (!WriteRaw(buf, "],\"className\":\"%s\"}", className)) {
                    return false;
                }
            } break;
            }
        } break;
        } // switch (type)
    } // type != LUA_TNIL

    return true;
}


bool
DebuggerState::ProcessClearBreakpoint(buffer* response, int64_t seq, json_value* args) {
    int64_t id;
    if (!args ||
        !Get(args, "breakpoint", id)) {
        return WritePayload(response,
       "{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
       "\"command\":\"clearbreakpoint\",\"success\":false,\"running\":%s}",
                      OutputSequence++, seq, Running ? "true" : "false");
    }

    for (auto* pBp = m_Breakpoints.load(std::memory_order_relaxed); pBp; pBp = pBp->Next) {
        if (pBp->Id == id) {
            pBp->Dead = true;
            break;
        }
    }

     return WritePayload(response,
"{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
"\"command\":\"clearbreakpoint\",\"success\":true,\"running\":%s}",
                   OutputSequence++, seq, Running ? "true" : "false");
}

bool
DebuggerState::ProcessSetBreakpoint(buffer* response, int64_t seq, json_value* args) {

    /*
     * { "seq"         : <number>,
  "type"        : "response",
  "request_seq" : <number>,
  "command"     : "setbreakpoint",
  "body"        : { "type"       : <"function" or "script">
                    "breakpoint" : <break point number of the new break point>
                  }
  "running"     : <is the VM running after sending this response>
  "success"     : true


{ "type"        : <"function" or "script" or "scriptId" or "scriptRegExp">
                  "target"      : <function expression or script identification>
                  "line"        : <line in script or function>
                  "column"      : <character position within the line>
                  "enabled"     : <initial enabled state. True or false, default is true>
                  "condition"   : <string with break point condition>
                  "ignoreCount" : <number specifying the number of break point hits to ignore, default value is 0>
                }

}*/
    const char* typePtr;
    size_t typeLen;
    const char* targetPtr;
    size_t targetLen;
    const char* conditionPtr;
    size_t conditionLen;
    int64_t line, ignoreCount;
    int64_t enabled;
    if (!args ||
        !Get(args, "type", typePtr, typeLen) ||
        !Get(args, "target", targetPtr, targetLen)||
        !Get(args, "line", line) ||
        !Get(args, "enabled", enabled)) {
        return WritePayload(response,
       "{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
       "\"command\":\"setbreakpoint\",\"success\":false,\"running\":%s}",
                      OutputSequence++, seq, Running ? "true" : "false");
    }

    if (!Get(args, "ignoreCount", ignoreCount)) {
        ignoreCount = 0;
    }

    if (!Get(args, "condition", conditionPtr, conditionLen)) {
        conditionPtr = "";
        conditionLen = 0;
    }

    const bool isFunction = strcmp("function", typePtr) == 0;
    int id = m_NextBreakpointId++;
    std::unique_ptr<Breakpoint> bp(new Breakpoint());
    bp->Condition.assign(conditionPtr, conditionPtr + conditionLen);
    //bp.Regex = std::regex(targetPtr);
    bp->Regex.assign(targetPtr, targetPtr + targetLen);
    bp->Id = id;
    bp->IgnoreCount = (int)ignoreCount;
    bp->Enabled = enabled != 0;
    bp->Line = (int)(line + 1);
    bp->Dead = false;
    bp->Next = m_Breakpoints.load(std::memory_order_relaxed);
    m_Breakpoints.store(bp.release());

     return WritePayload(response,
"{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
"\"command\":\"setbreakpoint\",\"success\":true,\"running\":%s,\"body\":"
"{\"type\":\"%s\",\"breakpoint\":%d}}",
                   OutputSequence++, seq, Running ? "true" : "false", isFunction ? "function" : "script", id);

}

bool
DebuggerState::ProcessLookup(buffer* response, int64_t seq, json_value* args) {
    if (Running) {
        return WritePayload(response,
    "{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
    "\"command\":\"lookup\",\"success\":false,\"running\":true}",
                   OutputSequence++, seq);
    }

    json_value* handles;
    if (!args ||
        (handles = GetKey(args, "handles")) == NULL ||
        handles->type != json_array) {
        return WritePayload(response,
    "{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
    "\"command\":\"lookup\",\"success\":false,\"running\":false}",
                   OutputSequence++, seq);
    }

    const size_t offset = buf_used(response);

    if (!Write4Net(response, 0) || // sizeof following string
        !WriteRaw(response,
"{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
"\"command\":\"lookup\",\"success\":true,\"running\":false,\"body\":{",
                  OutputSequence++, seq)) {
        return false;
    }

    GetPokemonTables(L, Pokemon_Handles, Pokemon_RefObjects, 0);
    LuaPopGuard handleTable(L, 2);
    const int handleTableIndex = lua_gettop(L)-1;
    const int refTableIndex = lua_gettop(L);

    bool first = true;
    for (size_t i = 0; i < handles->u.array.length; ++i) {
        auto handleObject = handles->u.array.values[i];
        if (handleObject->type == json_integer) {
            if (!first) {
                if (!WriteRaw(response, ",")) {
                    return false;
                }
            }

            int handle = (int)handleObject->u.integer;

            if (!WriteRaw(response, "\"%d\":", handle)) {
                return false;
            }

            if (IsValueHandle(handle)) {
                if (!WriteValue(response, handle)) {
                    return false;
                }
            } else {
                if (!WriteObject(response, handle, handleTableIndex, refTableIndex)) {
                    return false;
                }
            }

            first = false;
        }
    }

    if (!WriteRaw(response, "},\"refs\":[")) {
        return false;
    }

    if (!WriteRefs(response)) {
        return false;
    }

    if (!WriteRaw(response, "]}")) {
        return false;
    }

    uint32_t size = buf_used(response) - offset - 4;
    unsigned char* p = response->beg + offset;
    Patch4Net(response, p, size);

    return true;
}

bool
DebuggerState::ProcessScope(buffer* response, int64_t seq, json_value* args) {
    if (Running) {
        return WritePayload(response,
    "{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
    "\"command\":\"scope\",\"success\":false,\"running\":true}",
                   OutputSequence++, seq);
    }

    if (!args) {
        return WritePayload(response,
    "{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
    "\"command\":\"scope\",\"success\":false,\"running\":false}",
                   OutputSequence++, seq);
    }

    int frame = m_Frame;
    int64_t x;
    if (Get(args, "frameNumber", x)) {
        frame = (int)x;
    }

    if (frame < 0 ||
        !Get(args, "number", x) ||
        x < 0 ||
        x > 2) {
        return WritePayload(response,
    "{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
    "\"command\":\"scope\",\"success\":false,\"running\":false}",
                   OutputSequence++, seq);
    }

    const int scope = (int)x;

    lua_Debug dbg;
    if (!lua_getstack(L, frame, &dbg) ||
        !lua_getinfo(L, "flnSu", &dbg)) {
            return false;
    }

    const bool isC = strcmp("C", dbg.what) == 0;
    const size_t offset = buf_used(response);

    if (!Write4Net(response, 0) || // sizeof following string
        !WriteRaw(response,
"{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
"\"command\":\"scope\",\"success\":true,\"running\":false,\"body\":",
                  OutputSequence++, seq)) {
        return false;
    }

    switch (scope) {
    case 0: { // local
        lua_pop(L, 1);
        int handle = m_NextValueHandle--;
        if (!WriteRaw(response,
"{\"index\":%d,\"frameIndex\":%d,\"type\":1,\"object\":{\"handle\":%d,"
"\"type\":\"object\",\"properties\":[", scope, frame, handle)) {
            return false;
        }

        // count locals and filter out temporaries
        int locals = 0;
        const char* name;
        for (int j = 1; (name = lua_getlocal(L, &dbg, j)) != NULL; ++j, ++locals) {
            lua_pop(L, 1);
            assert(name);
            if (!isC) {
                // temporary
                if (*name == '(') {
                    break;
                }
            }
        }


        GetPokemonTable(L, Pokemon_RefObjects);
        const int refTableIndex = lua_gettop(L);
        LuaPopGuard metaTablesPopGuard(L, 1);

        int cArgs = 0;
        char cArgBuffer[32];
        for (int j = 1; j <= locals; ++j) {
            name = lua_getlocal(L, &dbg, j);
            assert(name);
            LuaPopGuard g(L, 1);
            if (isC) {
                snprintf(cArgBuffer, sizeof(cArgBuffer), "arg%d", cArgs++);
                name = cArgBuffer;
            }

            lua_pushvalue(L, -1);
            lua_rawget(L, refTableIndex);
            int handle = (int)lua_tointeger(L, -1);
            lua_pop(L, 1);

            if (!handle) {
                handle = m_NextValueHandle--;
                m_Values.insert(std::make_pair(std::move(handle), std::move(LuaValue::fromStack(L, -1, handle))));
            }

            m_HandlesToExpose.emplace_back(handle);

            if (j > 1) {
                if (!WriteRaw(response, ",")) {
                    return false;
                }
            }

            if (!WriteRaw(response, "{\"name\":\"%s\",\"ref\":%d}", name, handle)) {
                return false;
            }
        }

        /*
        if (locals) {
            if (!WriteRaw(response, ",")) {
                return false;
            }
        }
        if (!WriteRaw(response, "{\"name\":\"%s\",\"ref\":%d}", "_G", GlobalTableHandle)) {
            return false;
        }
        m_HandlesToExpose.emplace_back(GlobalTableHandle);
        */



        if (!WriteRaw(response, "]},\"refs\":[")) {
            return false;
        }

        if (!WriteRefs(response)) {
            return false;
        }

        if (!WriteRaw(response, "]}")) {
            return false;
        }
    } break;
    case 1: { // closure
        assert(lua_isfunction(L, -1));
        LuaPopGuard function(L, 1);
        int handle = m_NextValueHandle--;
        if (!WriteRaw(response,
"{\"index\":%d,\"frameIndex\":%d,\"type\":3,\"object\":{\"handle\":%d,"
"\"type\":\"object\",\"properties\":[", scope, frame, handle)) {
            return false;
        }

        // remember upvalues

        GetPokemonTable(L, Pokemon_RefObjects);
        const int refTableIndex = lua_gettop(L);
        LuaPopGuard metaTablesPopGuard(L, 1);

        const char* name;
        for (int j = 1; j <= dbg.nups; ++j) {
            name = lua_getupvalue(L, -2, j);
            assert(name);
            LuaPopGuard g(L, 1);

            lua_pushvalue(L, -1);
            lua_rawget(L, refTableIndex);
            int handle = (int)lua_tointeger(L, -1);
            lua_pop(L, 1);

            if (!handle) {
                handle = m_NextValueHandle--;
                m_Values.insert(std::make_pair(std::move(handle), std::move(LuaValue::fromStack(L, -1, handle))));
            }

            m_HandlesToExpose.emplace_back(handle);

            if (j > 1) {
                if (!WriteRaw(response, ",")) {
                    return false;
                }
            }

            if (!WriteRaw(response, "{\"name\":\"%s\",\"ref\":%d}", name, handle)) {
                return false;
            }

        }

        if (!WriteRaw(response, "]},\"refs\":[")) {
            return false;
        }

        if (!WriteRefs(response)) {
            return false;
        }

        if (!WriteRaw(response, "]}")) {
            return false;
        }
    } break;
    case 2: { // global
        lua_pop(L, 1);
        assert(false);
//        if (!WriteRaw(response, "{\"index\":%d,\"frameIndex\":%d,\"type\":0,\"object\":", scope, frame)) {
//            return false;
//        }

//        lua_getglobal(L, POKEMONTABLE);
//        assert(lua_type(L, -1) == LUA_TTABLE);
//        lua_rawgeti(L, -1, Pokemon_Handles);
//        assert(lua_type(L, -1) == LUA_TTABLE);
//        lua_rawgeti(L, -2, Pokemon_Handles);
//        assert(lua_type(L, -1) == LUA_TTABLE);

//        const int shadowTableIndex =  lua_gettop(L);
//        const int handleTableIndex = shadowTableIndex-1;
//        //const int pokemonTableIndex = handleTableIndex-1;

//        LuaPopGuard metaTables(L, 3);

//        lua_getglobal(L, "_G");
//        lua_rawget(L, handleTableIndex);
//        int handle = lua_tointeger(L, -1);
//        lua_pop(L, 1);

//        if (!WriteObject(response, LUA_GLOBALSINDEX)) {
//            return false;
//        }

//        if (!WriteRaw(response, "]}}")) {
//            return false;
//        }
    } break;
    default:
        return false;
    }

    if (!WriteRaw(response, "}")) {
        return false;
    }

    uint32_t size = buf_used(response) - offset - 4;
    unsigned char* p = response->beg + offset;
    Patch4Net(response, p, size);

    return true;
}

bool
DebuggerState::ProcessEvaluate(buffer* response, int64_t seq, json_value* args) {
    int64_t frame;
    char* expression;
    size_t len;
    if (Running ||
        !args ||
        !Get(args, "frame", frame) ||
        frame < 0 ||
        !Get(args, "expression", expression, len) ||
        !len) {
        return WritePayload(response,
    "{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
    "\"command\":\"evaluate\",\"success\":false,\"running\":true}",
                   OutputSequence++, seq);
    }

    const size_t offset = buf_used(response);

    if (!Write4Net(response, 0) || // sizeof following string
        !WriteRaw(response,
"{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
"\"command\":\"evaluate\",\"success\":true,\"running\":false,\"body\":",
                  OutputSequence++, seq)) {
        return false;
    }

    GetPokemonTable(L, Pokemon_RefObjects);
    const int refTableIndex = lua_gettop(L);
    LuaPopGuard metaTablesPopGuard(L, 1);

    char* value = NULL;
    char* equal = (char*)strchr(expression, '=');

    if (equal) {
        // chop ;
        expression[--len] = 0;
        value = equal + 1;
        while (isspace(*value)) ++value;
        do {
            *equal-- = 0;
        } while (isspace(*equal));
    }

    char* point = strchr(expression, '.');
    if (point) {
        *point = 0;
    }

    bool local = true;
    bool found = false;
    lua_Debug dbg;
    const char* name = NULL;
    int localNumber = 0;

    for (int frame = 0; !found && lua_getstack(L, frame, &dbg); ++frame) {
        for (localNumber = 1; !found && (name = lua_getlocal(L, &dbg, localNumber)) != NULL; ++localNumber) {
            assert(name);

            if (strcmp(name, expression) == 0) {
                found = true;
                break;
            } else {
                lua_pop(L, 1);
            }
        }
    }

    if (!found) {
        lua_getglobal(L, "_G");
        found = true;
        local = false;
    }

    if (found) {
        if (point) {
            expression = point + 1;
        }
        LuaPopGuard g(L, 1);
        while (true) {
            if (lua_istable(L, -1)) {
                point = strchr(expression, '.');
                if (point) {
                    *point = 0;
                    lua_pushstring(L, expression);
                    lua_rawget(L, -2);
                    lua_replace(L, -2); // replace table with value
                    expression = point + 1;
                } else { // no point
                    lua_pushvalue(L, -1);
                    lua_rawget(L, refTableIndex);
                    const int tableHandle = (int)lua_tointeger(L, -1);
                    lua_pop(L, 1);
                    int handle = 0;
                    if (equal) { // table assigment
                        if (IsReservedKey(expression)) {
                            // Changing the meta table is not supported
                            handle = m_NextValueHandle--;
                            if (!WriteRaw(response, "{\"handle\":%d,\"type\":\"undefined\"}", handle)) {
                                return false;
                            }
                        } else {
                            // do table assignment
                            lua_pushstring(L, expression);
                            lua_pushstring(L, value);
                            lua_rawset(L, -3);

                            m_HandlesToExpose.emplace_back(tableHandle);

                            if (!WriteRaw(response, "{\"ref\":%d}", tableHandle)) {
                                return false;
                            }
                        }
                    } else { // table lookup
                        if (strcmp(METATABLE, expression) == 0) {
                            lua_getmetatable(L, -1);
                            lua_replace(L, -2); // replace table with value
                        } else if (strcmp(ADDRESS, expression) == 0) {
                            handle = m_NextValueHandle--;
                            auto ptr = lua_topointer(L, -1);
                            POKEMON_PTR_TO_STRING(ptr, strPtr);
                            m_Values.insert(std::make_pair(std::move(handle), std::move(LuaValue(handle, strPtr, strlen(strPtr)))));
                            m_HandlesToExpose.emplace_back(handle);
                        } else {
                            lua_pushstring(L, expression);
                            lua_rawget(L, -2);
                            lua_replace(L, -2);
                        }
                        lua_pushvalue(L, -1);
                        lua_rawget(L, refTableIndex);
                        handle = (int)lua_tointeger(L, -1);
                        lua_pop(L, 1);
                        if (handle == 0) {
                            handle = m_NextValueHandle--;
                            m_Values.insert(std::make_pair(std::move(handle), std::move(LuaValue::fromStack(L, -1, handle))));
                        }

                        m_HandlesToExpose.emplace_back(handle);

                        if (!WriteRaw(response, "{\"ref\":%d}", handle)) {
                            return false;
                        }
                    }
                    break;
                }
            } else { // no a table
                int handle = 0;
                if (equal) {
                    if (local) {
#if LUA_VERSION_NUM >= 502
                        lua_pushstring(L, value);
                        handle = m_NextValueHandle--;
                        m_Values.insert(std::make_pair(std::move(handle), std::move(LuaValue::fromStack(L, -1, handle))));
                        m_HandlesToExpose.emplace_back(handle);
                        lua_setlocal(L, &dbg, localNumber);

                        if (!WriteRaw(response, "{\"ref\":%d}", handle)) {
                            return false;
                        }
#else
                        // assignment of non-table entries not supported
                        handle = m_NextValueHandle--;
                        if (!WriteRaw(response, "{\"handle\":%d,\"type\":\"undefined\"}", handle)) {
                            return false;
                        }
#endif
                    } else { // global assignment
                        if (IsReservedKey(expression)) {
                            // Changing the meta table is not supported
                            handle = m_NextValueHandle--;
                            if (!WriteRaw(response, "{\"handle\":%d,\"type\":\"undefined\"}", handle)) {
                                return false;
                            }
                        } else {
#if LUA_VERSION_NUM >= 502
                            lua_rawgeti(L, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS);
                            lua_pushstring(L, expression);
                            lua_pushstring(L, value);
                            lua_rawset(L, -3);
                            lua_pop(L, 1);
#else
                            lua_pushstring(L, expression);
                            lua_pushstring(L, value);
                            lua_rawset(L, LUA_GLOBALSINDEX);
#endif
                            // don't expose global table?
                            if (!WriteRaw(response, "{\"handle\":%d,\"type\":\"undefined\"}", handle)) {
                                return false;
                            }
                        }
                    }
                } else {
                    lua_pushvalue(L, -1);
                    lua_rawget(L, refTableIndex);
                    handle = (int)lua_tointeger(L, -1);
                    lua_pop(L, 1);
                    if (handle == 0) {
                        handle = m_NextValueHandle--;
                        m_Values.insert(std::make_pair(std::move(handle), std::move(LuaValue::fromStack(L, -1, handle))));
                        m_HandlesToExpose.emplace_back(handle);
                    }

                    if (!WriteRaw(response, "{\"ref\":%d}", handle)) {
                        return false;
                    }
                }
                break;
            }
        } // while has point
    } else { // not found
        int handle = m_NextValueHandle--;
        if (!WriteRaw(response, "{\"handle\":%d,\"type\":\"undefined\"}", handle)) {
            return false;
        }

        fprintf(stderr, "%s: undef, handle %d\n", expression, handle);
    }

#if 0
    } else { // no equal sign in expression
        const int oldTop = lua_gettop(L);
        sprintf((char*)newExpression->beg, "return %s", expression);
        int error = luaL_loadstring(L, (char*)newExpression->beg);
        if (error) {
            lua_pop(L, 1); // error message
            int handle = m_NextValueHandle--;
            if (!WriteRaw(response, "{\"handle\":%d,\"type\":\"undefined\"}", handle)) {
                return false;
            }
        } else { // no load error
            error = lua_pcall(L, 0, LUA_MULTRET, 0);
            const int results = lua_gettop(L) - oldTop;
            if (error) {
                if (results) {
                    lua_pop(L, results);
                }
                int handle = m_NextValueHandle--;
                if (!WriteRaw(response, "{\"handle\":%d,\"type\":\"undefined\"}", handle)) {
                    return false;
                }
            } else { // no call error
                assert(results == 1);
                lua_pop(L, results);
                int handle;
                auto ptr = lua_topointer(L, -1);
                if (ptr) {
                    const int index = lua_gettop(L);
                    lua_getglobal(L, "_G");
                    GetPokemonTable(L, Pokemon_Handles);
                    const int handleTableIndex = lua_gettop(L);
                    const int globalTableIndex = handleTableIndex-1;
                    LuaPopGuard g(L, 2);
                    handle = Mnemonize(index, handleTableIndex, globalTableIndex, NULL, 0);
                    m_HandlesToExpose.emplace_back(handle);
                } else {
                    handle = m_NextValueHandle--;
                    m_Values.insert(std::make_pair(std::move(handle), std::move(LuaValue::fromStack(L, -1, handle))));
                    m_HandlesToExpose.emplace_back(handle);
                }

                if (!WriteRaw(response, "{\"ref\":%d}", handle)) {
                    return false;
                }
            }
        }
    } // no equal sign
#endif

    if (!WriteRaw(response, ",\"refs\":[")) {
        return false;
    }

    if (!WriteRefs(response)) {
        return false;
    }

    if (!WriteRaw(response, "]}")) {
        return false;
    }

    uint32_t size = buf_used(response) - offset - 4;
    unsigned char* p = response->beg + offset;
    Patch4Net(response, p, size);

    return true;
}

bool
DebuggerState::ProcessFrame(buffer* response, int64_t seq, json_value* args) {
    if (Running) {
        return WritePayload(response,
    "{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
    "\"command\":\"frame\",\"success\":false,\"running\":true}",
                   OutputSequence++, seq);
    } else {
        int frame = 0;
        if (args) {
            int64_t n;
            if (Get(args, "number", n)) {
                frame = (int)n;
            }
        }

        lua_getglobal(L, "_G");
        GetPokemonTables(L, Pokemon_Handles, Pokemon_RefObjects, 0);
        const int refTableIndex = lua_gettop(L);
        const int handleTableIndex = refTableIndex - 1;
        const int globalTableIndex = handleTableIndex-1;
        LuaPopGuard metatableGuard(L, 3);

        BufferPtr filePathBuffer;
        lua_Debug dbg;
        if (lua_getstack(L, frame, &dbg)) {
            if (!lua_getinfo(L, "flnSu", &dbg)) {
                return false;
            }

            assert(lua_isfunction(L, -1));
            // This call can come directly in response to a breakpoint being hit
            // thus we need to mno
            int functionHandle = Mnemonize(lua_gettop(L), handleTableIndex, refTableIndex, globalTableIndex, NULL, 0);
            m_HandlesToExpose.push_back(functionHandle);
            lua_pop(L, 1);


            int thisHandle = GetThis(dbg);
            if (thisHandle >= GlobalTableHandle) {
                m_HandlesToExpose.push_back(thisHandle);
            }

             const size_t offset = buf_used(response);

            if (!Write4Net(response, 0) || // sizeof following string
                !WriteRaw(response,
"{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
"\"command\":\"frame\",\"success\":true,\"running\":false,\"body\":{"
"\"index\":%d,\"receiver\":{\"ref\":%d}", OutputSequence++, seq, frame, thisHandle)) {
                return false;
            }


            const char* filePath;
            int line;
            GetLocation(L, dbg, filePathBuffer, filePath, line);
            if (!GetJsonString(filePath, strlen(filePath))) {
                return false;
            }


            if (!WriteRaw(response,
",\"func\":{\"ref\":%d},\"script\":{\"type\":\"script\",\"name\":\"%s\"},\"debuggerFrame\":false,"
"\"line\":%d,\"column\":1,\"sourceLineText\":\"%s\",\"scopes\":[",
                  functionHandle, m_JsonString->beg, line, dbg.name)) {
                return false;
            }





            /*
             * 0: Global
                                     1: Local
                                     2: With
                                     3: Closure
                                     4: Catch >,
*/
            int localHandle = m_NextValueHandle--;
            int localClosureHandle = m_NextValueHandle--;


            if (!WriteRaw(response,
"{\"index\":0,\"frameIndex\":%d,\"type\":1,\"object\":{\"handle\":%d}},"
"{\"index\":1,\"frameIndex\":%d,\"type\":3,\"object\":{\"handle\":%d}},"
"{\"index\":2,\"frameIndex\":%d,\"type\":0,\"object\":{\"ref\":%d}}]",
                          frame, localHandle, frame, localClosureHandle, frame, GlobalTableHandle)) {
                return false;
            }

            if (!WriteRaw(response, ",\"refs\":[")) {
                    return false;
            }

            if (!WriteRefs(response)) {
                return false;
            }

            if (!WriteRaw(response, "]}}")) {
                    return false;
            }

            uint32_t size = buf_used(response) - offset - 4;
            unsigned char* p = response->beg + offset;
            Patch4Net(response, p, size);

            m_Frame = frame;

        } else { // no such frame
            return WritePayload(response,
        "{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
        "\"command\":\"frame\",\"success\":false,\"running\":false}",
                       OutputSequence++, seq);
        }
    }
    return true;
}



bool
DebuggerState::ProcessBacktrace(buffer* response, int64_t seq, json_value* args) {
    if (Running) {
        return WritePayload(response,
    "{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
    "\"command\":\"backtrace\",\"success\":false,\"running\":true}",
                   OutputSequence++, seq);
    } else {
        int fromFrame = 0;
        int toFrame = 10;
        if (args) {

        }

        const size_t offset = buf_used(response);

        if (!Write4Net(response, 0) || // sizeof following string
            !WriteRaw(response,
"{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
"\"command\":\"backtrace\",\"success\":true,\"running\":false,\"body\":{"
"\"fromFrame\":%d,\"frames\":[",
               OutputSequence++, seq, fromFrame)) {
            return false;
        }

        lua_getglobal(L, "_G");
        GetPokemonTables(L, Pokemon_Handles, Pokemon_RefObjects, 0);
        const int refTableIndex = lua_gettop(L);
        const int handleTableIndex = refTableIndex - 1;
        const int globalTableIndex = handleTableIndex-1;
        const int extraLocals = 3;
        LuaPopGuard metatableGuard(L, extraLocals);

        BufferPtr filePathBuffer;
        lua_Debug dbg;

        char functionPointer[sizeof(void*)*3];
        int frame;
        for (frame = fromFrame; lua_getstack(L, frame, &dbg) && frame <= toFrame; ++frame) {
            if (!lua_getinfo(L, "flnSu", &dbg)) {
                break;
            }

            assert(lua_isfunction(L, -1));

            const bool isMain = strcmp("main", dbg.what) == 0;
            const bool isC = !isMain && strcmp("C", dbg.what) == 0;

            if (isMain) {
                dbg.name = "Lua entry";
            } else if (isC) {
                snprintf(functionPointer, sizeof(functionPointer), sizeof(void*) == 4 ? ("0x%08" PRIxPTR) : ("0x%016" PRIxPTR), (uintptr_t)lua_topointer(L, -1));
                dbg.name = functionPointer;
            }

            // remember upvalues
            const char* name;
            for (int i = 1; i <= dbg.nups; ++i) {
                name = lua_getupvalue(L, -1, i);
                assert(name);
                Mnemonize(lua_gettop(L), handleTableIndex, refTableIndex, globalTableIndex, NULL, 0);
                lua_pop(L, 1);
            }



            lua_pop(L, 1); // function

            // count locals
            int locals = 0;
            for (int j = 1; (name = lua_getlocal(L, &dbg, j)) != NULL; ++j, ++locals) {
                lua_pop(L, 1);
            }

            // remove works stuff on stack;
            locals -= extraLocals;

            // remember locals
            for (int j = 1; j < locals; ++j) {
                name = lua_getlocal(L, &dbg, j);
                assert(name);
                Mnemonize(lua_gettop(L), handleTableIndex, refTableIndex, globalTableIndex, NULL, 0);
                lua_pop(L, 1);
            }


            if (frame > fromFrame) {
                if (!WriteRaw(response, ",")) {
                    return false;
                }
            }

            const char* filePath = "";
            int line = -1;
            GetLocation(L, dbg, filePathBuffer, filePath, line);

            if (!GetJsonString(filePath, strlen(filePath))) {
                break;
            }

            int thisHandle = GetThis(dbg);
            if (thisHandle >= GlobalTableHandle) {
                m_HandlesToExpose.push_back(thisHandle);
            }

            int functionHandle = m_NextValueHandle--;



            if (!WriteRaw(response,
"{\"index\":%d,\"receiver\":{\"ref\":%d},\"func\":{\"handle\":%d,\"type\":\"function\",\"name\":\"%s\"},\"script\":{\"type\":\"script\",\"name\":\"%s\"},"
"\"debuggerFrame\":false,"
"\"line\":%d,\"column\":1,\"sourceLineText\":\"%s\",\"scopes\":[{\"index\":0,\"type\":1},{\"index\":1,\"type\":3},{\"index\":2,\"type\":0}]}",
                          frame, thisHandle, functionHandle, dbg.name, m_JsonString->beg, line-1, dbg.name)) {
                break;
            }

        }

        if (!WriteRaw(response, "],\"toFrame\":%d,\"totalFrames\":%d},\"refs\":[", frame-1, frame-fromFrame)) {
            return false;
        }

        if (!WriteRefs(response)) {
            return false;
        }

        if (!WriteRaw(response, "]}")) {
            return false;
        }

        uint32_t size = buf_used(response) - offset - 4;
        unsigned char* p = response->beg + offset;
        Patch4Net(response, p, size);

        return true;
    }

}

bool
DebuggerState::ProcessContinue(buffer* response, int64_t seq, json_value* args) {
    bool resume = false;
    if (args) {
        const char* stepaction;
        size_t len;
        int64_t stepCount;
        if (!Get(args, "stepaction", stepaction, len)) {
            resume = true;
        } else {
            if (!Get(args, "stepcount", stepCount)) {
                stepCount = 1;
            }
            if (strcmp("in", stepaction) == 0) {
                m_Step.store(-1 << Step_Count_Shift | m_Level << Level_Shift | Step_In);
                //m_Step.store(m_Level << Level_Shift | Step_Count);
            } else if (strcmp("out", stepaction) == 0) {
                m_Step.store(-1 << Step_Count_Shift | m_Level << Level_Shift | Step_Out);
            } else {
                m_Step.store((((int)stepCount)-1) << Step_Count_Shift | m_Level << Level_Shift | Step_Count);
            }
            m_Resume.notify_all();
        }
    } else {
       resume = true;
    }

    if (resume) {
        Resume();
    }

    return WritePayload(response,
"{\"seq\":%" PRId64 ",\"type\":\"response\",\"request_seq\":%" PRId64 ","
"\"command\":\"continue\",\"success\":true,\"running\":true}",
               OutputSequence++, seq);
}


void
DebuggerState::Connect() {
    std::lock_guard<std::mutex> g(m_Lock);
    KillBreakpoints();
    m_NextBreakpointId = 0;

    ResetHandleTables();
}

void
DebuggerState::Disconnect() {
    std::lock_guard<std::mutex> g(m_Lock);
    KillBreakpoints();

    ResetHandleTables();
}

void
DebuggerState::ResetHandleTables()
{
    const int before = lua_gettop(L);
    // fetch pokemon table
    lua_getglobal(L, POKEMONTABLE);
    assert(lua_type(L, -1) == LUA_TTABLE);

    // handle -> ref => weak values
    lua_newtable(L); // handle table
    lua_newtable(L); // handle meta table
    lua_pushstring(L, "__mode");
    lua_pushstring(L, "v");
    lua_rawset(L, -3);
    lua_setmetatable(L, -2);

    // set new handle table
    lua_rawseti(L, -2, Pokemon_Handles);

    // ref -> handle => weak keys
    lua_newtable(L); // ref obj table
    lua_newtable(L); // handle meta table
    lua_pushstring(L, "__mode");
    lua_pushstring(L, "k");
    lua_rawset(L, -3);
    lua_setmetatable(L, -2);

    // set new ref obj table
    lua_rawseti(L, -2, Pokemon_RefObjects);


    lua_pop(L, 1); // pokemon table
    const int after = lua_gettop(L);
    assert(before == after);
    POKEMON_UNUSED(before);
    POKEMON_UNUSED(after);
}

void
DebuggerState::KillBreakpoints() {
    for (auto* pBp = m_Breakpoints.load(std::memory_order_relaxed); pBp; pBp = pBp->Next) {
        pBp->Dead = true;
    }
}

void
DebuggerState::PruneDeadBreakpoints() {
    Breakpoint* oldHead = m_Breakpoints.load(std::memory_order_relaxed);
    Breakpoint* newHead = nullptr;

    while (oldHead) {
        // forward oldHead, keep current in x
        auto x = oldHead;
        oldHead = oldHead->Next;

        if (x->Dead) {
            delete x;
        } else {
            x->Next = newHead;
            newHead = x;
        }
    }

    m_Breakpoints.store(newHead, std::memory_order_relaxed);
}

bool s_Connected;
int s_Counter;
std::mutex s_Lock;
typedef std::unordered_map<lua_State*, std::shared_ptr<DebuggerState>> StateTable;
StateTable s_States;
std::shared_ptr<DebuggerState> s_Selected;
std::deque<buffer*> s_SendQueue;
buffer* s_ReceiveBuffer;
buffer* s_SendBuffer;
size_t s_SendBufferOffset;
uint32_t s_Packetsize = 0;
bool s_HelloReceived;

void ProcessSend();

void
Send(buffer* buffer)
{
    std::lock_guard<std::mutex> g(s_Lock);
    if (s_Connected) {
        s_SendQueue.push_back(buffer);
        ProcessSend();
    } else {
        buf_free(buffer);
    }
}

void
ReleaseDataToSend() {
    while (s_SendQueue.size()) {
        buf_free(s_SendQueue.back());
        s_SendQueue.pop_back();
    }
    if (s_SendBuffer) {
        buf_free(s_SendBuffer);
        s_SendBuffer = NULL;
    }

    s_SendBufferOffset = 0;
}

void
ReleaseReceiveData() {
    if (s_ReceiveBuffer) {
        buf_free(s_ReceiveBuffer);
        s_ReceiveBuffer = NULL;
    }

    s_Packetsize = 0;
    s_HelloReceived = false;
}

//void
//PushToRequestQueue(JsonPtr&& json) {
//    if (!s_Selected) {
//        if (s_States.size() > 0) {
//            s_Selected = s_States.begin()->second.get();
//        }
//    }

//    if (s_Selected) {
//        s_Selected->RequestQueue.push_back(std::move(json));
//    }
//}

void
ProcessSend() {
    while (true) {
        if (!s_SendBuffer) {
            if (s_SendQueue.size() > 0) {
                s_SendBuffer = s_SendQueue.front();
                s_SendQueue.pop_front();
#if POKEMON_DEBUG_MESSAGES
                fprintf(stderr, "Send\n");
                for (unsigned char* p = s_SendBuffer->beg; p != s_SendBuffer->end; ++p) {
                    fprintf(stderr, "%02x", *p);
                }
                fprintf(stderr, "\n");
                for (unsigned char* p = s_SendBuffer->beg; p != s_SendBuffer->end; ++p) {
                    fprintf(stderr, "%c", *p);
                }
                fprintf(stderr, "\n");
                fflush(stderr);
#endif
            } else {
                break;
            }
        }

        size_t size = buf_used(s_SendBuffer);
        int sent = net_send((const char*)(s_SendBuffer->beg + s_SendBufferOffset), size - s_SendBufferOffset);
        if (sent > 0) {
            s_SendBufferOffset += sent;
            if (s_SendBufferOffset == size) {
                buf_free(s_SendBuffer);
                s_SendBuffer = NULL;
                s_SendBufferOffset = 0;
            }
        else if (sent == 0) {
                break;
            }
        } else {
            net_close();
            break;
        }

    }
}

template<typename T>
bool
Read4(buffer* buf, unsigned char*& p, T& value) {
    if (p + 4 > buf->end) {
        return false;
    }

    value = p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3];
    p += 4;

    return true;
}

//bool
//Read(buffer* buf, unsigned char*& p, wchar_t* str, size_t chars) {
//    if (p + sizeof(*str) * chars > buf->end) {
//        return false;
//    }

//    for (size_t i = 0; i < chars; ++i) {
//        str[i] = p[0] << 8 | p[1];
//        p += 2;
//    }

//    return true;
//}

template<typename T>
bool
Write4(buffer* buf, T value) {
    if (!buf_reserve(buf, 4)) {
        return false;
    }

    *buf->end++ = ((uint32_t)value >> 24) & 0xff;
    *buf->end++ = ((uint32_t)value >> 16) & 0xff;
    *buf->end++ = ((uint32_t)value >> 8) & 0xff;
    *buf->end++ = ((uint32_t)value >> 0) & 0xff;

    return true;
}

//bool
//Write(buffer* buf, const wchar_t* str, size_t chars) {
//    if (!buf_reserve(buf, chars * 2)) {
//        return false;
//    }

//    for (size_t i = 0; i < chars; ++i) {
//        *buf->end++ = (str[i] >> 8) & 0xff;
//        *buf->end++ = (str[i] >> 0) & 0xff;
//    }

//    return true;
//}


//bool
//Write(buffer* buf, const wchar_t* str) {
//    return Write(buf, str, wcslen(str));
//}


bool
Write(buffer* buf, const char* str, size_t chars) {
    if (!buf_reserve(buf, chars * 2)) {
        return false;
    }

    for (size_t i = 0; i < chars; ++i) {
        *buf->end++ = 0;
        *buf->end++ = str[i];
    }

    return true;
}

bool
Write(buffer* buf, const char* str) {
    return Write(buf, str, strlen(str));
}


buffer*
ToWString(buffer* buf, unsigned char*& p, int chars) {
    if (p + sizeof(wchar_t) * chars > buf->end) {
        return nullptr;
    }
    buffer* result = buf_alloc((chars  + 1) * sizeof(wchar_t));
    if (!result) {
        return nullptr;
    }

    for (int i = 0; i < chars; ++i, p += 2) {
        switch (sizeof(wchar_t)) {
        case 2:
            *result->end++ = p[1];
            *result->end++ = p[0];
            break;
        case 4:
            *result->end++ = p[1];
            *result->end++ = p[0];
            *result->end++ = 0;
            *result->end++ = 0;
            break;
        default:
            assert(false);
            break;
        }
    }

    memset(result->end, 0, sizeof(wchar_t));
    result->end += sizeof(wchar_t);

    return result;
}

buffer*
ToString(buffer* buf, unsigned char*& p, int chars) {
    if (p + chars > buf->end) {
        return nullptr;
    }
    buffer* result = buf_alloc(chars  + 1);
    if (!result) {
        return nullptr;
    }

    memcpy(result->beg, p, chars);
    result->end += chars;
    p += chars;

    *result->end++ = 0;

    return result;
}

buffer*
SetResponseSize(buffer* b) {
    // Qt....
    uint32_t size = buf_used(b);
    *((uint32_t*)b->beg) = (size);

    return b;
}


buffer*
MakeHelloResponse() {
    buffer* b = buf_alloc(128);
    if (!b) {
        return NULL;
    }
    assert(0 == buf_used(b));
    if (!Write4(b, static_cast<uint32_t>(0)) ||
        !Write4(b, static_cast<uint32_t>(46)) || // strlen in bytes
        !Write(b, "QDeclarativeDebugClient") ||
        !Write4(b, static_cast<int32_t>(0)) || // op
        !Write4(b, static_cast<int32_t>(1)) || // version
        !Write4(b, static_cast<uint32_t>(1)) || // plugins name count
        !Write4(b, static_cast<uint32_t>(20)) || // strlen in bytes
        !Write(b, "V8Debugger") ||
        !Write4(b, static_cast<uint32_t>(1)) || // plugins version count
        !Write4(b, 1.0f) || // V8Debugger
        !Write4(b, static_cast<int32_t>(12)) || // stream version
        false) {
        buf_free(b);
        return NULL;
    }

    return SetResponseSize(b);
}

buffer*
BeginQmlDebuggerResponse() {
    buffer* b = buf_alloc(128);
    if (!b) {
        return NULL;
    }
    assert(0 == buf_used(b));
    if (!Write4(b, static_cast<uint32_t>(0)) || // total size, patched in later
        !Write4(b, static_cast<uint32_t>(20)) || // strlen in bytes
        !Write(b, "V8Debugger") ||
        false) {
        buf_free(b);
        return NULL;
    }

    return b;
}



buffer*
BeginV8DebuggerResponse() {
    buffer* b = BeginQmlDebuggerResponse();
    if (!b) {
        return NULL;
    }
    assert(buf_used(b) == 28);
    if (!Write4(b, static_cast<uint32_t>(0)) || // non Qml instracture payload size, patched in later
        !WritePayload(b, "V8DEBUG") ||
        false) {
        buf_free(b);
        return NULL;
    }

    return b;
}

buffer*
EndV8DebuggerResponse(buffer* buf) {
    uint32_t sizeofV8Data = buf_used(buf)-32;
    sizeofV8Data = htonl(sizeofV8Data);
    unsigned char* p = buf->beg + 28;
    *p++ = (sizeofV8Data >> 0) & 0xff;
    *p++ = (sizeofV8Data >> 8) & 0xff;
    *p++ = (sizeofV8Data >> 16) & 0xff;
    *p++ = (sizeofV8Data >> 24) & 0xff;
    return SetResponseSize(buf);
}

buffer*
MakeV8ResponseResponseHeader() {
    buffer* b = BeginV8DebuggerResponse();
    if (!b) {
        return NULL;
    }

    if (!WritePayload(b, "v8message") ||
        false) {
        buf_free(b);
        return NULL;
    }
    return b;
}


buffer*
MakeConnectResponse() {
    buffer* b = BeginV8DebuggerResponse();
    if (!b) {
        return NULL;
    }

    if (!WritePayload(b, "connect") ||
            //!Write4(b, static_cast<int32_t>(1)) || // version
            //!Write4(b, static_cast<int32_t>(1)) || // magic
        false) {
        buf_free(b);
        return NULL;
    }

    return EndV8DebuggerResponse(b);
}


buffer*
MakeInterruptResponse() {
    buffer* b = BeginV8DebuggerResponse();
    if (!b) {
        return NULL;
    }

    if (!WritePayload(b, "interrupt") ||
        //!Write4(b, static_cast<int32_t>(1)) || // version
        //!Write4(b, static_cast<int32_t>(1)) || // magic
        false) {
        buf_free(b);
        return NULL;
    }

    return EndV8DebuggerResponse(b);
}

// Qt version 12 data stream
// 1 big endian
// string : 4 byte size if bytes
//          bytes UTF-16 data?
//
void
ProcessReceive() {
    while (true) {
        if (s_Packetsize) {
            if (buf_used(s_ReceiveBuffer) == s_Packetsize) {
#if POKEMON_DEBUG_MESSAGES
                fprintf(stderr, "Receive\n");
                for (unsigned char* p = s_ReceiveBuffer->beg; p != s_ReceiveBuffer->end; ++p) {
                    fprintf(stderr, "%02x", *p);
                }
                fprintf(stderr, "\n");
                for (unsigned char* p = s_ReceiveBuffer->beg; p != s_ReceiveBuffer->end; ++p) {
                    fprintf(stderr, "%c", *p);
                }
                fprintf(stderr, "\n");
                fflush(stderr);
#endif
                unsigned char* p = s_ReceiveBuffer->beg;
                uint32_t bytes;

                if (!Read4(s_ReceiveBuffer, p, bytes)) {
                    net_close();
                    break;
                }

                BufferPtr wstr(ToWString(s_ReceiveBuffer, p, bytes / 2));
                if (!wstr) {
                    net_close();
                    break;
                }

                wchar_t* name =  (wchar_t*)wstr->beg;

                if (s_HelloReceived) {
                    if (wcscmp(name, L"V8Debugger") == 0) {
                        // next
                        // 4 bytes payload size
                        // 4 bytes key length in bytes
                        // bytes string (const char*) , e.g. V8DEBUG
                        if (!Read4(s_ReceiveBuffer, p, bytes)) { // payload bytes
                            net_close();
                            break;
                        }

                        uint32_t keyLen = 0;
                        if (!Read4(s_ReceiveBuffer, p, keyLen)) {
                            net_close();
                            break;
                        }
                        BufferPtr str(ToString(s_ReceiveBuffer, p, keyLen));
                        if (!str) {
                            net_close();
                            break;
                        }

                        if (strcmp("V8DEBUG", (char*)str->beg) == 0) {

                            if (!Read4(s_ReceiveBuffer, p, keyLen)) {
                                net_close();
                                break;
                            }
                            str.reset(ToString(s_ReceiveBuffer, p, keyLen));
                            if (!str) {
                                net_close();
                                break;
                            }

                            if (strcmp("disconnect", (char*)str->beg) == 0) {
                                if (s_Selected) {
                                    s_Selected->Disconnect();
                                }
                                for (auto it = s_States.begin(); it != s_States.end(); ++it) {
                                    it->second->Resume();
                                }
                                net_close();
                            } else if (strcmp("connect", (char*)str->beg) == 0) {
                                if (s_Selected) {
                                    s_Selected->Connect();
                                }
                                buffer* response = MakeConnectResponse();
                                if (!response) {
                                    net_close();
                                    break;
                                }

                                s_Packetsize = 0;
                                s_SendQueue.push_back(response);
                                ProcessSend();
                            } else if (strcmp("v8request", (char*)str->beg) == 0) {
                                if (p + 6 < s_ReceiveBuffer->end) {
                                    p += 4;
                                    size_t len = s_ReceiveBuffer->end - p;
                                    JsonPtr json(json_parse((char*)p, len));
                                    if (json) {
                                        if (json->type != json_object) {
                                            net_close();
                                            break;
                                        } else {
                                            // Start response heaer
                                            buffer* response = MakeV8ResponseResponseHeader();
                                            if (!response) {
                                                net_close();
                                                break;
                                            }

                                            // call into active state
                                            response = s_Selected->ProcessRequest(response, std::move(json));
                                            if (!response) {
                                                net_close();
                                                break;
                                            }

                                            response = EndV8DebuggerResponse(response);
                                            s_Packetsize = 0;
                                            s_SendQueue.push_back(response);
                                            ProcessSend();
                                        }
                                    } else { // JSON parse failed
                                        net_close();
                                        break;
                                    }
                                } else { // not enought space for JSON
                                    net_close();
                                    break;
                                }
                            } else if (strcmp("interrupt", (char*)str->beg) == 0) {
                                buffer* response = MakeInterruptResponse();
                                if (!response) {
                                    net_close();
                                    break;
                                }

                                for (auto it = s_States.begin(); it != s_States.end(); ++it) {
                                    it->second->Break();
                                }

                                s_Packetsize = 0;
                                s_SendQueue.push_back(response);
                                ProcessSend();
                            } else { // unknonwn 2nd level command
                                net_close();
                                break;
                            }
                        } else { // unknonwn first level command
                            net_close();
                            break;
                        }
                    } else { // unknown plugin (not V8)
                        net_close();
                        break;
                    }
                } else { // no hello message yet

//                    // debugger hello: pack << serverId << 0 << protocolVersion << plugins.keys() << QDataStream().version();
//                    // Extract QDataStream version 12
                    int32_t zero;
                    int32_t version;

                    if (!Read4(s_ReceiveBuffer, p, zero)) {
                        net_close();
                        break;
                    }

                    if (!Read4(s_ReceiveBuffer, p, version)) {
                        net_close();
                        break;
                    }

                    if (version > 1) {
                        //
                        net_close();
                        break;
                    }
                    // plugin keys...
                    // ds version

                    // send response
                    buffer* response = MakeHelloResponse();
                    if (!response) {
                        net_close();
                        break;
                    }

                    s_Packetsize = 0;
                    s_HelloReceived = true;

                    s_SendQueue.push_back(response);
                    ProcessSend();

//                    fprintf(stdout, "Hello response sent\n");
//                    fflush(stdout);
                }
            } else {
                int recv = net_receive((char*)s_ReceiveBuffer->end, s_Packetsize - buf_used(s_ReceiveBuffer));
                if (recv > 0) {
                    s_ReceiveBuffer->end += recv;
                } else if (recv == 0) {
                    break;
                } else {
                    net_close();
                    break;
                }
            }
        } else {
            int recv = net_receive((char*)&s_Packetsize, sizeof(s_Packetsize));
            if (recv == 0) {
                break;
            } else if (recv < 0) {
                net_close();
                break;
            } else if (recv != (int)sizeof(s_Packetsize)) {
                net_close();
                break;
            } else {
                // Sure why not Qt people
                if (s_Packetsize <= 4) { // wrong packet
                    net_close();
                    break;
                } else {
                    s_Packetsize -= sizeof(s_Packetsize);
                    if (!s_ReceiveBuffer) {
                        s_ReceiveBuffer = buf_alloc(s_Packetsize);
                        if (!s_ReceiveBuffer) {
                            net_close();
                            break;
                        }
                    } else if (!buf_resize(s_ReceiveBuffer, s_Packetsize)) {
                        net_close();
                        break;
                    }
                    buf_clear(s_ReceiveBuffer);
                }
            }
        }
    }
}

void
NetCallback(void* ctx, int events) {
    std::lock_guard<std::mutex> g(s_Lock);
    if (events & NET_EVENT_HANGUP) {
        s_Connected = false;
        ReleaseDataToSend();
        ReleaseReceiveData();
    } else if (events & NET_EVENT_CONNECT) {
        s_Connected = true;
    } else {
        if (events & NET_EVENT_SEND) {
            ProcessSend();
        }
        if (events & NET_EVENT_RECEIVE) {
            ProcessReceive();
        }
    }
}

void
LuaHook(lua_State* L, lua_Debug* d) {
    std::shared_ptr<DebuggerState> state;
    {
        std::lock_guard<std::mutex> g(s_Lock);

        StateTable::iterator it = s_States.find(L);

        if (it != s_States.end()) {
            state = it->second;
        }
    }

    if (state) {
        state->ProcessLuaStep(d);
    }
}

} // anon

extern "C"
int
luaD_setup(int* argc, char** argv) {
    std::lock_guard<std::mutex> g(s_Lock);
    if (s_Counter++ == 0) {
//        auto L =  lua_open();
//        std::shared_ptr<DebuggerState> state(new DebuggerState(L));
//        s_Selected = state.get();
//        s_States.insert(std::make_pair(L, state));
        net_set_callback(NULL, NetCallback);
        auto error = net_listen(3768, 0);
        if (error < 0) {
            return PKMN_E_CHECK_SYSTEM_ERROR;
        }
    }

    return 0;
//    while (true) {
//        auto x = s_SetupCounter.load();
//        if (x > 0) {
//            if (s_SetupCounter.compare_exchange_strong(x, x + 1)) {
//                return PKMN_E_NONE;
//            }
//        } else if (x == 0) {
//            if (s_SetupCounter.compare_exchange_strong(x, -1)) {
//                try {
//                    s_Thread = std::thread(LuaDebuggerLoop);
//                } catch (std::exception& e) {
//                    s_SetupCounter.store(0);
//                    return PKMN_E_OUT_OF_RESOURCES;
//                }
//                s_SetupCounter.store(x + 1);
//                return PKMN_E_NONE;
//            }
//        }
//        std::this_thread::yield();
//    }
}

extern "C"
void
luaD_teardown()
{
    std::lock_guard<std::mutex> g(s_Lock);
    if (--s_Counter == 0) {
        net_set_callback(NULL, NULL);
        net_hangup();
        s_Selected = NULL;
        ReleaseDataToSend();
        ReleaseReceiveData();
    }
//    while (true) {
//        auto x = s_SetupCounter.load();
//        if (x > 0) {
//            if (x == 1) {
//                if (s_SetupCounter.compare_exchange_strong(x, -2)) {
//                    Teardown();
//                    s_SetupCounter.store(0);
//                    return;
//                }
//            } else {
//                if (s_SetupCounter.compare_exchange_strong(x, x - 1)) {
//                    return;
//                }
//            }
//        } else if (x == 0) {
//            return; // never initialized
//        }
//        std::this_thread::yield();
//    }
}

extern "C"
int
luaD_register(lua_State* L) {
    if (!L) {
        return PKMN_E_INVALID_PARAM;
    }

    std::lock_guard<std::mutex> g(s_Lock);
    if (s_Counter <= 0) {
        return PKMN_E_NOT_INITIALIZED;
    }

    StateTable::iterator it = s_States.find(L);
    if (it != s_States.end()) {
        return PKMN_E_ALREADY_REGISTERED;
    }

    try {
        std::shared_ptr<DebuggerState> state(new DebuggerState(L));

        state->Lock();

        s_States.insert(std::make_pair(L, state));
        if (!s_Selected) {
            s_Selected = state;
        }

        lua_newtable(L);
        for (int i = 0; i < Pokemon_Count; ++i) {
            lua_newtable(L);
            lua_rawseti(L, -2, i + 1);
        }
        lua_setglobal(L, POKEMONTABLE);

        state->ResetHandleTables();

        state->Init();
        state->Unlock();
    } catch (...) {
        return PKMN_E_OUT_OF_RESOURCES;
    }

    return PKMN_E_NONE;
}

extern "C"
int
luaD_unregister(lua_State* L) {
    if (!L) {
        return PKMN_E_INVALID_PARAM;
    }

    std::lock_guard<std::mutex> g(s_Lock);
    if (s_Counter <= 0) {
        return PKMN_E_NOT_INITIALIZED;
    }
    StateTable::iterator it = s_States.find(L);
    if (it != s_States.end()) {
        return PKMN_E_NOT_REGISTERED;
    }
    std::shared_ptr<DebuggerState> state(it->second);
    state->Lock();
    state->Uninit();
    s_States.erase(it);
    if (s_Selected == state) {
        s_Selected.reset();
    }
    if (!s_Selected && s_States.size()) {
        s_Selected = s_States.begin()->second;
    }
    lua_pushnil(L);
    lua_setglobal(L, POKEMONTABLE);
    state->Unlock();
    return PKMN_E_NONE;
}

extern "C"
int
luaD_push_location(lua_State* L, const char* filePath, int line) {
    if (!L || !filePath || !*filePath || line <= 0) {
        return PKMN_E_INVALID_PARAM;
    }

    std::lock_guard<std::mutex> g(s_Lock);
    if (s_Counter <= 0) {
        return PKMN_E_NOT_INITIALIZED;
    }
    StateTable::iterator it = s_States.find(L);
    if (it == s_States.end()) {
        return PKMN_E_NOT_REGISTERED;
    }
    int error = PKMN_E_NONE;
    std::size_t len = strlen(filePath);
    buffer* str = buf_alloc(32+len);
    if (!str) {
        error = PKMN_E_OUT_OF_RESOURCES;
    } else {
        it->second->Lock();
        GetPokemonTable(L, Pokemon_Locations);
        lua_rawgeti(L, -1, 1);
        const int entries = (int)lua_tointeger(L, -1);
        lua_pop(L, 1);

        // push value
        const int chars = sprintf((char*)str->beg, "%d:%s", line, filePath);

        // set entry
        lua_pushlstring(L, (char*)str->beg, chars);
        lua_rawseti(L, -2, entries + 2);

        // update size
        lua_pushinteger(L, entries + 1);
        lua_rawseti(L, -2, 1);

        // pop table
        lua_pop(L, 1);
        it->second->Unlock();

        // free string
        buf_free(str);
    }
    return error;
}


extern "C"
int
luaD_pop_location(lua_State* L) {
    if (!L) {
        return PKMN_E_INVALID_PARAM;
    }

    std::lock_guard<std::mutex> g(s_Lock);
    if (s_Counter <= 0) {
        return PKMN_E_NOT_INITIALIZED;
    }
    StateTable::iterator it = s_States.find(L);
    if (it == s_States.end()) {
        return PKMN_E_NOT_REGISTERED;
    }
    int error = PKMN_E_NONE;
    it->second->Lock();
    GetPokemonTable(L, Pokemon_Locations);
    // get size of table
    lua_rawgeti(L, -1, 1);
    const int entries = (int)lua_tointeger(L, -1);
    lua_pop(L, 1);
    if (entries == 0) {
        error = PKMN_E_NOT_REGISTERED;
    } else {
        // clear slot
        lua_pushnil(L);
        lua_rawseti(L, -2, entries + 2);
        // update count
        lua_pushinteger(L, entries - 1);
        lua_rawseti(L, -2, 1);
    }
    // pop table
    lua_pop(L, 1);
    it->second->Unlock();
    return error;
}
