#include "buffer.h"


#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>

#if defined(_WIN64) || defined(_WIN32)
#   include <windows.h>
#   include <inttypes.h>
/*#define cas(ptr, new, old) InterlockedCompareExchange128(ptr, (*((int64_t*)new) >> 64, *((int64_t*)new))*/
#elif defined(__GNUC__)
#define membar() __sync_synchronize()
#   if __WORDSIZE == 32
#       define cas __sync_bool_compare_and_swap((__int64_t*)ptr, *((__int64_t*)old), *((__int64_t*)new))
#   else
#       define cas(ptr, new, old) __sync_bool_compare_and_swap((__int128*)ptr, *((__int128_t*)old), *((__int128_t*)new))
#   endif
#endif

static aba_ptr s_Stack;

static
void
Push(buffer* node)
{
    aba_ptr* head = &s_Stack;
    aba_ptr* nodeNext = (aba_ptr*)node;
    aba_ptr oldHead, newHead;

    do {
        membar();

        oldHead = *head;

        nodeNext->Ptr = oldHead.Ptr;

        membar(); /* make write visible */

        newHead.Aba = oldHead.Aba + 1;
        newHead.Ptr = (uintptr_t*)node;
    } while (!cas(head, &newHead, &oldHead));
}

static
buffer*
Pop()
{
    aba_ptr* head = &s_Stack;
    buffer* result = NULL;
    aba_ptr oldHead, newHead;

    do {
        membar();

        oldHead = *head;

        if (!oldHead.Ptr) {
            result = NULL;
            break;
        }

        result = (buffer*)oldHead.Ptr;

        newHead.Aba = oldHead.Aba + 1;
        newHead.Ptr = result->next.Ptr;
    } while (!cas(head, &newHead, &oldHead));

    return result;
}


static
void
Teardown() {
    buffer* buf = NULL;
    while ((buf = Pop()) != NULL) {
        free(buf->beg);
        free(buf);
    }
}

static
inline
size_t
Max(size_t lhs, size_t rhs) {
    return lhs < rhs ? rhs : lhs;
}

#if defined(__GNUC__)
__attribute__((constructor))
#endif
static void Setup() {
   atexit(Teardown);
}

extern
buffer*
buf_alloc(size_t bytes)
{
    buffer* buf = Pop(&s_Stack);

    if (!buf) {
        buf = (buffer*)malloc(sizeof(*buf));
        if (!buf) {
            return NULL;
        }
        memset(buf, 0, sizeof(*buf));
    }

    if (!buf_resize(buf, bytes)) {
        Push(buf);
        return NULL;
    }

   //fprintf(stderr, "out %p\n", buf);

    return buf;
}

extern
int
buf_grow(buffer* buf, size_t bytes)
{
    size_t oldSize, oldUsed, newSize;

    assert(buf);

    oldUsed = buf_used(buf);
    oldSize = buf->cap - buf->beg;
    newSize = Max((oldSize * 168) / 100, bytes);
    buf->beg = realloc(buf->beg, newSize);
    if (!buf->beg) {
        buf->cap = NULL;
        buf->end = NULL;
        return 0;
    }

    buf->end = buf->beg + oldUsed;
    buf->cap = buf->beg + newSize;

    return 1;
}

extern
void
buf_free(buffer* buf)
{
    //fprintf(stderr, "in  %p\n", buf);
    assert(buf);
    buf_clear(buf);

    Push(buf);
}


