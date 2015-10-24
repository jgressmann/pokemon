/* The MIT License (MIT)
 *
 * Copyright (c) 2015 Jean Gressmann <jean@0x42.de>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */


#include "buffer.h"


#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdio.h>



#if defined(_WIN64) || defined(_WIN32)
#   include <windows.h>
#   include <inttypes.h>
#   define membar() MemoryBarrier()
#   define INLINE __forceinline
#   if defined(_WIN64)
#       define cas2(ptr, new, old) InterlockedCompareExchange128((LONGLONG volatile *)ptr, (*((LONGLONG*)new) >> 64, *((LONGLONG*)new), (LONGLONG*)old)
#   else
#       define cas2(ptr, new, old) (InterlockedCompareExchange64((LONGLONG volatile *)ptr, *((LONGLONG*)new), *((LONGLONG*)old)) == *((LONGLONG*)old))
#   endif
#   define cas1(ptr, new, old) InterlockedCompareExchange((LONG volatile *)ptr, *((LONG*)old), *((LONG*)new))
#   define yield() Sleep(0)
#elif defined(__GNUC__)
#   include <pthread.h>
#   define membar() __sync_synchronize()
#   define INLINE inline
#   if __WORDSIZE == 32
#       define cas2(ptr, new, old) __sync_bool_compare_and_swap((__int64_t*)ptr, *((__int64_t*)old), *((__int64_t*)new))
#   else
#       define cas2(ptr, new, old) __sync_bool_compare_and_swap((__int128*)ptr, *((__int128_t*)old), *((__int128_t*)new))
#   endif
#   define cas1(ptr, new, old) __sync_bool_compare_and_swap((__int32_t*)ptr, *((__int32_t*)old), *((__int32_t*)new))
#   define yield() pthread_yield()
#endif


#ifdef SINGLECORE
#   undef membar
#   define membar()
#   undef cas2
#   define cas2  Cas
static volatile int s_Lock;
static
int
Cas(aba_ptr volatile * ptr, aba_ptr* new, aba_ptr* old) {
    int result, one = 1, zero = 0;
    while (!cas1(&s_Lock, &one, &zero)) {
        yield();
    }

    if ((result = ((ptr->Ptr == old->Ptr) & (ptr->Aba == old->Aba)))) {
        *ptr = *new;
    }

    s_Lock = 0;

    return result;
}
#endif

/* assert sizeof aba_ptr == 2 * sizeof(void*) */
typedef char AssertSizeofAbaPtrEqualsTwiceSizeofVoidStar[sizeof(aba_ptr) == 2 * sizeof(void*) ? 1 : -1];

static aba_ptr s_Stack;
#define DEFAULT_MIN_SIZE 64
static size_t s_MinSize = DEFAULT_MIN_SIZE;
static size_t s_Limit = 0;
static volatile size_t s_Use = 0;

static
void
Push(buffer* node) {
    aba_ptr volatile * head = &s_Stack;
    aba_ptr volatile * nodeNext = (aba_ptr*)node;
    aba_ptr oldHead, newHead;

    do {
        membar();

        oldHead = *head;

        nodeNext->Ptr = oldHead.Ptr;

        membar(); /* make write visible */

        newHead.Aba = oldHead.Aba + 1;
        newHead.Ptr = node;
    } while (!cas2(head, &newHead, &oldHead));
}

static
buffer*
Pop() {
    aba_ptr volatile * head = &s_Stack;
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
    } while (!cas2(head, &newHead, &oldHead));

    return result;
}

static
INLINE
size_t
Max(size_t lhs, size_t rhs) {
    return lhs < rhs ? rhs : lhs;
}

static
size_t
AtomicAdd(size_t volatile * counter, intptr_t value) {
    size_t old, new;
    do {
        old = *counter;
        new = old + value;
    } while (!cas1(counter, &new, &old));

    return new;
}

#if defined(__GNUC__)
__attribute__((constructor))
#endif
static void Setup() {
   atexit(buf_clear_cache);
}

extern
buffer*
buf_alloc(size_t bytes) {
    buffer* buf = Pop(&s_Stack);

    if (!buf) {
        buf = (buffer*)malloc(sizeof(*buf));
        if (!buf) {
            return NULL;
        }
        memset(buf, 0, sizeof(*buf));
    }

    AtomicAdd(&s_Use, -(intptr_t)buf_size(buf));

    if (!buf_resize(buf, bytes)) {
        AtomicAdd(&s_Use, (intptr_t)buf_size(buf));
        Push(buf);
        return NULL;
    }

    //fprintf(stderr, "out %p %p\n", buf, buf->cap);

    return buf;
}

extern
int
buf_grow(buffer* buf, size_t bytes) {
    size_t oldSize, oldUsed, newSize;

    assert(buf);

    oldUsed = buf_used(buf);
    oldSize = buf_size(buf);
    newSize = Max((oldSize * 168) / 100, Max(bytes, s_MinSize));
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
    assert(buf);

    //fprintf(stderr, "in  %p %p\n", buf, buf->cap);

    if (s_Limit && s_Use >= s_Limit) {
        free(buf->beg);
        buf->beg = NULL;
        buf->end = NULL;
        buf->cap = NULL;
    } else {
        buf_clear(buf);
        AtomicAdd(&s_Use, (intptr_t)buf_size(buf));
    }

    Push(buf);
}

extern
void
buf_set_min_size(size_t bytes) {
    s_MinSize = bytes ? bytes : DEFAULT_MIN_SIZE;
}

extern
void
buf_set_cache_limit(size_t bytes) {
    s_Limit = bytes;
}

void
buf_clear_cache() {
    buffer* buf = NULL;
    while ((buf = Pop()) != NULL) {
        free(buf->beg);
        free(buf);
    }

    s_Use = 0;
}
