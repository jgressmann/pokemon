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
#       define cas(ptr, new, old) InterlockedCompareExchange128((LONGLONG volatile *)ptr, (*((LONGLONG*)new) >> 64, *((LONGLONG*)new), (LONGLONG*)old)
#   else
#       define cas(ptr, new, old) (InterlockedCompareExchange64((LONGLONG volatile *)ptr, *((LONGLONG*)new), *((LONGLONG*)old)) == *((LONGLONG*)old))
#   endif
#elif defined(__GNUC__)
#   define membar() __sync_synchronize()
#   define INLINE inline
#   if __WORDSIZE == 32
#       define cas __sync_bool_compare_and_swap((__int64_t*)ptr, *((__int64_t*)old), *((__int64_t*)new))
#   else
#       define cas(ptr, new, old) __sync_bool_compare_and_swap((__int128*)ptr, *((__int128_t*)old), *((__int128_t*)new))
#   endif
#endif

/* assert sizeof aba_ptr == 2 * sizeof(void*) */
typedef char AssertSizeofAbaPtrEqualsTwiceSizeofVoidStar[sizeof(aba_ptr) == 2 * sizeof(void*) ? 1 : -1];

static aba_ptr s_Stack;

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
    } while (!cas(head, &newHead, &oldHead));
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
    } while (!cas(head, &newHead, &oldHead));

    return result;
}


static
void
Teardown(void) {
    buffer* buf = NULL;
    while ((buf = Pop()) != NULL) {
        free(buf->beg);
        free(buf);
    }
}

static
INLINE
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
buf_alloc(size_t bytes) {
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
    newSize = Max((oldSize * 168) / 100, Max(bytes, sizeof(void*)));
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

    buf_clear(buf);

    Push(buf);
}


