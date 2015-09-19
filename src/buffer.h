/* See buffer.c for license information */

#ifndef BUFFER_94993292_H
#define BUFFER_94993292_H

#include <stddef.h>
#include <stdint.h>

#if defined( _MSC_VER)
#   if defined(_WIN64)
#      define ALIGN(x) __declspec(align(16))
#   else
#      define ALIGN(x) __declspec(align(8))
#   endif
#elif defined(__GNUC__)
#   define ALIGN(x) __attribute__((aligned (x)))
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef ALIGN(2 * sizeof(void*)) struct
{
    void* Ptr;
    uintptr_t Aba;
}
aba_ptr;

typedef struct
{
    aba_ptr next;
    unsigned char* beg;
    unsigned char* end;
    unsigned char* cap;
}
buffer;

/* Creates a buffer of the given size.
 *
 * Returns NULL if malloc fails
 * */
buffer*
buf_alloc(size_t bytes);


/* Resizes the buffer to the specified size
 *
 * Returns 1 on success, 0 on failure.
 * */
int
buf_grow(buffer* buf, size_t bytes);

/* Destroyes the buffer */
void
buf_free(buffer* buf);

/* Evaluates to the capacity of a buffer */
#define buf_size(buf) ((size_t)((buf)->cap - (buf)->beg))
/* Evaluates to the used bytes of a buffer. Always <= buffer capacity */
#define buf_used(buf) ((size_t)((buf)->end - (buf)->beg))
/* Evaluates to the number of unused bytes left in buffer. Always in range [0, capacity] */
#define buf_left(buf) ((size_t)((buf)->cap - (buf)->end))
/* Resizes the buffer to fit size bytes */
#define buf_resize(buf, size) (buf_size(buf) < (size) ? buf_grow(buf, size) : 1)
/* Clears the buffer i.e. sets used to 0 */
#define buf_clear(buf) buf->end = buf->beg
/* Reserves space for size bytes at then end */
#define buf_reserve(buf, size) buf_resize(buf, buf_used(buf) + size)

#ifdef __cplusplus
}
#endif

#endif /* BUFFER_94993292_H */

