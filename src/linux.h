/* For copyright information see the LICENSE file */

#ifndef LINUX_039939933_H
#define LINUX_039939933_H

#include <sys/epoll.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Closes the handle and retries on EINTR */
void safe_close(int handle);

/* Closes the handle and then sets it to -1 */
void safe_close_ref(int* handle);

/* Callback function type for epoll events */
typedef void (*epoll_callback_t)(void* ctx, struct epoll_event* ev);

/* Structure for callback data */
typedef struct _epoll_callback_data
{
    void* ctx;
    epoll_callback_t callback;
}
epoll_callback_data;

/* Creates the epoll event loop
 *
 * Return: The epoll file descriptor on success, else -1. Use errno for details.
 *
 */
int epoll_loop_create();

/* Returns the epoll file descriptor. The value is -1 if no loop exists. */
int epoll_loop_get_fd();

/* Decrement the loop reference cout
 *
 * If the ref count drops to 0 the epoll instance and other resources related
 * to the loop will be freed.
 *
 */
void epoll_loop_destroy();

/* Sets an event callback for a file descriptor
 *
 * Return: 0 on success; otherwise -1. Use errno to get details.
 *
 */
int epoll_loop_set_callback(int handle, epoll_callback_data callback);

#define NET_EVENT_SEND 1
#define NET_EVENT_RECEIVE 2
#define NET_EVENT_HANGUP 4
#define NET_EVENT_CONNECT 8
typedef void (*net_callback)(void* ctx, int events);

int net_listen(int port, int flags);
void net_close();
int net_hangup();
void net_set_callback(void* ctx, net_callback callback);
int net_send(const char* buffer, int bytes);
int net_receive(char* buffer, int bytes);

#ifdef __cplusplus
}
#endif

#endif // LINUX_H
