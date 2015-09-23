/* For copyright information see the LICENSE file */

#ifndef PLATFORM_039939933_H
#define PLATFORM_039939933_H

#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif


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

int is_absolute_file_path(const char* filePath);
int to_absolute_file_path(const char** filePath, buffer** filePathBuffer);

#ifdef __cplusplus
}
#endif

#endif /* PLATFORM_039939933_H */
