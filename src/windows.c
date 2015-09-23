#include "platform.h"

#include <WinSock2.h>
#include <Windows.h>

int
net_listen(int port, int flags) {
    return 0;
}

void
net_close() {

}

int
net_hangup() {
    return 0;
}

void
net_set_callback(void* ctx, net_callback callback) {

}

int
net_send(const char* buffer, int bytes) {
    return bytes;
}

int
net_receive(char* buffer, int bytes) {
    return 0;
}

int
is_absolute_file_path(const char* filePath) {
    return 0;
}

int
to_absolute_file_path(const char** filePath, buffer** filePathBuffer) {
    return 0;
}
