/* For copyright information see the LICENSE file */

#include "platform.h"
#include "buffer.h"


#include <assert.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netdb.h>
#include <netinet/tcp.h>

static
void
safe_close(int fd) {
    int error;
    while ((error = close(fd)) == -1 && errno == EINTR) {
        pthread_yield();
    }
}

static
void
safe_close_ref(int* fd) {
    assert(fd);

    if (*fd >= 0) {
        safe_close(*fd);
        *fd = -1;
    }
}


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
static int epoll_loop_create();

/* Returns the epoll file descriptor. The value is -1 if no loop exists. */
static int epoll_loop_get_fd();

/* Decrement the loop reference cout
 *
 * If the ref count drops to 0 the epoll instance and other resources related
 * to the loop will be freed.
 *
 */
static void epoll_loop_destroy();

/* Sets an event callback for a file descriptor
 *
 * Return: 0 on success; otherwise -1. Use errno to get details.
 *
 */
static int epoll_loop_set_callback(int handle, epoll_callback_data callback);

#define MinBufferSize  4

static pthread_mutex_t s_Lock = PTHREAD_RECURSIVE_MUTEX_INITIALIZER_NP;
static pthread_t s_EPollThread;
static int s_RefCount;
static int s_EPollFd = -1;
static epoll_callback_data* s_Callbacks;
static int s_CallbacksSize;
static volatile int s_Running = 0;
static struct epoll_event* s_Events = NULL;

static
void*
EPollThreadMain(void* arg) {
    const int epollFd = s_EPollFd;
    int count = 0, bufferSize = 0;

    s_Running = 1;

    for (;;) {
        pthread_mutex_lock(&s_Lock);
        if (!s_Events) {
            bufferSize = s_CallbacksSize >= MinBufferSize ? s_CallbacksSize : MinBufferSize;
            s_Events = (struct epoll_event*)malloc(bufferSize * sizeof(*s_Events));
            if (!s_Events) goto Exit;
        } else if (bufferSize < s_CallbacksSize) {
            s_Events = (struct epoll_event*)realloc(s_Events, s_CallbacksSize * sizeof(*s_Events));
            if (!s_Events) goto Exit;
            bufferSize = s_CallbacksSize;
        }
        pthread_mutex_unlock(&s_Lock);

        count = epoll_wait(epollFd, s_Events, bufferSize, -1);

        if (count < 0) {
            switch (errno) {
            case EINTR:
                break;
            case EBADF:
                goto Exit;
            default:
                fprintf(stderr, "epoll thread received errno %d: %s\n", errno, strerror(errno));
                goto Exit;
            }
        } else {
            int i;

            pthread_mutex_lock(&s_Lock);

            for (i = 0; i < count; ++i) {
                struct epoll_event* ev = &s_Events[i];

                if (ev->data.fd < s_CallbacksSize) {
                    if (s_Callbacks[ev->data.fd].callback) {
                        s_Callbacks[ev->data.fd].callback(s_Callbacks[ev->data.fd].ctx, ev);
                    }
                }
            }

            pthread_mutex_unlock(&s_Lock);
        }
    }

Exit:
    s_Running = 0;

    return NULL;
}

int
epoll_loop_create() {
    int error = 0;

    pthread_mutex_lock(&s_Lock);

    if (++s_RefCount == 1) {
        s_EPollFd = -1;
        s_Callbacks = NULL;
        s_CallbacksSize = 0;
        s_Events = NULL;
        s_Running = 0;

        if ((s_EPollFd = epoll_create1(O_CLOEXEC)) < 0) {
            goto Error;
        }

        if ((error = pthread_create(&s_EPollThread, NULL, EPollThreadMain, NULL)) < 0) {
            goto Error;
        }

        while (!s_Running) {
            pthread_yield();
        }
    }

    error = s_EPollFd;

Exit:
    pthread_mutex_unlock(&s_Lock);
    return error;

Error:
    error = errno;
    safe_close_ref(&s_EPollFd);
    errno = error;
    error = -1;
    goto Exit;
}

void
epoll_loop_destroy() {
    pthread_mutex_lock(&s_Lock);

    if (--s_RefCount == 0) {
        const int epollFd = s_EPollFd;
        struct epoll_event* events = s_Events;
        epoll_callback_data* callbacks = s_Callbacks;
        pthread_t thread = s_EPollThread;

        pthread_mutex_unlock(&s_Lock);
        pthread_cancel(thread);
        pthread_join(thread, NULL);

        safe_close(epollFd);
        free(events);
        free(callbacks);
    } else {
        pthread_mutex_unlock(&s_Lock);
    }
}

static
int
epoll_loop_set_callback(int handle, epoll_callback_data callback)
{
    if (handle < 0)
    {
        errno = EINVAL;
        return -1;
    }

    pthread_mutex_lock(&s_Lock);

    if (!s_Callbacks)
    {
        size_t bytes;
        s_CallbacksSize = MinBufferSize;

        if (handle + 1 > s_CallbacksSize)
        {
            s_CallbacksSize = handle + 1;
        }

        bytes = sizeof(*s_Callbacks) * (size_t)s_CallbacksSize;
        s_Callbacks = (epoll_callback_data*)malloc(bytes);
        memset(s_Callbacks, 0, bytes);
    }
    else if (handle >= s_CallbacksSize)
    {
        size_t bytes;
        int previousSize;

        previousSize = s_CallbacksSize;
        s_CallbacksSize = (s_CallbacksSize * 17) / 10; /* x 1.68 */
        if (handle + 1 > s_CallbacksSize)
        {
            s_CallbacksSize = handle + 1;
        }

        bytes = sizeof(*s_Callbacks) * (size_t)s_CallbacksSize;
        s_Callbacks = (epoll_callback_data*)realloc(s_Callbacks, bytes);

        memset(s_Callbacks + previousSize, 0, sizeof(*s_Callbacks) * (size_t)(s_CallbacksSize - previousSize));
    }

    s_Callbacks[handle] = callback;

    pthread_mutex_unlock(&s_Lock);

    return 0;
}

static
int
epoll_loop_get_fd()
{
    return s_EPollFd;
}


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
static int s_SocketFd = -1;
static int s_DebuggerFd = -1;
static void* s_Ctx;
static net_callback s_Callback;


static
void
EPollConnectionDataHandler(void *ctx, struct epoll_event *ev)
{
    assert(ev);

    if (ev->events & (EPOLLHUP | EPOLLRDHUP | EPOLLERR))
    {
        epoll_callback_data ecd;
        memset(&ecd, 0, sizeof(ecd));
        epoll_loop_set_callback(ev->data.fd, ecd);

        safe_close(ev->data.fd);
        s_DebuggerFd = -1;

        if (s_Callback)
        {
            s_Callback(s_Ctx, NET_EVENT_HANGUP);
        }
    }
    else
    {
        int flags = 0;
        if (ev->events & EPOLLIN)
        {
            flags |= NET_EVENT_RECEIVE;
        }

        if (ev->events & EPOLLOUT)
        {
            flags |= NET_EVENT_SEND;
        }

        if (flags && s_Callback) {
            s_Callback(s_Ctx, flags);
        }
    }
}


static
void
EPollAcceptHandler(void *ctx, struct epoll_event* ev)
{
    assert(ev);

    if (ev->events & (EPOLLHUP | EPOLLERR))
    {
        epoll_callback_data ecd;
        memset(&ecd, 0, sizeof(ecd));
        epoll_loop_set_callback(ev->data.fd, ecd);

        // HANDLE THIS
    }
    else if (ev->events & EPOLLIN)
    {
        int fd = accept4(ev->data.fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);

        if (fd >= 0)
        {
            if (s_DebuggerFd >= 0)
            {
                safe_close(fd);
            }
            else
            {
                int i = 1;
                setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &i, sizeof(i));

                ev->data.fd = fd;
                ev->events = EPOLLIN | EPOLLOUT | EPOLLET;

                if (epoll_ctl(epoll_loop_get_fd(), EPOLL_CTL_ADD, ev->data.fd, ev) == 0)
                {
                    epoll_callback_data ecd;
                    memset(&ecd, 0, sizeof(ecd));
                    ecd.callback = EPollConnectionDataHandler;
                    epoll_loop_set_callback(fd, ecd);

                    s_DebuggerFd = fd;

                    if (s_Callback) {
                        s_Callback(s_Ctx, NET_EVENT_CONNECT);
                    }
                }
                else
                {
                    safe_close(fd);
                }
            }
        }
    }
}


int
net_listen(int p, int flags)
{
    int error = 0;
    int Limit = 10;
    int fd = -1;
    int on = 1;
    int i = 0;
    char port[6];
    struct addrinfo hints;
    struct addrinfo * info = NULL;
    struct epoll_event ev;
    epoll_callback_data ecd;

    memset(&hints, 0, sizeof(hints));
    memset(&ev, 0, sizeof(ev));
    memset(&ecd, 0, sizeof(ecd));

    error = epoll_loop_create();
    if (error < 0)
    {
        goto Out;
    }

    snprintf(port, sizeof(port), "%d", p);

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_protocol = IPPROTO_TCP;

    for (i = 0; i < Limit; ++i)
    {
        error = getaddrinfo("0.0.0.0", port, &hints, &info);

        switch (error)
        {
        case 0:
            i = Limit;
            break;
        case EAI_AGAIN:
            info = NULL;
            usleep(100000);
            break;
        case EAI_NODATA: // this happens if DNS can't resolve the host name
        case EAI_SERVICE: // happens if there is no DNS server entry in resolv.conf
        default:
            error = -1;
            errno = ENETDOWN;
            goto Exit;
        }
    }


    fd = socket(info->ai_family, info->ai_socktype | SOCK_NONBLOCK | SOCK_CLOEXEC, info->ai_protocol);
    if (fd == -1)
    {
        error = -1;
        goto Exit;
    }

    // Allow address resuse
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

    error = bind(fd, info->ai_addr, info->ai_addrlen);
    if (error == -1)
    {
        goto Exit;
    }

    if (listen(fd, SOMAXCONN) < 0)
    {
        error = -1;
        goto Exit;
    }


    ev.data.fd = fd;
    ev.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(epoll_loop_get_fd(), EPOLL_CTL_ADD, ev.data.fd, &ev) < 0)
    {
        error = -1;
        goto Exit;
    }

    ecd.callback = EPollAcceptHandler;
    if (epoll_loop_set_callback(fd, ecd) < 0)
    {
        error = -1;
        goto Exit;
    }

    s_SocketFd = fd;

    goto Out;

Exit:
    epoll_loop_destroy();
    if (fd >= 0) safe_close(fd);
Out:
    if (info) freeaddrinfo(info);
    return error;
}

void
net_set_callback(void* ctx, net_callback callback)
{
    s_Ctx = ctx;
    s_Callback = callback;
}

void
net_close()
{
    if (s_DebuggerFd >= 0)
    {
        shutdown(s_DebuggerFd, O_RDWR);
    }
}

int
net_hangup()
{
    epoll_callback_data ecd;
    memset(&ecd, 0, sizeof(ecd));

    if (s_SocketFd >= 0)
    {
        epoll_loop_set_callback(s_SocketFd, ecd);
        safe_close_ref(&s_SocketFd);

        net_close();

        epoll_loop_destroy();
    }

    return 0;
}

int
net_send(const char* buffer, int bytes)
{
    ssize_t s;
Send:
    s = write(s_DebuggerFd, buffer, bytes);

    if (s < 0)
    {
        switch (errno)
        {
        case EAGAIN:
        case EINTR:
            goto Send;
        default:
            return -1;
        }
    }


    return (int)s;
}


int
net_receive(char* buffer, int bytes) {
    int re = 0;

    while (re < bytes) {
        ssize_t r = read(s_DebuggerFd, buffer, bytes);

        if (r < 0) {
            switch (errno)
            {
            case EINTR:
                break;
            case EAGAIN:
                return re;
            default:
                return -1;
            }
        } else if (r > 0) {
            buffer += r;
            re += r;
        } else {
            break;
        }
    }

    return re;
}

int
is_absolute_file_path(const char* filePath) {
    return filePath && *filePath == '/';
}

int
to_absolute_file_path(const char** filePath, buffer** filePathBuffer) {
    int result = 1;
    int fd = -1;
    int allocated = 0;

    assert(filePath);
    assert(filePathBuffer);


    if (is_absolute_file_path(*filePath)) {
        goto Exit;
    }

    if (!*filePathBuffer) {
        *filePathBuffer = buf_alloc(strlen(*filePath) * 2);
        if (!*filePathBuffer) {
            goto Error;
        }
        allocated = 1;
    }

    fd = open(*filePath, O_CLOEXEC | O_PATH);
    if (fd == -1) {
        goto Error;
    }

    char fdPath[32];
    snprintf(fdPath, sizeof(fdPath), "/proc/self/fd/%d", fd);\
    int previousBytes = -1;
    int bytes = -1;
    while (1) {
        size_t size = buf_size(*filePathBuffer);
        assert(size);
        bytes = readlink(fdPath, (char*)(*filePathBuffer)->beg, size);
        if (bytes < 0) {
            goto Error;
        }

        if (bytes == previousBytes) {
            break;
        }

        previousBytes = bytes;

        buf_resize(*filePathBuffer, 2 * bytes);
    }

    if (buf_size(*filePathBuffer) == bytes) {
        if (!buf_reserve(*filePathBuffer, 1)) {
            goto Error;
        }
    }

    (*filePathBuffer)->end = (*filePathBuffer)->beg + bytes;
    *(*filePathBuffer)->end = 0;
    *filePath = (char*)(*filePathBuffer)->beg;

Exit:
    if (fd >= 0) {
        safe_close(fd);
    }

    return result;

Error:
    result = 0;

    if (allocated) {
        buf_free(*filePathBuffer);
        *filePathBuffer = NULL;
    }
    goto Exit;
}

