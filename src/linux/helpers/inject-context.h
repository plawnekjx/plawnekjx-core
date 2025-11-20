#ifndef __PLAWNEKJX_INJECT_CONTEXT_H__
#define __PLAWNEKJX_INJECT_CONTEXT_H__

#ifdef NOLIBC
typedef void * pthread_t;
typedef struct _pthread_attr_t pthread_attr_t;
struct msghdr;
struct sockaddr;
typedef unsigned int socklen_t;
#else
# include <dlfcn.h>
# include <pthread.h>
# include <stdint.h>
# include <sys/mman.h>
# include <sys/socket.h>
#endif

typedef size_t PlawnekjxBootstrapStatus;
typedef struct _PlawnekjxBootstrapContext PlawnekjxBootstrapContext;
typedef struct _PlawnekjxLoaderContext PlawnekjxLoaderContext;
typedef struct _PlawnekjxLibcApi PlawnekjxLibcApi;
typedef uint8_t PlawnekjxMessageType;
typedef struct _PlawnekjxHelloMessage PlawnekjxHelloMessage;
typedef struct _PlawnekjxByeMessage PlawnekjxByeMessage;
typedef int PlawnekjxRtldFlavor;

enum _PlawnekjxBootstrapStatus
{
  PLAWNEKJX_BOOTSTRAP_ALLOCATION_SUCCESS,
  PLAWNEKJX_BOOTSTRAP_ALLOCATION_ERROR,

  PLAWNEKJX_BOOTSTRAP_SUCCESS,
  PLAWNEKJX_BOOTSTRAP_AUXV_NOT_FOUND,
  PLAWNEKJX_BOOTSTRAP_TOO_EARLY,
  PLAWNEKJX_BOOTSTRAP_LIBC_LOAD_ERROR,
  PLAWNEKJX_BOOTSTRAP_LIBC_UNSUPPORTED,
};

struct _PlawnekjxBootstrapContext
{
  void * allocation_base;
  size_t allocation_size;

  size_t page_size;
  const char * fallback_ld;
  const char * fallback_libc;
  PlawnekjxRtldFlavor rtld_flavor;
  void * rtld_base;
  void * r_brk;
  int enable_ctrlfds;
  int ctrlfds[2];
  PlawnekjxLibcApi * libc;
};

struct _PlawnekjxLoaderContext
{
  int ctrlfds[2];
  const char * agent_entrypoint;
  const char * agent_data;
  const char * fallback_address;
  PlawnekjxLibcApi * libc;

  pthread_t worker;
  void * agent_handle;
  void (* agent_entrypoint_impl) (const char * data, int * unload_policy, void * injector_state);
};

struct _PlawnekjxLibcApi
{
  int (* printf) (const char * format, ...);
  int (* sprintf) (char * str, const char * format, ...);

  void * (* mmap) (void * addr, size_t length, int prot, int flags, int fd, off_t offset);
  int (* munmap) (void * addr, size_t length);
  int (* socket) (int domain, int type, int protocol);
  int (* socketpair) (int domain, int type, int protocol, int sv[2]);
  int (* connect) (int sockfd, const struct sockaddr * addr, socklen_t addrlen);
  ssize_t (* recvmsg) (int sockfd, struct msghdr * msg, int flags);
  ssize_t (* send) (int sockfd, const void * buf, size_t len, int flags);
  int (* fcntl) (int fd, int cmd, ...);
  int (* close) (int fd);

  int (* pthread_create) (pthread_t * thread, const pthread_attr_t * attr, void * (* start_routine) (void *), void * arg);
  int (* pthread_detach) (pthread_t thread);

  void * (* dlopen) (const char * filename, int flags, const void * caller_addr);
  int dlopen_flags;
  int (* dlclose) (void * handle);
  void * (* dlsym) (void * handle, const char * symbol, const void * caller_addr);
  char * (* dlerror) (void);
};

enum _PlawnekjxMessageType
{
  PLAWNEKJX_MESSAGE_HELLO,
  PLAWNEKJX_MESSAGE_READY,
  PLAWNEKJX_MESSAGE_ACK,
  PLAWNEKJX_MESSAGE_BYE,
  PLAWNEKJX_MESSAGE_ERROR_DLOPEN,
  PLAWNEKJX_MESSAGE_ERROR_DLSYM,
};

struct _PlawnekjxHelloMessage
{
  pid_t thread_id;
};

struct _PlawnekjxByeMessage
{
  int unload_policy;
};

enum _PlawnekjxRtldFlavor
{
  PLAWNEKJX_RTLD_UNKNOWN,
  PLAWNEKJX_RTLD_NONE,
  PLAWNEKJX_RTLD_GLIBC,
  PLAWNEKJX_RTLD_UCLIBC,
  PLAWNEKJX_RTLD_MUSL,
  PLAWNEKJX_RTLD_ANDROID,
};

#endif
