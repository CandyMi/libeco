#ifndef __ECO_H__
#define __ECO_H__ 1

#if defined(__ANDROID__) || defined(linux) || defined(__linux__)
  #ifdef __ANDROID__
    #define ECO_OS ("Android")
  #else
    #define ECO_OS ("Linux")
  #endif
  #define ECO_EPOLL (1)
  #define ECO_EVENT ECO_EPOLL
  #include <sys/epoll.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)
  #ifdef __APPLE__
    #define ECO_OS ("Apple")
  #else
    #define ECO_OS ("BSD")
  #endif
  #ifndef MSG_NOSIGNAL
    #define MSG_NOSIGNAL (0)
  #endif
  #define ECO_KQUEUE (2)
  #define ECO_EVENT ECO_KQUEUE
  #include <sys/event.h>
#else
  #error "Unsupported platforms."
#endif

#if defined(ECO_JEMALLOC)
  #include <jemalloc/jemalloc.h>
  #define eco_malloc(size)        malloc((size))
  #define eco_calloc(num, size)   calloc((num), (size))
  #define eco_realloc(ptr, size)  realloc((ptr), (size))
  #define eco_free(ptr)           free((ptr))
#elif defined(ECO_TCMALLOC)
  #include <gperftools/tcmalloc.h>
  #define eco_malloc(size)        tc_malloc((size))
  #define eco_calloc(num, size)   tc_calloc((num), (size))
  #define eco_realloc(ptr, size)  tc_realloc((ptr), (size))
  #define eco_free(ptr)           tc_free((ptr))
#else
  #include <cstdlib>
  #define eco_malloc(size)        malloc((size))
  #define eco_calloc(num, size)   calloc((num), (size))
  #define eco_realloc(ptr, size)  realloc((ptr), (size))
  #define eco_free(ptr)           free((ptr))
#endif

// #define ECO_OPENSSL 1
#ifdef ECO_OPENSSL
  #include <openssl/ssl.h>
  #include <openssl/err.h>
  #include <openssl/crypto.h>
#endif

#include <functional>
#include <unistd.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/types.h> 
#include <sys/socket.h> 

/* Coroutine callback */
typedef std::function<void()> eco_cocb_t;

/* DNS query type */
typedef enum {
  ECO_FAIL = 0,
  ECO_IPV4 = 1,
  ECO_IPV6 = 2,
} eco_ip_t;

#define pipe(fds)                                eco::eco_pipe(fds)
#define socket(domain, type, protocol)           eco::eco_socket((domain), (type), (protocol))
#define socketpair(domain, type, protocol, fds)  eco::eco_socketpair((domain), (type), (protocol), (fds))

#define bind(fd, address, address_len)           eco::eco_bind((fd), (address), (address_len))
#define listen(fd, backlog)                      eco::eco_listen((fd), (backlog))

#define accept(fd, address, address_len_ptr)     eco::eco_accept((fd), (address), (address_len_ptr))
#define connect(fd, address, address_len)        eco::eco_connect((fd), (address), (address_len), 0)

#define recv(fd, buffer, bsize, flags)           eco::eco_recv((fd), (buffer), (bsize), (flags), 0)
#define send(fd, buffer, bsize, flags)           eco::eco_send((fd), (buffer), (bsize), (flags), 0)

#define read(fd, buffer, bsize)                  eco::eco_read((fd), (buffer), (bsize), 0)
#define write(fd, buffer, bsize)                 eco::eco_write((fd), (buffer), (bsize), 0)

#define close(fd)                                eco::eco_close((fd))

#ifdef ECO_OPENSSL

#define SSL_accept(ssl)                          eco::eco_sslaccept((ssl), 0)
#define SSL_connect(ssl)                         eco::eco_sslconnect((ssl), 0)

#define SSL_read(ssl, buffer, bsize)             eco::eco_sslrecv((ssl), (buffer), (bsize), 0)
#define SSL_write(ssl, buffer, bsize)            eco::eco_sslsend((ssl), (buffer), (bsize), 0)

#endif

namespace eco {

  int eco_pipe(int fds[2]);
  int eco_socketpair(int domain, int type, int protocol, int fds[2]);

  int eco_socket(int domain, int type, int protocol);
  int eco_close(int fd);

  int eco_bind(int fd, const struct sockaddr *address, socklen_t address_len);
  int eco_listen(int fd, int backlog);

  int eco_accept(int fd, struct sockaddr *address, socklen_t* address_len);
  int eco_connect(int fd, const struct sockaddr *address, socklen_t address_len, uint32_t timeout);

  ssize_t eco_write(int fd, const void *buffer, int bsize, uint32_t timeout);
  ssize_t eco_read(int fd, void *buffer, int bsize, uint32_t timeout);

  ssize_t eco_send(int fd, const void *buffer, int bsize, int flags, uint32_t timeout);
  ssize_t eco_recv(int fd, void *buffer, int bsize, int flags, uint32_t timeout);

  ssize_t eco_sendto(int fd, const void *buffer, int bsize, int flags, const struct sockaddr *address, socklen_t addrlen, uint32_t timeout);
  ssize_t eco_recvfrom(int fd, void *buffer, int bsize, int flags, struct sockaddr *address, socklen_t* addrlen, uint32_t timeout);

  /* Set dns server ip */
  void eco_init_dns(const char* ip);
  /* Load host cache */
  void eco_load_hosts();
  /* Use IPv4 first, then IPv6. */
  eco_ip_t eco_dns_query(const char* domain, char **ip);
  /* Only IPv4 */
  eco_ip_t eco_dns_query4(const char* domain, char **ip);
  /* Only IPv6 */
  eco_ip_t eco_dns_query6(const char* domain, char **ip);

#ifdef ECO_OPENSSL
  int eco_sslaccept(SSL *ssl);
  int eco_sslconnect(SSL *ssl, uint32_t timeout);

  int eco_sslrecv(SSL *ssl, void* buffer, int bsize, uint32_t timeout);
  int eco_sslsend(SSL *ssl, const void* buffer, int bsize, uint32_t timeout);
#endif

  /* Create a daemon that runs in the background (optional) */
  void eco_daemon_init();

  /* Used to ignore some associated special signals (optional) */
  void eco_signal_init();

  /*
    Let the current coroutine sleep for a specified time,
    If `timeout = 100` then it means sleep for 1 second. 
  */
  void eco_sleep(uint32_t timeout);

  /* In any coroutine, create and start another coroutine.  */
  void eco_fork(eco_cocb_t co_cb);

  /* Start your first coroutine! `eco_fork` or `eco_sleep` all start from here.  */
  void eco_run(eco_cocb_t main_cb);

}

#endif
