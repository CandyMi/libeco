#include <iostream>
#include <memory>

#include "eco.hpp"
#include "eco_aco.hpp"
#include "eco_event.hpp"

#include <sys/stat.h>

typedef enum {
  ECO_FAIL_FD = 0,
  ECO_FILE_FD = 1,
  ECO_SOCK_FD = 2,
  ECO_PIPE_FD = 3,
} eco_fd_type_t;

static inline eco_fd_type_t eco_check_sfd(int fd) {
  struct stat st;
  if (fstat(fd, &st))
    eco_abort(strerror(errno));
  if (S_ISSOCK(st.st_mode))
    return ECO_SOCK_FD;
  if (S_ISFIFO(st.st_mode))
    return ECO_PIPE_FD;
  if (S_ISREG(st.st_mode))
    return ECO_FILE_FD;
  return ECO_FAIL_FD;
}

static void co_main()
{
  eco_cocb_t* cb = (eco_cocb_t*)aco_get_arg();
  // printf("开始\n");
  ((eco_cocb_t )*cb)();
  // printf("结束\n");
  aco_exit();
}

/* 启动任务协程 */
void eco::eco_fork(eco_cocb_t cb)
{
  aco_t *co = (aco_t *)aco_get_co();
  if (!co)
    eco_abort("No main coroutine.");
  aco_share_stack_t* st = aco_share_stack_new(0);
  if (!st)
    eco_abort("Create share stack failed.");

  /* 防止回调被销毁 */
  aco_t *nco = aco_create(co->main_co, st, 0, co_main, (void*)new eco_cocb_t(cb));
  if (!nco)
    eco_abort("Create coroutine failed.");
  /* 已创建的协程放在队列尾部 */
  ((co_loop_t*)co->main_co->arg)->g_queue.push(nco);
}

/* 休眠当前协程 */
void eco::eco_sleep(uint32_t timeout)
{
  if (timeout == 0)
    return ;

  aco_t *co = (aco_t *)aco_get_co();
  if (!co || !co->main_co) 
    eco_abort("Cannot sleep outside of the coroutine.");

  eco_event::efd_set_tevent(((co_loop_t*)co->main_co->arg)->efd, timeout, co);
}

void eco::eco_daemon_init()
{
  if (fork() != 0)
    exit(EXIT_SUCCESS);

  /* 设置`SID` */
  setsid();

  /* 关闭标准输入输出资源 */
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
}

void eco::eco_signal_init()
{
  std::signal(SIGHUP,  SIG_IGN);
  std::signal(SIGPIPE, SIG_IGN);
  std::signal(SIGTSTP, SIG_IGN);
}

void eco::eco_run(eco_cocb_t main_cb)
{
  /* 初始化环境 */
  aco_thread_init(nullptr);

  co_loop_t g;

  /* 初始化主协程 */
  aco_t* g_main = aco_create(nullptr, nullptr, 0, nullptr, (void*)&g);
  if (!g_main)
    eco_abort("can't create g_main coroutine.");

  /* 当前超时时间 */
  g.interval = 0;
  /* 事件描述符 */
  g.efd = eco_event::efd_create();

  /* 将第一个协程放入队列 */
  g.g_queue.push(aco_create(g_main, aco_share_stack_new(0), 0, co_main, (void*) new eco_cocb_t(main_cb)));

  for (;;)
  {
    while(g.g_queue.size() > 0)
    {
      aco_t *co = g.g_queue.front();
      g.g_queue.pop();
      aco_resume(co);
      /* 协程结束就销毁它 */
      if (co->is_end){
        delete (eco_cocb_t*)co->arg;
        aco_share_stack_destroy(co->share_stack);
        aco_destroy(co);
      }
    }
    /* 从这里获得事件(定时器、网络)  */
    eco_event::efd_poll(g.efd);
  }

  /*  END  */
}

static inline int eco_wait_event(int fd, int events, uint32_t timeout)
{
  aco_t* co = aco_get_co();
  if (!co or !co->main_co)
    eco_abort("Can't find main coroutine in event wait.");

  int ret = 1;
  int efd = ((co_loop_t*)co->main_co->arg)->efd;
  std::shared_ptr<bool> over = std::make_shared<bool>(false);

  /* 读事件 */
  if (((events & ECO_EVENT_READ) == ECO_EVENT_READ) and fd >= 0)
  {
    eco::eco_fork([over, co, efd, fd]()
    {
      // printf("注册读事件\n");
      eco_event::efd_set_revent(efd, fd, aco_get_co());
      // printf("读事件通知.\n");
      if (*over)
        return;
      *over = true;
      /* 加入到等待运行的队列内 */
      ((co_loop_t*)co->main_co->arg)->g_queue.push(co);
    });
  }

  /* 写事件 */
  if ((events & ECO_EVENT_WRITE) == ECO_EVENT_WRITE and fd >= 0)
  {
    eco::eco_fork([over, co, efd, fd]()
    {
      // printf("注册写事件\n");
      eco_event::efd_set_wevent(efd, fd, aco_get_co());
      // printf("写事件通知.\n");
      if (*over)
        return;
      *over = true;
      /* 加入到等待运行的队列内 */
      ((co_loop_t*)co->main_co->arg)->g_queue.push(co);
    });
  }

  /* 定时器 */
  if ((events & ECO_EVENT_TIMER) == ECO_EVENT_TIMER and timeout > 0)
  {
    eco::eco_fork([over, co, efd, timeout, &ret]()
    {
      // printf("注册定时器事件\n");
      eco_event::efd_set_tevent(efd, timeout, aco_get_co());
      // printf("定时器事件通知\n");
      if (*over)
        return;
      *over = true;
      ret = 0;
      /* 加入到等待运行的队列内 */
      ((co_loop_t*)co->main_co->arg)->g_queue.push(co);
    });
  }
  /* 等待唤醒 */
  aco_yield();
  return ret;
}

/* 原型与函数声明 */
typedef ssize_t (*pipe_hook_t)(int fds[2]);
static pipe_hook_t hook_pipe = (pipe_hook_t)dlsym(RTLD_NEXT, "pipe");

typedef ssize_t (*socketpair_hook_t)(int domain, int type, int protocol, int sv[2]);
static socketpair_hook_t hook_socketpair = (socketpair_hook_t)dlsym(RTLD_NEXT, "socketpair");

typedef ssize_t (*socket_hook_t)(int domain, int type, int protocol);
static socket_hook_t hook_socket = (socket_hook_t)dlsym(RTLD_NEXT, "socket");

typedef ssize_t (*read_hook_t)(int fd, void *buffer, int bsize);
static read_hook_t hook_read = (read_hook_t)dlsym(RTLD_NEXT, "read");

typedef ssize_t (*write_hook_t)(int fd, const void *buffer, int bsize);
static write_hook_t hook_write = (write_hook_t)dlsym(RTLD_NEXT, "write");

typedef ssize_t (*recv_hook_t)(int fd, void *buffer, int bsize, int flags);
static recv_hook_t hook_recv = (recv_hook_t)dlsym(RTLD_NEXT, "recv");

typedef ssize_t (*send_hook_t)(int fd, const void *buffer, int bsize, int flags);
static send_hook_t hook_send = (send_hook_t)dlsym(RTLD_NEXT, "send");

// typedef ssize_t (*sendmsg_hook_t)(int fd, const struct msghdr *msg, int flags);
// static sendmsg_hook_t hook_sendmsg = (sendmsg_hook_t)dlsym(RTLD_NEXT, "sendmsg");

// typedef ssize_t (*recvmsg_hook_t)(int fd, struct msghdr *msg, int flags);
// static recvmsg_hook_t hook_recvmsg = (recvmsg_hook_t)dlsym(RTLD_NEXT, "recvmsg");

// typedef ssize_t (*sendto_hook_t)(int fd, const void *buffer, int bsize, int flags, const struct sockaddr *address, socklen_t addrlen);
// static sendto_hook_t hook_sendto = (sendto_hook_t)dlsym(RTLD_NEXT, "sendto");

// typedef ssize_t (*recvfrom_hook_t)(int fd, void *buffer, int bsize, int flags, struct sockaddr *address, socklen_t* addrlen);
// static recvfrom_hook_t hook_recvfrom = (recvfrom_hook_t)dlsym(RTLD_NEXT, "recvfrom");

typedef int (*accept_hook_t)(int fd, const struct sockaddr *address, socklen_t* address_len);
static accept_hook_t hook_accept = (accept_hook_t)dlsym(RTLD_NEXT, "accept");

typedef int (*connect_hook_t)(int fd, const struct sockaddr *address, socklen_t address_len);
static connect_hook_t hook_connect = (connect_hook_t)dlsym(RTLD_NEXT, "connect");

typedef int (*shutdown_hook_t) (int fd, int how);
static shutdown_hook_t hook_shutdown = (shutdown_hook_t)dlsym(RTLD_NEXT, "shutdown");

typedef int (*close_hook_t)(int fd);
static close_hook_t hook_close = (close_hook_t)dlsym(RTLD_NEXT, "close");

typedef int (*listen_hook_t)(int fd, int backlog);
static listen_hook_t hook_listen = (listen_hook_t)dlsym(RTLD_NEXT, "listen");

typedef int (*bind_hook_t)(int fd, const struct sockaddr *address, socklen_t address_len);
static bind_hook_t hook_bind = (bind_hook_t)dlsym(RTLD_NEXT, "bind");

#define HOOK_INIT(name)  if (!hook_##name) {hook_##name = (name##_hook_t)dlsym(RTLD_NEXT, #name);}

int eco::eco_close(int fd)
{
  HOOK_INIT(close);
  aco_t* co = aco_get_co();
  if (co and co->main_co)
    eco_event::efd_unset_ioevent(((co_loop_t*)co->main_co->arg)->efd, fd);
  /* 不管怎么样，都要关闭fd */
  return hook_close(fd);
}

int eco::eco_bind(int fd, const struct sockaddr *address, socklen_t address_len)
{
  HOOK_INIT(bind);
  return hook_bind(fd, address, address_len);
}

int eco::eco_listen(int fd, int backlog)
{
  HOOK_INIT(listen);
  return hook_listen(fd, backlog);
}

int eco::eco_socket(int domain, int type, int protocol)
{
  HOOK_INIT(socket);
  int fd = hook_socket((domain), (type), (protocol));
  if (fd > 0) {
    fcntl (fd, F_SETFD, FD_CLOEXEC);
    fcntl (fd, F_SETFL, O_NONBLOCK);
  #ifdef __APPLE__
    socklen_t enable = 1;
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &enable, sizeof(enable));
  #endif
  }
  return fd;
}

int eco::eco_pipe(int fds[2])
{
  HOOK_INIT(pipe);
  int no = hook_pipe(fds);
  if (!no) {
    fcntl (fds[0], F_SETFD, FD_CLOEXEC);
    fcntl (fds[0], F_SETFL, O_NONBLOCK);
    fcntl (fds[1], F_SETFD, FD_CLOEXEC);
    fcntl (fds[1], F_SETFL, O_NONBLOCK);
  #ifdef __APPLE__
    socklen_t enable = 1;
    setsockopt(fds[0], SOL_SOCKET, SO_NOSIGPIPE, &enable, sizeof(enable));
    setsockopt(fds[1], SOL_SOCKET, SO_NOSIGPIPE, &enable, sizeof(enable));
  #endif
  }
  return no;
}

int eco::eco_socketpair(int domain, int type, int protocol, int fds[2])
{
  HOOK_INIT(socketpair);
  int no = hook_socketpair((domain), (type), (protocol), fds);
  if (!no) {
    fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    fcntl(fds[1], F_SETFL, O_NONBLOCK);
  #ifdef __APPLE__
    socklen_t enable = 1;
    setsockopt(fds[0], SOL_SOCKET, SO_NOSIGPIPE, &enable, sizeof(enable));
    setsockopt(fds[1], SOL_SOCKET, SO_NOSIGPIPE, &enable, sizeof(enable));
  #endif
  }
  return no;
}

int eco::eco_accept(int fd, struct sockaddr *address, socklen_t* address_len)
{
  HOOK_INIT(accept);
  CONTINUE:
  errno = 0;
  int cfd = hook_accept(fd, address, address_len);
  if (cfd < 0 and (errno == EAGAIN or errno == EINTR)) {
    if (errno == EAGAIN)
      eco_wait_event(fd, ECO_EVENT_READ, 0);
    goto CONTINUE;
  }
  if (cfd > 0){
    #ifdef __APPLE__
      socklen_t enable = 1;
      setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &enable, sizeof(enable));
    #endif
    fcntl(cfd, F_SETFD, FD_CLOEXEC);
    fcntl(cfd, F_SETFL, O_NONBLOCK);
    errno = 0;
  }
  return cfd;
}

int eco::eco_connect(int fd, const struct sockaddr *address, socklen_t address_len, uint32_t timeout)
{
  HOOK_INIT(connect);
  CONTINUE:
  errno = 0;
  int cret = hook_connect((fd), (address), (address_len));
  // printf(" ret = %d, errno = %s\n", cret, strerror(errno));
  if (errno == EINPROGRESS){
    if (!eco_wait_event(fd, ECO_EVENT_WRITE | ECO_EVENT_TIMER, timeout > 0 ? timeout : 0))
      return 0;
    goto CONTINUE;
  }

  /* 返回0可能出错. */
  if (cret == 0)
    cret = hook_connect((fd), (address), (address_len));

  /* 再次检查 */
  if (errno == EISCONN) {
    cret = 1;
    errno = 0;
  }

  return cret;
}

ssize_t eco::eco_read(int fd, void* buffer, int bsize, uint32_t timeout)
{
  HOOK_INIT(read);
  eco_fd_type_t ret = eco_check_sfd(fd);
  if (ret == ECO_SOCK_FD || ret == ECO_PIPE_FD)
    return eco::eco_recv(fd, buffer, bsize, 0, timeout);
  if (ret == ECO_FILE_FD)
    return hook_read(fd, buffer, bsize);
  errno = EBADF;
  return -1;
}

ssize_t eco::eco_recv(int fd, void *buffer, int bsize, int flags, uint32_t timeout)
{
  HOOK_INIT(recv);
  CONTINUE:
  // printf("recv 1\n");
  errno = 0;
  ssize_t rsize = hook_recv((fd), (buffer), (bsize), (flags) | MSG_DONTWAIT | MSG_NOSIGNAL);
  if (rsize >= 0)
    return rsize;
  // printf("rsize = %d, errno = %ld, err = [%s]\n", rsize, errno, strerror(errno));
  /* 检查是否需要重试 */
  if (errno == EINTR)
    goto CONTINUE;
  if (errno == EAGAIN){
    if (!eco_wait_event(fd, ECO_EVENT_READ | ECO_EVENT_TIMER, timeout > 0 ? timeout : 0))
      return 0;
    goto CONTINUE;
  }
  // printf("recv 2\n");
  /* 其他情况都当成无法恢复的错误. */
  return 0;
}

ssize_t eco::eco_write(int fd, const void* buffer, int bsize, uint32_t timeout)
{
  HOOK_INIT(write);
  eco_fd_type_t ret = eco_check_sfd(fd);
  if (ret == ECO_SOCK_FD || ret == ECO_PIPE_FD)
    return eco::eco_send(fd, buffer, bsize, 0, timeout);
  if (ret == ECO_FILE_FD)
    return hook_write(fd, buffer, bsize);
  errno = EBADF;
  return -1;
}

ssize_t eco::eco_send(int fd, const void *buffer, int bsize, int flags, uint32_t timeout)
{
  HOOK_INIT(send);
  ssize_t total = bsize;
  CONTINUE:
  errno = 0;
  ssize_t wsize = hook_send((fd), (buffer), (bsize), (flags) | MSG_DONTWAIT | MSG_NOSIGNAL);
  /* 如果`以及断开链接`或`已经完成` */
  if (0 == wsize or wsize == bsize) {
    if (wsize == bsize)
      wsize = total;
    return wsize;
  }

  /* 如果缓冲区已满 */
  if (wsize > 0) {
    bsize -= wsize;
    buffer = (char*)buffer + wsize;
    if (!eco_wait_event(fd, ECO_EVENT_WRITE | ECO_EVENT_TIMER, timeout > 0 ? timeout : 0))
      return 0;
    goto CONTINUE;
  }
  /* 如果`信号中断`或`已经写满`. */
  if (-1 == wsize and (errno == EAGAIN or errno == EINTR)) {
    if (errno == EAGAIN) {
      if (!eco_wait_event(fd, ECO_EVENT_WRITE | ECO_EVENT_TIMER, timeout > 0 ? timeout : 0))
        return 0;
    }
    goto CONTINUE;
  }

  /* 其他情况都当成无法恢复的错误. */
  return 0;
}

#ifdef ECO_OPENSSL

static inline int eco_ssl_do_handshake(SSL *ssl, int fd, uint32_t timeout)
{
  /* 检查与设置标志位 */
  if ((fcntl(fd, F_GETFL, 0) & O_NONBLOCK) != O_NONBLOCK)
    fcntl(fd, F_SETFL, O_NONBLOCK);

  CONTINUE:

  int ret = SSL_do_handshake(ssl);
  if (ret != -1)
    return ret;

  int event = SSL_get_error(ssl, ret);
  /* 等待读事件 */
  if(event == SSL_ERROR_WANT_READ) {
    if (!eco_wait_event(fd, ECO_EVENT_READ | ECO_EVENT_TIMER, timeout > 0 ? timeout : 0))
      return 0;
    goto CONTINUE;
  }
  /* 等待写事件 */
  if(event == SSL_ERROR_WANT_WRITE) {
    if (!eco_wait_event(fd, ECO_EVENT_WRITE | ECO_EVENT_TIMER, timeout > 0 ? timeout : 0))
      return 0;
    goto CONTINUE;
  }
  /* 其它情况下都当成无法恢复的错误. */
  return -1;
}

int eco::eco_sslaccept(SSL *ssl)
{
  /* 设置状态 */
  SSL_set_accept_state(ssl);
  /* 被动握手 */
  return eco_ssl_do_handshake(ssl, SSL_get_fd(ssl), 0);
}

int eco::eco_sslconnect(SSL *ssl, uint32_t timeout)
{
  /* 设置状态 */
  SSL_set_connect_state(ssl);
  /* 主动握手 */
  return eco_ssl_do_handshake(ssl, SSL_get_fd(ssl), timeout);
}

int eco::eco_sslsend(SSL *ssl, const void* buffer, int bsize, uint32_t timeout)
{
  int total = bsize;
  /* 检查与设置标志位 */
  int fd = SSL_get_fd(ssl);
  if ((fcntl(fd, F_GETFL, 0) & O_NONBLOCK) != O_NONBLOCK)
    fcntl(fd, F_SETFL, O_NONBLOCK);

  CONTINUE:

  size_t wsize = 0;
  int ret = SSL_write_ex(ssl, buffer, bsize, &wsize);
  if ((int)wsize == bsize)
    return total;

  if (wsize > 0) {
    bsize -= wsize;
    buffer = (char*)buffer + wsize;
    if (!eco_wait_event(fd, ECO_EVENT_WRITE | ECO_EVENT_TIMER, timeout > 0 ? timeout : 0))
      return 0;
    goto CONTINUE;
  }

  int event = SSL_get_error(ssl, ret);
  /* 等待读事件 */
  // if(event == SSL_ERROR_WANT_READ) {
  //   if (!eco_wait_event(fd, ECO_EVENT_READ | ECO_EVENT_TIMER, timeout > 0 ? timeout : 0))
  //     return 0;
  //   goto CONTINUE;
  // }
  /* 等待写事件 */
  if(event == SSL_ERROR_WANT_WRITE) {
    if (!eco_wait_event(fd, ECO_EVENT_WRITE | ECO_EVENT_TIMER, timeout > 0 ? timeout : 0))
      return 0;
    goto CONTINUE;
  }
  /* 其它情况下都当成无法恢复的错误. */
  return 0;
}

int eco::eco_sslrecv(SSL *ssl, void* buffer, int bsize, uint32_t timeout)
{
  /* 检查与设置标志位 */
  int fd = SSL_get_fd(ssl);
  if ((fcntl(fd, F_GETFL, 0) & O_NONBLOCK) != O_NONBLOCK)
    fcntl(fd, F_SETFL, O_NONBLOCK);

  CONTINUE:

  size_t rsize = 0;
  int ret = SSL_read_ex(ssl, buffer, bsize, &rsize);
  if (rsize > 0)
    return rsize;

  int event = SSL_get_error(ssl, ret);
  /* 等待读事件 */
  if(event == SSL_ERROR_WANT_READ) {
    if (!eco_wait_event(fd, ECO_EVENT_READ | ECO_EVENT_TIMER, timeout > 0 ? timeout : 0))
      return 0;
    goto CONTINUE;
  }
  /* 等待写事件 */
  // if(event == SSL_ERROR_WANT_WRITE) {
  //   if (!eco_wait_event(fd, ECO_EVENT_WRITE | ECO_EVENT_TIMER, timeout > 0 ? timeout : 0))
  //     return 0;
  //   goto CONTINUE;
  // }
  /* 其它情况下都当成无法恢复的错误. */
  return 0;
}

#endif