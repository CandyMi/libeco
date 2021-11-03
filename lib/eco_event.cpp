#include "eco_event.hpp"

namespace eco_event{};

#define eco_event_get_io_slot(g, fid)    (g->io_map[fid])

#define eco_event_get_timer_slot(g, tid) (g->timer_map[fid])

#if defined(ECO_EPOLL)

  #define eco_event_get_fd(e, eid)   (((struct epoll_event)(e)[(eid)]).data.fd)

  #define eco_event_is_read(e, eid)  ((((struct epoll_event)(e)[(eid)]).events & EPOLLIN) == EPOLLIN ? true : false)

  #define eco_event_is_write(e, eid) ((((struct epoll_event)(e)[(eid)]).events & EPOLLOUT) == EPOLLOUT ? true : false)

#elif defined(ECO_KQUEUE)

  #define eco_event_get_fd(e, eid)   (((struct kevent)(e)[eid]).ident)

  #define eco_event_is_read(e, eid)  ((((struct kevent)(e)[eid]).filter & EVFILT_READ)  == EVFILT_READ ? true : false) 

  #define eco_event_is_write(e, eid) ((((struct kevent)(e)[eid]).filter & EVFILT_WRITE)  == EVFILT_WRITE ? true : false) 

#endif

static inline uint64_t efd_get_now()
{
  struct timeval ts;
  gettimeofday(&ts, nullptr);
  return (uint64_t)((uint64_t)(ts.tv_sec * 1e2)) + ((uint64_t)(ts.tv_usec *1e-4));
}

int eco_event::efd_create()
{
  int efd;
#if defined(ECO_EPOLL)
  efd = epoll_create (256);
#elif defined(ECO_KQUEUE)
  efd = kqueue();
#endif
  fcntl (efd, F_SETFD, FD_CLOEXEC);
  return efd;
}

void eco_event::efd_poll(int efd)
{
  int ret;
  co_loop_t* g = (co_loop_t*)(aco_get_co()->arg);
  uint64_t before = g->interval == 0 ? efd_get_now() : g->interval;
#if defined(ECO_EPOLL)
  struct epoll_event event_waits[eco_max_events];
  ret = epoll_wait(efd, event_waits, eco_max_events, 10);
#elif defined(ECO_KQUEUE)
  struct timespec ts;
  ts.tv_sec = 0; ts.tv_nsec = 1e7;
  struct kevent event_waits[eco_max_events];
  ret = kevent(efd, nullptr, 0, event_waits, eco_max_events, &ts);
#endif
  // printf("ret = %d, io = %lu, timer = %lu\n", ret, g->io_map.size(), g->timer_map.size());
  /* 1. 检查定时器 */
  uint64_t now = efd_get_now();
  if (before <= now and g->timer_map.size() > 0)
  {
    // printf("1.1\n");
    for (uint64_t t_idx = before; t_idx <= now; t_idx++)
    {
      // printf("1.2\n");
      if (g->timer_map.count(t_idx))
      {
        std::queue<aco_t*> *q = g->timer_map[t_idx];
        while (!q->empty())
        {
          g->g_queue.push(q->front());
          q->pop();
        }
        g->timer_map.erase(t_idx);
        delete q;
      }
      // printf("1.3\n");
    }
    // printf("1.4\n");
  }
  /* 2. 检查I/O事件 */
  if (ret > 0 and g->io_map.size() > 0)
  {
    // printf("2.1\n");
    for (int fd_idx = 0; fd_idx < ret; fd_idx++)
    {
      int fd = eco_event_get_fd(event_waits, fd_idx);
      if (g->io_map.count(fd))
      {
        /* 唤醒读事件 */
        if (eco_event_is_read(event_waits, fd_idx))
        {
          co_io_slot* io = eco_event_get_io_slot(g, fd);
          if (io->recv_co) {
            g->g_queue.push(io->recv_co);
            io->recv_co = nullptr;
          }
          // printf("2.2 aco = %p\n", io->recv_co);
        }
        /* 唤醒写事件 */
        if (eco_event_is_write(event_waits, fd_idx))
        {
          co_io_slot* io = eco_event_get_io_slot(g, fd);
          if (io->send_co)
          {
            g->g_queue.push(io->send_co);
            io->send_co = nullptr;
          }
          // printf("2.3 aco = %p\n", io->send_co);
        }
      }
    }
    // printf("2.4\n");
  }
  g->interval = now + 1;
}

/* 定时器 */
void eco_event::efd_set_tevent(int efd, uint32_t timeout, aco_t* co)
{
  uint64_t now = efd_get_now() + timeout;
  co_loop_t* g = (co_loop_t*)(aco_get_co()->main_co->arg);
  if (g->timer_map.count(now) == 0)
  {
    std::queue<aco_t*> *q = new std::queue<aco_t*>;
    g->timer_map[now] = q;
    q->push(co);
  }
  else
  {
    std::queue<aco_t*> *q = g->timer_map[now];
    q->push(co);
  }
  return aco_yield();
}

void eco_event::efd_set_revent(int efd, int fd, aco_t* co)
{
  co_io_slot_t *io = nullptr;
  co_loop_t* g = (co_loop_t*)(aco_get_co()->main_co->arg);
  bool already = g->io_map.count(fd) == 1;
  if (already)
  {
    io = g->io_map[fd];
    if (io->recv_co)
      eco_abort("Disallow concurrent `recv` operations on multiple coroutines.");
  }
  else
  {
    io = new co_io_slot_t;
    io->send_co = nullptr;
    g->io_map[fd] = io;
  }
  io->recv_co = co;

#if defined(ECO_EPOLL)
  struct epoll_event event;
  event.data.fd = fd;
  event.events = EPOLLIN | EPOLLONESHOT | (io->send_co ? EPOLLOUT : 0) ;
  if (-1 == (already ? epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event) : epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event)))
    eco_abort(strerror(errno));
#elif defined(ECO_KQUEUE)
  // printf("注册 r 1\n");
  struct kevent event;
  EV_SET(&event, fd, EVFILT_READ, EV_ADD | EV_ENABLE | EV_ONESHOT, 0, 0, nullptr);
  if (kevent(efd, &event, 1, nullptr, 0, nullptr) == -1 || event.flags & EV_ERROR)
    eco_abort(strerror(errno));
  // printf("注册 r 2\n");
#endif
  return aco_yield();
}

void eco_event::efd_set_wevent(int efd, int fd, aco_t* co)
{
  co_io_slot_t *io = nullptr;
  co_loop_t* g = (co_loop_t*)(aco_get_co()->main_co->arg);
  bool already = g->io_map.count(fd) == 1;
  if (already)
  {
    io = g->io_map[fd];
    if (io->send_co)
      eco_abort("Disallow concurrent `send` operations on multiple coroutines.");
  }
  else
  {
    io = new co_io_slot_t;
    io->recv_co = nullptr;
    g->io_map[fd] = io;
  }
  io->send_co = co;

#if defined(ECO_EPOLL)
  struct epoll_event event;
  event.data.fd = fd;
  event.events = EPOLLOUT | EPOLLONESHOT | (io->recv_co ? EPOLLIN : 0) ;
  if (-1 == (already ? epoll_ctl(efd, EPOLL_CTL_MOD, fd, &event) : epoll_ctl(efd, EPOLL_CTL_ADD, fd, &event)))
    eco_abort(strerror(errno));
#elif defined(ECO_KQUEUE)
  // printf("注册 w 1\n");
  struct kevent event;
  EV_SET(&event, fd, EVFILT_WRITE, EV_ADD | EV_ENABLE | EV_ONESHOT, 0, 0, nullptr);
  if (kevent(efd, &event, 1, nullptr, 0, nullptr) == -1 || event.flags & EV_ERROR)
    eco_abort(strerror(errno));
  // printf("注册 w 2\n");
#endif
  return aco_yield();
}

void eco_event::efd_unset_ioevent(int efd, int fd)
{
  co_loop_t* g = (co_loop_t*)(aco_get_co()->main_co->arg);
  if (g->io_map.count(fd) > 0)
  {
    co_io_slot_t *io = g->io_map[fd];

    /* 如果是读事件就唤醒读 */
    if (io->recv_co)
      g->g_queue.push(io->recv_co);

    /* 如果是写事件就唤醒写 */
    if (io->send_co)
      g->g_queue.push(io->send_co);

    // 清除对象
    g->io_map.erase(fd);
    /* 清除内存 */
    delete io;

#if defined(ECO_EPOLL)
  epoll_ctl(g->efd, EPOLL_CTL_DEL, fd, nullptr);
#elif defined(ECO_KQUEUE)
  struct kevent event;
  EV_SET(&event, fd, EVFILT_WRITE, EV_DELETE, 0, 0, nullptr);
  kevent(efd, &event, 1, nullptr, 0, nullptr);
  EV_SET(&event, fd, EVFILT_READ, EV_DELETE, 0, 0, nullptr);
  kevent(efd, &event, 1, nullptr, 0, nullptr);
#endif

  }
}