#ifndef __ECO_EVENT_H__
#define __ECO_EVENT_H__ 1

#include <iostream>
#include <memory>
#include <queue>
#include <csignal>
#include <cerrno>
#include <ctime>
#include <sys/time.h>
#include <unordered_map>
#include <functional>

#include "eco.hpp"
#include "eco_aco.hpp"

#define eco_max_events (8192)

#define eco_abort(reason) {                                                 \
  printf("[function: %s][Line: %d]: %s\n", __FUNCTION__, __LINE__, reason); \
  abort();                                                                  \
}

typedef enum {
  ECO_EVENT_READ   = 1,
  ECO_EVENT_WRITE  = 2,
  ECO_EVENT_TIMER  = 4,
} eco_event_t;

typedef struct co_io_slot {
  aco_t* send_co;
  aco_t* recv_co;
}co_io_slot_t;

typedef struct co_loop {
  int32_t efd;
  uint64_t interval;
  std::queue< aco_t * > g_queue;
  std::unordered_map< uint32_t, co_io_slot_t* > io_map;
  std::unordered_map< uint64_t, std::queue<aco_t *>* > timer_map;
}co_loop_t;


namespace eco_event {

  /* 创建事件描述符 */
  int efd_create();

  /* 监听事件 */
  void efd_poll(int efd);

  /* 注册读事件 */
  void efd_set_revent(int efd, int fd, aco_t* co);

  /* 注册写事件 */
  void efd_set_wevent(int efd, int fd, aco_t* co);

  /* 删除所有I/O事件 */
  void efd_unset_ioevent(int efd, int fd);

  /* 注册定时器事件 */
  void efd_set_tevent(int efd, uint32_t timeout, aco_t* co);
}

#endif
