# libeco

  基于协程实现的`C++ 11`高性能事件驱动网络框架.

## Features

  * `HOOK`的系统调用包括 : `send`、`recv`、`accept`、`connect`、`socket`、`socketpair`、`pipe`等.

  * 支持`任性`的创建海量的定时器, 使用紧凑的结构实现而不用担心内存占用等问题.

  * 基于协程的**同步非阻塞**逻辑编写模式, 比异步与回调的模型更加容易编写业务与库.

  * 内部自实现的`DNS`请求与解析协议与`Hosts`缓存机制, 不用担心封装业务不完善的问题.

## LICENSE

  [MIT License](https://github.com/cfadmin-cn/libeco/blob/main/LICENSE)
