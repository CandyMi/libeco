# libeco

  基于协程实现的`C++ 11`高性能事件驱动网络框架.

## Features

  * `HOOK`的系统调用包括 : `send`、`recv`、`accept`、`connect`、`socket`、`socketpair`、`pipe`等.

  * 支持`任性`的创建海量的定时器, 使用紧凑的结构实现而不用担心内存占用等问题.

  * 基于协程的**同步非阻塞**逻辑编写模式, 比异步与回调的模型更加容易编写业务与库.

  * 内部自实现的`DNS`请求与解析协议与`Hosts`缓存机制, 不用担心封装业务不完善的问题.

## Build


### 1. 创建目录

  `mkdir -p build && cd build`
  
### 2. 检查环境与编译

  `cmake .. && make`

### 3. 安装到文件夹

  `make install`

### 4. 清理

  `make clean`

## Build Arguments.

 `cmake .. `构建命令的尾部可以增加下列参数:

|宏名称|命令行语法|实际含义|
|------|------|------|
|ECO_RELEASE|-DECO_RELEASE=1|使用RELEASE模式编译(默认为DEBUG)|
|ECO_OPENSSL|-DECO_OPENSSL=1|告知链接`HOOK`住`openssl`的`API`|
|ECO_JEMALLOC|-DECO_JEMALLOC=1|告知链接使用`jemalloc`|
|ECO_TCMALLOC|-DECO_TCMALLOC=1|告知链接使用`tcmalloc`|

例如: `cmake .. -DECO_OPENSSL=1 && make && make install`

## Notice

  文档可能会因为过期而更新, 请在任何情况下以实际代码为准。

## LICENSE

  [MIT License](https://github.com/CandyMi/libeco/blob/master/LICENSE)
