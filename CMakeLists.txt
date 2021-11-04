# 作者信息
message("======================================")
message("Author Name   : CandyMi")
message("Author Email  : 869646063@qq.com")
message("Author Github : github.com/CandyMi")
message("======================================")


# 最低版本号
cmake_minimum_required(VERSION 3.0)

# 项目名称
project("libeco")

# 需要开启汇编支持
enable_language(ASM)

# 支持C++11特性
set(CMAKE_CXX_STANDARD 11)

# 选择编译类型
if (ECO_RELEASE)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2 -Wall")
else ()
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O0 -g -ggdb -Wall")
endif()

set(ECO_RPATH 
  "-Wl,-rpath,."
  "-Wl,-rpath,./lib"
  "-Wl,-rpath,/usr/local/lib"
)

set(ECO_INC 
  inc/eco.hpp
  # inc/eco_aco.hpp
  # inc/eco_event.hpp
)

set(ECO_LIBS
  lib/eco.cpp
  lib/eco_mem.cpp
  lib/eco_acosw.S
  lib/eco_aco.cpp
  lib/eco_dns.cpp
  lib/eco_event.cpp
)

# 选择合适的内存池
if (ECO_JEMALLOC)
  link_libraries( jemalloc )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DECO_JEMALLOC")
elseif(ECO_TCMALLOC)
  link_libraries( tcmalloc )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DECO_TCMALLOC")
endif()

# 开启SSL HOOK支持
if (ECO_OPENSSL)
  link_libraries( ssl crypto )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DECO_OPENSSL")
endif()

# 头文件存放位置
include_directories( . inc /usr/local/include )

link_directories( . lib /usr/local/lib )

link_libraries( dl )

# 编译成动态库/静态库
add_library(eco SHARED ${ECO_LIBS})

# 设置RPATH
set_target_properties(eco PROPERTIES LINK_FLAGS ${ECO_RPATH})

# 安装动态库
install(TARGETS eco
  LIBRARY DESTINATION lib
)

# 安装头文件
install(FILES ${ECO_INC} DESTINATION include)
