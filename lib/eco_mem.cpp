#include <iostream>
#include <execinfo.h>

#include "eco.hpp"
#include "eco_event.hpp"

#define BACKTRACE_SIZE   (32)
void *buffer[BACKTRACE_SIZE];

/* NEW */

void* operator new(size_t size) throw(std::bad_alloc)
{
#ifdef ECO_PRINTSTACK
  int nptrs = backtrace(buffer, BACKTRACE_SIZE);
  char **strings = backtrace_symbols(buffer, nptrs);
  if (strings){
    std::cout<< "`new`试图申请: " << size << "字节." << std::endl;
    for (int j = 0; j < nptrs; j++)  
      printf("  [%02d] %s\n", j, strings[j]);
  }
#endif
  if (size < 1)
    throw std::bad_alloc();
  /* malloc */
  void *ptr = eco_malloc(size);
  if (!ptr)
    throw std::bad_alloc();
  return ptr;
}

void* operator new[](size_t size) throw(std::bad_alloc)
{
#ifdef ECO_PRINTSTACK
  int nptrs = backtrace(buffer, BACKTRACE_SIZE);
  char **strings = backtrace_symbols(buffer, nptrs);
  if (strings){
    std::cout<< "`new[]`试图申请: " << size << "字节." << std::endl;
    for (int j = 0; j < nptrs; j++)  
      printf("  [%02d] %s\n", j, strings[j]);
  }
#endif
  if (size < 1)
    throw std::bad_alloc();
  /* malloc */
  void *ptr = eco_malloc(size);
  if (!ptr)
    throw std::bad_alloc();
  return ptr;
}

/* Delete */

void operator delete(void* ptr) throw()
{
#ifdef ECO_PRINTSTACK
  int nptrs = backtrace(buffer, BACKTRACE_SIZE);
  char **strings = backtrace_symbols(buffer, nptrs);
  if (strings){
    std::cout<< "`delete`试图释放内存"<< std::endl;
    for (int j = 0; j < nptrs; j++)  
      printf("  [%02d] %s\n", j, strings[j]);
  }
#endif
  if (!ptr)
    return;
  return eco_free(ptr);
}

void operator delete[] (void* ptr) throw()
{
#ifdef ECO_PRINTSTACK
  int nptrs = backtrace(buffer, BACKTRACE_SIZE);
  char **strings = backtrace_symbols(buffer, nptrs);
  if (strings){
    std::cout<< "`delete[]`试图释放内存"<< std::endl;
    for (int j = 0; j < nptrs; j++)  
      printf("  [%02d] %s\n", j, strings[j]);
  }
#endif
  if (!ptr)
    return;
  return eco_free(ptr);
}