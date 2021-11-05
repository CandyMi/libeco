#include <iostream>

#include "eco.hpp"
#include "eco_event.hpp"

/* NEW */
void* operator new(size_t size) noexcept(false)
{
  if (size < 1)
    throw std::bad_alloc();
  /* malloc */
  void *ptr = eco_malloc(size);
  if (!ptr)
    throw std::bad_alloc();
  return ptr;
}

void* operator new[](size_t size) noexcept(false)
{
  if (size < 1)
    throw std::bad_alloc();
  /* malloc */
  void *ptr = eco_malloc(size);
  if (!ptr)
    throw std::bad_alloc();
  return ptr;
}

/* Delete */
void operator delete(void* ptr) noexcept(true)
{
  if (!ptr)
    return;
  return eco_free(ptr);
}

void operator delete[] (void* ptr) noexcept(true)
{
  if (!ptr)
    return;
  return eco_free(ptr);
}