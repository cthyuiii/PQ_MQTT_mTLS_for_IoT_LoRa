// host stub: just enough of Arduino for aead_bench.ino's crypto functions
#pragma once
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define F(x) x
#define F_CPU 133000000u
struct FakeSerial {
  template <class T> void print(T) {} template <class T> void print(T, int) {}
  template <class T> void println(T) {} template <class T> void println(T, int) {} void println() {}
  void begin(int) {} void flush() {} operator bool() { return true; }
};
static FakeSerial Serial;
struct FakeRP { uint32_t hwrand32() { return (uint32_t)rand(); } int getFreeStack() { return 0; } int getFreeHeap() { return 0; } };
static FakeRP rp2040;
static inline uint64_t time_us_64() { return 0; }
static inline void delay(int) {}
