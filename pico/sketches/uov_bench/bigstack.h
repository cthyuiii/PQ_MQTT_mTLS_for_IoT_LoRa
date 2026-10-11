// bigstack.h - run a crypto op on a large stack carved from SRAM, via a one-time stack-pointer
//   switch, so algorithms whose peak stack exceeds arduino-pico's 8 KB guard run unmodified.
//   Define BIG_STACK_BYTES before #include.
//
//   BOARD-CONDITIONAL (ESP32 below too): the correct switch is selected at COMPILE time from the target arch
//   (which the runner sets via the FQBN), so the same source flashes the right version per board:
//     * RP2040  / Cortex-M0+  (ARMv6-M): plain SP switch. No stack-limit register exists.
//                 This is the on-device-validated version (MAYO-1/2, MQOM-cat1, SDitH-cat1).
//     * RP2350  / Cortex-M33  (ARMv8-M): the M33 has MSPLIM (a hardware stack-limit). The core
//                 may set it to the system stack bottom, which would fault the moment we switch
//                 SP into the big BSS buffer. So this build also saves/clears/restores MSPLIM
//                 around the switch. (Reasoned for the M33 ABI; validate on real RP2350 hardware.)
#ifndef BIGSTACK_H
#define BIGSTACK_H
#include <stdint.h>
#include <string.h>
#ifndef BIG_STACK_BYTES
#define BIG_STACK_BYTES (32u * 1024u)
#endif
#if defined(ARDUINO_ARCH_ESP32)
// the ESP32 linker caps static DRAM near 136 KB, below what one heap block gives (~110 KB free at boot): the big stack
// is a heap block there, allocated on the first big_stack_paint() (NULL if the heap can't give it)
#include <esp_heap_caps.h>
static uint8_t *g_bigstk;
#else
static uint8_t g_bigstk[BIG_STACK_BYTES] __attribute__((aligned(16)));
#endif
#if defined(ARDUINO_ARCH_ESP32)
#define STK_PAT 0xA5  // esp_execute_shared_stack_function fills the whole stack with 0xA5 (FreeRTOS's fill byte)
                      // before each call, over any paint of ours: the high-water scan looks for its fill
#else
#define STK_PAT 0x5A
#endif

#if defined(ARDUINO_ARCH_ESP32)
// ---- ESP32 (Xtensa, windowed registers): no hand-written SP switch. ESP-IDF's esp_execute_shared_stack_function runs
//      a function on a caller-supplied stack in the same task (it spills the register windows and restores them).
//      The stack is g_bigstk as on the Pico, so big_stack_paint / big_stack_peak work unchanged.
#include <freertos/FreeRTOS.h>
#include <freertos/semphr.h>
#include <esp_expression_with_stack.h>
static int (*g_bs_fn)(void);
static int g_bs_ret;
static void bs_trampoline(void) { g_bs_ret = g_bs_fn(); }
static int run_on_stack(void *new_top, int (*fn)(void)) {
  (void)new_top;
  static SemaphoreHandle_t lock = NULL;
  if (!lock) lock = xSemaphoreCreateMutex();
  g_bs_fn = fn;
  esp_execute_shared_stack_function(lock, g_bigstk, BIG_STACK_BYTES, bs_trampoline);
  return g_bs_ret;
}
#elif defined(__ARM_ARCH_8M_MAIN__) || defined(__ARM_ARCH_8M_BASE__)
// ---- RP2350 / Cortex-M33 (ARMv8-M): clear MSPLIM across the switch ----
__attribute__((naked, noinline))
static int run_on_stack(void *new_top, int (*fn)(void)) {   // r0=new_top, r1=fn
  __asm volatile(
    "mrs  r2, msplim       \n"   // r2 = old MSPLIM
    "mov  r3, sp           \n"   // r3 = old SP
    "mov  sp, r0           \n"   // SP = big-stack top
    "movs r0, #0           \n"
    "msr  msplim, r0       \n"   // disable the stack limit on the big stack
    "push {r2, r3, r4, lr} \n"   // save MSPLIM, old SP, r4(pad), lr  (4 words -> 8-byte aligned)
    "blx  r1               \n"   // fn(); int result stays in r0
    "pop  {r2, r3, r4, lr} \n"
    "msr  msplim, r2       \n"   // restore MSPLIM
    "mov  sp, r3           \n"   // restore the original stack
    "bx   lr               \n"
  );
}
#else
// ---- RP2040 / Cortex-M0+ (ARMv6-M): plain switch (validated) ----
__attribute__((naked, noinline))
static int run_on_stack(void *new_top, int (*fn)(void)) {
  __asm volatile(
    "mov  r2, sp   \n"   // save old sp
    "mov  sp, r0   \n"   // switch to the big stack
    "push {r2, lr} \n"   // save old sp + return addr (keeps 8-byte alignment)
    "blx  r1       \n"   // call fn(); int result stays in r0
    "pop  {r2, r3} \n"
    "mov  sp, r2   \n"   // restore the original stack
    "bx   r3       \n"
  );
}
#endif

static uint32_t big_stack_peak(void) {     // approx high-water of the big stack (paint + scan)
  uint32_t i = 0; while (i < BIG_STACK_BYTES && g_bigstk[i] == STK_PAT) i++;
  return BIG_STACK_BYTES - i;
}
static inline void big_stack_paint(void) {
#if defined(ARDUINO_ARCH_ESP32)
  if (!g_bigstk) g_bigstk = (uint8_t *)heap_caps_aligned_alloc(16, BIG_STACK_BYTES, MALLOC_CAP_8BIT);
  if (!g_bigstk) { Serial.printf("OUT OF MEMORY: big stack %u bytes; largest free block %u\n", (unsigned)BIG_STACK_BYTES,
                                 (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)); Serial.flush(); for (;;) delay(1000); }
#endif
  memset(g_bigstk, STK_PAT, BIG_STACK_BYTES);
}
static inline int  big_stack_run(int (*fn)(void)) { return run_on_stack(&g_bigstk[BIG_STACK_BYTES], fn); }
#endif
