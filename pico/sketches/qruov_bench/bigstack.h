// bigstack.h - run a crypto op on a large stack carved from SRAM, via a one-time stack-pointer
//   switch, so algorithms whose peak stack exceeds arduino-pico's 8 KB guard run unmodified.
//   Define BIG_STACK_BYTES before #include.
//
//   BOARD-CONDITIONAL: the correct switch is selected at COMPILE time from the target arch
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
static uint8_t g_bigstk[BIG_STACK_BYTES] __attribute__((aligned(16)));
#define STK_PAT 0x5A

#if defined(__ARM_ARCH_8M_MAIN__) || defined(__ARM_ARCH_8M_BASE__)
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
static inline void big_stack_paint(void) { memset(g_bigstk, STK_PAT, BIG_STACK_BYTES); }
static inline int  big_stack_run(int (*fn)(void)) { return run_on_stack(&g_bigstk[BIG_STACK_BYTES], fn); }
#endif
