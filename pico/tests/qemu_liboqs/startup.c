/* Bare-metal start-up for QEMU's MPS2 boards: vector table, .data/.bss set-up, semihosting I/O
 * (newlib rdimon), and an instruction counter. Under `-icount shift=0` QEMU retires one instruction
 * per virtual ns and SysTick (25 MHz CPU clock) ticks every 40 instructions, so
 * instructions = 40 * SysTick ticks (+/- 40). Deterministic, but instructions, not cycles. */
#include <stdint.h>
#include <stdlib.h>
#include <sys/lock.h>

extern uint32_t _sidata, _sdata, _edata, _sbss, _ebss, _estack;
extern int main(void);
extern void initialise_monitor_handles(void);

#define SYST_CSR (*(volatile uint32_t *)0xE000E010)
#define SYST_RVR (*(volatile uint32_t *)0xE000E014)
#define SYST_CVR (*(volatile uint32_t *)0xE000E018)
static volatile uint32_t wraps;

void SysTick_Handler(void) { wraps++; }
uint64_t insn_count(void) {  /* read wraps and the down-counter consistently */
    uint32_t w, v;
    do { w = wraps; v = SYST_CVR; } while (w != wraps);
    return 40ull * (((uint64_t)w << 24) + (0xFFFFFFu - v));
}
/* arduino-pico's newlib is built with retargetable locks (the core supplies them); one thread here, so no-ops */
struct __lock __lock___sfp_recursive_mutex, __lock___atexit_recursive_mutex, __lock___malloc_recursive_mutex;
void __retarget_lock_init_recursive(_LOCK_T l) { (void)l; }
void __retarget_lock_close_recursive(_LOCK_T l) { (void)l; }
void __retarget_lock_acquire_recursive(_LOCK_T l) { (void)l; }
void __retarget_lock_release_recursive(_LOCK_T l) { (void)l; }

static void fault(void) { for (;;) {} }
void Reset_Handler(void) {
    for (uint32_t *s = &_sidata, *d = &_sdata; d < &_edata;) *d++ = *s++;
    for (uint32_t *d = &_sbss; d < &_ebss;) *d++ = 0;
    SYST_RVR = 0xFFFFFF; SYST_CVR = 0; SYST_CSR = 7;  /* CPU clock, interrupt on wrap, enable */
#if defined(__ARM_FP)
    *(volatile uint32_t *)0xE000ED88 |= 0xFu << 20;  /* CPACR: FPU on (the M33 build may use it) */
#endif
    initialise_monitor_handles();
    exit(main());
}
__attribute__((section(".vectors"), used)) void (*const vectors[16])(void) = {
    (void (*)(void))&_estack, Reset_Handler, fault, fault, fault, fault, fault, 0, 0, 0, 0,
    fault, fault, 0, fault, SysTick_Handler,
};
