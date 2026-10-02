/* TEXT / RAM origins come from the command line: -Wl,--defsym=TEXT=..,--defsym=RAM=.. */
MEMORY { text (rx) : ORIGIN = TEXT, LENGTH = 4M  ram (rwx) : ORIGIN = RAM, LENGTH = 4M }
ENTRY(Reset_Handler)
SECTIONS {
  .text : { KEEP(*(.vectors)) *(.text*) *(.rodata*) . = ALIGN(4); } > text
  .ARM.exidx : { *(.ARM.exidx*) } > text
  _sidata = LOADADDR(.data);
  .data : { _sdata = .; *(.data*) *(.got*) . = ALIGN(4); _edata = .; } > ram AT > text  /* liboqs is -fPIC: its GOT must be copied too */
  .bss (NOLOAD) : { _sbss = .; *(.bss*) *(COMMON) . = ALIGN(4); _ebss = .; } > ram
  end = .; PROVIDE(_end = .);
  _estack = ORIGIN(ram) + LENGTH(ram);
}
