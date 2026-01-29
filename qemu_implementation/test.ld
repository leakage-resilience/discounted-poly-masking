MEMORY
{
    FLASH : ORIGIN = 0x00000000, LENGTH = 0x100000
    SRAM : ORIGIN  = 0x20000000, LENGTH = 0x100000
}
SECTIONS
{
   .text : { *(.text*) } > FLASH
   .rodata : { *(.rodata*) } > FLASH
   __data_rom_start__ = .;
   .data : {
    __data_start__ = .;
    *(.data*)
   } > SRAM AT > FLASH
   __data_end__ = .;
}