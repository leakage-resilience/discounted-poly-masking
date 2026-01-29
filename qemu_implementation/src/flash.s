
.thumb
.global _start
_start:
.word 0x20001000
.word reset

.thumb_func
reset:
    ldr r0,=__data_rom_start__
    ldr r1,=__data_start__
    ldr r2,=__data_end__
data_loop:
    ldrb r3,[r0]
    strb r3,[r1]
    add r0,r0,#1
    add r1,r1,#1
    cmp r1,r2
    bne data_loop
    bl entry
    b .
