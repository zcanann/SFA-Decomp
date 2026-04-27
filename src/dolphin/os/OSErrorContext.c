#include <dolphin.h>
#include <dolphin/os.h>

extern void DBPrintf(char*, ...);
void OSSwitchFPUContext(__OSException exception, OSContext* context);

static char _oscontext_msg[] = "FPU-unavailable handler installed\n";

asm void __OSContextInit(void) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x8(r1)
    lis r3, OSSwitchFPUContext@ha
    addi r4, r3, OSSwitchFPUContext@l
    li r3, 0x7
    bl __OSSetExceptionHandler
    li r0, 0x0
    crxor 6, 6, 6
    lis r4, 0x8000
    lis r3, _oscontext_msg@ha
    stw r0, 0xd8(r4)
    addi r3, r3, _oscontext_msg@l
    bl DBPrintf
    lwz r0, 0xc(r1)
    addi r1, r1, 0x8
    mtlr r0
    blr
}
