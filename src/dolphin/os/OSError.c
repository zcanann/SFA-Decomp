#include <stdarg.h>
#include <dolphin.h>
#include <dolphin/os.h>

#include "dolphin/os/__os.h"

int vsprintf(const char* format, va_list arg);
extern void DBPrintf(char*, ...);
extern volatile OSContext* __OSFPUContext AT_ADDRESS(OS_BASE_CACHED | 0x00D8);
void OSSwitchFPUContext(__OSException exception, OSContext* context);

OSErrorHandler __OSErrorTable[17];

#define FPSCR_ENABLE (FPSCR_VE | FPSCR_OE | FPSCR_UE | FPSCR_ZE | FPSCR_XE)
u32 __OSFpscrEnableBits = FPSCR_ENABLE;

void OSPanic(const char* file, int line, const char* msg, ...) {
    va_list marker;
    u32 i;
    u32* p;

    OSDisableInterrupts();
    va_start(marker, msg);
    vsprintf(msg, marker);
    va_end(marker);
    OSReport(" in \"%s\" on line %d.\n", file, line);

    OSReport("\nAddress:      Back Chain    LR Save\n");
    for (i = 0, p = (u32*)OSGetStackPointer(); p && (u32)p != 0xffffffff && i++ < 16; p = (u32*)*p) {
        OSReport("0x%08x:   0x%08x    0x%08x\n", p, p[0], p[1]);
    }

    PPCHalt();
}

OSErrorHandler OSSetErrorHandler(OSError error, OSErrorHandler handler) {
    OSErrorHandler oldHandler;
    oldHandler = __OSErrorTable[error];
    __OSErrorTable[error] = handler;
    return oldHandler;
}

void __OSUnhandledException(__OSException exception, OSContext* context, u32 dsisr, u32 dar) {
    if (!(context->srr1 & MSR_RI)) {
        OSReport("Non-recoverable Exception %d", exception);
    } else {
        if (__OSErrorTable[exception]) {
            OSDisableScheduler();
            __OSErrorTable[exception](exception, context, dsisr, dar);
            OSEnableScheduler();
            __OSReschedule();
            OSLoadContext(context);
        }

        if (exception == __OS_EXCEPTION_DECREMENTER) {
            OSLoadContext(context);
        }

        OSReport("Unhandled Exception %d", exception);
    }

    OSReport("\n");
    OSDumpContext(context);
    OSReport("\nDSISR = 0x%08x                   DAR  = 0x%08x\n", dsisr, dar);
    OSReport("TB = 0x%016llx\n", OSGetTime());

    switch(exception) {
    case __OS_EXCEPTION_DSI:
        OSReport("\nInstruction at 0x%x (read from SRR0) attempted to access "
                    "invalid address 0x%x (read from DAR)\n",
                    context->srr0, dar);
        break;
    case __OS_EXCEPTION_ISI:
        OSReport("\nAttempted to fetch instruction from invalid address 0x%x "
                    "(read from SRR0)\n",
                    context->srr0);
        break;
    case __OS_EXCEPTION_ALIGNMENT:
        OSReport("\nInstruction at 0x%x (read from SRR0) attempted to access "
                    "unaligned address 0x%x (read from DAR)\n",
                    context->srr0, dar);
        break;
    case __OS_EXCEPTION_PROGRAM:
        OSReport("\nProgram exception : Possible illegal instruction/operation "
                    "at or around 0x%x (read from SRR0)\n",
                    context->srr0, dar);
        break;
    case __OS_EXCEPTION_MEMORY_PROTECTION:
        OSReport("\n");
        OSReport("AI DMA Address =   0x%04x%04x\n", __DSPRegs[DSP_DMA_START_HI],
                __DSPRegs[DSP_DMA_START_LO]);
        OSReport("ARAM DMA Address = 0x%04x%04x\n", __DSPRegs[DSP_ARAM_DMA_MM_HI],
                __DSPRegs[DSP_ARAM_DMA_MM_LO]);
        OSReport("DI DMA Address =   0x%08x\n", __DIRegs[5]);
        break;
    }

    OSReport("\nLast interrupt (%d): SRR0 = 0x%08x  TB = 0x%016llx\n", __OSLastInterrupt,
             __OSLastInterruptSrr0, __OSLastInterruptTime);
    PPCHalt();
}

static const char _oscontext_msg[] = "FPU-unavailable handler installed\n";

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
