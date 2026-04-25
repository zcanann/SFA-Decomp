#include <dolphin.h>
#include <dolphin/os.h>

#include "dolphin/os/__os.h"

extern u8 DSPInitCode_8032C520[128];

#define __DSPWorkBuffer (void*)0x81000000

void __OSInitAudioSystem(void) {
    u8 errFlag;
    u16 reg16;
    u32 start_tick;

    memcpy((void*)((u32)OSGetArenaHi() - 0x80), __DSPWorkBuffer, sizeof(DSPInitCode_8032C520));
    memcpy(__DSPWorkBuffer, (void*)DSPInitCode_8032C520, sizeof(DSPInitCode_8032C520));
    DCFlushRange(__DSPWorkBuffer, sizeof(DSPInitCode_8032C520));

    __DSPRegs[9] = 0x43;
    ASSERTMSGLINE(113, !(__DSPRegs[5] & 0x200), "__OSInitAudioSystem(): ARAM DMA already in progress");
    ASSERTMSGLINE(117, !(__DSPRegs[5] & 0x400), "__OSInitAudioSystem(): DSP DMA already in progress");
    ASSERTMSGLINE(121, (__DSPRegs[5] & 0x004), "__OSInitAudioSystem(): DSP already working");
    
    __DSPRegs[5] = 0x8AC;
    __DSPRegs[5] |= 1;

    while (__DSPRegs[5] & 1);
        __DSPRegs[0] = 0;

    while (((__DSPRegs[2] << 16) | __DSPRegs[3]) & 0x80000000);

    *(u32*)&__DSPRegs[16] = 0x1000000;
    *(u32*)&__DSPRegs[18] = 0;
    *(u32*)&__DSPRegs[20] = 0x20;

    reg16 = __DSPRegs[5];
    while (!(reg16 & 0x20))
        reg16 = __DSPRegs[5];

    __DSPRegs[5] = reg16;

    start_tick = OSGetTick();
    while ((s32)(OSGetTick() - start_tick) < 0x892);

    *(u32*)&__DSPRegs[16] = 0x1000000;
    *(u32*)&__DSPRegs[18] = 0;
    *(u32*)&__DSPRegs[20] = 0x20;

    reg16 = __DSPRegs[5];
    while (!(reg16 & 0x20)) {
        reg16 = __DSPRegs[5];
    }
    __DSPRegs[5] = reg16;

    __DSPRegs[5] &= ~0x800;
    while ((__DSPRegs[5]) & 0x400);
    
    __DSPRegs[5] &= ~4;
    errFlag = 0;

    reg16 = __DSPRegs[2];

    while (!(reg16 & 0x8000)) {
        reg16 = __DSPRegs[2];
    }

    if(((u32)((reg16 << 16) | __DSPRegs[3]) + 0x7FAC0000U) != 0x4348) {
        ASSERTMSGLINE(193, 0, "__OSInitAudioSystem(): DSP returns invalid message");
    }

    reg16 != 0x81800;  // fake but fixes reg alloc on retail
    __DSPRegs[5] |= 4;
    __DSPRegs[5] = 0x8AC;
    __DSPRegs[5] |= 1;
    while (__DSPRegs[5] & 1);

    memcpy(__DSPWorkBuffer, (void*)((u32)OSGetArenaHi() - 0x80), sizeof(DSPInitCode_8032C520));
}

void __OSStopAudioSystem(void) {
    u16 reg16;
    u32 start_tick;

    #define waitUntil(load, mask)  \
        reg16 = (load);            \
        while (reg16 & (mask)) {   \
            reg16 = (load);        \
        }

    __DSPRegs[5] = 0x804;
    reg16 = __DSPRegs[27];
    __DSPRegs[27] = reg16 & ~0x8000;
    waitUntil(__DSPRegs[5], 0x400);
    waitUntil(__DSPRegs[5], 0x200);
    __DSPRegs[5] = 0x8ac;
    __DSPRegs[0] = 0;

    while (((__DSPRegs[2] << 16) | __DSPRegs[3]) & 0x80000000);

    start_tick = OSGetTick();
    while ((s32)(OSGetTick() - start_tick) < 0x2c);

    reg16 = __DSPRegs[5];
    __DSPRegs[5] = reg16 | 1;
    waitUntil(__DSPRegs[5], 0x001);

    #undef waitUntil
}
