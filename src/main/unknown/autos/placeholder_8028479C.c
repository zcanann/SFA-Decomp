#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8028479C.h"
#include "dolphin/os.h"
#include "dolphin/ai.h"

extern void *salMalloc(u32 size);
extern void salFree(void *ptr);
extern void *memset(void *, int, u32);
extern void DCFlushRange(void *src, u32 size);

extern u8 lbl_803BD150[];
extern void *salAiCallback;
extern u32 salAiDmaBuffer;
extern u32 salDspCallbackEnabled;
extern u32 salDspCallbackPending;
extern u32 salCallbackActive;
extern u32 salLastTick;
extern u32 salDspInitIsDone;
extern u8 salAIBufferIndex;

/*
 * AI DMA done callback: bumps the round-robin buffer index and
 * re-issues AIInitDMA on the next 0x280-byte chunk. If a higher-
 * level user callback is registered, runs it under a re-entrancy
 * guard with interrupts re-enabled.
 *
 * EN v1.0 Address: 0x80284670
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x8028479C
 * EN v1.1 Size: 164b
 */
void salCallback(u32 p1, u32 p2, u32 p3, int p4, u32 p5, u32 p6)
{
    salAIBufferIndex = (salAIBufferIndex + 1) % 4;
    AIInitDMA((u32)(u8 *)salAiDmaBuffer | 0x80000000U + salAIBufferIndex * 0x280, 0x280);
    salLastTick = OSGetTick();
    if (salDspCallbackEnabled != 0) {
        if (salCallbackActive == 0) {
            salCallbackActive = 1;
            OSEnableInterrupts();
            ((void (*)(void))salAiCallback)();
            OSDisableInterrupts();
            salCallbackActive = 0;
        }
    } else {
        salDspCallbackPending = 1;
    }
}

/*
 * Mark "needs callback" + "frame done".
 *
 * EN v1.1 Address: 0x80284714
 */
void dspInitCallback(void)
{
    salDspCallbackEnabled = 1;
    salDspInitIsDone = 1;
}

/*
 * Run pending user callback (if any) under a re-entrancy guard.
 *
 * EN v1.1 Address: 0x80284724
 */
void dspResumeCallback(void)
{
    salDspCallbackEnabled = 1;
    if (salDspCallbackPending != 0) {
        salDspCallbackPending = 0;
        if (salCallbackActive == 0) {
            salCallbackActive = 1;
            OSEnableInterrupts();
            ((void (*)(void))salAiCallback)();
            OSDisableInterrupts();
            salCallbackActive = 0;
        }
    }
}

/*
 * Audio output setup: allocate 0xa00-byte (4 x 0x280) DMA buffer,
 * zero it, register the AI DMA callback, and kick off the first DMA.
 * Returns 1 on success, 0 if allocation failed.
 *
 * EN v1.1 Address: 0x8028478C
 */
int salInitAi(void *userCallback, u32 unused, u32 *outSampleCount)
{
    void *buf;

    buf = salMalloc(0xa00);
    salAiDmaBuffer = (u32)buf;
    if (buf == NULL) {
        return 0;
    }
    memset(buf, 0, 0xa00);
    DCFlushRange(buf, 0xa00);
    salAiCallback = userCallback;
    salDspCallbackPending = 0;
    salDspCallbackEnabled = 1;
    salAIBufferIndex = 1;
    salCallbackActive = 0;
    AIRegisterDMACallback(salCallback);
    AIInitDMA((u32)(u8 *)salAiDmaBuffer | 0x80000000U + salAIBufferIndex * 0x280, 0x280);
    *(u32 *)(lbl_803BD150 + 4) = 0x20;
    *outSampleCount = 0x7d00;
    return 1;
}

/*
 * Start AI DMA.
 *
 * EN v1.1 Address: 0x80284858
 */
void salStartAi(void)
{
    AIStartDMA();
}

int salExitAi(void)
{
    AIRegisterDMACallback(0);
    AIStopDMA();
    salFree((void *)salAiDmaBuffer);
    return 1;
}

int salAiGetDest(void)
{
    int nextBuffer;

    nextBuffer = salAIBufferIndex + 2;
    return salAiDmaBuffer + ((u8)(nextBuffer - (nextBuffer / 4) * 4)) * 0x280;
}
