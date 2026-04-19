#include <dolphin.h>
#include <dolphin/db.h>
#include <dolphin/os.h>

#include "dolphin/os/__os.h"

#ifndef __GEKKO__
#define __GEKKO__
#endif

#define HID2 920

// prototypes
void DMAErrorHandler(OSError error, OSContext* context, ...);

static struct {
    char l2InvalidateShouldNeverHappen[0x29];
    unsigned char pad0[0x3];
    char machineCheckReceived[0x18];
    char hid2Srr1Fmt[0x1B];
    unsigned char pad1[0x1];
    char machineCheckNotDmaLockedCacheRelated[0x30];
    char dmaErrorOccurredWhileProcessingDma[0x3C];
    char dmaErrorsDetectedAndCleared[0x37];
    unsigned char pad2[0x1];
    char requestedLockedCacheTagAlreadyInCache[0x3F];
    unsigned char pad2b[0x1];
    char dmaAttemptedToAccessNormalCache[0x29];
    unsigned char pad3[0x3];
    char dmaMissedInDataCache[0x1D];
    unsigned char pad4[0x3];
    char dmaQueueOverflowed[0x19];
    unsigned char pad5[0x3];
    char l1ICachesInitialized[0x19];
    unsigned char pad6[0x3];
    char l1DCachesInitialized[0x19];
    unsigned char pad7[0x3];
    char l2CacheInitialized[0x16];
    unsigned char pad8[0x2];
    char lockedCacheMachineCheckHandlerInstalled[0x2E];
    unsigned char pad9[0x6];
} s_osCacheData = {
    ">>> L2 INVALIDATE : SHOULD NEVER HAPPEN\n",
    {0x00, 0x00, 0x00},
    "Machine check received\n",
    "HID2 = 0x%x   SRR1 = 0x%x\n",
    {0x00},
    "Machine check was not DMA/locked cache related\n",
    "DMAErrorHandler(): An error occurred while processing DMA.\n",
    "The following errors have been detected and cleared :\n",
    {0x00},
    "\t- Requested a locked cache tag that was already in the cache\n",
    {0x00},
    "\t- DMA attempted to access normal cache\n",
    {0x00, 0x00, 0x00},
    "\t- DMA missed in data cache\n",
    {0x00, 0x00, 0x00},
    "\t- DMA queue overflowed\n",
    {0x00, 0x00, 0x00},
    "L1 i-caches initialized\n",
    {0x00, 0x00, 0x00},
    "L1 d-caches initialized\n",
    {0x00, 0x00, 0x00},
    "L2 cache initialized\n",
    {0x00, 0x00},
    "Locked cache machine check handler installed\n",
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
};

#ifdef __GEKKO__
asm void DCFlashInvalidate(void) {
    nofralloc
    mfspr r3, HID0
    ori r3, r3, 0x400
    mtspr HID0, r3
    blr
}

asm void DCEnable(void) {
    nofralloc
    sync
    mfspr r3, HID0
    ori   r3, r3, 0x4000
    mtspr HID0, r3
    blr
}

asm void DCDisable(void) {
    nofralloc
    sync
    mfspr r3, HID0
    rlwinm r3, r3, 0, 18, 16
    mtspr HID0, r3
    blr
}

asm void DCFreeze(void) {
    nofralloc
    sync
    mfspr r3, HID0
    ori r3, r3, 0x1000
    mtspr HID0, r3
    blr
}

asm void DCUnfreeze(void) {
    nofralloc
    mfspr r3, HID0
    rlwinm r3, r3, 0, 20, 18
    mtspr HID0, r3
    blr
}

asm void DCTouchLoad(register void* addr) {
    nofralloc
    dcbt r0, addr
    blr
}

asm void DCBlockZero(register void* addr) {
    nofralloc
    dcbz r0, addr
    blr
}

asm void DCBlockStore(register void* addr) {
    nofralloc
    dcbst r0, addr
    blr
}

asm void DCBlockFlush(register void* addr) {
    nofralloc
    dcbf r0, addr
    blr
}

asm void DCBlockInvalidate(register void* addr) {
    nofralloc
    dcbi r0, addr
    blr
}

asm void DCInvalidateRange(register void* addr, register u32 nBytes) {
    nofralloc
    cmplwi nBytes, 0
    blelr
    clrlwi. r5, addr, 27
    beq @2
    addi   nBytes, nBytes, 32
@2
    addi   nBytes, nBytes, 31
    srwi   nBytes, nBytes, 5
    mtctr  nBytes

@1
    dcbi r0, addr
    addi addr, addr, 32
    bdnz @1
    blr
}

asm void DCFlushRange(register void* addr, register u32 nBytes) {
    nofralloc
    cmplwi nBytes, 0
    blelr
    clrlwi. r5, addr, 27
    beq @2
    addi nBytes, nBytes, 32
@2
    addi nBytes, nBytes, 31
    srwi nBytes, nBytes, 5
    mtctr nBytes

@1
    dcbf r0, addr
    addi addr, addr, 32
    bdnz @1
    sc
    blr
}

asm void DCStoreRange(register void* addr, register u32 nBytes) {
    nofralloc
    cmplwi nBytes, 0
    blelr
    clrlwi. r5, addr, 27
    beq @2
    addi nBytes, nBytes, 32
@2
    addi nBytes, nBytes, 31
    srwi nBytes, nBytes, 5
    mtctr nBytes

@1
    dcbst r0, addr
    addi addr, addr, 32
    bdnz @1
    sc

    blr
}

asm void DCFlushRangeNoSync(register void* addr, register u32 nBytes) {
    nofralloc
    cmplwi nBytes, 0
    blelr
    clrlwi. r5, addr, 27
    beq @2
    addi nBytes, nBytes, 32
@2
    addi nBytes, nBytes, 31
    srwi nBytes, nBytes, 5
    mtctr nBytes

@1
    dcbf r0, addr
    addi addr, addr, 32
    bdnz @1
    blr
}

asm void DCStoreRangeNoSync(register void* addr, register u32 nBytes) {
    nofralloc
    cmplwi nBytes, 0
    blelr
    clrlwi. r5, addr, 27
    beq @2
    addi nBytes, nBytes, 32
@2
    addi nBytes, nBytes, 31
    srwi nBytes, nBytes, 5
    mtctr nBytes

@1
    dcbst r0, addr
    addi addr, addr, 32
    bdnz @1

    blr
}

asm void DCZeroRange(register void* addr, register u32 nBytes) {
  nofralloc
  cmplwi nBytes, 0
  blelr
  clrlwi. r5, addr, 27
  beq @2
  addi nBytes, nBytes, 32
@2
  addi nBytes, nBytes, 31
  srwi nBytes, nBytes, 5
  mtctr nBytes

@1
  dcbz r0, addr
  addi addr, addr, 32
  bdnz @1

  blr
}

asm void DCTouchRange(register void* addr, register u32 nBytes) {
    nofralloc
    cmplwi nBytes, 0
    blelr
    clrlwi. r5, addr, 27
    beq @2
    addi nBytes, nBytes, 32
@2
    addi nBytes, nBytes, 31
    srwi nBytes, nBytes, 5
    mtctr nBytes

@1
    dcbt r0, addr
    addi addr, addr, 32
    bdnz @1

    blr
}

asm void ICInvalidateRange(register void* addr, register u32 nBytes) {
    nofralloc
    cmplwi nBytes, 0
    blelr
    clrlwi. r5, addr, 27
    beq @2
    addi nBytes, nBytes, 32
@2
    addi nBytes, nBytes, 31
    srwi nBytes, nBytes, 5
    mtctr nBytes

@1
    icbi r0, addr
    addi addr, addr, 32
    bdnz @1
    sync
    isync

    blr
}

asm void ICFlashInvalidate(void) {
    nofralloc
    mfspr r3, HID0
    ori r3, r3, 0x800
    mtspr HID0, r3
    blr
}

asm void ICEnable(void) {
    nofralloc
    isync
    mfspr r3, HID0
    ori r3, r3, 0x8000
    mtspr HID0, r3
    blr
}

asm void ICDisable(void) {
    nofralloc
    isync
    mfspr r3, HID0
    rlwinm r3, r3, 0, 17, 15
    mtspr HID0, r3
    blr
}

asm void ICFreeze(void) {
    nofralloc
    isync
    mfspr r3, HID0
    ori r3, r3, 0x2000
    mtspr HID0, r3
    blr
}

asm void ICUnfreeze(void) {
    nofralloc
    mfspr r3, HID0
    rlwinm r3, r3, 0, 19, 17
    mtspr HID0, r3
    blr
}

asm void ICBlockInvalidate(register void* addr) {
    nofralloc
    icbi r0, addr
    blr
}

asm void ICSync(void) {
    nofralloc
    isync
    blr
}

#define LC_LINES    512
#define CACHE_LINES 1024

static asm void __LCEnable(void) {
    nofralloc
    mfmsr   r5
    ori     r5, r5, 0x1000
    mtmsr   r5

    lis     r3, OS_CACHED_REGION_PREFIX
    li      r4, CACHE_LINES
    mtctr   r4
_touchloop:
    dcbt    0,r3
    dcbst   0,r3
    addi    r3,r3,32
    bdnz    _touchloop
    mfspr   r4, HID2
    oris    r4, r4, 0x100F
    mtspr   HID2, r4

    nop 
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    lis     r3, LC_BASE_PREFIX
    ori     r3, r3, 0x0002
    mtspr   DBAT3L, r3
    ori     r3, r3, 0x01fe
    mtspr   DBAT3U, r3
    isync
    lis     r3, LC_BASE_PREFIX
    li      r6, LC_LINES
    mtctr   r6
    li      r6, 0

_lockloop:
    dcbz_l  r6, r3
    addi    r3, r3, 32
    bdnz+    _lockloop

    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop
    nop

    blr
}

void LCEnable(void) {
    BOOL enabled;

    enabled = OSDisableInterrupts();
    __LCEnable();
    OSRestoreInterrupts(enabled);
}

asm void LCDisable(void) {
    nofralloc
    lis     r3, LC_BASE_PREFIX
    li      r4, LC_LINES
    mtctr r4
@1
    dcbi r0, r3
    addi r3, r3, 32
    bdnz @1
    mfspr r4, HID2
    rlwinm r4, r4, 0, 4, 2
    mtspr HID2, r4
    blr
}

asm void LCAllocOneTag(register BOOL invalidate, register void* tag) {
    nofralloc
    cmpwi invalidate, 0
    beq @1
    dcbi r0, tag
@1
    dcbz_l r0, tag
    blr
}

asm void LCAllocTags(register BOOL invalidate, register void* startTag, register u32 numBlocks) {
    nofralloc
    mflr r6
    cmplwi numBlocks, 0
    ble @3
    mtctr numBlocks
    cmpwi invalidate, 0
    beq @2
@1
    dcbi r0, startTag
    dcbz_l r0, startTag
    addi startTag, startTag, 32
    bdnz @1
    b @3
@2
    dcbz_l r0, startTag
    addi startTag, startTag, 32
    bdnz @2
@3
    mtlr r6
    blr
}

asm void LCLoadBlocks(register void* destTag, register void* srcAddr, register u32 numBlocks) {
    nofralloc
    rlwinm  r6, numBlocks, 30, 27, 31
    rlwinm  srcAddr, srcAddr, 0, 4, 31
    or      r6, r6, srcAddr
    mtspr   DMA_U, r6
    rlwinm  r6, numBlocks, 2, 28, 29
    or      r6, r6, destTag
    ori     r6, r6, 0x12
    mtspr   DMA_L, r6
    blr
}

asm void LCStoreBlocks(register void* destAddr, register void* srcTag, register u32 numBlocks) {
    nofralloc
    rlwinm  r6, numBlocks, 30, 27, 31
    rlwinm  destAddr, destAddr, 0, 4, 31
    or      r6, r6, destAddr
    mtspr   DMA_U, r6
    rlwinm  r6, numBlocks, 2, 28, 29
    or      r6, r6, srcTag
    ori     r6, r6, 0x2
    mtspr   DMA_L, r6
    blr
}
#endif

void LCAlloc(void* addr, u32 nBytes) {
    u32 numBlocks = nBytes >> 5;
    u32 hid2 = PPCMfhid2();

    ASSERTMSGLINE(1319, !((u32)addr & 31), "LCAlloc(): addr must be 32 byte aligned");
    ASSERTMSGLINE(1321, !((u32)nBytes & 31), "LCAlloc(): nBytes must be 32 byte aligned");

    if ((hid2 & 0x10000000) == 0) {
        LCEnable();
    }
    LCAllocTags(TRUE, addr, numBlocks);
}

void LCAllocNoInvalidate(void* addr, u32 nBytes) {
    u32 numBlocks = nBytes >> 5;
    u32 hid2 = PPCMfhid2();

    ASSERTMSGLINE(1366, !((u32)addr & 31), "LCAllocNoFlush(): addr must be 32 byte aligned");
    ASSERTMSGLINE(1368, !((u32)nBytes & 31), "LCAllocNoFlush(): nBytes must be 32 byte aligned");

    if ((hid2 & 0x10000000) == 0) {
        LCEnable();
    }
    LCAllocTags(FALSE, addr, numBlocks);
}

u32 LCLoadData(void* destAddr, void* srcAddr, u32 nBytes) {
    u32 numBlocks = (nBytes + 31) / 32;
    u32 numTransactions = (numBlocks + 128 - 1) / 128;

    ASSERTMSGLINE(1426, !((u32)srcAddr & 31), "LCLoadData(): srcAddr not 32 byte aligned");
    ASSERTMSGLINE(1428, !((u32)destAddr & 31), "LCLoadData(): destAddr not 32 byte aligned");

    while (numBlocks > 0) {
        if (numBlocks < 128) {
            LCLoadBlocks(destAddr, srcAddr, numBlocks);
            numBlocks = 0;
        } else {
            LCLoadBlocks(destAddr, srcAddr, 0);
            numBlocks -= 128;
            destAddr = (void*)((u32)destAddr + 4096);
            srcAddr = (void*)((u32)srcAddr + 4096);
        }
    }

    return numTransactions;
}

u32 LCStoreData(void* destAddr, void* srcAddr, u32 nBytes) {
    u32 numBlocks = (nBytes + 31) / 32;
    u32 numTransactions = (numBlocks + 128 - 1) / 128;

    ASSERTMSGLINE(1494, !((u32)srcAddr & 31), "LCStoreData(): srcAddr not 32 byte aligned");
    ASSERTMSGLINE(1496, !((u32)destAddr & 31), "LCStoreData(): destAddr not 32 byte aligned");

    while (numBlocks > 0) {
        if (numBlocks < 128) {
            LCStoreBlocks(destAddr, srcAddr, numBlocks);
            numBlocks = 0;
        } else {
            LCStoreBlocks(destAddr, srcAddr, 0);
            numBlocks -= 128;
            destAddr = (void*)((u32)destAddr + 4096);
            srcAddr = (void*)((u32)srcAddr + 4096);
        }
    }

    return numTransactions;
}

#ifdef __GEKKO__
asm u32 LCQueueLength(void) {
    nofralloc
    mfspr   r4, HID2
    rlwinm  r3, r4, 8, 28, 31
    blr
}

asm void LCQueueWait(register u32 len) {
    nofralloc
    addi r3, r3, 1
@1
    mfspr r4, HID2
    rlwinm r4, r4, 8, 28, 31
    cmpw cr2, r4, r3
    bge cr2, @1
    blr
}
#endif

void LCFlushQueue() {
    union {
        u32 val;
        struct {
            u32 lcAddr : 27;
            u32 dmaLd : 1;
            u32 dmaLenL : 2;
            u32 dmaTrigger : 1;
            u32 dmaFlush : 1;
        } f;
    } dmaL;

    dmaL.val = 0;
    dmaL.f.dmaFlush = 1;
    PPCMtdmaU(0);
    PPCMtdmaL(dmaL.val);
    PPCSync();
}

static void L2Init(void) {
    u32 oldMSR;
    oldMSR = PPCMfmsr();
    __sync();
    PPCMtmsr(MSR_IR | MSR_DR);
    __sync();
    L2Disable();
    L2GlobalInvalidate();
    PPCMtmsr(oldMSR);
}

void L2Enable(void) { 
    PPCMtl2cr((PPCMfl2cr() | L2CR_L2E) & ~L2CR_L2I);
}

void L2Disable(void) {
    __sync();
    PPCMtl2cr(PPCMfl2cr() & ~0x80000000);
    __sync();
}

void L2GlobalInvalidate(void) {
    L2Disable();
    PPCMtl2cr(PPCMfl2cr() | 0x00200000);
    while (PPCMfl2cr() & 0x00000001u);

    PPCMtl2cr(PPCMfl2cr() & ~0x00200000);
    while (PPCMfl2cr() & 0x00000001u) {
        DBPrintf(s_osCacheData.l2InvalidateShouldNeverHappen);
    }
}

void L2SetDataOnly(BOOL dataOnly) {
    if (dataOnly) {
        PPCMtl2cr(PPCMfl2cr() | 0x400000);
        return;
    }
    PPCMtl2cr(PPCMfl2cr() & 0xFFBFFFFF);
}

void L2SetWriteThrough(BOOL writeThrough) {
    if (writeThrough) {
        PPCMtl2cr(PPCMfl2cr() | 0x80000);
        return;
    }
    PPCMtl2cr(PPCMfl2cr() & 0xFFF7FFFF);
}

void DMAErrorHandler(OSError error, OSContext* context, ...) {
    u32 hid2 = PPCMfhid2();

    OSReport(s_osCacheData.machineCheckReceived);
    OSReport(s_osCacheData.hid2Srr1Fmt, hid2, context->srr1);
    if (!(hid2 & (HID2_DCHERR | HID2_DNCERR | HID2_DCMERR | HID2_DQOERR)) || !(context->srr1 & SRR1_DMA_BIT)) {
        OSReport(s_osCacheData.machineCheckNotDmaLockedCacheRelated);
        OSDumpContext(context);
        PPCHalt();
    }

    OSReport(s_osCacheData.dmaErrorOccurredWhileProcessingDma);
    OSReport(s_osCacheData.dmaErrorsDetectedAndCleared);

    if (hid2 & HID2_DCHERR) {
        OSReport(s_osCacheData.requestedLockedCacheTagAlreadyInCache);
    }

    if (hid2 & HID2_DNCERR) {
        OSReport(s_osCacheData.dmaAttemptedToAccessNormalCache);
    }

    if (hid2 & HID2_DCMERR) {
        OSReport(s_osCacheData.dmaMissedInDataCache);
    }

    if (hid2 & HID2_DQOERR) {
        OSReport(s_osCacheData.dmaQueueOverflowed);
    }

    // write hid2 back to clear the error bits
    PPCMthid2(hid2);
}

void __OSCacheInit() {
    if (!(PPCMfhid0() & HID0_ICE)) {
        ICEnable();
        DBPrintf(s_osCacheData.l1ICachesInitialized);
    }

    if (!(PPCMfhid0() & HID0_DCE)) {
        DCEnable();
        DBPrintf(s_osCacheData.l1DCachesInitialized);
    }

    if (!(PPCMfl2cr() & L2CR_L2E)) {
        L2Init();
        L2Enable();
        DBPrintf(s_osCacheData.l2CacheInitialized);
    }

    OSSetErrorHandler(OS_ERROR_MACHINE_CHECK, DMAErrorHandler);
    DBPrintf(s_osCacheData.lockedCacheMachineCheckHandlerInstalled);
}
