#include <dolphin.h>
#include <dolphin/os.h>

#include "dolphin/os/__os.h"
#include <dolphin/dvd/__dvd.h>

extern u32 BOOT_REGION_START AT_ADDRESS(0x812FDFF0);
extern u32 BOOT_REGION_END AT_ADDRESS(0x812FDFEC);
extern u8 g_unk_800030E2 AT_ADDRESS(0x800030E2);
extern u32 g_unk_817FFFF8 AT_ADDRESS(0x817FFFF8);
extern u32 g_unk_817FFFFC AT_ADDRESS(0x817FFFFC);

static void* SaveStart_803DEAD0;
static void* SaveEnd_803DEAD4;
static volatile BOOL Prepared_803DEAD8;

typedef struct {
    char date[16];
    u32 entry;
    u32 size;
    u32 rebootSize;
    u32 reserved2;
} AppLoaderStruct;

static AppLoaderStruct FatalParam ATTRIBUTE_ALIGN(32);

#pragma dont_inline on
static asm void Run(register void* entryPoint) {
    nofralloc
    mflr r0
    stw r0, 4(r1)
    stwu r1, -0x18(r1)
    stw r31, 0x14(r1)
    mr r31, r3
    bl OSDisableInterrupts
    bl ICFlashInvalidate
    sync
    isync
    mtlr r31
    blr
}

static asm void fn_80244C78(void) {
    nofralloc
    lwz r0, 0x1c(r1)
    lwz r31, 0x14(r1)
    addi r1, r1, 0x18
    mtlr r0
    blr
}
#pragma dont_inline reset

static void Callback(s32 result, DVDCommandBlock* block) {
    (void)result;
    (void)block;
    Prepared_803DEAD8 = TRUE;
}

asm void __OSReboot(u32 resetCode, u32 bootDol) {
    nofralloc
    mflr r0
    stw r0, 0x4(r1)
    stwu r1, -0x340(r1)
    stw r31, 0x33c(r1)
    stw r30, 0x338(r1)
    lis r3, FatalParam@ha
    addi r30, r3, FatalParam@l
    bl OSDisableInterrupts
    lwz r5, SaveStart_803DEAD0(r13)
    lis r4, 0x8130
    lwz r0, SaveEnd_803DEAD4(r13)
    li r3, 0x0
    lis r31, 0x8180
    li r7, 0x1
    stw r3, -0x4(r31)
    lis r6, 0x8000
    stw r3, -0x8(r31)
    addi r3, r1, 0x70
    stb r7, 0x30e2(r6)
    stw r5, -0x2010(r4)
    stw r0, -0x2014(r4)
    bl OSClearContext
    addi r3, r1, 0x70
    bl OSSetCurrentContext
    bl DVDInit
    li r3, 0x1
    bl DVDSetAutoInvalidation
    lis r3, Callback@ha
    addi r3, r3, Callback@l
    bl __DVDPrepareResetAsync
    bl DVDCheckDisk
    cmpwi r3, 0x0
    bne _rb_1
    lwz r3, -0x4(r31)
    bl __OSDoHotReset
_rb_1:
    li r3, -0x20
    bl __OSMaskInterrupts
    li r3, 0x400
    bl __OSUnmaskInterrupts
    bl OSEnableInterrupts
    b _rb_2
_rb_2:
    b _rb_3
_rb_3:
    lwz r0, Prepared_803DEAD8(r13)
    cmpwi r0, 0x0
    beq _rb_3
    mr r4, r30
    addi r3, r1, 0x40
    li r5, 0x20
    li r6, 0x2440
    li r7, 0x0
    bl DVDReadAbsAsyncForBS
    lis r31, 0x8180
    b _rb_4
_rb_4:
    b _rb_5
_rb_5:
    lwz r0, 0x4c(r1)
    cmpwi r0, 0x1
    beq _rb_5
    bge _rb_6
    cmpwi r0, -0x1
    beq _rb_7
    bge _rb_8
    b _rb_5
_rb_6:
    cmpwi r0, 0xc
    bge _rb_5
    b _rb_7
_rb_7:
    lwz r3, -0x4(r31)
    bl __OSDoHotReset
    b _rb_5
_rb_8:
    lwz r3, 0x18(r30)
    lwz r4, 0x14(r30)
    addi r0, r3, 0x1f
    addi r4, r4, 0x20
    clrrwi r30, r0, 5
    b _rb_9
_rb_9:
    b _rb_10
_rb_10:
    lwz r0, Prepared_803DEAD8(r13)
    cmpwi r0, 0x0
    beq _rb_10
    mr r5, r30
    addi r3, r1, 0x10
    addi r6, r4, 0x2440
    lis r4, 0x8130
    li r7, 0x0
    bl DVDReadAbsAsyncForBS
    lis r31, 0x8180
    b _rb_11
_rb_11:
    b _rb_12
_rb_12:
    lwz r0, 0x1c(r1)
    cmpwi r0, 0x1
    beq _rb_12
    bge _rb_13
    cmpwi r0, -0x1
    beq _rb_14
    bge _rb_15
    b _rb_12
_rb_13:
    cmpwi r0, 0xc
    bge _rb_12
    b _rb_14
_rb_14:
    lwz r3, -0x4(r31)
    bl __OSDoHotReset
    b _rb_12
_rb_15:
    lis r3, 0x8130
    mr r4, r30
    bl ICInvalidateRange
    lis r3, 0x8130
    bl Run
    lwz r0, 0x344(r1)
    lwz r31, 0x33c(r1)
    lwz r30, 0x338(r1)
    addi r1, r1, 0x340
    mtlr r0
    blr
}

void OSSetSaveRegion(void* start, void* end) {
    SaveStart_803DEAD0 = start;
    SaveEnd_803DEAD4 = end;
}
