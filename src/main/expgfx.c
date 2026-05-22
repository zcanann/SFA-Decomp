#include "ghidra_import.h"
#include "dolphin/mtx.h"
#include "dolphin/os/OSCache.h"
#include "main/expgfx.h"
#include "main/expgfx_internal.h"
#include "main/object_descriptor.h"

extern undefined4 ABS();
extern int Camera_GetViewMatrix(void);
extern int renderModeSetOrGet(int mode);
extern int FUN_80006714();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068d4();
extern undefined4 FUN_80006964();
extern undefined4 FUN_80006974();
extern undefined4 FUN_80006988();
extern undefined4 FUN_8000698c();
extern void* FUN_800069a8();
extern undefined4 FUN_800069cc();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void mm_free(void *ptr);
extern undefined4 FUN_8004812c();
extern undefined8 FUN_80053754();
extern void textureFree(void *resource);
extern int FUN_8005b024();
extern undefined4 FUN_8005d340();
extern undefined4 FUN_8005e1d8();
extern void fn_8005DE94(uint slotPoolBase,int poolIndex,float *position);
extern uint FUN_8005e558();
extern u8 fn_8005E97C();
extern undefined4 FUN_8006f8a4();
extern undefined4 FUN_8006f8fc();
extern void trackIntersect_drawColorBand(void);
extern int FUN_80080f40();
extern undefined4 FUN_80080f84();
extern undefined4 FUN_80080f8c();
extern undefined4 FUN_80081130();
extern int FUN_80081134();
extern void expgfx_updateActivePools(u8 sourceMode,int sourceId,int param_3);
extern undefined8 FUN_80135810();
extern void debugPrintf(char *message,...);
extern double FUN_80136594();
extern undefined4 FUN_802420e0();
extern undefined4 FUN_802475e4();
/* PSMTXMultVec is declared by dolphin/mtx.h */
extern undefined4 FUN_80247bf8();
extern undefined4 FUN_80247ef8();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_80259000();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025a5bc();
extern undefined4 FUN_8025a608();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d888();
extern undefined8 FUN_8028680c();
extern undefined8 FUN_80286824();
extern int FUN_80286828();
extern undefined8 FUN_8028682c();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286838();
extern undefined4 FUN_80286858();
extern undefined4 FUN_80286870();
extern undefined4 FUN_80286874();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80293470();
extern double FUN_80293900();
extern double FUN_80294c4c();
extern void _savegpr_20(void);
extern void _restgpr_20(void);
extern void _savegpr_21(void);
extern void _restgpr_21(void);
extern void _savegpr_23(void);
extern void _restgpr_23(void);
extern void _savegpr_25(void);
extern void _restgpr_25(void);

extern ExpgfxBounds gExpgfxBoundsTemplates;
extern undefined2 gExpgfxPoolSlotTypeIds;
extern undefined gExpgfxPoolFrameFlags;
extern undefined2 DAT_803105a8;
extern undefined4 DAT_80397420;
extern int DAT_8039b7b8;
extern ExpgfxBounds gExpgfxPoolBounds;
extern int DAT_8039c138;
extern undefined4 DAT_8039c13c;
extern undefined4 DAT_8039c140;
extern short DAT_8039c144;
extern undefined4 DAT_8039c146;
extern byte gExpgfxPoolSourceModes;
extern int gExpgfxPoolSourceIds;
extern undefined4 DAT_8039c7c8;
extern undefined4 DAT_8039c7cc;
extern byte gExpgfxPoolBoundsTemplateIds;
extern char gExpgfxPoolActiveCounts;
extern char DAT_8039c829;
extern u32 gExpgfxPoolActiveMasks[];
extern u32 gExpgfxSlotPoolBases[];
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dd430;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd718;
extern undefined4 DAT_803dded4;
extern undefined4 DAT_803dded8;
extern undefined4 DAT_803ddee8;
extern undefined4 DAT_803ddeea;
extern undefined2* DAT_803ddeec;
extern undefined4 DAT_803ddef0;
extern undefined4 DAT_803ddef4;
extern undefined4 DAT_803ddef8;
extern undefined4 DAT_cc008000;
extern u8 gExpgfxStaticPoolFrameFlags[];
extern undefined4* gPartfxInterface;
extern u8 lbl_803DC7B0;
extern u8 lbl_803DD253;
extern u8 lbl_803DD254;
extern volatile f32 timeDelta;
extern volatile f32 lbl_803DD25C;
extern volatile f32 lbl_803DD260;
extern volatile f32 lbl_803DD264;
extern volatile f32 lbl_803DF354;
extern volatile f32 lbl_803DF35C;
extern volatile f32 lbl_803DF384;
extern volatile f32 lbl_803DF418;
extern f32 lbl_803DF358;
extern f64 DOUBLE_803dffe0;
extern f64 DOUBLE_803dfff8;
extern f32 lbl_803DC074;
extern f32 lbl_803DC3F0;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f64 lbl_803DF378;
extern f32 lbl_803DF3B4;
extern f32 lbl_803DF3B8;
extern f32 lbl_803DF3BC;
extern f32 lbl_803DF3C0;
extern f32 lbl_803DF3C4;
extern f32 lbl_803DDEDC;
extern f32 lbl_803DDEE0;
extern f32 lbl_803DDEE4;
extern f32 lbl_803DFFD0;
extern f32 lbl_803DFFD4;
extern f32 lbl_803DFFD8;
extern f32 lbl_803DFFDC;
extern f32 lbl_803E0004;
extern f32 lbl_803E000C;
extern f32 lbl_803E0010;
extern f32 lbl_803E0030;
extern f32 lbl_803E0034;
extern f32 lbl_803E0038;
extern f32 lbl_803E003C;
extern f32 lbl_803E0040;
extern f32 lbl_803E0044;
extern f32 lbl_803E0048;
extern f32 lbl_803E004C;
extern f32 lbl_803E0050;
extern f32 lbl_803E0054;
extern f32 lbl_803E0058;
extern f32 lbl_803E005C;
extern f32 lbl_803E0060;
extern f32 lbl_803E0064;
extern f32 lbl_803E0068;
extern f32 lbl_803E006C;
extern f32 lbl_803E0070;
extern f32 lbl_803E0074;
extern f32 lbl_803E0078;
extern f32 lbl_803E007C;
extern f32 lbl_803E0080;
extern f32 lbl_803E0084;
extern f32 lbl_803E0088;
extern f32 lbl_803E008C;
extern f32 lbl_803E0090;
extern f32 lbl_803E0094;
extern f32 lbl_803E0098;
extern f32 lbl_803E009C;
extern f32 lbl_803E00A0;
extern f32 lbl_803E00A4;
extern f32 lbl_803E00A8;
extern u8 gExpgfxStaticData[];
extern u8 gExpgfxRuntimeData[];
extern u32 gExpgfxTrackedPoolSourceIds[];
extern ExpgfxTrackedSourceFrameMask gExpgfxTrackedSourceFrameMasks[];
extern s16 gExpgfxStaticPoolSlotTypeIds[];
extern int gExpgfxTextureFreeInProgress;
extern volatile s16 gExpgfxSequenceCounter;
extern volatile u8 gExpgfxFrameParityBit;
extern char sExpgfxAddToTableUsageOverflow[];
extern char sExpgfxExpTabIsFull[];
extern char sExpgfxInvalidTabIndex[];
extern char sExpgfxMismatchInAddRemove[];
extern char sExpgfxScaleOverflow[];
extern char sExpgfxNoTexture[];

ObjectDescriptor14 expgfx_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_14_SLOTS,
    (ObjectDescriptorCallback)expgfx_initialise,
    (ObjectDescriptorCallback)expgfx_release,
    0,
    (ObjectDescriptorCallback)expgfx_onMapSetup,
    (ObjectDescriptorCallback)expgfx_addremove,
    (ObjectDescriptorCallback)expgfx_updateFrameState,
    (ObjectDescriptorCallback)expgfx_resetAllPools,
    (ObjectDescriptorCallback)expgfx_free,
    (ObjectDescriptorCallback)expgfx_free2,
    (ObjectDescriptorCallback)expgfx_func09,
    (ObjectDescriptorCallback)expgfx_func0A_nop,
    (ObjectDescriptorCallback)expgfx_func0B_nop,
    (ObjectDescriptorCallback)expgfx_ownerFree3,
    (ObjectDescriptorCallback)expgfx_updateSourceFrameFlags,
};

#define EXPGFX_SLOT_TABLE_INDEX_OFFSET 0x8A
#define gExpgfxTrackedPoolMaskHighWords DAT_8039c7c8
#define gExpgfxTrackedPoolMaskLowWords DAT_8039c7cc
extern ExpgfxTableEntry gExpgfxTableEntries[];

static inline ExpgfxTableEntry *Expgfx_GetTableEntry(int tableIndex) {
  return &gExpgfxTableEntries[tableIndex];
}

static inline u8 Expgfx_GetSlotTableIndex(const ExpgfxSlot *slot) {
  return ((u32)slot->encodedTableIndex >> 1) & EXPGFX_SLOT_TABLE_INDEX_MASK;
}

static inline void Expgfx_SetSlotTableIndex(ExpgfxSlot *slot, u8 tableIndex) {
  slot->encodedTableIndex = (u8)((tableIndex << 1) | (slot->encodedTableIndex & 1));
}

static inline ExpgfxSlot *Expgfx_GetSlot(int poolIndex, int slotIndex) {
  return (ExpgfxSlot *)(gExpgfxSlotPoolBases[poolIndex] + slotIndex * EXPGFX_SLOT_SIZE);
}

static inline ExpgfxBounds *Expgfx_GetBoundsTemplate(int templateIndex) {
  return &((ExpgfxBounds *)&gExpgfxBoundsTemplates)[templateIndex];
}

static inline ExpgfxBounds *Expgfx_GetPoolBounds(int poolIndex) {
  return &((ExpgfxBounds *)&gExpgfxPoolBounds)[poolIndex];
}

static inline f64 Expgfx_U16AsDouble(u16 value) {
  u64 bits;

  bits = CONCAT44(0x43300000, (u32)value);
  return *(f64 *)&bits - lbl_803DF378;
}

static inline ExpgfxCurrentSource Expgfx_GetCurrentSource(void) {
  undefined8 rawSource;
  ExpgfxCurrentSource currentSource;

  rawSource = FUN_80286830();
  currentSource.sourceId = (int)((ulonglong)rawSource >> 0x20);
  currentSource.sourceMode = (int)rawSource;
  return currentSource;
}

/*
 * --INFO--
 *
 * Function: expgfxRemove
 * EN v1.0 Address: 0x8009B0E0
 * EN v1.0 Size: 372b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
asm void expgfxRemove(uint slotPoolBase,int poolIndex,int slotIndex,int freeTexture,int clearActive)
{
  nofralloc
  stwu r1,-0x30(r1)
  mflr r0
  stw r0,0x34(r1)
  addi r11,r1,0x30
  bl _savegpr_25
  mr r25,r4
  mr r26,r7
  lis r4,gExpgfxRuntimeData@ha
  addi r31,r4,gExpgfxRuntimeData@l
  li r4,1
  slw r29,r4,r5
  slwi r0,r25,2
  add r28,r31,r0
  addi r28,r28,0x10c0
  lwz r0,0(r28)
  and r0,r29,r0
  cmplwi r0,0
  beq expgfxRemove_done
  mulli r0,r5,0xa0
  add r27,r3,r0
  li r0,0
  stw r0,0x7c(r27)
  cmpwi r6,0
  bne expgfxRemove_clearSlot
  addi r30,r31,0x988
  lbz r0,0x8a(r27)
  rlwinm r0,r0,31,25,31
  slwi r0,r0,4
  lwzx r0,r30,r0
  cmplwi r0,0
  beq expgfxRemove_updateRef
  stw r4,gExpgfxTextureFreeInProgress
  lbz r0,0x8a(r27)
  rlwinm r0,r0,31,25,31
  slwi r0,r0,4
  lwzx r3,r30,r0
  bl textureFree
  li r0,0
  stw r0,gExpgfxTextureFreeInProgress
expgfxRemove_updateRef:
  lbz r0,0x8a(r27)
  rlwinm r0,r0,31,25,31
  slwi r5,r0,4
  add r4,r31,r5
  addi r4,r4,0x98c
  lhz r3,0(r4)
  cmplwi r3,0
  beq expgfxRemove_mismatch
  addi r0,r3,-1
  sth r0,0(r4)
  lhz r0,0(r4)
  cmplwi r0,0
  bne expgfxRemove_clearSlot
  li r0,0
  stwx r0,r30,r5
  add r3,r31,r5
  stw r0,0x980(r3)
  b expgfxRemove_clearSlot
expgfxRemove_mismatch:
  lis r3,sExpgfxMismatchInAddRemove@ha
  addi r3,r3,sExpgfxMismatchInAddRemove@l
  crclr 4*cr1+eq
  bl debugPrintf
expgfxRemove_clearSlot:
  li r0,-1
  sth r0,0x26(r27)
  clrlwi r0,r26,24
  cmplwi r0,0
  beq expgfxRemove_clearActiveMask
  mr r3,r27
  li r4,0xa0
  bl DCFlushRange
expgfxRemove_clearActiveMask:
  lwz r3,0(r28)
  not r0,r29
  and r0,r3,r0
  stw r0,0(r28)
  add r4,r31,r25
  addi r4,r4,0x1070
  lbz r3,0(r4)
  addi r0,r3,-1
  stb r0,0(r4)
  lbz r0,0(r4)
  extsb r0,r0
  cmpwi r0,0
  bne expgfxRemove_done
  li r4,-1
  slwi r0,r25,1
  lis r3,gExpgfxStaticPoolSlotTypeIds@ha
  addi r3,r3,gExpgfxStaticPoolSlotTypeIds@l
  sthx r4,r3,r0
expgfxRemove_done:
  addi r11,r1,0x30
  bl _restgpr_25
  lwz r0,0x34(r1)
  mtlr r0
  addi r1,r1,0x30
  blr
}

/*
 * --INFO--
 *
 * Function: expgfxRemoveAll
 * EN v1.0 Address: 0x8009B254
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x8009B36C
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
asm void expgfxRemoveAll(void)
{
  nofralloc
  stwu r1,-0x30(r1)
  mflr r0
  stw r0,0x34(r1)
  addi r11,r1,0x30
  bl _savegpr_23
  lis r3,gExpgfxRuntimeData@ha
  addi r31,r3,gExpgfxRuntimeData@l
  li r25,0
  addi r30,r31,0x1200
  addi r29,r31,0x10c0
  addi r28,r31,0x1070
  lis r3,gExpgfxStaticPoolSlotTypeIds@ha
  addi r27,r3,gExpgfxStaticPoolSlotTypeIds@l
expgfxRemoveAll_poolLoop:
  lwz r23,0(r30)
  li r24,0
expgfxRemoveAll_slotLoop:
  li r4,1
  slw r26,r4,r24
  lwz r0,0(r29)
  and r0,r26,r0
  cmplwi r0,0
  beq expgfxRemoveAll_nextSlot
  lbz r0,0x8a(r23)
  rlwinm r0,r0,31,25,31
  slwi r0,r0,4
  add r3,r31,r0
  lwz r0,0x988(r3)
  cmplwi r0,0
  beq expgfxRemoveAll_updateRef
  beq expgfxRemoveAll_updateRef
  stw r4,gExpgfxTextureFreeInProgress
  lbz r0,0x8a(r23)
  rlwinm r0,r0,31,25,31
  slwi r0,r0,4
  add r3,r31,r0
  lwz r3,0x988(r3)
  bl textureFree
  li r0,0
  stw r0,gExpgfxTextureFreeInProgress
expgfxRemoveAll_updateRef:
  lbz r0,0x8a(r23)
  rlwinm r0,r0,31,25,31
  slwi r0,r0,4
  add r5,r31,r0
  addi r5,r5,0x980
  addi r4,r5,0xc
  lhz r3,0(r4)
  cmplwi r3,0
  beq expgfxRemoveAll_mismatch
  subi r0,r3,1
  sth r0,0(r4)
  lhz r0,0(r4)
  cmplwi r0,0
  bne expgfxRemoveAll_clearSlot
  li r0,0
  stw r0,8(r5)
  stw r0,0(r5)
  b expgfxRemoveAll_clearSlot
expgfxRemoveAll_mismatch:
  lis r3,sExpgfxMismatchInAddRemove@ha
  addi r3,r3,sExpgfxMismatchInAddRemove@l
  crclr 4*cr1+eq
  bl debugPrintf
expgfxRemoveAll_clearSlot:
  li r0,-1
  sth r0,0x26(r23)
  lwz r3,0(r29)
  not r0,r26
  and r0,r3,r0
  stw r0,0(r29)
expgfxRemoveAll_nextSlot:
  addi r23,r23,0xa0
  addi r24,r24,1
  cmpwi r24,0x19
  blt expgfxRemoveAll_slotLoop
  li r0,0
  stb r0,0(r28)
  li r0,-1
  sth r0,0(r27)
  lwz r3,0(r30)
  li r4,0xfa0
  bl DCFlushRange
  addi r30,r30,4
  addi r29,r29,4
  addi r28,r28,1
  addi r27,r27,2
  addi r25,r25,1
  cmpwi r25,0x50
  blt expgfxRemoveAll_poolLoop
  addi r11,r1,0x30
  bl _restgpr_23
  lwz r0,0x34(r1)
  mtlr r0
  addi r1,r1,0x30
  blr
}

/*
 * --INFO--
 *
 * Function: expgfxGetSlot
 * EN v1.0 Address: 0x8009B6A4
 * EN v1.0 Size: 752b
 * EN v1.1 Address: 0x8009B648
 * EN v1.1 Size: 792b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
asm int expgfxGetSlot(short *poolIndexOut,short *slotIndexOut,short slotType,
                       int preferredPoolIndex,uint sourceId)
{
  nofralloc
  stwu r1,-0x20(r1)
  stw r31,0x1c(r1)
  stw r30,0x18(r1)
  stw r29,0x14(r1)
  stw r28,0x10(r1)
  lis r8,gExpgfxRuntimeData@ha
  addi r8,r8,gExpgfxRuntimeData@l
  li r0,-1
  li r28,0
  li r10,0
  addi r31,r8,EXPGFX_POOL_SOURCE_IDS_OFFSET
  lis r9,gExpgfxStaticPoolSlotTypeIds@ha
  addi r30,r9,gExpgfxStaticPoolSlotTypeIds@l
  addi r9,r8,EXPGFX_POOL_ACTIVE_COUNTS_OFFSET
  mr r29,r9
  extsh r12,r5
  li r11,EXPGFX_POOL_SEARCH_BATCH_COUNT
  mtctr r11
expgfxGetSlot_findMatchingPool:
  lwz r11,0(r31)
  cmplw r7,r11
  bne expgfxGetSlot_checkMatch1
  lha r11,0(r30)
  cmpw r12,r11
  bne expgfxGetSlot_checkMatch1
  lbz r11,0(r29)
  extsb r11,r11
  cmpwi r11,EXPGFX_SLOTS_PER_POOL
  bge expgfxGetSlot_checkMatch1
  extsh r0,r10
  li r28,1
  b expgfxGetSlot_tryMatchedPool
expgfxGetSlot_checkMatch1:
  addi r30,r30,2
  addi r10,r10,1
  lwz r11,4(r31)
  cmplw r7,r11
  bne expgfxGetSlot_checkMatch2
  lha r11,0(r30)
  cmpw r12,r11
  bne expgfxGetSlot_checkMatch2
  lbz r11,1(r29)
  extsb r11,r11
  cmpwi r11,EXPGFX_SLOTS_PER_POOL
  bge expgfxGetSlot_checkMatch2
  extsh r0,r10
  li r28,1
  b expgfxGetSlot_tryMatchedPool
expgfxGetSlot_checkMatch2:
  addi r30,r30,2
  addi r10,r10,1
  lwz r11,8(r31)
  cmplw r7,r11
  bne expgfxGetSlot_checkMatch3
  lha r11,0(r30)
  cmpw r12,r11
  bne expgfxGetSlot_checkMatch3
  lbz r11,2(r29)
  extsb r11,r11
  cmpwi r11,EXPGFX_SLOTS_PER_POOL
  bge expgfxGetSlot_checkMatch3
  extsh r0,r10
  li r28,1
  b expgfxGetSlot_tryMatchedPool
expgfxGetSlot_checkMatch3:
  addi r30,r30,2
  addi r10,r10,1
  lwz r11,0xc(r31)
  cmplw r7,r11
  bne expgfxGetSlot_checkMatch4
  lha r11,0(r30)
  cmpw r12,r11
  bne expgfxGetSlot_checkMatch4
  lbz r11,3(r29)
  extsb r11,r11
  cmpwi r11,EXPGFX_SLOTS_PER_POOL
  bge expgfxGetSlot_checkMatch4
  extsh r0,r10
  li r28,1
  b expgfxGetSlot_tryMatchedPool
expgfxGetSlot_checkMatch4:
  addi r30,r30,2
  addi r10,r10,1
  lwz r11,0x10(r31)
  cmplw r7,r11
  bne expgfxGetSlot_advanceBatch
  lha r11,0(r30)
  cmpw r12,r11
  bne expgfxGetSlot_advanceBatch
  lbz r11,4(r29)
  extsb r11,r11
  cmpwi r11,EXPGFX_SLOTS_PER_POOL
  bge expgfxGetSlot_advanceBatch
  extsh r0,r10
  li r28,1
  b expgfxGetSlot_tryMatchedPool
expgfxGetSlot_advanceBatch:
  addi r31,r31,0x14
  addi r30,r30,2
  addi r29,r29,EXPGFX_POOL_SEARCH_BATCH_SIZE
  addi r10,r10,1
  bdnz expgfxGetSlot_findMatchingPool
expgfxGetSlot_tryMatchedPool:
  extsh r7,r28
  cmpwi r7,0
  beq expgfxGetSlot_findReplacementPool
  li r28,0
  extsh r31,r0
  slwi r7,r31,2
  add r30,r8,r7
  addi r30,r30,EXPGFX_POOL_ACTIVE_MASKS_OFFSET
  li r12,1
  lwz r11,0(r30)
  li r7,EXPGFX_SLOTS_PER_POOL
  mtctr r7
expgfxGetSlot_scanMatchedSlots:
  slw r29,r12,r28
  and r7,r29,r11
  cmplwi r7,0
  bne expgfxGetSlot_nextMatchedSlot
  extsh r5,r28
  sth r5,0(r4)
  sth r0,0(r3)
  lwz r0,0(r30)
  or r0,r0,r29
  stw r0,0(r30)
  add r4,r8,r31
  lbz r3,EXPGFX_POOL_ACTIVE_COUNTS_OFFSET(r4)
  addi r0,r3,1
  stb r0,EXPGFX_POOL_ACTIVE_COUNTS_OFFSET(r4)
  li r3,1
  b expgfxGetSlot_done
expgfxGetSlot_nextMatchedSlot:
  addi r28,r28,1
  bdnz expgfxGetSlot_scanMatchedSlots
expgfxGetSlot_findReplacementPool:
  li r11,0
  cmpwi r6,-1
  bne expgfxGetSlot_preferredPool
  li r10,0
  li r6,EXPGFX_POOL_COUNT - 1
  mtctr r6
expgfxGetSlot_emptyPoolLoop:
  lbz r6,0(r9)
  extsb r6,r6
  cmpwi r6,0
  bgt expgfxGetSlot_nextEmptyPool
  extsh r0,r10
  li r11,1
  li r7,0
  add r6,r8,r10
  stb r7,EXPGFX_POOL_ACTIVE_COUNTS_OFFSET(r6)
  b expgfxGetSlot_tryReplacementPool
expgfxGetSlot_nextEmptyPool:
  addi r9,r9,1
  addi r10,r10,1
  bdnz expgfxGetSlot_emptyPoolLoop
  b expgfxGetSlot_tryReplacementPool
expgfxGetSlot_preferredPool:
  beq expgfxGetSlot_tryReplacementPool
  mr r10,r6
  add r7,r8,r6
  lbz r7,EXPGFX_POOL_ACTIVE_COUNTS_OFFSET(r7)
  extsb r7,r7
  cmpwi r7,EXPGFX_SLOTS_PER_POOL
  bge expgfxGetSlot_tryReplacementPool
  extsh r0,r6
  li r11,1
expgfxGetSlot_tryReplacementPool:
  extsh r6,r11
  cmpwi r6,0
  beq expgfxGetSlot_fail
  li r30,0
  extsh r29,r0
  slwi r6,r29,2
  add r12,r8,r6
  addi r12,r12,EXPGFX_POOL_ACTIVE_MASKS_OFFSET
  li r9,1
  lwz r7,0(r12)
  li r6,EXPGFX_SLOTS_PER_POOL
  mtctr r6
expgfxGetSlot_scanReplacementSlots:
  slw r11,r9,r30
  and r6,r11,r7
  cmplwi r6,0
  bne expgfxGetSlot_nextReplacementSlot
  extsh r6,r30
  sth r6,0(r4)
  sth r0,0(r3)
  lwz r0,0(r12)
  or r0,r0,r11
  stw r0,0(r12)
  slwi r0,r10,1
  lis r3,gExpgfxStaticPoolSlotTypeIds@ha
  addi r3,r3,gExpgfxStaticPoolSlotTypeIds@l
  sthx r5,r3,r0
  add r4,r8,r29
  lbz r3,EXPGFX_POOL_ACTIVE_COUNTS_OFFSET(r4)
  addi r0,r3,1
  stb r0,EXPGFX_POOL_ACTIVE_COUNTS_OFFSET(r4)
  li r3,1
  b expgfxGetSlot_done
expgfxGetSlot_nextReplacementSlot:
  addi r30,r30,1
  bdnz expgfxGetSlot_scanReplacementSlots
  li r3,-1
  b expgfxGetSlot_done
expgfxGetSlot_fail:
  li r3,-1
expgfxGetSlot_done:
  lwz r31,0x1c(r1)
  lwz r30,0x18(r1)
  lwz r29,0x14(r1)
  lwz r28,0x10(r1)
  addi r1,r1,0x20
  blr
}

/*
 * --INFO--
 *
 * Function: expgfx_initSlotQuad
 * EN v1.0 Address: 0x8009B6D4
 * EN v1.0 Size: 756b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: 756b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
asm void expgfx_initSlotQuad(void *slotPtr)
{
  nofralloc
  stwu r1,-0x20(r1)
  mflr r0
  stw r0,0x24(r1)
  lis r4,gExpgfxStaticData@ha
  addi r4,r4,gExpgfxStaticData@l
  lis r5,gExpgfxTableEntries@ha
  addi r5,r5,gExpgfxTableEntries@l
  lbz r0,0x8a(r3)
  extrwi r0,r0,7,24
  slwi r0,r0,EXPGFX_TABLE_ENTRY_SHIFT
  add r5,r5,r0
  lwz r7,8(r5)
  li r5,0
  lbz r0,0x8b(r3)
  rlwimi r0,r5,0,31,31
  stb r0,0x8b(r3)
  li r5,1
  lbz r0,0x8b(r3)
  rlwimi r0,r5,1,30,30
  stb r0,0x8b(r3)
  lwz r6,0x7c(r3)
  rlwinm r0,r6,0,4,4
  cmplwi r0,0
  beq expgfx_initSlotQuad_useTemplateB
  addi r5,r4,EXPGFX_STATIC_QUAD_TEMPLATE_A_OFFSET
  b expgfx_initSlotQuad_checkLowBounce
expgfx_initSlotQuad_useTemplateB:
  addi r5,r4,EXPGFX_STATIC_QUAD_TEMPLATE_B_OFFSET
expgfx_initSlotQuad_checkLowBounce:
  rlwinm r0,r6,0,1,1
  cmplwi r0,0
  beq expgfx_initSlotQuad_checkHighFast
  lfs f2,0x74(r3)
  lfs f0,lbl_803DF3B4
  fcmpo cr0,f2,f0
  bge expgfx_initSlotQuad_checkHighFast
  rlwinm r0,r6,0,7,7
  cmplwi r0,0
  beq expgfx_initSlotQuad_lowSlow
  fcmpo cr0,f2,f0
  bge expgfx_initSlotQuad_lowSlow
  lfs f1,lbl_803DF3B8
  lfs f0,timeDelta
  fnmsubs f0,f1,f0,f2
  stfs f0,0x74(r3)
  b expgfx_initSlotQuad_integratePosition
expgfx_initSlotQuad_lowSlow:
  lfs f2,lbl_803DF3BC
  lfs f1,timeDelta
  lfs f0,0x74(r3)
  fnmsubs f0,f2,f1,f0
  stfs f0,0x74(r3)
  b expgfx_initSlotQuad_integratePosition
expgfx_initSlotQuad_checkHighFast:
  rlwinm r0,r6,0,7,7
  cmplwi r0,0
  beq expgfx_initSlotQuad_checkHighSlow
  lfs f2,0x74(r3)
  lfs f0,lbl_803DF3C0
  fcmpo cr0,f2,f0
  ble expgfx_initSlotQuad_checkHighSlow
  lfs f1,lbl_803DF3B8
  lfs f0,timeDelta
  fmadds f0,f1,f0,f2
  stfs f0,0x74(r3)
  b expgfx_initSlotQuad_integratePosition
expgfx_initSlotQuad_checkHighSlow:
  rlwinm r0,r6,0,28,28
  cmplwi r0,0
  beq expgfx_initSlotQuad_integratePosition
  lfs f2,0x74(r3)
  lfs f0,lbl_803DF3C0
  fcmpo cr0,f2,f0
  ble expgfx_initSlotQuad_integratePosition
  lfs f1,lbl_803DF3BC
  lfs f0,timeDelta
  fmadds f0,f1,f0,f2
  stfs f0,0x74(r3)
expgfx_initSlotQuad_integratePosition:
  lfs f1,0x70(r3)
  lfs f3,lbl_803DF3C4
  lfs f0,0x58(r3)
  fmadds f0,f1,f3,f0
  stfs f0,0x58(r3)
  lfs f1,0x74(r3)
  lfs f0,0x5c(r3)
  fmadds f0,f1,f3,f0
  stfs f0,0x5c(r3)
  lfs f1,0x78(r3)
  lfs f0,0x60(r3)
  fmadds f0,f1,f3,f0
  stfs f0,0x60(r3)
  lwz r0,0x7c(r3)
  rlwinm r0,r0,0,11,11
  cmplwi r0,0
  beq expgfx_initSlotQuad_checkScaleDown
  lhz r0,0x88(r3)
  lfd f2,lbl_803DF378
  stw r0,0xc(r1)
  lis r6,0x4330
  stw r6,8(r1)
  lfd f0,8(r1)
  fsubs f1,f0,f2
  lhz r0,0x84(r3)
  stw r0,0x14(r1)
  stw r6,0x10(r1)
  lfd f0,0x10(r1)
  fsubs f0,f0,f2
  fmadds f0,f1,f3,f0
  fctiwz f0,f0
  stfd f0,0x18(r1)
  lwz r0,0x1c(r1)
  sth r0,0x84(r3)
  b expgfx_initSlotQuad_writeQuad
expgfx_initSlotQuad_checkScaleDown:
  lwz r0,0x80(r3)
  rlwinm r0,r0,0,18,18
  cmplwi r0,0
  beq expgfx_initSlotQuad_writeQuad
  lhz r0,0x88(r3)
  lfd f2,lbl_803DF378
  stw r0,0x1c(r1)
  lis r6,0x4330
  stw r6,0x18(r1)
  lfd f0,0x18(r1)
  fsubs f1,f0,f2
  lhz r0,0x84(r3)
  stw r0,0x14(r1)
  stw r6,0x10(r1)
  lfd f0,0x10(r1)
  fsubs f0,f0,f2
  fnmsubs f0,f1,f3,f0
  fctiwz f0,f0
  stfd f0,8(r1)
  lwz r0,0xc(r1)
  sth r0,0x84(r3)
expgfx_initSlotQuad_writeQuad:
  cmplwi r7,0
  bne expgfx_initSlotQuad_hasTexture
  addi r3,r4,0x384
  crclr 4*cr1+eq
  bl debugPrintf
  b expgfx_initSlotQuad_done
expgfx_initSlotQuad_hasTexture:
  li r7,0
  li r6,0
  li r9,0
  li r8,0
  beq expgfx_initSlotQuad_storeQuad
  li r9,EXPGFX_QUAD_TEXCOORD_MAX
  li r7,EXPGFX_QUAD_TEXCOORD_MAX
  lwz r4,0x7c(r3)
  rlwinm r0,r4,0,24,24
  cmplwi r0,0
  beq expgfx_initSlotQuad_checkFlipTex0
  li r8,EXPGFX_QUAD_TEXCOORD_MAX
  li r9,0
expgfx_initSlotQuad_checkFlipTex0:
  rlwinm r0,r4,0,25,25
  cmplwi r0,0
  beq expgfx_initSlotQuad_storeQuad
  li r6,EXPGFX_QUAD_TEXCOORD_MAX
  li r7,0
expgfx_initSlotQuad_storeQuad:
  lha r0,0(r5)
  sth r0,0(r3)
  lha r0,2(r5)
  sth r0,2(r3)
  lha r0,4(r5)
  sth r0,4(r3)
  sth r9,8(r3)
  sth r7,0xa(r3)
  lha r0,6(r5)
  sth r0,0x10(r3)
  lha r0,8(r5)
  sth r0,0x12(r3)
  lha r0,0xa(r5)
  sth r0,0x14(r3)
  sth r8,0x18(r3)
  sth r7,0x1a(r3)
  lha r0,0xc(r5)
  sth r0,0x20(r3)
  lha r0,0xe(r5)
  sth r0,0x22(r3)
  lha r0,0x10(r5)
  sth r0,0x24(r3)
  sth r8,0x28(r3)
  sth r6,0x2a(r3)
  lha r0,0x12(r5)
  sth r0,0x30(r3)
  lha r0,0x14(r5)
  sth r0,0x32(r3)
  lha r0,0x16(r5)
  sth r0,0x34(r3)
  sth r9,0x38(r3)
  sth r6,0x3a(r3)
expgfx_initSlotQuad_done:
  lwz r0,0x24(r1)
  mtlr r0
  addi r1,r1,0x20
  blr
}

/*
 * --INFO--
 *
 * Function: FUN_8009bd84
 * EN v1.0 Address: 0x8009BD84
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009BC54
 * EN v1.1 Size: 9252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009bd84(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: expgfx_addToTable
 * EN v1.0 Address: 0x8009DDEC
 * EN v1.0 Size: 288b
 * EN v1.1 Address: 0x8009E078
 * EN v1.1 Size: 536b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
asm int expgfx_addToTable(uint textureOrResource,uint key0,uint key1,s16 slotType)
{
  nofralloc
  stwu r1,-0x10(r1)
  mflr r0
  stw r0,0x14(r1)
  li r9,0
  lis r7,gExpgfxTableEntries@ha
  addi r8,r7,gExpgfxTableEntries@l
  mr r7,r8
  li r0,0x50
  mtctr r0
addToTable_findExisting:
  lhz r0,0xc(r7)
  cmplwi r0,0
  beq addToTable_nextExisting
  lwz r0,8(r7)
  cmplw r0,r3
  bne addToTable_nextExisting
  lwz r0,0(r7)
  cmplw r0,r4
  bne addToTable_nextExisting
  lwz r0,4(r7)
  cmplw r0,r5
  bne addToTable_nextExisting
  lis r3,gExpgfxTableEntries@ha
  addi r3,r3,gExpgfxTableEntries@l
  slwi r0,r9,4
  add r4,r3,r0
  addi r4,r4,0xc
  lhz r3,0(r4)
  cmplwi r3,0xffff
  blt addToTable_incrementRef
  lis r3,sExpgfxAddToTableUsageOverflow@ha
  addi r3,r3,sExpgfxAddToTableUsageOverflow@l
  crclr 4*cr1+eq
  bl debugPrintf
  li r3,-1
  b addToTable_done
addToTable_incrementRef:
  addi r0,r3,1
  sth r0,0(r4)
  extsh r3,r9
  b addToTable_done
addToTable_nextExisting:
  addi r7,r7,0x10
  addi r9,r9,1
  bdnz addToTable_findExisting
  li r10,0
  li r0,0x50
  mtctr r0
addToTable_findFree:
  lhz r0,0xc(r8)
  cmplwi r0,0
  bne addToTable_nextFree
  li r0,1
  lis r7,gExpgfxTableEntries@ha
  addi r8,r7,gExpgfxTableEntries@l
  slwi r9,r10,4
  add r7,r8,r9
  sth r0,0xc(r7)
  stw r3,8(r7)
  stwx r4,r8,r9
  stw r5,4(r7)
  sth r6,0xe(r7)
  extsh r3,r10
  b addToTable_done
addToTable_nextFree:
  addi r8,r8,0x10
  addi r10,r10,1
  bdnz addToTable_findFree
  lis r3,sExpgfxExpTabIsFull@ha
  addi r3,r3,sExpgfxExpTabIsFull@l
  crclr 4*cr1+eq
  bl debugPrintf
  li r3,-1
addToTable_done:
  lwz r0,0x14(r1)
  mtlr r0
  addi r1,r1,0x10
  blr
}

/*
 * --INFO--
 *
 * Function: expgfx_updateSourceFrameFlags
 * EN v1.0 Address: 0x8009DF0C
 * EN v1.0 Size: 248b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
asm int expgfx_updateSourceFrameFlags(void *sourceObject)
{
  nofralloc
  li r0, 0x0
  li r4, 0x0
  stb r4, lbl_803DD253
  li r5, 0x0
  lis r4, gExpgfxTrackedPoolSourceIds@ha
  addi r4, r4, gExpgfxTrackedPoolSourceIds@l
  lis r6, gExpgfxStaticPoolFrameFlags@ha
  addi r11, r6, gExpgfxStaticPoolFrameFlags@l
  b expgfx_updateSourceFrameFlags_L_8009DFF0
expgfx_updateSourceFrameFlags_L_8009DF30:
  lha r6, 0x46(r3)
  cmpwi r6, 0xd4
  beq expgfx_updateSourceFrameFlags_L_8009DF48
  lwz r6, 0x0(r4)
  cmplw r6, r3
  bne expgfx_updateSourceFrameFlags_L_8009DFDC
expgfx_updateSourceFrameFlags_L_8009DF48:
  extsh r7, r5
  li r10, 0x1
  srawi r6, r7, 1
  slw r9, r10, r6
  srawi r8, r9, 31
  clrlwi r6, r7, 31
  slwi r7, r6, 3
  lis r6, gExpgfxTrackedSourceFrameMasks@ha
  addi r6, r6, gExpgfxTrackedSourceFrameMasks@l
  add r7, r6, r7
  lwz r6, 0x0(r7)
  lwz r7, 0x4(r7)
  and r7, r9, r7
  and r8, r8, r6
  li r6, 0x0
  xor r7, r7, r6
  xor r6, r8, r6
  or r6, r7, r6
  cmpwi r6, 0x0
  beq expgfx_updateSourceFrameFlags_L_8009DFBC
  li r6, 0x2
  stb r6, 0x0(r11)
  extsb r0, r0
  cmpwi r0, 0x1
  bne expgfx_updateSourceFrameFlags_L_8009DFB4
  li r0, 0x3
  b expgfx_updateSourceFrameFlags_L_8009DFE4
expgfx_updateSourceFrameFlags_L_8009DFB4:
  li r0, 0x2
  b expgfx_updateSourceFrameFlags_L_8009DFE4
expgfx_updateSourceFrameFlags_L_8009DFBC:
  stb r10, 0x0(r11)
  extsb r0, r0
  cmpwi r0, 0x2
  bne expgfx_updateSourceFrameFlags_L_8009DFD4
  li r0, 0x3
  b expgfx_updateSourceFrameFlags_L_8009DFE4
expgfx_updateSourceFrameFlags_L_8009DFD4:
  li r0, 0x1
  b expgfx_updateSourceFrameFlags_L_8009DFE4
expgfx_updateSourceFrameFlags_L_8009DFDC:
  li r6, 0x0
  stb r6, 0x0(r11)
expgfx_updateSourceFrameFlags_L_8009DFE4:
  addi r4, r4, 0x4
  addi r11, r11, 0x1
  addi r5, r5, 0x1
expgfx_updateSourceFrameFlags_L_8009DFF0:
  extsh r6, r5
  cmpwi r6, 0x50
  blt expgfx_updateSourceFrameFlags_L_8009DF30
  mr r3, r0
  blr
}

/*
 * --INFO--
 *
 * Function: expgfx_ownerFree3
 * EN v1.0 Address: 0x8009E004
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8009E290
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void expgfx_ownerFree3(u32 sourceId)
{
  expgfx_free(sourceId);
  return;
}

/*
 * --INFO--
 *
 * Function: expgfx_func0B_nop
 * EN v1.0 Address: 0x8009E024
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void expgfx_func0B_nop(void)
{
}

/*
 * --INFO--
 *
 * Function: expgfx_func0A_nop
 * EN v1.0 Address: 0x8009E028
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void expgfx_func0A_nop(void)
{
}

/*
 * --INFO--
 *
 * Function: expgfx_func09
 * EN v1.0 Address: 0x8009E02C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int expgfx_func09(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: expgfx_renderSourcePools
 * EN v1.0 Address: 0x8009E034
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x8009E2C0
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
asm void expgfx_renderSourcePools(int sourceId,int sourceMode)
{
  nofralloc
  stwu r1,-0x30(r1)
  mflr r0
  stw r0,0x34(r1)
  addi r11,r1,0x30
  bl _savegpr_23
  mr r23,r3
  mr r24,r4
  lis r3,gExpgfxRuntimeData@ha
  addi r3,r3,gExpgfxRuntimeData@l
  li r25,0
  addi r31,r3,0x1070
  addi r30,r3,0xed0
  addi r29,r3,0xe80
  addi r28,r3,0x1020
  addi r27,r3,0x200
  addi r26,r3,0x1200
expgfx_renderSourcePools_loop:
  lbz r0,0(r31)
  extsb r0,r0
  cmpwi r0,0
  beq expgfx_renderSourcePools_next
  lwz r0,0(r30)
  cmplw r0,r23
  bne expgfx_renderSourcePools_next
  lbz r3,0(r29)
  addi r0,r24,1
  cmpw r3,r0
  bne expgfx_renderSourcePools_next
  lfs f6,playerMapOffsetZ
  lfs f2,playerMapOffsetX
  lfs f0,0(r27)
  fsubs f1,f0,f2
  lfs f0,4(r27)
  fsubs f2,f0,f2
  lfs f3,8(r27)
  lfs f4,0xc(r27)
  lfs f0,0x10(r27)
  fsubs f5,f0,f6
  lfs f0,0x14(r27)
  fsubs f6,f0,f6
  lbz r0,0(r28)
  mulli r4,r0,0x18
  lis r3,gExpgfxStaticData@ha
  addi r0,r3,gExpgfxStaticData@l
  add r3,r0,r4
  bl fn_8005E97C
  clrlwi r0,r3,24
  cmplwi r0,0
  beq expgfx_renderSourcePools_next
  lwz r3,0(r26)
  mr r4,r25
  bl drawGlow
expgfx_renderSourcePools_next:
  addi r31,r31,1
  addi r30,r30,4
  addi r29,r29,1
  addi r28,r28,1
  addi r27,r27,0x18
  addi r26,r26,4
  addi r25,r25,1
  cmpwi r25,0x50
  blt expgfx_renderSourcePools_loop
  addi r11,r1,0x30
  bl _restgpr_23
  lwz r0,0x34(r1)
  mtlr r0
  addi r1,r1,0x30
  blr
}

/*
 * --INFO--
 *
 * Function: drawGlow
 * EN v1.0 Address: 0x8009E13C
 * EN v1.0 Size: 2984b
 * EN v1.1 Address: 0x8009E3C8
 * EN v1.1 Size: 2984b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void *getCache(void);
extern int getHudHiddenFrameCount(void);
extern void copyToCache(void *dst, void *src, int blockCount);
extern void cacheFn_800229c4(int wait);
extern int Camera_GetProjectionMatrix(void);
extern void Camera_ApplyFullViewport(void);
extern void *Camera_GetCurrentViewSlot(void);
extern void _textSetColor(int reg, u8 r, u8 g, u8 b, u8 a);
extern void fn_8000F83C(void);
extern void fn_8009AD44(int param);
extern u32 randomGetRange(int min, int max);
extern s16 getAngle(f32 deltaX, f32 deltaZ);
extern void angleToVec2(int angle, f32 *cosOut, f32 *sinOut);
extern void selectTexture(int handle, int slot);
extern void textureSetupFn_800799c0(void);
extern void textRenderSetupFn_80079804(void);
extern void fn_80079180(void);
extern void geomDrawFn_800796f0(void);
extern void fn_8007C3D0(u32 flag);
extern void fn_8007D670(void);
extern void _gxSetFogParams(void);
extern void gxSetZMode_(u32 a, int b, u32 c);
extern void gxSetPeControl_ZCompLoc_(u32 a);

extern u32 gExpgfxSlotActiveMasks[];
extern f32 lbl_803967C0[3][4];
extern f32 lbl_803DF410;
extern f32 lbl_803DF414;
extern f32 lbl_803DB790;
extern u16 gExpgfxPhaseAngleA;
extern u16 gExpgfxPhaseAngleB;

#pragma scheduling off
#pragma peephole off
void drawGlow(uint slotPoolBase,int poolIndex)
{
  void *dstBuf;
  int trackedFlags;
  int zCompLoc;
  int zMode;
  int blendMode;
  int alphaMode;
  void *viewMatrix;
  void *cameraSlot;
  ExpgfxSlot *slot;
  ExpgfxTableEntry *tabEntry;
  ExpgfxSourceObject *sourceObject;
  uint texture;
  int slotIndex;
  uint behaviorFlags;
  uint renderFlags;
  uint state;
  int alpha;
  s16 lifetimeFrame;
  s16 lifetimeFrameLimit;
  f32 lifeFraction;
  f32 scaleSize;
  f32 scaleFactor;
  s16 angleA;
  s16 angleB;
  f32 cosA, sinA;
  f32 cosB, sinB;
  f32 cosC, sinC;
  f32 worldX, worldY, worldZ;
  f32 aimDelta[3];
  s16 *vtxStream;
  int vertexIndex;
  f32 sx, sy, sz;
  f32 viewProjW;
  volatile int dummy;

  dstBuf = getCache();
  trackedFlags = 0;
  dummy = getHudHiddenFrameCount();
  Camera_GetProjectionMatrix();
  copyToCache(dstBuf, (void *)slotPoolBase, 0x7e);

  GXClearVtxDesc();
  GXSetVtxDesc(9, 1);
  GXSetVtxDesc(0xb, 1);
  GXSetVtxDesc(0xd, 1);
  GXSetCurrentMtx(0);
  GXSetChanCtrl(0, 0, 0, 1, 0, 0, 2);
  GXSetChanCtrl(2, 0, 0, 1, 0, 0, 2);
  GXSetNumChans(1);
  GXSetCullMode(0);
  viewMatrix = (void *)Camera_GetViewMatrix();
  GXLoadPosMtxImm((void *)viewMatrix, 0);
  PSMTXCopy((void *)viewMatrix, lbl_803967C0);
  fn_8007D670();
  _gxSetFogParams();
  if ((short)renderModeSetOrGet(-1) == 1) {
    return;
  }
  cameraSlot = Camera_GetCurrentViewSlot();
  _textSetColor(0, 0xff, 0xff, 0xff, 0xff);
  alphaMode = -1;
  blendMode = -1;
  zMode = -1;
  zCompLoc = -1;
  cacheFn_800229c4(0);

  slot = (ExpgfxSlot *)((char *)dstBuf - EXPGFX_SLOT_SIZE);
  slotIndex = 0;
  dstBuf = gExpgfxTableEntries;
  do {
    slot = (ExpgfxSlot *)((char *)slot + EXPGFX_SLOT_SIZE);
    tabEntry = &((ExpgfxTableEntry *)dstBuf)[((u32)slot->encodedTableIndex >> 1) &
                                             EXPGFX_SLOT_TABLE_INDEX_MASK];
    sourceObject = (ExpgfxSourceObject *)tabEntry->key0;
    texture = tabEntry->textureOrResource;
    if ((1U << slotIndex & gExpgfxSlotActiveMasks[poolIndex]) == 0) goto next_slot;
    state = slot->stateBits.value;
    if (((state >> 2) & 3) != 0) goto next_slot;
    if (((state >> 1) & 1) == 0) goto next_slot;
    if (slot->sequenceId == EXPGFX_INVALID_SEQUENCE_ID) goto next_slot;
    if ((state & 1) != 0) goto next_slot;

    lifetimeFrame = slot->lifetimeFrame;
    lifetimeFrameLimit = slot->lifetimeFrameLimit;
    lifeFraction = lbl_803DF358 * (f32)(s32)lifetimeFrameLimit;
    behaviorFlags = slot->behaviorFlags;
    if ((behaviorFlags & EXPGFX_BEHAVIOR_ALPHA_FADE_TO_OPAQUE) != 0) {
      f32 ratio = (f32)(s32)lifetimeFrame / (f32)(s32)lifetimeFrameLimit;
      if (ratio < lbl_803DF35C) {
        ratio = lbl_803DF35C;
      } else if (ratio > lbl_803DF354) {
        ratio = lbl_803DF354;
      }
      alpha = (int)((f32)((s32)slot->initialStateByte - 0xff) * ratio + (f32)(u32)slot->initialStateByte);
    } else if ((behaviorFlags & EXPGFX_BEHAVIOR_ALPHA_FADE_OUT) != 0) {
      f32 ratio = (f32)(s32)lifetimeFrame / (f32)(s32)lifetimeFrameLimit;
      if (ratio < lbl_803DF35C) {
        ratio = lbl_803DF35C;
      } else if (ratio > lbl_803DF354) {
        ratio = lbl_803DF354;
      }
      alpha = (int)((f32)(u32)slot->initialStateByte * ratio);
    } else if ((slot->renderFlags & EXPGFX_RENDER_ALPHA_FADE_IN) != 0 &&
               (f32)(s32)lifetimeFrame <= lifeFraction) {
      f32 ratio = (f32)(s32)lifetimeFrame / lifeFraction;
      if (ratio < lbl_803DF35C) {
        ratio = lbl_803DF35C;
      } else if (ratio > lbl_803DF354) {
        ratio = lbl_803DF354;
      }
      alpha = (int)((f32)(u32)slot->initialStateByte * ratio);
    } else if ((behaviorFlags & EXPGFX_BEHAVIOR_ALPHA_PULSE) != 0) {
      f32 ratio;
      if ((f32)(s32)lifetimeFrame <= lifeFraction) {
        ratio = (f32)(s32)lifetimeFrame / lifeFraction;
      } else {
        ratio = (lifeFraction - ((f32)(s32)lifetimeFrame - lifeFraction)) / lifeFraction;
      }
      if (ratio < lbl_803DF35C) {
        ratio = lbl_803DF35C;
      } else if (ratio > lbl_803DF354) {
        ratio = lbl_803DF354;
      }
      alpha = (int)((f32)(u32)slot->initialStateByte * ratio);
    } else {
      alpha = slot->initialStateByte;
    }

    angleA = 0;
    angleB = 0;
    sx = slot->renderX;
    sy = slot->renderY;
    sz = slot->renderZ;
    scaleSize = lbl_803DF410 * (f32)(u32)(u16)slot->scaleCounter;
    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_RANDOMIZE_SCALE) != 0 && dummy == 0) {
      f32 base = lbl_803DF358 * scaleSize;
      f32 rnd = (f32)(s32)randomGetRange(1, 10);
      scaleFactor = base + base / rnd;
    } else {
      scaleFactor = scaleSize;
    }

    {
      uint behavior = slot->behaviorFlags;
      if ((behavior & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_B) != 0) {
        angleA = 0;
        angleB = 0;
      } else if ((behavior & EXPGFX_BEHAVIOR_BILLBOARD_LOCK_A) != 0) {
        angleA = 0;
        angleB = 0;
      } else if ((behavior & 0x00100000) != 0) {
        if ((slot->renderFlags & EXPGFX_RENDER_AIM_AT_SOURCE_OBJECT) != 0 && sourceObject != NULL) {
          aimDelta[0] = *(f32 *)((char *)cameraSlot + 0xc) - sourceObject->posX;
          aimDelta[1] = *(f32 *)((char *)cameraSlot + 0x10) - sourceObject->posY;
          aimDelta[2] = *(f32 *)((char *)cameraSlot + 0x14) - sourceObject->posZ;
          PSVECNormalize((Vec *)aimDelta, (Vec *)aimDelta);
          {
            f32 absX = (f32)__fabs(aimDelta[0]);
            f32 absZ = (f32)__fabs(aimDelta[2]);
            if (absX > absZ) {
              getAngle(absX, aimDelta[1]);
              angleB = (s16)(getAngle(absX, aimDelta[1]) - 0x3800);
            } else {
              getAngle(absZ, aimDelta[1]);
              angleB = (s16)(getAngle(absZ, aimDelta[1]) - 0x3800);
            }
            angleA = getAngle(aimDelta[0], aimDelta[2]);
          }
        } else {
          angleA = (s16)(0x10000 - *(s16 *)cameraSlot);
          angleB = *(s16 *)((char *)cameraSlot + 2);
        }
      } else {
        angleA = (s16)(0x10000 - *(s16 *)cameraSlot);
      }
    }

    angleToVec2((u16)angleA, &cosA, &sinA);
    angleToVec2((u16)angleB, &cosB, &sinB);
    if ((slot->renderFlags & EXPGFX_RENDER_PHASE_ROTATE_A) != 0) {
      angleToVec2((u16)(gExpgfxPhaseAngleA + (((u32)slot & 0xff) << 8)), &sinC, &cosC);
    } else if ((slot->renderFlags & EXPGFX_RENDER_PHASE_ROTATE_B) != 0) {
      angleToVec2((u16)(gExpgfxPhaseAngleB + (((u32)slot & 0xff) << 8)), &sinC, &cosC);
    }
    if (sourceObject != NULL && (slot->renderFlags & EXPGFX_RENDER_MODULATE_ALPHA_SOURCE) != 0) {
      alpha = (alpha * sourceObject->alpha) >> 8;
    }

    if (slotPoolBase != texture) {
      selectTexture(texture, 0);
      slotPoolBase = texture;
    }

    {
      uint flags = slot->renderFlags;
      if ((flags & EXPGFX_RENDER_ALPHA_TEXTURE_SETUP) != 0) {
        if ((s8)alphaMode != 0) {
          textureSetupFn_800799c0();
          fn_80079180();
          textRenderSetupFn_80079804();
          alphaMode = 0;
        }
      } else if ((flags & EXPGFX_RENDER_ALT_ALPHA_SETUP) != 0) {
        if (!((s8)alphaMode == 4 && trackedFlags == (int)(flags & EXPGFX_RENDER_OVERRIDE_COLORS))) {
          fn_8007C3D0(flags & EXPGFX_RENDER_OVERRIDE_COLORS);
          alphaMode = 4;
          trackedFlags = (int)(slot->renderFlags & EXPGFX_RENDER_OVERRIDE_COLORS);
        }
      } else if ((s8)alphaMode != 1) {
        textureSetupFn_800799c0();
        geomDrawFn_800796f0();
        textRenderSetupFn_80079804();
        alphaMode = 1;
      }
    }
    if ((slot->renderFlags & EXPGFX_RENDER_DEPTH_BLEND_MODE) != 0) {
      if ((s8)blendMode != 0) {
        Camera_ApplyFullViewport();
        gxSetZMode_(1, 3, 1);
        GXSetBlendMode(0, 1, 0, 5);
        gxSetPeControl_ZCompLoc_(0);
        GXSetAlphaCompare(4, 0xfe, 0, 4, 0xfe);
        blendMode = 0;
        zMode = 0;
        zCompLoc = 0;
      }
    } else {
      if ((s8)zCompLoc != 1) {
        gxSetPeControl_ZCompLoc_(1);
        GXSetAlphaCompare(7, 0, 0, 7, 0);
        zCompLoc = 1;
      }
      if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_DEPTH_MODE_OVERRIDE) != 0) {
        if ((s8)zMode != 1) {
          fn_8000F83C();
          gxSetZMode_(1, 3, 0);
          zMode = 1;
        }
      } else if ((s8)zMode != 2) {
        Camera_ApplyFullViewport();
        gxSetZMode_(1, 3, 0);
        zMode = 2;
      }
      if ((slot->renderFlags & EXPGFX_RENDER_BLEND_ADDITIVE) != 0) {
        if ((s8)blendMode != 1) {
          GXSetBlendMode(1, 4, 1, 5);
          blendMode = 1;
        }
      } else if ((s8)blendMode != 2) {
        GXSetBlendMode(1, 4, 5, 5);
        blendMode = 2;
      }
    }

    sx -= playerMapOffsetX;
    sz -= playerMapOffsetZ;
    vtxStream = (s16 *)slot;
    GXBegin(0x80, 4, 4);
    for (vertexIndex = 0; vertexIndex < 4; vertexIndex++) {
      f32 px = scaleFactor * (f32)vtxStream[0];
      f32 py = scaleFactor * (f32)vtxStream[1];
      f32 pz = scaleFactor * (f32)vtxStream[2];
      f32 outX, outY, outZ;
      f32 ax, ay;
      f32 ay_cosB, pz_sinB;
      if ((slot->renderFlags & (EXPGFX_RENDER_PHASE_ROTATE_A | EXPGFX_RENDER_PHASE_ROTATE_B)) != 0) {
        f32 nx = px * cosC - py * sinC;
        f32 ny = px * sinC + py * cosC;
        ay_cosB = ny * cosB;
        pz_sinB = pz * sinB;
        outX = sx + cosA * ay_cosB + nx * sinA + cosA * pz_sinB;
        outY = sy + ny * sinB + (-pz) * cosB;
        outZ = sz + sinA * ay_cosB + (-nx) * cosA + sinA * pz_sinB;
      } else {
        ay_cosB = py * cosB;
        pz_sinB = pz * sinB;
        outX = sx + cosA * ay_cosB + px * sinA + cosA * pz_sinB;
        outY = sy + py * sinB + (-pz) * cosB;
        outZ = sz + sinA * ay_cosB + (-px) * cosA + sinA * pz_sinB;
      }
      viewProjW = ((f32 *)viewMatrix)[8] * outX
                + ((f32 *)viewMatrix)[9] * outY
                + ((f32 *)viewMatrix)[10] * outZ
                + ((f32 *)viewMatrix)[11];
      if (viewProjW > lbl_803DB790) {
        alpha = (int)((double)(s32)alpha * (double)((-viewProjW) - lbl_803DF414) /
                      (double)((-lbl_803DB790) - lbl_803DF414));
      }
      *(volatile f32 *)0xCC008000 = outX;
      *(volatile f32 *)0xCC008000 = outY;
      *(volatile f32 *)0xCC008000 = outZ;
      *(volatile u8 *)0xCC008000 = slot->colorByte0;
      *(volatile u8 *)0xCC008000 = slot->colorByte1;
      *(volatile u8 *)0xCC008000 = slot->colorByte2;
      *(volatile u8 *)0xCC008000 = (u8)alpha;
      *(volatile s16 *)0xCC008000 = vtxStream[4];
      *(volatile s16 *)0xCC008000 = vtxStream[5];
      vtxStream += 8;
    }

  next_slot:
    slotIndex++;
  } while (slotIndex < EXPGFX_SLOTS_PER_POOL);

  if (lbl_803DD254 != 0) {
    fn_8009AD44(0);
    lbl_803DD254 = 0;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: renderParticles
 * EN v1.0 Address: 0x8009ECE4
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x8009EF70
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void renderParticles(void)
{
  ExpgfxBounds *boundsTemplate;
  ExpgfxPoolSourcePosition *sourcePosition;
  register u8 *expgfxBase = gExpgfxRuntimeData;
  char *poolActiveCounts;
  u8 *poolSourceModes;
  u8 *poolBoundsTemplateIds;
  ExpgfxBounds *poolBounds;
  u32 *poolSourceIds;
  register s16 *poolSlotTypeIds;
  register s16 *poolSlotTypeIdBase;
  uint *slotPoolBases;
  int poolIndex;
  int currentMatrix;
  float queuePosition[3];

  asm {
    mr expgfxBase, expgfxBase
  }
  currentMatrix = Camera_GetViewMatrix();
  poolIndex = 0;
  poolActiveCounts = (char *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
  poolSourceModes = expgfxBase + EXPGFX_POOL_SOURCE_MODES_OFFSET;
  poolBoundsTemplateIds = expgfxBase + EXPGFX_POOL_BOUNDS_TEMPLATE_IDS_OFFSET;
  poolBounds = (ExpgfxBounds *)(expgfxBase + EXPGFX_POOL_BOUNDS_OFFSET);
  poolSourceIds = (u32 *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET);
  asm {
    lis poolSlotTypeIdBase, gExpgfxStaticPoolSlotTypeIds@ha
    addi poolSlotTypeIds, poolSlotTypeIdBase, gExpgfxStaticPoolSlotTypeIds@l
  }
  slotPoolBases = (uint *)(expgfxBase + EXPGFX_SLOT_POOL_BASES_OFFSET);
  do {
    if ((*poolActiveCounts != '\0') &&
        (*poolSourceModes == EXPGFX_POOL_SOURCE_MODE_STANDALONE)) {
      boundsTemplate =
          (ExpgfxBounds *)(gExpgfxStaticData +
                           (uint)*poolBoundsTemplateIds * EXPGFX_BOUNDS_TEMPLATE_SIZE);
      if (fn_8005E97C((double)(poolBounds->minX - playerMapOffsetX),
                      (double)(poolBounds->maxX - playerMapOffsetX),
                      (double)poolBounds->minY,(double)poolBounds->maxY,
                      (double)(poolBounds->minZ - playerMapOffsetZ),
                      (double)(poolBounds->maxZ - playerMapOffsetZ),boundsTemplate) != 0) {
        sourcePosition = (ExpgfxPoolSourcePosition *)*poolSourceIds;
        if (sourcePosition != (ExpgfxPoolSourcePosition *)0x0) {
          queuePosition[0] = sourcePosition->x - playerMapOffsetX;
          queuePosition[1] = sourcePosition->y;
          queuePosition[2] = sourcePosition->z - playerMapOffsetZ;
        }
        else {
          queuePosition[0] =
              lbl_803DF358 * (poolBounds->minX + poolBounds->maxX) - playerMapOffsetX;
          queuePosition[1] = lbl_803DF358 * (poolBounds->minY + poolBounds->maxY);
          queuePosition[2] =
              lbl_803DF358 * (poolBounds->minZ + poolBounds->maxZ) - playerMapOffsetZ;
        }
        PSMTXMultVec((float (*)[4])currentMatrix,(Vec *)queuePosition,(Vec *)queuePosition);
        if (*poolSourceIds != 0) {
          queuePosition[2] =
              queuePosition[2] - (float)(*poolSlotTypeIds & EXPGFX_QUEUE_DEPTH_SLOT_TYPE_MASK);
        }
        fn_8005DE94(*slotPoolBases,poolIndex,queuePosition);
      }
    }
    poolActiveCounts = poolActiveCounts + 1;
    poolSourceModes = poolSourceModes + 1;
    poolBoundsTemplateIds = poolBoundsTemplateIds + 1;
    poolBounds = poolBounds + 1;
    poolSourceIds = poolSourceIds + 1;
    poolSlotTypeIds = poolSlotTypeIds + 1;
    slotPoolBases = slotPoolBases + 1;
    poolIndex = poolIndex + 1;
  } while (poolIndex < EXPGFX_POOL_COUNT);
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: expgfx_free2
 * EN v1.0 Address: 0x8009EEB8
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8009F144
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void expgfx_free2(u32 sourceId)
{
  expgfx_free(sourceId);
  return;
}

/*
 * --INFO--
 *
 * Function: expgfx_free
 * EN v1.0 Address: 0x8009EED8
 * EN v1.0 Size: 260b
 * EN v1.1 Address: 0x8009F164
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
asm void expgfx_free(u32 sourceId)
{
  nofralloc
  stwu r1,-0x40(r1)
  mflr r0
  stw r0,0x44(r1)
  addi r11,r1,0x40
  bl _savegpr_21
  mr r23,r3
  lis r3,gExpgfxRuntimeData@ha
  addi r31,r3,gExpgfxRuntimeData@l
  cmplwi r23,0
  beq expgfx_free_done
  li r25,0
  addi r30,r31,0x1200
  addi r29,r31,0xed0
  addi r28,r31,0x1070
  lis r3,gExpgfxStaticPoolSlotTypeIds@ha
  addi r27,r3,gExpgfxStaticPoolSlotTypeIds@l
  lis r3,gExpgfxStaticPoolFrameFlags@ha
  addi r26,r3,gExpgfxStaticPoolFrameFlags@l
expgfx_free_poolLoop:
  lwz r24,0(r30)
  lwz r0,0(r29)
  cmplw r23,r0
  bne expgfx_free_nextPool
  li r21,0
  li r22,-1
expgfx_free_slotLoop:
  cmplwi r24,0
  beq expgfx_free_afterSlot
  lbz r0,0x8a(r24)
  rlwinm r0,r0,31,25,31
  slwi r0,r0,4
  add r3,r31,r0
  lwz r0,0x980(r3)
  cmplw r0,r23
  bne expgfx_free_afterSlot
  lwz r3,0(r30)
  mr r4,r25
  mr r5,r21
  li r6,0
  li r7,1
  bl expgfxRemove
expgfx_free_afterSlot:
  addi r24,r24,0xa0
  lbz r0,0(r28)
  extsb r0,r0
  cmpwi r0,0
  bne expgfx_free_nextSlot
  sth r22,0(r27)
expgfx_free_nextSlot:
  addi r21,r21,1
  cmpwi r21,0x19
  blt expgfx_free_slotLoop
  li r0,0
  stw r0,0(r29)
  stb r0,0(r26)
expgfx_free_nextPool:
  addi r30,r30,4
  addi r29,r29,4
  addi r28,r28,1
  addi r27,r27,2
  addi r26,r26,1
  addi r25,r25,1
  cmpwi r25,0x50
  blt expgfx_free_poolLoop
expgfx_free_done:
  addi r11,r1,0x40
  bl _restgpr_21
  lwz r0,0x44(r1)
  mtlr r0
  addi r1,r1,0x40
  blr
}

/*
 * --INFO--
 *
 * Function: expgfx_resetAllPools
 * EN v1.0 Address: 0x8009EFDC
 * EN v1.0 Size: 464b
 * EN v1.1 Address: 0x8009F268
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
asm void expgfx_resetAllPools(void)
{
  nofralloc
  stwu r1,-0x40(r1)
  mflr r0
  stw r0,0x44(r1)
  addi r11,r1,0x40
  bl _savegpr_20
  lis r3,gExpgfxStaticData@ha
  addi r31,r3,gExpgfxStaticData@l
  lis r3,gExpgfxRuntimeData@ha
  addi r24,r3,gExpgfxRuntimeData@l
  li r22,0
  addi r30,r24,0x1200
  addi r29,r24,0x10c0
  addi r28,r24,0x1070
  addi r27,r31,0x30
  addi r26,r24,0xed0
  addi r25,r31,0xd0
expgfx_resetAllPools_poolLoop:
  lwz r20,0(r30)
  li r21,0
expgfx_resetAllPools_slotLoop:
  li r4,1
  slw r23,r4,r21
  lwz r0,0(r29)
  and r0,r23,r0
  cmplwi r0,0
  beq expgfx_resetAllPools_nextSlot
  lbz r0,0x8a(r20)
  rlwinm r0,r0,31,25,31
  slwi r0,r0,4
  add r3,r24,r0
  lwz r0,0x988(r3)
  cmplwi r0,0
  beq expgfx_resetAllPools_updateRef
  stw r4,gExpgfxTextureFreeInProgress
  lbz r0,0x8a(r20)
  rlwinm r0,r0,31,25,31
  slwi r0,r0,4
  add r3,r24,r0
  lwz r3,0x988(r3)
  bl textureFree
  li r0,0
  stw r0,gExpgfxTextureFreeInProgress
expgfx_resetAllPools_updateRef:
  lbz r0,0x8a(r20)
  rlwinm r0,r0,31,25,31
  slwi r0,r0,4
  add r5,r24,r0
  addi r5,r5,0x980
  addi r4,r5,0xc
  lhz r3,0(r4)
  cmplwi r3,0
  beq expgfx_resetAllPools_mismatch
  subi r0,r3,1
  sth r0,0(r4)
  lhz r0,0(r4)
  cmplwi r0,0
  bne expgfx_resetAllPools_clearSlot
  li r0,0
  stw r0,8(r5)
  stw r0,0(r5)
  b expgfx_resetAllPools_clearSlot
expgfx_resetAllPools_mismatch:
  addi r3,r31,0x358
  crclr 4*cr1+eq
  bl debugPrintf
expgfx_resetAllPools_clearSlot:
  li r0,-1
  sth r0,0x26(r20)
  lwz r3,0(r29)
  not r0,r23
  and r0,r3,r0
  stw r0,0(r29)
expgfx_resetAllPools_nextSlot:
  addi r20,r20,0xa0
  addi r21,r21,1
  cmpwi r21,0x19
  blt expgfx_resetAllPools_slotLoop
  li r3,0
  stb r3,0(r28)
  li r0,-1
  sth r0,0(r27)
  stw r3,0(r26)
  stb r3,0(r25)
  lwz r3,0(r30)
  li r4,0xfa0
  bl DCFlushRange
  addi r30,r30,4
  addi r29,r29,4
  addi r28,r28,1
  addi r27,r27,2
  addi r26,r26,4
  addi r25,r25,1
  addi r22,r22,1
  cmpwi r22,0x50
  blt expgfx_resetAllPools_poolLoop
  li r27,0
  li r26,1
  mr r25,r27
  mr r23,r27
  mr r22,r27
  mr r21,r27
  mr r20,r27
expgfx_resetAllPools_resourceLoop:
  stw r26,gExpgfxTextureFreeInProgress
  lwz r3,0(r24)
  cmplwi r3,0
  beq expgfx_resetAllPools_clearResource
  bl textureFree
expgfx_resetAllPools_clearResource:
  stw r25,gExpgfxTextureFreeInProgress
  stw r23,0(r24)
  stw r22,8(r24)
  stw r21,4(r24)
  stw r20,0xc(r24)
  addi r24,r24,0x10
  addi r27,r27,1
  cmpwi r27,0x20
  blt expgfx_resetAllPools_resourceLoop
  addi r11,r1,0x40
  bl _restgpr_20
  lwz r0,0x44(r1)
  mtlr r0
  addi r1,r1,0x40
  blr
}

/*
 * --INFO--
 *
 * Function: expgfx_updateFrameState
 * EN v1.0 Address: 0x8009F1AC
 * EN v1.0 Size: 288b
 * EN v1.1 Address: 0x8009F438
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void expgfx_updateFrameState(int sourceMode,int sourceId)
{
  int renderMode;
  int poolIndex;
  f32 frameStep;
  f32 frameValue;

  renderMode = renderModeSetOrGet(EXPGFX_INVALID_SLOT_TYPE);
  if ((short)renderMode != 1) {
    frameValue = lbl_803DD25C + (frameStep = timeDelta);
    lbl_803DD25C = frameValue;
    if (frameValue >= lbl_803DF418) {
      lbl_803DD25C = lbl_803DF35C;
    }
    frameValue = lbl_803DD260 + frameStep;
    lbl_803DD260 = frameValue;
    if (frameValue >= lbl_803DF384) {
      lbl_803DD260 = lbl_803DF35C;
    }
    frameValue = lbl_803DD264 + frameStep;
    lbl_803DD264 = frameValue;
    if (frameValue >= lbl_803DF354) {
      lbl_803DD264 = lbl_803DF35C;
    }
    lbl_803DC7B0 = 1;
    expgfx_updateActivePools((u8)sourceMode,sourceId,0);
    lbl_803DC7B0 = 0;
    poolIndex = EXPGFX_POOL_COUNT;
    while ((u8)poolIndex > 0) {
      poolIndex--;
      gExpgfxStaticPoolFrameFlags[(u8)poolIndex] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    }
    (*(code *)(*gPartfxInterface + 0xc))(0);
    lbl_803DD254 = 1;
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: expgfx_addremove
 * EN v1.0 Address: 0x8009C21C
 * EN v1.0 Size: 3840b
 * EN v1.1 Address: 0x8009F558
 * EN v1.1 Size: 2576b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int expgfx_acquireResourceEntry(short slotType);
extern void *Obj_GetPlayerObject(void);
extern f32 lbl_803DF350;
extern f32 lbl_803DF41C;
extern f32 lbl_803DF420;
extern f32 lbl_803DF424;
extern f32 lbl_803DF428;
extern int lbl_803DD26C;
extern int lbl_803DD270;
extern int lbl_803DD274;
extern int lbl_803DD278;

#pragma scheduling off
#pragma peephole off
int expgfx_addremove(ExpgfxSpawnConfig *config, int preferredPoolIndex, short slotType,
                     u8 boundsTemplateId)
{
  ExpgfxSlot *slot;
  ExpgfxAttachedSourceState *attachedSource;
  ExpgfxResourceHandle *resourceHandle;
  void *playerObj;
  u8 *expgfxBase;
  uint behaviorFlags;
  int tableIndex;
  int subTableIndex;
  int attachedKey1;
  uint trackedMaskPair;
  uint bit;
  uint maskHighWord;
  uint maskLowWord;
  uint inverseBit;
  short poolIndex;
  short slotIndex;
  int polePosX = 0;
  int polePosY = 0;
  int poleVecY = 0;
  int poleVecZ = 0;
  f32 scaleVal;
  u8 *poolSourceModesByte;
  u8 modeFlag;
  uint *slotPoolBases;
  u32 *trackedFrameMasks;

  expgfxBase = gExpgfxRuntimeData;
  poolIndex = 0;
  slotIndex = 0;
  polePosX = 0;
  polePosY = 0;
  poleVecY = 0;
  poleVecZ = 0;
  if (getHudHiddenFrameCount() != 0) {
    return EXPGFX_INVALID_POOL_INDEX;
  }
  if (expgfxGetSlot(&poolIndex, &slotIndex, slotType,
                          preferredPoolIndex, (uint)(int)config->attachedSource)
      == EXPGFX_INVALID_POOL_INDEX) {
    return EXPGFX_INVALID_POOL_INDEX;
  }
  {
  slotPoolBases = (uint *)(expgfxBase + EXPGFX_SLOT_POOL_BASES_OFFSET);
  trackedFrameMasks = (u32 *)(expgfxBase + EXPGFX_TRACKED_SOURCE_FRAME_MASKS_OFFSET);

  if ((int)poolIndex < EXPGFX_POOL_COUNT) {
    *(int *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET + ((int)poolIndex << 2)) =
        (int)config->attachedSource;
  }
  if ((int)poolIndex < EXPGFX_POOL_COUNT &&
      (config->behaviorFlags & EXPGFX_BEHAVIOR_TRACK_POOL_SOURCE) != 0) {
    trackedMaskPair = ((uint)poolIndex & 1) * 2;
    maskHighWord = trackedFrameMasks[trackedMaskPair];
    maskLowWord = trackedFrameMasks[trackedMaskPair + 1];
    bit = 1 << ((int)poolIndex >> 1);
    trackedFrameMasks[trackedMaskPair + 1] = maskLowWord | bit;
    trackedFrameMasks[trackedMaskPair] = maskHighWord | (uint)((int)bit >> 0x1f);
  } else {
    trackedMaskPair = ((uint)poolIndex & 1) * 2;
    maskHighWord = trackedFrameMasks[trackedMaskPair];
    maskLowWord = trackedFrameMasks[trackedMaskPair + 1];
    inverseBit = ~(uint)(1 << ((int)poolIndex >> 1));
    trackedFrameMasks[trackedMaskPair + 1] = maskLowWord & inverseBit;
    trackedFrameMasks[trackedMaskPair] = maskHighWord & (uint)((int)inverseBit >> 0x1f);
  }
  slot = (ExpgfxSlot *)(slotPoolBases[(int)poolIndex] + slotIndex * EXPGFX_SLOT_SIZE);
  gExpgfxSequenceCounter = gExpgfxSequenceCounter + 1;
  if ((short)EXPGFX_SEQUENCE_COUNTER_MAX < (short)gExpgfxSequenceCounter) {
    gExpgfxSequenceCounter = 0;
  }
  slot->sequenceId = gExpgfxSequenceCounter;
  slot->behaviorFlags = config->behaviorFlags;
  slot->renderFlags = config->renderFlags;
  slot->stateBits.value = slot->stateBits.value & ~EXPGFX_SLOT_STATE_INIT_PHASE_MASK;

  tableIndex = (int)(short)expgfx_acquireResourceEntry(config->tableKeyType);
  if (tableIndex < 0) {
    expgfxRemove(slotPoolBases[(int)poolIndex], (int)poolIndex, (int)slotIndex, 1, 1);
    return EXPGFX_INVALID_POOL_INDEX;
  }
  resourceHandle =
      (ExpgfxResourceHandle *)*(u32 *)(expgfxBase + (tableIndex << EXPGFX_TABLE_ENTRY_SHIFT));
  if (resourceHandle == NULL) {
    expgfxRemove(slotPoolBases[(int)poolIndex], (int)poolIndex, (int)slotIndex, 1, 1);
    return EXPGFX_INVALID_POOL_INDEX;
  }
  if (resourceHandle->refCount == EXPGFX_REFCOUNT_OVERFLOW) {
    expgfxRemove(slotPoolBases[(int)poolIndex], (int)poolIndex, (int)slotIndex, 1, 1);
    return EXPGFX_INVALID_POOL_INDEX;
  }
  resourceHandle->refCount = resourceHandle->refCount + 1;
  resourceHandle->linkGroup = (u16)config->linkGroup;

  behaviorFlags = slot->behaviorFlags;
  if ((behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX1_T) != 0) {
    polePosX = 0;
    polePosY = 0;
  }
  if ((behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX0_T) != 0) {
    poleVecZ = 0;
    poleVecY = 0;
  }

  attachedSource = (ExpgfxAttachedSourceState *)config->attachedSource;
  attachedKey1 = 0;
  if (attachedSource == NULL) {
    *(f32 *)&slot->sourcePosY = *(f32 *)&config->sourcePosYBits;
    *(f32 *)&slot->sourcePosZ = *(f32 *)&config->sourcePosZBits;
    *(f32 *)&slot->sourcePosW = *(f32 *)&config->sourcePosWBits;
    *(f32 *)&slot->sourcePosX = *(f32 *)&config->sourcePosXBits;
    slot->sourceVecZ = config->sourceVecZ;
    slot->sourceVecY = config->sourceVecY;
    slot->sourceVecX = config->sourceVecX;
  } else if ((behaviorFlags & EXPGFX_BEHAVIOR_COPY_ATTACHED_SOURCE) != 0) {
    *(f32 *)&slot->sourcePosY = *(f32 *)&attachedSource->sourcePosYBits;
    *(f32 *)&slot->sourcePosZ = *(f32 *)&attachedSource->sourcePosZBits;
    *(f32 *)&slot->sourcePosW = *(f32 *)&attachedSource->sourcePosWBits;
    *(f32 *)&slot->sourcePosX = *(f32 *)&attachedSource->sourcePosXBits;
    slot->sourceVecZ = attachedSource->sourceVecZ;
    slot->sourceVecY = attachedSource->sourceVecY;
    slot->sourceVecX = attachedSource->sourceVecX;
    if ((behaviorFlags & EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_A) != 0 ||
        (behaviorFlags & EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_B) != 0) {
      config->velocityX = config->velocityX + attachedSource->velocityX;
      config->velocityY = config->velocityY + attachedSource->velocityY;
      config->velocityZ = config->velocityZ + attachedSource->velocityZ;
    }
    attachedKey1 = attachedSource->tableKey1;
    attachedSource = NULL;
  }

  subTableIndex = expgfx_addToTable((uint)resourceHandle, (uint)attachedSource, attachedKey1,
                                     config->tableKeyType);
  if ((short)subTableIndex == EXPGFX_INVALID_TABLE_INDEX) {
    debugPrintf(sExpgfxInvalidTabIndex);
    expgfxRemove(slotPoolBases[(int)poolIndex], (int)poolIndex, (int)slotIndex, 1, 1);
    return EXPGFX_INVALID_POOL_INDEX;
  }
  Expgfx_SetSlotTableIndex(slot, (u8)subTableIndex);

  *(f32 *)&slot->posX = *(f32 *)&config->startPosXBits;
  *(f32 *)&slot->startPosX = *(f32 *)&config->startPosXBits;
  *(f32 *)&slot->posY = *(f32 *)&config->startPosYBits;
  *(f32 *)&slot->startPosY = *(f32 *)&config->startPosYBits;
  *(f32 *)&slot->posZ = *(f32 *)&config->startPosZBits;
  *(f32 *)&slot->startPosZ = *(f32 *)&config->startPosZBits;
  slot->velocityX = config->velocityX;
  slot->velocityY = config->velocityY;
  slot->velocityZ = config->velocityZ;
  slot->initialStateByte = config->initialStateByte;
  *(s16 *)((char *)slot + 0x36) = (s16)*(int *)((char *)config + 0x4);
  slot->lifetimeFrame = (s16)*(int *)((char *)config + 0x8);
  slot->lifetimeFrameLimit = (s16)*(int *)((char *)config + 0x8);

  if (config->scale > lbl_803DF354) {
    debugPrintf(sExpgfxScaleOverflow);
  }
  scaleVal = lbl_803DF350 * config->scale;

  if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_SCALE_FROM_ZERO) != 0) {
    slot->scaleCounter = 0;
    slot->scaleFrames = (s16)(int)(scaleVal / (f32)(s32)slot->lifetimeFrameLimit);
    slot->scaleTarget = (s16)(int)scaleVal;
  } else if ((slot->renderFlags & EXPGFX_RENDER_SCALE_OVER_LIFETIME) != 0) {
    slot->scaleCounter = (s16)(int)scaleVal;
    slot->scaleFrames = (s16)(int)(scaleVal / (f32)(s32)slot->lifetimeFrameLimit);
    slot->scaleTarget = slot->scaleCounter;
  } else {
    slot->scaleCounter = (s16)(int)scaleVal;
    slot->scaleTarget = slot->scaleCounter;
    slot->scaleFrames = 0;
  }

  if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A) != 0 ||
      (slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_B) != 0) {
    *(f32 *)&slot->sourcePosY = *(f32 *)&config->sourcePosYBits;
    *(f32 *)&slot->sourcePosZ = *(f32 *)&config->sourcePosZBits;
    *(f32 *)&slot->sourcePosW = *(f32 *)&config->sourcePosWBits;
    *(f32 *)&slot->sourcePosX = *(f32 *)&config->sourcePosXBits;
    slot->sourceVecZ = config->sourceVecZ;
    slot->sourceVecY = config->sourceVecY;
    slot->sourceVecX = config->sourceVecX;
  }
  slot->stateBits.bits.frameParity = gExpgfxFrameParityBit;

  if ((slot->renderFlags & EXPGFX_RENDER_BACKDATE_MOTION) != 0) {
    f32 step;
    slot->renderFlags = slot->renderFlags ^ EXPGFX_RENDER_BACKDATE_MOTION;
    step = lbl_803DF41C * (f32)(s32)slot->lifetimeFrame;
    *(f32 *)&slot->posX = slot->velocityX * step + *(f32 *)&slot->posX;
    *(f32 *)&slot->posY = slot->velocityY * step + *(f32 *)&slot->posY;
    *(f32 *)&slot->posZ = slot->velocityZ * step + *(f32 *)&slot->posZ;
    slot->velocityX = slot->velocityX * lbl_803DF420;
    slot->velocityY = slot->velocityY * lbl_803DF420;
    slot->velocityZ = slot->velocityZ * lbl_803DF420;
  }

  if ((slot->renderFlags & EXPGFX_RENDER_AIM_AT_ACTOR) != 0) {
    f32 dx;
    f32 dz;
    f32 distSq;
    f32 inv;
    playerObj = Obj_GetPlayerObject();
    slot->renderFlags = slot->renderFlags ^ EXPGFX_RENDER_AIM_AT_ACTOR;
    if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_AIM_VELOCITY_TOWARD_PLAYER) != 0) {
      dx = *(f32 *)((char *)playerObj + 0x18) - *(f32 *)&slot->startPosX;
      dz = *(f32 *)((char *)playerObj + 0x20) - *(f32 *)&slot->startPosZ;
      distSq = dx * dx + dz * dz;
      if (distSq < lbl_803DF424
          && lbl_803DF35C != *(f32 *)((char *)playerObj + 0x24)
          && lbl_803DF35C != *(f32 *)((char *)playerObj + 0x2c)) {
        slot->velocityX = slot->velocityX + dx / (f32)(s32)((int)slot->lifetimeFrame << 1);
        slot->velocityY = slot->velocityY +
            ((lbl_803DF428 + *(f32 *)((char *)playerObj + 0x1c)) - *(f32 *)&slot->startPosY) /
                (f32)(s32)((int)slot->lifetimeFrame << 1);
        slot->velocityZ = slot->velocityZ +
            (*(f32 *)((char *)playerObj + 0x20) - *(f32 *)&slot->startPosZ) /
                (f32)(s32)((int)slot->lifetimeFrame << 1);
      }
    } else {
      dx = *(f32 *)((char *)playerObj + 0x18) -
           (*(f32 *)&slot->startPosX + *(f32 *)((char *)config + 0xc));
      dz = *(f32 *)((char *)playerObj + 0x20) -
           (*(f32 *)&slot->startPosZ + *(f32 *)((char *)config + 0x14));
      distSq = dx * dx + dz * dz;
      if (distSq < lbl_803DF424
          && lbl_803DF35C != *(f32 *)((char *)playerObj + 0x24)
          && lbl_803DF35C != *(f32 *)((char *)playerObj + 0x2c)) {
        slot->velocityX = slot->velocityX - dx / (f32)(s32)((int)slot->lifetimeFrame << 1);
        slot->velocityY = slot->velocityY -
            ((lbl_803DF428 + *(f32 *)((char *)playerObj + 0x1c)) -
             (*(f32 *)&slot->startPosY + *(f32 *)((char *)config + 0x10))) /
                (f32)(s32)((int)slot->lifetimeFrame << 1);
        slot->velocityZ = slot->velocityZ -
            (*(f32 *)((char *)playerObj + 0x20) -
             (*(f32 *)&slot->startPosZ + *(f32 *)((char *)config + 0x14))) /
                (f32)(s32)((int)slot->lifetimeFrame << 1);
      }
    }
  }

  if (slotType == 1) {
    lbl_803DD270 = lbl_803DD270 + 1;
    lbl_803DD278 = lbl_803DD274 / lbl_803DD270;
  }

  slot->colorByte0 = (u8)((int)config->colorByte0Hi >> 8);
  slot->colorByte1 = (u8)((int)config->colorByte1Hi >> 8);
  slot->colorByte2 = (u8)((int)config->colorByte2Hi >> 8);

  if ((config->renderFlags & EXPGFX_RENDER_OVERRIDE_COLORS) != 0) {
    *(u8 *)((char *)slot + 0x1f) = (u8)((int)config->overrideColor0 >> 8);
    *(u8 *)((char *)slot + 0x2f) = (u8)((int)config->overrideColor1 >> 8);
    *(u8 *)((char *)slot + 0x3f) = (u8)((int)config->overrideColor2 >> 8);
  }

  *(u8 *)((char *)slot + 0xc) = 0xff;
  *(u8 *)((char *)slot + 0xd) = 0xff;
  *(u8 *)((char *)slot + 0xe) = 0xff;

  *(s16 *)((char *)slot + 0x08) = (s16)polePosY;
  *(s16 *)((char *)slot + 0x0a) = (s16)poleVecY;
  *(s16 *)((char *)slot + 0x18) = (s16)polePosX;
  *(s16 *)((char *)slot + 0x1a) = (s16)poleVecY;
  *(s16 *)((char *)slot + 0x28) = (s16)polePosX;
  *(s16 *)((char *)slot + 0x2a) = (s16)poleVecZ;
  *(s16 *)((char *)slot + 0x38) = (s16)polePosY;
  *(s16 *)((char *)slot + 0x3a) = (s16)poleVecZ;

  if ((slot->renderFlags & EXPGFX_RENDER_INIT_QUAD) != 0) {
    expgfx_initSlotQuad(slot);
  }

  poolSourceModesByte = expgfxBase + EXPGFX_POOL_SOURCE_MODES_OFFSET + (s16)poolIndex;
  modeFlag = (config->behaviorFlags & EXPGFX_BEHAVIOR_SOURCE_MODE_FLAG) != 0 ? 1 : 0;
  *poolSourceModesByte = modeFlag;
  if (*poolSourceModesByte != 0 &&
      (config->behaviorFlags & EXPGFX_BEHAVIOR_TRACK_POOL_SOURCE) == 0) {
    *poolSourceModesByte = *poolSourceModesByte + 1;
  }
  *(expgfxBase + EXPGFX_POOL_BOUNDS_TEMPLATE_IDS_OFFSET + (s16)poolIndex) =
      boundsTemplateId;

  DCFlushRange(slot, EXPGFX_SLOT_SIZE);
  lbl_803DD26C = (int)slot;
  return slot->sequenceId;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: expgfx_onMapSetup
 * EN v1.0 Address: 0x8009FCDC
 * EN v1.0 Size: 416b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
asm void expgfx_onMapSetup(void)
{
  nofralloc
  stwu r1,-0x20(r1)
  mflr r0
  stw r0,0x24(r1)
  stw r31,0x1c(r1)
  stw r30,0x18(r1)
  stw r29,0x14(r1)
  lis r3,gExpgfxRuntimeData@ha
  addi r30,r3,gExpgfxRuntimeData@l
  bl expgfxRemoveAll
  addi r4,r30,0x10c0
  addi r5,r30,0x1070
  lis r3,gExpgfxStaticPoolSlotTypeIds@ha
  addi r6,r3,gExpgfxStaticPoolSlotTypeIds@l
  lis r3,gExpgfxStaticPoolFrameFlags@ha
  addi r3,r3,gExpgfxStaticPoolFrameFlags@l
  addi r7,r30,0xe80
  addi r8,r30,0xed0
  li r0,0xa
  mtctr r0
expgfx_onMapSetup_poolResetLoop:
  li r31,0
  stw r31,0(r4)
  stb r31,0(r5)
  li r0,-1
  sth r0,0(r6)
  stb r31,0(r3)
  stb r31,0(r7)
  stw r31,0(r8)
  stw r31,4(r4)
  stb r31,1(r5)
  sth r0,2(r6)
  stb r31,1(r3)
  stb r31,1(r7)
  stw r31,4(r8)
  stw r31,8(r4)
  stb r31,2(r5)
  sth r0,4(r6)
  stb r31,2(r3)
  stb r31,2(r7)
  stw r31,8(r8)
  stw r31,0xc(r4)
  stb r31,3(r5)
  sth r0,6(r6)
  stb r31,3(r3)
  stb r31,3(r7)
  stw r31,0xc(r8)
  stw r31,0x10(r4)
  stb r31,4(r5)
  sth r0,8(r6)
  stb r31,4(r3)
  stb r31,4(r7)
  stw r31,0x10(r8)
  stw r31,0x14(r4)
  stb r31,5(r5)
  sth r0,0xa(r6)
  stb r31,5(r3)
  stb r31,5(r7)
  stw r31,0x14(r8)
  stw r31,0x18(r4)
  stb r31,6(r5)
  sth r0,0xc(r6)
  stb r31,6(r3)
  stb r31,6(r7)
  stw r31,0x18(r8)
  stw r31,0x1c(r4)
  stb r31,7(r5)
  sth r0,0xe(r6)
  stb r31,7(r3)
  stb r31,7(r7)
  stw r31,0x1c(r8)
  addi r4,r4,0x20
  addi r5,r5,8
  addi r6,r6,0x10
  addi r3,r3,8
  addi r7,r7,8
  addi r8,r8,0x20
  bdnz expgfx_onMapSetup_poolResetLoop
  stw r31,0x1014(r30)
  stw r31,0x1010(r30)
  stw r31,0x101c(r30)
  stw r31,0x1018(r30)
  li r0,1
  stw r0,gExpgfxTextureFreeInProgress
  mr r29,r31
expgfx_onMapSetup_resourceLoop:
  lwz r3,0(r30)
  cmplwi r3,0
  beq expgfx_onMapSetup_clearResource
  bl textureFree
expgfx_onMapSetup_clearResource:
  stw r31,0(r30)
  stw r31,8(r30)
  stw r31,4(r30)
  stw r31,0xc(r30)
  addi r30,r30,0x10
  addi r29,r29,1
  cmpwi r29,0x20
  blt expgfx_onMapSetup_resourceLoop
  li r0,0
  stw r0,gExpgfxTextureFreeInProgress
  lwz r31,0x1c(r1)
  lwz r30,0x18(r1)
  lwz r29,0x14(r1)
  lwz r0,0x24(r1)
  mtlr r0
  addi r1,r1,0x20
  blr
}

/*
 * --INFO--
 *
 * Function: expgfx_release
 * EN v1.0 Address: 0x8009FE7C
 * EN v1.0 Size: 84b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void expgfx_release(void)
{
  register void **slotPoolBases;
  int poolIndex;

  asm {
    bl expgfxRemoveAll
  }
  poolIndex = 0;
  asm {
    lis r3, gExpgfxSlotPoolBases@ha
    addi slotPoolBases, r3, gExpgfxSlotPoolBases@l
  }
  do {
    mm_free(*slotPoolBases);
    slotPoolBases = slotPoolBases + 1;
    poolIndex = poolIndex + 1;
  } while (poolIndex < EXPGFX_POOL_COUNT);
  return;
}
#pragma peephole reset
#pragma scheduling reset
