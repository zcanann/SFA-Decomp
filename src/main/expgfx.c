#include "ghidra_import.h"
#include "dolphin/mtx.h"
#include "dolphin/os/OSCache.h"
#include "main/expgfx.h"
#include "main/expgfx_internal.h"

extern undefined4 ABS();
extern int Camera_GetViewMatrix(void);
extern int fn_80008B4C(int param_1);
extern int FUN_80006714();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068d4();
extern undefined4 FUN_80006964();
extern undefined4 FUN_80006974();
extern undefined4 FUN_80006988();
extern undefined4 FUN_8000698c();
extern void* FUN_800069a8();
extern undefined4 FUN_800069cc();
extern int FUN_800176d0();
extern int FUN_80017730();
extern undefined4 FUN_80017748();
extern uint FUN_80017760();
extern undefined4 FUN_80017790();
extern undefined4 FUN_80017794();
extern undefined4 FUN_80017798();
extern uint FUN_8001779c();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern void fn_80023800(uint slotPoolBase);
extern undefined4 FUN_8004812c();
extern undefined8 FUN_80053754();
extern void fn_80054308(void *resource);
extern int FUN_8005b024();
extern undefined4 FUN_8005d340();
extern undefined4 FUN_8005e1d8();
extern void fn_8005DE94(uint slotPoolBase,int poolIndex,float *position);
extern uint FUN_8005e558();
extern u8 fn_8005E97C();
extern undefined4 FUN_8006f8a4();
extern undefined4 FUN_8006f8fc();
extern void trackIntersect_drawColorBand(void);
extern undefined4 FUN_80071908();
extern undefined4 FUN_80071e78();
extern undefined4 FUN_80071f8c();
extern undefined4 FUN_80071f90();
extern undefined4 FUN_8007204c();
extern undefined4 FUN_800722ec();
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
extern undefined4* pDll_expgfx;
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
extern u32 gExpgfxTrackedSourceFrameMasks[];
extern s16 gExpgfxStaticPoolSlotTypeIds[];
extern int lbl_803DD258;
extern volatile s16 lbl_803DD250;
extern volatile u8 lbl_803DD252;
extern char sExpgfxAddToTableUsageOverflow[];
extern char sExpgfxExpTabIsFull[];
extern char sExpgfxInvalidTabIndex[];
extern char sExpgfxMismatchInAddRemove[];
extern char sExpgfxScaleOverflow[];
extern char sExpgfxNoTexture[];

#define EXPGFX_SLOT_TABLE_INDEX_OFFSET 0x8A
#define gExpgfxTrackedPoolMaskHighWords DAT_8039c7c8
#define gExpgfxTrackedPoolMaskLowWords DAT_8039c7cc
#define gExpgfxSequenceCounter lbl_803DD250
#define gExpgfxFrameParityBit lbl_803DD252

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
 * Function: expgfx_release
 * EN v1.0 Address: 0x8009B0E0
 * EN v1.0 Size: 372b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void expgfx_release(uint slotPoolBase,int poolIndex,int slotIndex,int freeTexture,int clearActive)
{
  u8 *expgfxBase;
  u32 *poolActiveMask;
  char *poolActiveCount;
  ExpgfxSlot *slot;
  uint activeMask;
  uint tableOffset;
  u16 *refCount;
  u8 *tableTextureResources;

  expgfxBase = gExpgfxRuntimeData;
  activeMask = 1 << slotIndex;
  poolActiveMask = (u32 *)(expgfxBase + EXPGFX_POOL_ACTIVE_MASKS_OFFSET +
                           poolIndex * sizeof(u32));
  if ((activeMask & *poolActiveMask) != 0) {
    slot = (ExpgfxSlot *)(slotPoolBase + slotIndex * EXPGFX_SLOT_SIZE);
    slot->behaviorFlags = 0;
    if (freeTexture == 0) {
      tableTextureResources = expgfxBase + EXPGFX_EXPTAB_TEXTURE_RESOURCE_OFFSET;
      tableOffset = Expgfx_GetSlotTableIndex(slot) << EXPGFX_TABLE_ENTRY_SHIFT;
      if (*(u32 *)(tableTextureResources + tableOffset) != 0) {
        lbl_803DD258 = 1;
        fn_80054308(*(void **)(tableTextureResources +
                               (Expgfx_GetSlotTableIndex(slot) << EXPGFX_TABLE_ENTRY_SHIFT)));
        lbl_803DD258 = 0;
      }
      tableOffset = Expgfx_GetSlotTableIndex(slot) << EXPGFX_TABLE_ENTRY_SHIFT;
      refCount = (u16 *)(expgfxBase + EXPGFX_EXPTAB_REFCOUNT_OFFSET + tableOffset);
      if (*refCount != 0) {
        (*refCount)--;
        if (*refCount == 0) {
          *(u32 *)(tableTextureResources + tableOffset) = 0;
          *(u32 *)(expgfxBase + EXPGFX_EXPTAB_OFFSET + tableOffset) = 0;
        }
      }
      else {
        debugPrintf(sExpgfxMismatchInAddRemove);
      }
    }
    slot->sequenceId = EXPGFX_INVALID_SEQUENCE_ID;
    if (((u32)clearActive & EXPGFX_BYTE_VALUE_MASK) != 0) {
      DCFlushRange(slot,EXPGFX_SLOT_SIZE);
    }
    *poolActiveMask = *poolActiveMask & ~activeMask;
    poolActiveCount =
        (char *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET + poolIndex);
    (*poolActiveCount)--;
    if (*poolActiveCount == '\0') {
      gExpgfxStaticPoolSlotTypeIds[poolIndex] = EXPGFX_INVALID_SLOT_TYPE;
    }
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: expgfx_initialise
 * EN v1.0 Address: 0x8009B254
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x8009B36C
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void expgfx_initialise(void)
{
  ExpgfxTableEntry *tableEntry;
  ExpgfxSlot *slot;
  u8 *expgfxBase;
  uint tableIndex;
  int slotIndex;
  int poolIndex;
  s16 *poolSlotTypeIds;
  char *poolActiveCounts;
  uint *poolActiveMasks;
  uint *slotPoolBases;

  expgfxBase = gExpgfxRuntimeData;
  poolIndex = 0;
  slotPoolBases = (uint *)(expgfxBase + EXPGFX_SLOT_POOL_BASES_OFFSET);
  poolActiveMasks = (uint *)(expgfxBase + EXPGFX_POOL_ACTIVE_MASKS_OFFSET);
  poolActiveCounts = (char *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
  poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
  do {
    slot = (ExpgfxSlot *)*slotPoolBases;
    slotIndex = 0;
    do {
      if ((1 << slotIndex & *poolActiveMasks) != 0) {
        if ((((ExpgfxTableEntry *)(expgfxBase + EXPGFX_EXPTAB_OFFSET))[Expgfx_GetSlotTableIndex(slot)].
             textureOrResource != 0) &&
            (((ExpgfxTableEntry *)(expgfxBase + EXPGFX_EXPTAB_OFFSET))[Expgfx_GetSlotTableIndex(slot)].
             textureOrResource != 0)) {
          lbl_803DD258 = 1;
          fn_80054308((void *)((ExpgfxTableEntry *)(expgfxBase + EXPGFX_EXPTAB_OFFSET))
                          [Expgfx_GetSlotTableIndex(slot)].textureOrResource);
          lbl_803DD258 = 0;
        }
        tableIndex = Expgfx_GetSlotTableIndex(slot);
        tableEntry = &((ExpgfxTableEntry *)(expgfxBase + EXPGFX_EXPTAB_OFFSET))[tableIndex];
        if (tableEntry->refCount != 0) {
          tableEntry->refCount--;
          if (tableEntry->refCount == 0) {
            tableEntry->textureOrResource = 0;
            tableEntry->key0 = 0;
          }
        }
        else {
          debugPrintf(sExpgfxMismatchInAddRemove);
        }
        slot->sequenceId = EXPGFX_INVALID_SEQUENCE_ID;
        *poolActiveMasks = *poolActiveMasks & ~(1 << slotIndex);
      }
      slot = slot + 1;
      slotIndex = slotIndex + 1;
    } while (slotIndex < EXPGFX_SLOTS_PER_POOL);
    *poolActiveCounts = 0;
    *poolSlotTypeIds = EXPGFX_INVALID_SLOT_TYPE;
    DCFlushRange((void *)*slotPoolBases,EXPGFX_SLOTS_PER_POOL * EXPGFX_SLOT_SIZE);
    slotPoolBases++;
    poolActiveMasks++;
    poolActiveCounts++;
    poolSlotTypeIds++;
    poolIndex++;
  } while (poolIndex < EXPGFX_POOL_COUNT);
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: expgfx_reserveSlot
 * EN v1.0 Address: 0x8009B6A4
 * EN v1.0 Size: 752b
 * EN v1.1 Address: 0x8009B648
 * EN v1.1 Size: 792b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int expgfx_reserveSlot(short *poolIndexOut,short *slotIndexOut,short slotType,
                       int preferredPoolIndex,uint sourceId)
{
  short foundPool;
  short poolIndex;
  u8 *expgfxBase;
  char *poolActiveCounts;
  char *emptyPoolScan;
  int scanPoolIndex;
  char *activeCountBatch;
  short *slotTypeBatch;
  uint *poolActiveMask;
  int *sourceIdBatch;
  int batchCount;
  int freeSlotIndex;
  int slotTypeI;

  poolIndex = EXPGFX_INVALID_POOL_INDEX;
  foundPool = false;
  scanPoolIndex = 0;
  expgfxBase = gExpgfxRuntimeData;
  sourceIdBatch = (int *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET);
  slotTypeBatch = gExpgfxStaticPoolSlotTypeIds;
  poolActiveCounts = (char *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
  emptyPoolScan = poolActiveCounts;
  slotTypeI = (int)slotType;
  batchCount = EXPGFX_POOL_SEARCH_BATCH_COUNT;
  activeCountBatch = emptyPoolScan;
  do {
    if (sourceId == *sourceIdBatch && slotTypeI == *slotTypeBatch &&
        *activeCountBatch < EXPGFX_SLOTS_PER_POOL) {
      poolIndex = (short)scanPoolIndex;
      foundPool = true;
      break;
    }
    slotTypeBatch++;
    scanPoolIndex++;
    if (sourceId == sourceIdBatch[1] && slotTypeI == *slotTypeBatch &&
        activeCountBatch[1] < EXPGFX_SLOTS_PER_POOL) {
      poolIndex = (short)scanPoolIndex;
      foundPool = true;
      break;
    }
    slotTypeBatch++;
    scanPoolIndex++;
    if (sourceId == sourceIdBatch[2] && slotTypeI == *slotTypeBatch &&
        activeCountBatch[2] < EXPGFX_SLOTS_PER_POOL) {
      poolIndex = (short)scanPoolIndex;
      foundPool = true;
      break;
    }
    slotTypeBatch++;
    scanPoolIndex++;
    if (sourceId == sourceIdBatch[3] && slotTypeI == *slotTypeBatch &&
        activeCountBatch[3] < EXPGFX_SLOTS_PER_POOL) {
      poolIndex = (short)scanPoolIndex;
      foundPool = true;
      break;
    }
    slotTypeBatch++;
    scanPoolIndex++;
    if (sourceId == sourceIdBatch[4] && slotTypeI == *slotTypeBatch &&
        activeCountBatch[4] < EXPGFX_SLOTS_PER_POOL) {
      poolIndex = (short)scanPoolIndex;
      foundPool = true;
      break;
    }
    sourceIdBatch += EXPGFX_POOL_SEARCH_BATCH_SIZE;
    slotTypeBatch++;
    activeCountBatch += EXPGFX_POOL_SEARCH_BATCH_SIZE;
    scanPoolIndex++;
  } while (--batchCount != 0);
  if (foundPool) {
    freeSlotIndex = 0;
    poolActiveMask = (uint *)(expgfxBase + EXPGFX_POOL_ACTIVE_MASKS_OFFSET) + poolIndex;
    batchCount = EXPGFX_SLOTS_PER_POOL;
    do {
      if ((1 << freeSlotIndex & *poolActiveMask) == 0) {
        *slotIndexOut = (short)freeSlotIndex;
        *poolIndexOut = poolIndex;
        *poolActiveMask = *poolActiveMask | 1 << freeSlotIndex;
        poolActiveCounts[poolIndex] = poolActiveCounts[poolIndex] + 1;
        return 1;
      }
      freeSlotIndex = freeSlotIndex + 1;
      batchCount = batchCount + -1;
    } while (batchCount != 0);
  }
  foundPool = false;
  if (preferredPoolIndex != EXPGFX_INVALID_POOL_INDEX) {
    if ((preferredPoolIndex != EXPGFX_INVALID_POOL_INDEX) &&
        (scanPoolIndex = preferredPoolIndex, poolActiveCounts[preferredPoolIndex] < EXPGFX_SLOTS_PER_POOL)) {
      poolIndex = (short)preferredPoolIndex;
      foundPool = true;
    }
  }
  else {
    scanPoolIndex = 0;
    batchCount = EXPGFX_POOL_COUNT - 1;
    do {
      if (*emptyPoolScan < '\x01') {
        poolIndex = (short)scanPoolIndex;
        foundPool = true;
        poolActiveCounts[scanPoolIndex] = 0;
        break;
      }
      emptyPoolScan = emptyPoolScan + 1;
      scanPoolIndex = scanPoolIndex + 1;
      batchCount = batchCount + -1;
    } while (batchCount != 0);
  }
  if (foundPool) {
    freeSlotIndex = 0;
    poolActiveMask = (uint *)(expgfxBase + EXPGFX_POOL_ACTIVE_MASKS_OFFSET) + poolIndex;
    batchCount = EXPGFX_SLOTS_PER_POOL;
    do {
      if ((1 << freeSlotIndex & *poolActiveMask) == 0) {
        *slotIndexOut = (short)freeSlotIndex;
        *poolIndexOut = poolIndex;
        *poolActiveMask = *poolActiveMask | 1 << freeSlotIndex;
        gExpgfxStaticPoolSlotTypeIds[scanPoolIndex] = slotType;
        ((char *)(gExpgfxRuntimeData + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET))[poolIndex] =
            ((char *)(gExpgfxRuntimeData + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET))[poolIndex] + '\x01';
        return 1;
      }
      freeSlotIndex = freeSlotIndex + 1;
      batchCount = batchCount + -1;
    } while (batchCount != 0);
  }
  return EXPGFX_INVALID_POOL_INDEX;
}
#pragma peephole reset
#pragma scheduling reset

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
#pragma scheduling off
#pragma peephole off
void expgfx_initSlotQuad(void *slotPtr)
{
  ExpgfxSlot *slot;
  ExpgfxTableEntry *tableEntry;
  u8 *staticDataBase;
  s16 *slotWords;
  s16 *quadTemplate;
  u32 behaviorFlags;
  s16 tex0S;
  s16 tex0T;
  s16 tex1S;
  s16 tex1T;
  float frameStep;
  int texture;

  staticDataBase = gExpgfxStaticData;
  slot = (ExpgfxSlot *)slotPtr;
  tableEntry = Expgfx_GetTableEntry(Expgfx_GetSlotTableIndex(slot));
  texture = tableEntry->textureOrResource;
  slot->stateBits.bits.frameParity = 0;
  slot->stateBits.bits.quadReady = 1;
  behaviorFlags = slot->behaviorFlags;
  if ((behaviorFlags & EXPGFX_BEHAVIOR_USE_QUAD_TEMPLATE_A) != 0) {
    quadTemplate = (s16 *)(staticDataBase + EXPGFX_STATIC_QUAD_TEMPLATE_A_OFFSET);
  }
  else {
    quadTemplate = (s16 *)(staticDataBase + EXPGFX_STATIC_QUAD_TEMPLATE_B_OFFSET);
  }
  if ((behaviorFlags & EXPGFX_BEHAVIOR_BOUNCE_LOW_Y_VELOCITY) != 0) {
    if (slot->velocityY < lbl_803DF3B4) {
      if ((behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 &&
          slot->velocityY < lbl_803DF3B4) {
        slot->velocityY = -(lbl_803DF3B8 * timeDelta - slot->velocityY);
      }
      else {
        slot->velocityY = -(lbl_803DF3BC * timeDelta - slot->velocityY);
      }
      goto LAB_8009ba84;
    }
  }
  if ((behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 &&
      slot->velocityY > lbl_803DF3C0) {
    slot->velocityY = lbl_803DF3B8 * timeDelta + slot->velocityY;
  }
  else if ((behaviorFlags & EXPGFX_BEHAVIOR_ADD_HIGH_Y_VELOCITY) != 0 &&
           slot->velocityY > lbl_803DF3C0) {
    slot->velocityY = lbl_803DF3BC * timeDelta + slot->velocityY;
  }
LAB_8009ba84:
  frameStep = lbl_803DF3C4;
  *(float *)&slot->posX = slot->velocityX * frameStep + *(float *)&slot->posX;
  *(float *)&slot->posY = slot->velocityY * frameStep + *(float *)&slot->posY;
  *(float *)&slot->posZ = slot->velocityZ * frameStep + *(float *)&slot->posZ;
  if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_SCALE_FROM_ZERO) == 0) {
    if ((slot->renderFlags & EXPGFX_RENDER_SCALE_OVER_LIFETIME) != 0) {
      slot->scaleCounter =
           (short)(int)-((f32)(u32)*(u16 *)&slot->scaleFrames * frameStep -
                         (f32)(u32)*(u16 *)&slot->scaleCounter);
    }
  }
  else {
    slot->scaleCounter =
         (short)(int)((f32)(u32)*(u16 *)&slot->scaleFrames * frameStep +
                     (f32)(u32)*(u16 *)&slot->scaleCounter);
  }
  if (texture == 0) {
    debugPrintf(sExpgfxNoTexture);
  }
  else {
    tex0S = 0;
    tex0T = 0;
    tex1S = 0;
    tex1T = 0;
    if (texture != 0) {
      tex1S = EXPGFX_QUAD_TEXCOORD_MAX;
      tex0S = EXPGFX_QUAD_TEXCOORD_MAX;
      if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX1_T) != 0) {
        tex1T = EXPGFX_QUAD_TEXCOORD_MAX;
        tex1S = 0;
      }
      if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX0_T) != 0) {
        tex0T = EXPGFX_QUAD_TEXCOORD_MAX;
        tex0S = 0;
      }
    }
    slotWords = (s16 *)slot;
    slotWords[0] = quadTemplate[0];
    slotWords[1] = quadTemplate[1];
    slotWords[2] = quadTemplate[2];
    slotWords[4] = tex1S;
    slotWords[5] = tex0S;
    slotWords[8] = quadTemplate[3];
    slotWords[9] = quadTemplate[4];
    slotWords[10] = quadTemplate[5];
    slotWords[0xc] = tex1T;
    slotWords[0xd] = tex0S;
    slotWords[0x10] = quadTemplate[6];
    slotWords[0x11] = quadTemplate[7];
    slotWords[0x12] = quadTemplate[8];
    slotWords[0x14] = tex1T;
    slotWords[0x15] = tex0T;
    slotWords[0x18] = quadTemplate[9];
    slotWords[0x19] = quadTemplate[10];
    slotWords[0x1a] = quadTemplate[0xb];
    slotWords[0x1c] = tex1S;
    slotWords[0x1d] = tex0T;
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

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
#pragma scheduling off
#pragma peephole off
int expgfx_addToTable(uint textureOrResource,uint key0,uint key1,s16 slotType)
{
  ExpgfxTableEntry *entry;
  ExpgfxTableEntry *entryBase;
  u16 *refCount;
  int tableIndex;
  int freeIndex;
  
  tableIndex = 0;
  entryBase = gExpgfxTableEntries;
  entry = entryBase;
  for (; tableIndex < EXPGFX_EXPTAB_ENTRY_COUNT; tableIndex++) {
    if (((entry->refCount != 0 && (entry->textureOrResource == textureOrResource)) &&
        (entry->key0 == key0)) && (entry->key1 == key1)) {
      refCount = &gExpgfxTableEntries[tableIndex].refCount;
      if (*refCount >= EXPGFX_EXPTAB_REFCOUNT_MAX) {
        debugPrintf(sExpgfxAddToTableUsageOverflow);
        return EXPGFX_INVALID_TABLE_INDEX;
      }
      (*refCount)++;
      return (int)(short)tableIndex;
    }
    entry = entry + 1;
  }

  freeIndex = 0;
  for (; freeIndex < EXPGFX_EXPTAB_ENTRY_COUNT; freeIndex++) {
    if (entryBase->refCount == 0) {
      gExpgfxTableEntries[freeIndex].refCount = 1;
      gExpgfxTableEntries[freeIndex].textureOrResource = textureOrResource;
      gExpgfxTableEntries[freeIndex].key0 = key0;
      gExpgfxTableEntries[freeIndex].key1 = key1;
      gExpgfxTableEntries[freeIndex].slotType = slotType;
      return (int)(short)freeIndex;
    }
    entryBase = entryBase + 1;
  }

  debugPrintf(sExpgfxExpTabIsFull);
  return EXPGFX_INVALID_TABLE_INDEX;
}
#pragma peephole reset
#pragma scheduling reset

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
#pragma scheduling off
#pragma peephole off
int expgfx_updateSourceFrameFlags(void *sourceObject)
{
  ExpgfxSourceObject *source;
  u32 bit;
  s32 highBit;
  u32 *sourceMasks;
  u64 sourceMaskHit;
  u32 *poolSourceIds;
  int poolIndex;
  int aggregateState;

  aggregateState = 0;
  source = (ExpgfxSourceObject *)sourceObject;
  lbl_803DD253 = 0;
  poolIndex = 0;
  poolSourceIds = gExpgfxTrackedPoolSourceIds;
  while ((s16)poolIndex < EXPGFX_POOL_COUNT) {
    if ((source->objType == EXPGFX_SOURCE_OBJTYPE_MATCH_ALL) || (*poolSourceIds == (u32)sourceObject)) {
      bit = 1 << ((s16)poolIndex >> 1);
      highBit = (s32)bit >> 0x1f;
      sourceMasks = &gExpgfxTrackedSourceFrameMasks[((u32)(poolIndex & 1)) * 2];
      sourceMaskHit = CONCAT44(highBit & sourceMasks[0],bit & sourceMasks[1]);
      if (sourceMaskHit != 0) {
        gExpgfxStaticPoolFrameFlags[poolIndex] = EXPGFX_SOURCE_FRAME_STATE_B;
        if ((s8)aggregateState == EXPGFX_SOURCE_FRAME_STATE_A) {
          aggregateState = EXPGFX_SOURCE_FRAME_STATE_MIXED;
        }
        else {
          aggregateState = EXPGFX_SOURCE_FRAME_STATE_B;
        }
      }
      else {
        gExpgfxStaticPoolFrameFlags[poolIndex] = EXPGFX_SOURCE_FRAME_STATE_A;
        if ((s8)aggregateState == EXPGFX_SOURCE_FRAME_STATE_B) {
          aggregateState = EXPGFX_SOURCE_FRAME_STATE_MIXED;
        }
        else {
          aggregateState = EXPGFX_SOURCE_FRAME_STATE_A;
        }
      }
    }
    else {
      gExpgfxStaticPoolFrameFlags[poolIndex] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    }
    poolSourceIds = poolSourceIds + 1;
    poolIndex = poolIndex + 1;
  }
  return aggregateState;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: expgfx_free0C
 * EN v1.0 Address: 0x8009E004
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8009E290
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void expgfx_free0C(u32 sourceId)
{
  expgfx_releaseSourceSlots(sourceId);
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
 * Function: expgfx_func09_ret_0
 * EN v1.0 Address: 0x8009E02C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int expgfx_func09_ret_0(void)
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
#pragma scheduling off
#pragma peephole off
void expgfx_renderSourcePools(int sourceId,int sourceMode)
{
  ExpgfxBounds *boundsTemplate;
  u8 *expgfxBase;
  uint uVar1;
  char *poolActiveCounts;
  int *poolSourceIds;
  u8 *poolSourceModes;
  u8 *poolBoundsTemplateIds;
  ExpgfxBounds *poolBounds;
  uint *slotPoolBases;
  int poolIndex;
  
  expgfxBase = gExpgfxRuntimeData;
  poolIndex = 0;
  poolActiveCounts = (char *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
  poolSourceIds = (int *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET);
  poolSourceModes = expgfxBase + EXPGFX_POOL_SOURCE_MODES_OFFSET;
  poolBoundsTemplateIds = expgfxBase + EXPGFX_POOL_BOUNDS_TEMPLATE_IDS_OFFSET;
  poolBounds = (ExpgfxBounds *)(expgfxBase + EXPGFX_POOL_BOUNDS_OFFSET);
  slotPoolBases = (uint *)(expgfxBase + EXPGFX_SLOT_POOL_BASES_OFFSET);
  do {
    if (((*poolActiveCounts != '\0') && ((u32)*poolSourceIds == (u32)sourceId)) &&
       ((int)*poolSourceModes == sourceMode + EXPGFX_POOL_SOURCE_MODE_SOURCE_OFFSET)) {
      boundsTemplate =
          (ExpgfxBounds *)(gExpgfxStaticData +
                           (uint)*poolBoundsTemplateIds * EXPGFX_BOUNDS_TEMPLATE_SIZE);
      uVar1 = fn_8005E97C((double)(poolBounds->minX - playerMapOffsetX),
                           (double)(poolBounds->maxX - playerMapOffsetX),
                           (double)poolBounds->minY,(double)poolBounds->maxY,
                           (double)(poolBounds->minZ - playerMapOffsetZ),
                           (double)(poolBounds->maxZ - playerMapOffsetZ),boundsTemplate);
      if ((uVar1 & EXPGFX_BYTE_VALUE_MASK) != 0) {
        expgfx_renderPool(*slotPoolBases,poolIndex);
      }
    }
    poolActiveCounts = poolActiveCounts + 1;
    poolSourceIds = poolSourceIds + 1;
    poolSourceModes = poolSourceModes + 1;
    poolBoundsTemplateIds = poolBoundsTemplateIds + 1;
    poolBounds = poolBounds + 1;
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
 * Function: expgfx_renderPool
 * EN v1.0 Address: 0x8009E13C
 * EN v1.0 Size: 2984b
 * EN v1.1 Address: 0x8009E3C8
 * EN v1.1 Size: 2984b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void *fn_80022A48(void);
extern int fn_8002073C(void);
extern void fn_800229F8(void *dst, void *src, int blockCount);
extern void fn_800229C4(int wait);
extern int Camera_GetProjectionMatrix(void);
extern void Camera_ApplyFullViewport(void);
extern void *Camera_GetCurrentViewSlot(void);
extern void fn_8005D0E8(int reg, u8 r, u8 g, u8 b, u8 a);
extern void fn_8000F83C(void);
extern void fn_8009AD44(int param);
extern u32 randomGetRange(int min, int max);
extern s16 getAngle(f32 deltaX, f32 deltaZ);
extern void angleToVec2(int angle, f32 *cosOut, f32 *sinOut);
extern void selectTexture(int handle, int slot);
extern void textureSetupFn_800799c0(void);
extern void textRenderSetupFn_80079804(void);
extern void fn_80079180(void);
extern void fn_800796F0(void);
extern void fn_8007C3D0(u32 flag);
extern void fn_8007D670(void);
extern void fn_800703C4(void);
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
void expgfx_renderPool(uint slotPoolBase,int poolIndex)
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
  uint texture;
  uint textureKey0;
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

  dstBuf = fn_80022A48();
  trackedFlags = 0;
  dummy = fn_8002073C();
  Camera_GetProjectionMatrix();
  fn_800229F8(dstBuf, (void *)slotPoolBase, 0x7e);

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
  fn_800703C4();
  if ((short)fn_80008B4C(-1) == 1) {
    return;
  }
  cameraSlot = Camera_GetCurrentViewSlot();
  fn_8005D0E8(0, 0xff, 0xff, 0xff, 0xff);
  alphaMode = -1;
  blendMode = -1;
  zMode = -1;
  zCompLoc = -1;
  fn_800229C4(0);

  slot = (ExpgfxSlot *)((char *)dstBuf - EXPGFX_SLOT_SIZE);
  slotIndex = 0;
  dstBuf = gExpgfxTableEntries;
  do {
    slot = (ExpgfxSlot *)((char *)slot + EXPGFX_SLOT_SIZE);
    tabEntry = &((ExpgfxTableEntry *)dstBuf)[((u32)slot->encodedTableIndex >> 1) &
                                             EXPGFX_SLOT_TABLE_INDEX_MASK];
    textureKey0 = tabEntry->key0;
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
    if ((behaviorFlags & 0x00800000) != 0) {
      f32 ratio = (f32)(s32)lifetimeFrame / (f32)(s32)lifetimeFrameLimit;
      if (ratio < lbl_803DF35C) {
        ratio = lbl_803DF35C;
      } else if (ratio > lbl_803DF354) {
        ratio = lbl_803DF354;
      }
      alpha = (int)((f32)((s32)slot->initialStateByte - 0xff) * ratio + (f32)(u32)slot->initialStateByte);
    } else if ((behaviorFlags & 0x00000200) != 0) {
      f32 ratio = (f32)(s32)lifetimeFrame / (f32)(s32)lifetimeFrameLimit;
      if (ratio < lbl_803DF35C) {
        ratio = lbl_803DF35C;
      } else if (ratio > lbl_803DF354) {
        ratio = lbl_803DF354;
      }
      alpha = (int)((f32)(u32)slot->initialStateByte * ratio);
    } else if ((slot->renderFlags & 0x00400000) != 0 && (f32)(s32)lifetimeFrame <= lifeFraction) {
      f32 ratio = (f32)(s32)lifetimeFrame / lifeFraction;
      if (ratio < lbl_803DF35C) {
        ratio = lbl_803DF35C;
      } else if (ratio > lbl_803DF354) {
        ratio = lbl_803DF354;
      }
      alpha = (int)((f32)(u32)slot->initialStateByte * ratio);
    } else if ((behaviorFlags & 0x00000100) != 0) {
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
    sx = *(f32 *)((char *)slot + 0x90);
    sy = *(f32 *)((char *)slot + 0x94);
    sz = *(f32 *)((char *)slot + 0x98);
    scaleSize = lbl_803DF410 * (f32)(u32)(u16)slot->scaleCounter;
    if ((slot->behaviorFlags & 0x00400000) != 0 && dummy == 0) {
      f32 base = lbl_803DF358 * scaleSize;
      f32 rnd = (f32)(s32)randomGetRange(1, 10);
      scaleFactor = base + base / rnd;
    } else {
      scaleFactor = scaleSize;
    }

    {
      uint behavior = slot->behaviorFlags;
      if ((behavior & 0x04000000) != 0) {
        angleA = 0;
        angleB = 0;
      } else if ((behavior & 0x02000000) != 0) {
        angleA = 0;
        angleB = 0;
      } else if ((behavior & 0x00100000) != 0) {
        if ((slot->renderFlags & 0x00000400) != 0 && textureKey0 != 0) {
          aimDelta[0] = *(f32 *)((char *)cameraSlot + 0xc) - *(f32 *)((char *)textureKey0 + 0x18);
          aimDelta[1] = *(f32 *)((char *)cameraSlot + 0x10) - *(f32 *)((char *)textureKey0 + 0x1c);
          aimDelta[2] = *(f32 *)((char *)cameraSlot + 0x14) - *(f32 *)((char *)textureKey0 + 0x20);
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
    if (textureKey0 != 0 && (slot->renderFlags & 0x00000080) != 0) {
      alpha = (alpha * *(u8 *)((char *)textureKey0 + 0x36)) >> 8;
    }

    if (slotPoolBase != texture) {
      selectTexture(texture, 0);
      slotPoolBase = texture;
    }

    {
      uint flags = slot->renderFlags;
      if ((flags & 0x00000040) != 0) {
        if ((s8)alphaMode != 0) {
          textureSetupFn_800799c0();
          fn_80079180();
          textRenderSetupFn_80079804();
          alphaMode = 0;
        }
      } else if ((flags & 0x00010000) != 0) {
        if (!((s8)alphaMode == 4 && trackedFlags == (int)(flags & 0x00000020))) {
          fn_8007C3D0(flags & 0x00000020);
          alphaMode = 4;
          trackedFlags = (int)(slot->renderFlags & 0x00000020);
        }
      } else if ((s8)alphaMode != 1) {
        textureSetupFn_800799c0();
        fn_800796F0();
        textRenderSetupFn_80079804();
        alphaMode = 1;
      }
    }
    if ((slot->renderFlags & 0x00000001) != 0) {
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
      if ((slot->behaviorFlags & 0x00000010) != 0) {
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
      if ((slot->renderFlags & 0x00000800) != 0) {
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
        alpha = (int)((double)((s32)alpha - 0xff) * (double)((-viewProjW) - lbl_803DF414) /
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
 * Function: expgfx_queueStandalonePools
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
void expgfx_queueStandalonePools(void)
{
  ExpgfxBounds *boundsTemplate;
  float *sourcePosition;
  u8 *expgfxBase;
  char *poolActiveCounts;
  u8 *poolSourceModes;
  u8 *poolBoundsTemplateIds;
  ExpgfxBounds *poolBounds;
  int *poolSourceIds;
  s16 *poolSlotTypeIds;
  uint *slotPoolBases;
  int poolIndex;
  int currentMatrix;
  float queuePosition[3];

  expgfxBase = gExpgfxRuntimeData;
  currentMatrix = Camera_GetViewMatrix();
  poolIndex = 0;
  poolActiveCounts = (char *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
  poolSourceModes = expgfxBase + EXPGFX_POOL_SOURCE_MODES_OFFSET;
  poolBoundsTemplateIds = expgfxBase + EXPGFX_POOL_BOUNDS_TEMPLATE_IDS_OFFSET;
  poolBounds = (ExpgfxBounds *)(expgfxBase + EXPGFX_POOL_BOUNDS_OFFSET);
  poolSourceIds = (int *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET);
  poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
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
        sourcePosition = (float *)*poolSourceIds;
        if (sourcePosition != (float *)0x0) {
          queuePosition[0] = sourcePosition[3] - playerMapOffsetX;
          queuePosition[1] = sourcePosition[4];
          queuePosition[2] = sourcePosition[5] - playerMapOffsetZ;
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
 * Function: expgfx_free08
 * EN v1.0 Address: 0x8009EEB8
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8009F144
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void expgfx_free08(u32 sourceId)
{
  expgfx_releaseSourceSlots(sourceId);
  return;
}

/*
 * --INFO--
 *
 * Function: expgfx_releaseSourceSlots
 * EN v1.0 Address: 0x8009EED8
 * EN v1.0 Size: 260b
 * EN v1.1 Address: 0x8009F164
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void expgfx_releaseSourceSlots(u32 sourceId)
{
  u8 *expgfxBase;
  uint *slotPoolBases;
  u32 *poolSourceIds;
  char *poolActiveCounts;
  s16 *poolSlotTypeIds;
  u8 *poolFrameFlags;
  ExpgfxSlot *slot;
  s16 invalidSlotType;
  int poolIndex;
  int slotIndex;

  expgfxBase = gExpgfxRuntimeData;
  if (sourceId != 0) {
    poolIndex = 0;
    slotPoolBases = (uint *)(expgfxBase + EXPGFX_SLOT_POOL_BASES_OFFSET);
    poolSourceIds = (u32 *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET);
    poolActiveCounts = (char *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
    poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
    poolFrameFlags = gExpgfxStaticPoolFrameFlags;
    do {
      slot = (ExpgfxSlot *)*slotPoolBases;
      if (sourceId == *poolSourceIds) {
        slotIndex = 0;
        invalidSlotType = EXPGFX_INVALID_SLOT_TYPE;
        do {
          if ((slot != (ExpgfxSlot *)0x0) &&
              (((ExpgfxTableEntry *)(expgfxBase + EXPGFX_EXPTAB_OFFSET))
                   [Expgfx_GetSlotTableIndex(slot)].key0 == sourceId)) {
            expgfx_release(*slotPoolBases,poolIndex,slotIndex,0,1);
          }
          slot = slot + 1;
          if (*poolActiveCounts == '\0') {
            *poolSlotTypeIds = invalidSlotType;
          }
          slotIndex = slotIndex + 1;
        } while (slotIndex < EXPGFX_SLOTS_PER_POOL);
        *poolSourceIds = 0;
        *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_NONE;
      }
      slotPoolBases = slotPoolBases + 1;
      poolSourceIds = poolSourceIds + 1;
      poolActiveCounts = poolActiveCounts + 1;
      poolSlotTypeIds = poolSlotTypeIds + 1;
      poolFrameFlags = poolFrameFlags + 1;
      poolIndex = poolIndex + 1;
    } while (poolIndex < EXPGFX_POOL_COUNT);
  }
  return;
}
#pragma peephole reset
#pragma scheduling reset

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
#pragma scheduling off
#pragma peephole off
void expgfx_resetAllPools(void)
{
  ExpgfxTableEntry *tableEntry;
  u8 *staticDataBase;
  u8 *expgfxBase;
  u32 *slotPoolBases;
  u32 *poolActiveMasks;
  char *poolActiveCounts;
  s16 *poolSlotTypeIds;
  int *poolSourceIds;
  u8 *poolFrameFlags;
  int poolIndex;
  ExpgfxSlot *slot;
  int slotIndex;
  u32 activeBit;
  int resourceIndex;
  void *resource;

  staticDataBase = gExpgfxStaticData;
  expgfxBase = gExpgfxRuntimeData;
  poolIndex = 0;
  slotPoolBases = (u32 *)(expgfxBase + EXPGFX_SLOT_POOL_BASES_OFFSET);
  poolActiveMasks = (u32 *)(expgfxBase + EXPGFX_POOL_ACTIVE_MASKS_OFFSET);
  poolActiveCounts = (char *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
  poolSlotTypeIds = (s16 *)(staticDataBase + EXPGFX_STATIC_POOL_SLOT_TYPE_IDS_OFFSET);
  poolSourceIds = (int *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET);
  poolFrameFlags = staticDataBase + EXPGFX_STATIC_POOL_FRAME_FLAGS_OFFSET;
  do {
    slot = (ExpgfxSlot *)*slotPoolBases;
    slotIndex = 0;
    do {
      activeBit = 1 << slotIndex;
      if ((*poolActiveMasks & activeBit) != 0) {
        if (((ExpgfxTableEntry *)(expgfxBase + EXPGFX_EXPTAB_OFFSET))[Expgfx_GetSlotTableIndex(slot)].
            textureOrResource != 0) {
          lbl_803DD258 = 1;
          fn_80054308((void *)((ExpgfxTableEntry *)(expgfxBase + EXPGFX_EXPTAB_OFFSET))
                          [Expgfx_GetSlotTableIndex(slot)].textureOrResource);
          lbl_803DD258 = 0;
        }
        tableEntry =
            (ExpgfxTableEntry *)(expgfxBase + EXPGFX_EXPTAB_OFFSET +
                                 (Expgfx_GetSlotTableIndex(slot) << EXPGFX_TABLE_ENTRY_SHIFT));
        if (tableEntry->refCount != 0) {
          tableEntry->refCount--;
          if (tableEntry->refCount == 0) {
            tableEntry->textureOrResource = 0;
            tableEntry->key0 = 0;
          }
        }
        else {
          debugPrintf(sExpgfxMismatchInAddRemove);
        }
        slot->sequenceId = EXPGFX_INVALID_SEQUENCE_ID;
        *poolActiveMasks = *poolActiveMasks & ~activeBit;
      }
      slot = slot + 1;
      slotIndex = slotIndex + 1;
    } while (slotIndex < EXPGFX_SLOTS_PER_POOL);
    *poolActiveCounts = 0;
    *poolSlotTypeIds = EXPGFX_INVALID_SLOT_TYPE;
    *poolSourceIds = 0;
    *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_NONE;
    DCFlushRange((void *)*slotPoolBases,EXPGFX_POOL_BYTES);
    slotPoolBases = slotPoolBases + 1;
    poolActiveMasks = poolActiveMasks + 1;
    poolActiveCounts = poolActiveCounts + 1;
    poolSlotTypeIds = poolSlotTypeIds + 1;
    poolSourceIds = poolSourceIds + 1;
    poolFrameFlags = poolFrameFlags + 1;
    poolIndex = poolIndex + 1;
  } while (poolIndex < EXPGFX_POOL_COUNT);
  resourceIndex = 0;
  do {
    lbl_803DD258 = 1;
    resource = *(void **)expgfxBase;
    if (resource != (void *)0x0) {
      fn_80054308(resource);
    }
    lbl_803DD258 = 0;
    *(int *)(expgfxBase + 0) = 0;
    *(int *)(expgfxBase + 8) = 0;
    *(int *)(expgfxBase + 4) = 0;
    *(int *)(expgfxBase + 0xc) = 0;
    expgfxBase = expgfxBase + 0x10;
    resourceIndex = resourceIndex + 1;
  } while (resourceIndex < EXPGFX_RESOURCE_TABLE_COUNT);
  return;
}
#pragma peephole reset
#pragma scheduling reset

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

  renderMode = fn_80008B4C(EXPGFX_INVALID_SLOT_TYPE);
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
    (*(code *)(*pDll_expgfx + 0xc))(0);
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
int expgfx_addremove(ExpgfxSpawnConfig *config, int preferredPoolIdx, short slotType, u8 boundsTemplateId)
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
  uint pairIdx;
  uint bit;
  uint hi;
  uint lo;
  uint maskBit;
  short poolIdxOut;
  short slotIdxOut;
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
  poolIdxOut = 0;
  slotIdxOut = 0;
  polePosX = 0;
  polePosY = 0;
  poleVecY = 0;
  poleVecZ = 0;
  if (fn_8002073C() != 0) {
    return EXPGFX_INVALID_POOL_INDEX;
  }
  if (expgfx_reserveSlot(&poolIdxOut, &slotIdxOut, slotType,
                          preferredPoolIdx, (uint)(int)config->attachedSource)
      == EXPGFX_INVALID_POOL_INDEX) {
    return EXPGFX_INVALID_POOL_INDEX;
  }
  {
  slotPoolBases = (uint *)(expgfxBase + EXPGFX_SLOT_POOL_BASES_OFFSET);
  trackedFrameMasks = (u32 *)(expgfxBase + EXPGFX_TRACKED_SOURCE_FRAME_MASKS_OFFSET);

  if ((int)poolIdxOut < EXPGFX_POOL_COUNT) {
    *(int *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET + ((int)poolIdxOut << 2)) =
        (int)config->attachedSource;
  }
  if ((int)poolIdxOut < EXPGFX_POOL_COUNT &&
      (config->behaviorFlags & EXPGFX_BEHAVIOR_TRACK_POOL_SOURCE) != 0) {
    pairIdx = ((uint)poolIdxOut & 1) * 2;
    hi = trackedFrameMasks[pairIdx];
    lo = trackedFrameMasks[pairIdx + 1];
    bit = 1 << ((int)poolIdxOut >> 1);
    trackedFrameMasks[pairIdx + 1] = lo | bit;
    trackedFrameMasks[pairIdx] = hi | (uint)((int)bit >> 0x1f);
  } else {
    pairIdx = ((uint)poolIdxOut & 1) * 2;
    hi = trackedFrameMasks[pairIdx];
    lo = trackedFrameMasks[pairIdx + 1];
    maskBit = ~(uint)(1 << ((int)poolIdxOut >> 1));
    trackedFrameMasks[pairIdx + 1] = lo & maskBit;
    trackedFrameMasks[pairIdx] = hi & (uint)((int)maskBit >> 0x1f);
  }
  slot = (ExpgfxSlot *)(slotPoolBases[(int)poolIdxOut] + slotIdxOut * EXPGFX_SLOT_SIZE);
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
    expgfx_release(slotPoolBases[(int)poolIdxOut], (int)poolIdxOut, (int)slotIdxOut, 1, 1);
    return EXPGFX_INVALID_POOL_INDEX;
  }
  resourceHandle =
      (ExpgfxResourceHandle *)*(u32 *)(expgfxBase + (tableIndex << EXPGFX_TABLE_ENTRY_SHIFT));
  if (resourceHandle == NULL) {
    expgfx_release(slotPoolBases[(int)poolIdxOut], (int)poolIdxOut, (int)slotIdxOut, 1, 1);
    return EXPGFX_INVALID_POOL_INDEX;
  }
  if (resourceHandle->refCount >= EXPGFX_EXPTAB_REFCOUNT_MAX) {
    expgfx_release(slotPoolBases[(int)poolIdxOut], (int)poolIdxOut, (int)slotIdxOut, 1, 1);
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
    expgfx_release(slotPoolBases[(int)poolIdxOut], (int)poolIdxOut, (int)slotIdxOut, 1, 1);
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
    if ((slot->behaviorFlags & 1) != 0) {
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

  poolSourceModesByte = expgfxBase + EXPGFX_POOL_SOURCE_MODES_OFFSET + (s16)poolIdxOut;
  modeFlag = (config->behaviorFlags & EXPGFX_BEHAVIOR_SOURCE_MODE_FLAG) != 0 ? 1 : 0;
  *poolSourceModesByte = modeFlag;
  if (*poolSourceModesByte != 0 &&
      (config->behaviorFlags & EXPGFX_BEHAVIOR_TRACK_POOL_SOURCE) == 0) {
    *poolSourceModesByte = *poolSourceModesByte + 1;
  }
  *(expgfxBase + EXPGFX_POOL_BOUNDS_TEMPLATE_IDS_OFFSET + (s16)poolIdxOut) =
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
 * Function: expgfx_resetPoolResources
 * EN v1.0 Address: 0x8009FCDC
 * EN v1.0 Size: 416b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void expgfx_resetPoolResources(void)
{
  ExpgfxResourceEntry *resourceEntry;
  u8 *expgfxBase;
  u32 *poolActiveMasks;
  u8 *poolActiveCounts;
  s16 *poolSlotTypeIds;
  u8 *poolFrameFlags;
  u8 *poolSourceModes;
  u32 *poolSourceIds;
  int groupIndex;
  int resourceIndex;

  expgfxBase = gExpgfxRuntimeData;
  asm {
    bl expgfx_initialise
  }
  poolActiveMasks = (u32 *)(expgfxBase + EXPGFX_POOL_ACTIVE_MASKS_OFFSET);
  poolActiveCounts = expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET;
  poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
  poolFrameFlags = gExpgfxStaticPoolFrameFlags;
  poolSourceModes = expgfxBase + EXPGFX_POOL_SOURCE_MODES_OFFSET;
  poolSourceIds = (u32 *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET);
  for (groupIndex = 0; groupIndex < EXPGFX_POOL_GROUP_COUNT; groupIndex++) {
    poolActiveMasks[0] = 0;
    poolActiveCounts[0] = 0;
    poolSlotTypeIds[0] = EXPGFX_INVALID_SLOT_TYPE;
    poolFrameFlags[0] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[0] = 0;
    poolSourceIds[0] = 0;
    poolActiveMasks[1] = 0;
    poolActiveCounts[1] = 0;
    poolSlotTypeIds[1] = EXPGFX_INVALID_SLOT_TYPE;
    poolFrameFlags[1] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[1] = 0;
    poolSourceIds[1] = 0;
    poolActiveMasks[2] = 0;
    poolActiveCounts[2] = 0;
    poolSlotTypeIds[2] = EXPGFX_INVALID_SLOT_TYPE;
    poolFrameFlags[2] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[2] = 0;
    poolSourceIds[2] = 0;
    poolActiveMasks[3] = 0;
    poolActiveCounts[3] = 0;
    poolSlotTypeIds[3] = EXPGFX_INVALID_SLOT_TYPE;
    poolFrameFlags[3] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[3] = 0;
    poolSourceIds[3] = 0;
    poolActiveMasks[4] = 0;
    poolActiveCounts[4] = 0;
    poolSlotTypeIds[4] = EXPGFX_INVALID_SLOT_TYPE;
    poolFrameFlags[4] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[4] = 0;
    poolSourceIds[4] = 0;
    poolActiveMasks[5] = 0;
    poolActiveCounts[5] = 0;
    poolSlotTypeIds[5] = EXPGFX_INVALID_SLOT_TYPE;
    poolFrameFlags[5] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[5] = 0;
    poolSourceIds[5] = 0;
    poolActiveMasks[6] = 0;
    poolActiveCounts[6] = 0;
    poolSlotTypeIds[6] = EXPGFX_INVALID_SLOT_TYPE;
    poolFrameFlags[6] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[6] = 0;
    poolSourceIds[6] = 0;
    poolActiveMasks[7] = 0;
    poolActiveCounts[7] = 0;
    poolSlotTypeIds[7] = EXPGFX_INVALID_SLOT_TYPE;
    poolFrameFlags[7] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[7] = 0;
    poolSourceIds[7] = 0;
    poolActiveMasks = poolActiveMasks + 8;
    poolActiveCounts = poolActiveCounts + 8;
    poolSlotTypeIds = poolSlotTypeIds + 8;
    poolFrameFlags = poolFrameFlags + 8;
    poolSourceModes = poolSourceModes + 8;
    poolSourceIds = poolSourceIds + 8;
  }
  *(u32 *)(expgfxBase + EXPGFX_TRACKED_SOURCE_FRAME_MASKS_OFFSET + 4) = 0;
  *(u32 *)(expgfxBase + EXPGFX_TRACKED_SOURCE_FRAME_MASKS_OFFSET) = 0;
  *(u32 *)(expgfxBase + EXPGFX_TRACKED_SOURCE_FRAME_MASKS_OFFSET + 0xC) = 0;
  *(u32 *)(expgfxBase + EXPGFX_TRACKED_SOURCE_FRAME_MASKS_OFFSET + 8) = 0;
  lbl_803DD258 = 1;
  resourceIndex = 0;
  resourceEntry = (ExpgfxResourceEntry *)(expgfxBase + EXPGFX_RESOURCE_TABLE_OFFSET);
  do {
    if (resourceEntry->resource != (void *)0x0) {
      fn_80054308(resourceEntry->resource);
    }
    resourceEntry->resource = (void *)0x0;
    resourceEntry->tableKeyType = 0;
    resourceEntry->evictionScore = 0;
    resourceEntry->wordC = 0;
    resourceEntry = resourceEntry + 1;
    resourceIndex = resourceIndex + 1;
  } while (resourceIndex < EXPGFX_RESOURCE_TABLE_COUNT);
  lbl_803DD258 = 0;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: expgfx_releaseSlotPoolHandles
 * EN v1.0 Address: 0x8009FE7C
 * EN v1.0 Size: 84b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void expgfx_releaseSlotPoolHandles(void)
{
  int poolIndex;
  u32 *slotPoolBases;

  asm {
    bl expgfx_initialise
  }
  poolIndex = 0;
  slotPoolBases = gExpgfxSlotPoolBases;
  do {
    fn_80023800(*slotPoolBases);
    slotPoolBases = slotPoolBases + 1;
    poolIndex = poolIndex + 1;
  } while (poolIndex < EXPGFX_POOL_COUNT);
  return;
}
