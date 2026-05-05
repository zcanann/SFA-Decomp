#include "ghidra_import.h"
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
extern void fn_8009B9C8(u8 sourceMode,int sourceId,int param_3);
extern undefined8 FUN_80135810();
extern void fn_801378A8(char *message,...);
extern double FUN_80136594();
extern undefined4 FUN_802420e0();
extern undefined4 FUN_802475e4();
extern void PSMTXMultVec(int matrix,float *src,float *dst);
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
extern uint gExpgfxPoolActiveMasks;
extern uint gExpgfxSlotPoolBases;
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
extern undefined4* lbl_803DCA88;
extern u8 lbl_803DC7B0;
extern u8 lbl_803DD253;
extern u8 lbl_803DD254;
extern volatile f32 lbl_803DB414;
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
extern f32 lbl_803DCDD8;
extern f32 lbl_803DCDDC;
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
extern u8 lbl_8039AB58[];
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

typedef struct ExpgfxResourceEntry {
  void *resource;
  u32 word4;
  u32 word8;
  u32 wordC;
} ExpgfxResourceEntry;

typedef union ExpgfxSlotStateBits {
  u8 value;
  struct {
    u8 padHi : 4;
    u8 initPhase : 2;
    u8 quadReady : 1;
    u8 frameParity : 1;
  } bits;
} ExpgfxSlotStateBits;

typedef struct ExpgfxSlot {
  u8 pad00[0x06];
  s16 lifetimeFrame;
  u8 pad08[0x0F - 0x08];
  u8 initialStateByte;
  u8 pad10[0x16 - 0x10];
  s16 lifetimeFrameLimit;
  u8 pad18[0x26 - 0x18];
  s16 sequenceId;
  u8 pad28[0x40 - 0x28];
  s16 sourceVecX;
  s16 sourceVecY;
  s16 sourceVecZ;
  u8 pad46[0x48 - 0x46];
  int sourcePosX;
  int sourcePosY;
  int sourcePosZ;
  int sourcePosW;
  int posX;
  int posY;
  int posZ;
  int startPosX;
  int startPosY;
  int startPosZ;
  float velocityX;
  float velocityY;
  float velocityZ;
  u32 behaviorFlags;
  u32 renderFlags;
  s16 scaleCounter;
  s16 scaleTarget;
  s16 scaleFrames;
  u8 encodedTableIndex;
  ExpgfxSlotStateBits stateBits;
  u8 colorByte0;
  u8 colorByte1;
  u8 colorByte2;
  u8 pad8F[0xA0 - 0x8F];
} ExpgfxSlot;

static inline ExpgfxTableEntry *Expgfx_GetTableEntry(int tableIndex) {
  return &gExpgfxTableEntries[tableIndex];
}

static inline u8 Expgfx_GetSlotTableIndex(const ExpgfxSlot *slot) {
  return ((u32)slot->encodedTableIndex >> 1) & 0x7F;
}

static inline void Expgfx_SetSlotTableIndex(ExpgfxSlot *slot, u8 tableIndex) {
  slot->encodedTableIndex = (u8)((tableIndex << 1) | (slot->encodedTableIndex & 1));
}

static inline ExpgfxSlot *Expgfx_GetSlot(int poolIndex, int slotIndex) {
  return (ExpgfxSlot *)((&gExpgfxSlotPoolBases)[poolIndex] + slotIndex * EXPGFX_SLOT_SIZE);
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

  expgfxBase = lbl_8039AB58;
  activeMask = 1 << slotIndex;
  poolActiveMask = (u32 *)(expgfxBase + EXPGFX_POOL_ACTIVE_MASKS_OFFSET +
                           poolIndex * sizeof(u32));
  if ((activeMask & *poolActiveMask) != 0) {
    slot = (ExpgfxSlot *)(slotPoolBase + slotIndex * EXPGFX_SLOT_SIZE);
    slot->behaviorFlags = 0;
    if (freeTexture == 0) {
      tableTextureResources = expgfxBase + EXPGFX_EXPTAB_TEXTURE_RESOURCE_OFFSET;
      tableOffset = Expgfx_GetSlotTableIndex(slot) << 4;
      if (*(u32 *)(tableTextureResources + tableOffset) != 0) {
        lbl_803DD258 = 1;
        fn_80054308(*(void **)(tableTextureResources + (Expgfx_GetSlotTableIndex(slot) << 4)));
        lbl_803DD258 = 0;
      }
      tableOffset = Expgfx_GetSlotTableIndex(slot) << 4;
      refCount = (u16 *)(expgfxBase + EXPGFX_EXPTAB_REFCOUNT_OFFSET + tableOffset);
      if (*refCount != 0) {
        (*refCount)--;
        if (*refCount == 0) {
          *(u32 *)(tableTextureResources + tableOffset) = 0;
          *(u32 *)(expgfxBase + EXPGFX_EXPTAB_OFFSET + tableOffset) = 0;
        }
      }
      else {
        fn_801378A8(sExpgfxMismatchInAddRemove);
      }
    }
    slot->sequenceId = -1;
    if ((clearActive & 0xff) != 0) {
      DCFlushRange(slot,EXPGFX_SLOT_SIZE);
    }
    *poolActiveMask = *poolActiveMask & ~activeMask;
    poolActiveCount =
        (char *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET + poolIndex);
    (*poolActiveCount)--;
    if (*poolActiveCount == '\0') {
      gExpgfxStaticPoolSlotTypeIds[poolIndex] = -1;
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

  poolIndex = 0;
  expgfxBase = lbl_8039AB58;
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
          fn_801378A8(sExpgfxMismatchInAddRemove);
        }
        slot->sequenceId = -1;
        *poolActiveMasks = *poolActiveMasks & ~(1 << slotIndex);
      }
      slot = slot + 1;
      slotIndex = slotIndex + 1;
    } while (slotIndex < EXPGFX_SLOTS_PER_POOL);
    *poolActiveCounts = 0;
    *poolSlotTypeIds = -1;
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
int expgfx_reserveSlot(short *poolIndexOut,undefined2 *slotIndexOut,short slotType,
                       int preferredPoolIndex,uint sourceId)
{
  bool foundPool;
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

  poolIndex = -1;
  foundPool = false;
  scanPoolIndex = 0;
  expgfxBase = lbl_8039AB58;
  sourceIdBatch = (int *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET);
  slotTypeBatch = gExpgfxStaticPoolSlotTypeIds;
  poolActiveCounts = (char *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
  emptyPoolScan = poolActiveCounts;
  batchCount = EXPGFX_POOL_SEARCH_BATCH_COUNT;
  activeCountBatch = emptyPoolScan;
  do {
    if (((sourceId == *sourceIdBatch) && (slotType == *slotTypeBatch)) &&
        (*activeCountBatch < EXPGFX_SLOTS_PER_POOL)) {
      poolIndex = (short)scanPoolIndex;
      foundPool = true;
      break;
    }
    if (((sourceId == sourceIdBatch[1]) && (slotType == slotTypeBatch[1])) &&
        (activeCountBatch[1] < EXPGFX_SLOTS_PER_POOL)) {
      poolIndex = (short)(scanPoolIndex + 1);
      foundPool = true;
      scanPoolIndex = scanPoolIndex + 1;
      break;
    }
    if (((sourceId == sourceIdBatch[2]) && (slotType == slotTypeBatch[2])) &&
        (activeCountBatch[2] < EXPGFX_SLOTS_PER_POOL)) {
      poolIndex = (short)(scanPoolIndex + 2);
      foundPool = true;
      scanPoolIndex = scanPoolIndex + 2;
      break;
    }
    if (((sourceId == sourceIdBatch[3]) && (slotType == slotTypeBatch[3])) &&
        (activeCountBatch[3] < EXPGFX_SLOTS_PER_POOL)) {
      poolIndex = (short)(scanPoolIndex + 3);
      foundPool = true;
      scanPoolIndex = scanPoolIndex + 3;
      break;
    }
    if (((sourceId == sourceIdBatch[4]) && (slotType == slotTypeBatch[4])) &&
        (activeCountBatch[4] < EXPGFX_SLOTS_PER_POOL)) {
      poolIndex = (short)(scanPoolIndex + 4);
      foundPool = true;
      scanPoolIndex = scanPoolIndex + 4;
      break;
    }
    sourceIdBatch = sourceIdBatch + EXPGFX_POOL_SEARCH_BATCH_SIZE;
    slotTypeBatch = slotTypeBatch + EXPGFX_POOL_SEARCH_BATCH_SIZE;
    activeCountBatch = activeCountBatch + EXPGFX_POOL_SEARCH_BATCH_SIZE;
    scanPoolIndex = scanPoolIndex + EXPGFX_POOL_SEARCH_BATCH_SIZE;
    batchCount = batchCount + -1;
  } while (batchCount != 0);
  if (foundPool) {
    freeSlotIndex = 0;
    poolActiveMask = (uint *)(expgfxBase + EXPGFX_POOL_ACTIVE_MASKS_OFFSET) + poolIndex;
    batchCount = EXPGFX_SLOTS_PER_POOL;
    do {
      if ((1 << freeSlotIndex & *poolActiveMask) == 0) {
        *slotIndexOut = (short)freeSlotIndex;
        *poolIndexOut = poolIndex;
        *poolActiveMask = *poolActiveMask | 1 << freeSlotIndex;
        poolActiveCounts[poolIndex] = poolActiveCounts[poolIndex] + '\x01';
        return 1;
      }
      freeSlotIndex = freeSlotIndex + 1;
      batchCount = batchCount + -1;
    } while (batchCount != 0);
  }
  foundPool = false;
  if (preferredPoolIndex != -1) {
    if ((preferredPoolIndex != -1) &&
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
        ((char *)(lbl_8039AB58 + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET))[poolIndex] =
            ((char *)(lbl_8039AB58 + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET))[poolIndex] + '\x01';
        return 1;
      }
      freeSlotIndex = freeSlotIndex + 1;
      batchCount = batchCount + -1;
    } while (batchCount != 0);
  }
  return 0xffffffff;
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
  if ((behaviorFlags & EXPGFX_BEHAVIOR_USE_QUAD_TEMPLATE_A) == 0) {
    quadTemplate = (s16 *)(staticDataBase + EXPGFX_STATIC_QUAD_TEMPLATE_B_OFFSET);
  }
  else {
    quadTemplate = (s16 *)(staticDataBase + EXPGFX_STATIC_QUAD_TEMPLATE_A_OFFSET);
  }
  if ((behaviorFlags & EXPGFX_BEHAVIOR_BOUNCE_LOW_Y_VELOCITY) != 0) {
    if (slot->velocityY < lbl_803DF3B4) {
      if (((behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) == 0) ||
          (lbl_803DF3B4 <= slot->velocityY)) {
        slot->velocityY = -(lbl_803DF3BC * lbl_803DB414 - slot->velocityY);
      }
      else {
        slot->velocityY = -(lbl_803DF3B8 * lbl_803DB414 - slot->velocityY);
      }
      goto LAB_8009ba84;
    }
  }
  if (((behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) == 0) ||
      (slot->velocityY <= lbl_803DF3C0)) {
    if (((behaviorFlags & EXPGFX_BEHAVIOR_ADD_HIGH_Y_VELOCITY) != 0) &&
        (lbl_803DF3C0 < slot->velocityY)) {
      slot->velocityY = lbl_803DF3BC * lbl_803DB414 + slot->velocityY;
    }
  }
  else {
    slot->velocityY = lbl_803DF3B8 * lbl_803DB414 + slot->velocityY;
  }
LAB_8009ba84:
  frameStep = lbl_803DF3C4;
  *(float *)&slot->posX = slot->velocityX * frameStep + *(float *)&slot->posX;
  *(float *)&slot->posY = slot->velocityY * frameStep + *(float *)&slot->posY;
  *(float *)&slot->posZ = slot->velocityZ * frameStep + *(float *)&slot->posZ;
  if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_SCALE_FROM_ZERO) == 0) {
    if ((slot->renderFlags & EXPGFX_RENDER_SCALE_OVER_LIFETIME) != 0) {
      slot->scaleCounter =
           (short)(int)-(Expgfx_U16AsDouble((u16)slot->scaleFrames) * frameStep -
                         Expgfx_U16AsDouble((u16)slot->scaleCounter));
    }
  }
  else {
    slot->scaleCounter =
         (short)(int)(Expgfx_U16AsDouble((u16)slot->scaleFrames) * frameStep +
                     Expgfx_U16AsDouble((u16)slot->scaleCounter));
  }
  if (texture != 0) {
    tex0S = 0;
    tex0T = 0;
    tex1S = 0;
    tex1T = 0;
    if (texture != 0) {
      tex1S = 0x80;
      tex0S = 0x80;
      if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX1_T) != 0) {
        tex1T = 0x80;
        tex1S = 0;
      }
      if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX0_T) != 0) {
        tex0T = 0x80;
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
  else {
    fn_801378A8(sExpgfxNoTexture);
  }
  return;
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
#pragma scheduling off
#pragma peephole off
int expgfx_addToTable(uint textureOrResource,uint key0,uint key1,s16 slotType)
{
  ExpgfxTableEntry *entryBase;
  ExpgfxTableEntry *entry;
  u16 *refCount;
  int tableIndex;
  int freeIndex;
  
  tableIndex = 0;
  entryBase = Expgfx_GetTableEntry(0);
  entry = entryBase;
  for (; tableIndex < EXPGFX_POOL_COUNT; tableIndex++) {
    if (((entry->refCount != 0 && (entry->textureOrResource == textureOrResource)) &&
        (entry->key0 == key0)) && (entry->key1 == key1)) {
      refCount = &gExpgfxTableEntries[tableIndex].refCount;
      if (*refCount >= EXPGFX_EXPTAB_REFCOUNT_MAX) {
        fn_801378A8(sExpgfxAddToTableUsageOverflow);
        return EXPGFX_INVALID_TABLE_INDEX;
      }
      (*refCount)++;
      return (int)(short)tableIndex;
    }
    entry = entry + 1;
  }

  freeIndex = 0;
  for (; freeIndex < EXPGFX_POOL_COUNT; freeIndex++) {
    if (entryBase->refCount == 0) {
      entry = &gExpgfxTableEntries[freeIndex];
      entry->refCount = 1;
      entry->textureOrResource = textureOrResource;
      entry->key0 = key0;
      entry->key1 = key1;
      entry->slotType = slotType;
      return (int)(short)freeIndex;
    }
    entryBase = entryBase + 1;
  }

  fn_801378A8(sExpgfxExpTabIsFull);
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
  u8 *poolFrameFlags;
  int aggregateState;
  int poolIndex;

  aggregateState = 0;
  source = (ExpgfxSourceObject *)sourceObject;
  poolIndex = 0;
  lbl_803DD253 = 0;
  poolSourceIds = gExpgfxTrackedPoolSourceIds;
  poolFrameFlags = gExpgfxStaticPoolFrameFlags;
  while ((s16)poolIndex < EXPGFX_POOL_COUNT) {
    if ((source->objType == 0xd4) || (*poolSourceIds == (u32)sourceObject)) {
      bit = 1 << ((s16)poolIndex >> 1);
      highBit = (s32)bit >> 0x1f;
      sourceMasks = &gExpgfxTrackedSourceFrameMasks[((u32)(poolIndex & 1)) * 2];
      sourceMaskHit = CONCAT44(highBit & sourceMasks[0],bit & sourceMasks[1]);
      if (sourceMaskHit != 0) {
        *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_B;
        if (aggregateState == EXPGFX_SOURCE_FRAME_STATE_A) {
          aggregateState = EXPGFX_SOURCE_FRAME_STATE_MIXED;
        }
        else {
          aggregateState = EXPGFX_SOURCE_FRAME_STATE_B;
        }
      }
      else {
        *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_A;
        if (aggregateState == EXPGFX_SOURCE_FRAME_STATE_B) {
          aggregateState = EXPGFX_SOURCE_FRAME_STATE_MIXED;
        }
        else {
          aggregateState = EXPGFX_SOURCE_FRAME_STATE_A;
        }
      }
    }
    else {
      *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_NONE;
    }
    poolSourceIds = poolSourceIds + 1;
    poolFrameFlags = poolFrameFlags + 1;
    poolIndex = poolIndex + 1;
  }
  return aggregateState;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_8009E004
 * EN v1.0 Address: 0x8009E004
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8009E290
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8009E004(u32 sourceId)
{
  expgfx_releaseSourceSlots(sourceId);
  return;
}

/*
 * --INFO--
 *
 * Function: fn_8009E024
 * EN v1.0 Address: 0x8009E024
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8009E024(void)
{
}

/*
 * --INFO--
 *
 * Function: fn_8009E028
 * EN v1.0 Address: 0x8009E028
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8009E028(void)
{
}

/*
 * --INFO--
 *
 * Function: fn_8009E02C
 * EN v1.0 Address: 0x8009E02C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fn_8009E02C(void)
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
  ExpgfxBounds *poolBounds;
  u8 *expgfxBase;
  uint uVar1;
  int poolIndex;
  uint *slotPoolBases;
  u8 *poolBoundsTemplateIds;
  u8 *poolSourceModes;
  int *poolSourceIds;
  char *poolActiveCounts;
  
  expgfxBase = lbl_8039AB58;
  poolIndex = 0;
  poolActiveCounts = (char *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
  poolSourceIds = (int *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET);
  poolSourceModes = expgfxBase + EXPGFX_POOL_SOURCE_MODES_OFFSET;
  poolBoundsTemplateIds = expgfxBase + EXPGFX_POOL_BOUNDS_TEMPLATE_IDS_OFFSET;
  poolBounds = (ExpgfxBounds *)(expgfxBase + EXPGFX_POOL_BOUNDS_OFFSET);
  slotPoolBases = (uint *)(expgfxBase + EXPGFX_SLOT_POOL_BASES_OFFSET);
  do {
    if (((*poolActiveCounts != '\0') && ((u32)*poolSourceIds == (u32)sourceId)) &&
       ((int)*poolSourceModes == sourceMode + 1)) {
      boundsTemplate = (ExpgfxBounds *)(gExpgfxStaticData + (uint)*poolBoundsTemplateIds * 0x18);
      uVar1 = fn_8005E97C((double)(poolBounds->minX - lbl_803DCDD8),
                           (double)(poolBounds->maxX - lbl_803DCDD8),
                           (double)poolBounds->minY,(double)poolBounds->maxY,
                           (double)(poolBounds->minZ - lbl_803DCDDC),
                           (double)(poolBounds->maxZ - lbl_803DCDDC),boundsTemplate);
      if ((uVar1 & 0xff) != 0) {
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
void expgfx_renderPool(uint slotPoolBase,int poolIndex)
{
}

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
  ExpgfxBounds *poolBounds;
  float *sourcePosition;
  u8 *expgfxBase;
  u8 *poolSourceModes;
  u8 *poolBoundsTemplateIds;
  int *poolSourceIds;
  char *poolActiveCounts;
  s16 *poolSlotTypeIds;
  uint *slotPoolBases;
  int currentMatrix;
  int poolIndex;
  float queuePosition[3];

  expgfxBase = lbl_8039AB58;
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
    if ((*poolActiveCounts != '\0') && (*poolSourceModes == 0)) {
      boundsTemplate = (ExpgfxBounds *)(gExpgfxStaticData + (uint)*poolBoundsTemplateIds * 0x18);
      if (fn_8005E97C((double)(poolBounds->minX - lbl_803DCDD8),
                      (double)(poolBounds->maxX - lbl_803DCDD8),
                      (double)poolBounds->minY,(double)poolBounds->maxY,
                      (double)(poolBounds->minZ - lbl_803DCDDC),
                      (double)(poolBounds->maxZ - lbl_803DCDDC),boundsTemplate) != 0) {
        sourcePosition = (float *)*poolSourceIds;
        if (sourcePosition != (float *)0x0) {
          queuePosition[0] = sourcePosition[3] - lbl_803DCDD8;
          queuePosition[1] = sourcePosition[4];
          queuePosition[2] = sourcePosition[5] - lbl_803DCDDC;
        }
        else {
          queuePosition[0] =
              lbl_803DF358 * (poolBounds->minX + poolBounds->maxX) - lbl_803DCDD8;
          queuePosition[1] = lbl_803DF358 * (poolBounds->minY + poolBounds->maxY);
          queuePosition[2] =
              lbl_803DF358 * (poolBounds->minZ + poolBounds->maxZ) - lbl_803DCDDC;
        }
        PSMTXMultVec(currentMatrix,queuePosition,queuePosition);
        if (*poolSourceIds != 0) {
          queuePosition[2] = queuePosition[2] - (float)(*poolSlotTypeIds & 0x21);
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
 * Function: fn_8009EEB8
 * EN v1.0 Address: 0x8009EEB8
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x8009F144
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8009EEB8(u32 sourceId)
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

  expgfxBase = lbl_8039AB58;
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
        invalidSlotType = -1;
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
  ExpgfxSlot *slot;
  u8 *expgfxBase;
  int *poolSourceIds;
  s16 *poolSlotTypeIds;
  u8 *poolFrameFlags;
  char *poolActiveCounts;
  u32 *poolActiveMasks;
  u32 *slotPoolBases;
  u8 *staticDataBase;
  u32 activeBit;
  int poolIndex;
  int resourceIndex;
  int slotIndex;
  void *resource;

  staticDataBase = gExpgfxStaticData;
  expgfxBase = lbl_8039AB58;
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
            (ExpgfxTableEntry *)(expgfxBase + EXPGFX_EXPTAB_OFFSET + (Expgfx_GetSlotTableIndex(slot) << 4));
        if (tableEntry->refCount != 0) {
          tableEntry->refCount--;
          if (tableEntry->refCount == 0) {
            tableEntry->textureOrResource = 0;
            tableEntry->key0 = 0;
          }
        }
        else {
          fn_801378A8(sExpgfxMismatchInAddRemove);
        }
        slot->sequenceId = -1;
        *poolActiveMasks = *poolActiveMasks & ~activeBit;
      }
      slot = slot + 1;
      slotIndex = slotIndex + 1;
    } while (slotIndex < EXPGFX_SLOTS_PER_POOL);
    *poolActiveCounts = 0;
    *poolSlotTypeIds = -1;
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
  } while (resourceIndex < 0x20);
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
  
  renderMode = fn_80008B4C(-1);
  if ((short)renderMode != 1) {
    frameValue = lbl_803DD25C + (frameStep = lbl_803DB414);
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
    fn_8009B9C8((u8)sourceMode,sourceId,0);
    lbl_803DC7B0 = 0;
    poolIndex = EXPGFX_POOL_COUNT;
    while ((u8)poolIndex > 0) {
      poolIndex--;
      gExpgfxStaticPoolFrameFlags[(u8)poolIndex] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    }
    (*(code *)(*lbl_803DCA88 + 0xc))(0);
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
void expgfx_addremove(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5,
                      undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                      undefined4 param_10,short param_11,undefined param_12,undefined4 param_13,
                      undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  ExpgfxSpawnConfig *spawnConfig;
  ExpgfxSlot *slot;
  float fVar1;
  uint uVar2;
  uint uVar3;
  undefined2 uVar4;
  int *spawnWords;
  int iVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  undefined2 *puVar10;
  byte *pbVar11;
  uint uVar12;
  int iVar13;
  uint uVar14;
  int iVar15;
  int *piVar16;
  ExpgfxAttachedSourceState *attachedSource;
  undefined2 *puVar18;
  double extraout_f1;
  double dVar19;
  double dVar20;
  double dVar21;
  undefined8 uVar22;
  undefined2 local_58;
  short local_56 [3];
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  
  uVar22 = FUN_8028682c();
  spawnConfig = (ExpgfxSpawnConfig *)((ulonglong)uVar22 >> 0x20);
  spawnWords = (int *)spawnConfig;
  local_56[0] = 0;
  local_58 = 0;
  dVar19 = extraout_f1;
  iVar6 = FUN_800176d0();
  if ((iVar6 == 0) &&
     (iVar6 = expgfx_reserveSlot(local_56,&local_58,param_11,(int)uVar22,
                                 (int)spawnConfig->attachedSource), iVar6 != -1)) {
    uVar3 = (uint)local_56[0];
    if ((int)uVar3 < EXPGFX_POOL_COUNT) {
      (&gExpgfxPoolSourceIds)[uVar3] = (int)spawnConfig->attachedSource;
    }
    if (((int)uVar3 < EXPGFX_POOL_COUNT) &&
        ((spawnConfig->behaviorFlags & EXPGFX_BEHAVIOR_TRACK_POOL_SOURCE) != 0)) {
      uVar2 = uVar3 & 1;
      uVar12 = (&gExpgfxTrackedPoolMaskHighWords)[uVar2 * EXPGFX_TRACKED_POOL_MASK_WORD_STRIDE];
      uVar14 = (&gExpgfxTrackedPoolMaskLowWords)[uVar2 * EXPGFX_TRACKED_POOL_MASK_WORD_STRIDE];
      uVar8 = 1 << ((int)uVar3 >> 1);
      uVar9 = uVar14 | uVar8;
      (&gExpgfxTrackedPoolMaskLowWords)[uVar2 * EXPGFX_TRACKED_POOL_MASK_WORD_STRIDE] = uVar9;
      (&gExpgfxTrackedPoolMaskHighWords)[uVar2 * EXPGFX_TRACKED_POOL_MASK_WORD_STRIDE] =
          uVar12 | (int)uVar8 >> 0x1f;
    }
    else {
      uVar2 = uVar3 & 1;
      uVar12 = (&gExpgfxTrackedPoolMaskHighWords)[uVar2 * EXPGFX_TRACKED_POOL_MASK_WORD_STRIDE];
      uVar14 = (&gExpgfxTrackedPoolMaskLowWords)[uVar2 * EXPGFX_TRACKED_POOL_MASK_WORD_STRIDE];
      uVar8 = ~(1 << ((int)uVar3 >> 1));
      uVar9 = uVar14 & uVar8;
      (&gExpgfxTrackedPoolMaskLowWords)[uVar2 * EXPGFX_TRACKED_POOL_MASK_WORD_STRIDE] = uVar9;
      (&gExpgfxTrackedPoolMaskHighWords)[uVar2 * EXPGFX_TRACKED_POOL_MASK_WORD_STRIDE] =
          uVar12 & (int)uVar8 >> 0x1f;
    }
    piVar16 = &DAT_8039b7b8 + (uVar3 & 1) * 2;
    slot = Expgfx_GetSlot(uVar3, local_58);
    puVar18 = (undefined2 *)slot;
    gExpgfxSequenceCounter = gExpgfxSequenceCounter + 1;
    if (30000 < gExpgfxSequenceCounter) {
      gExpgfxSequenceCounter = 0;
    }
    slot->sequenceId = gExpgfxSequenceCounter;
    slot->behaviorFlags = spawnConfig->behaviorFlags;
    slot->renderFlags = spawnConfig->renderFlags;
    slot->stateBits.value = slot->stateBits.value & ~EXPGFX_SLOT_STATE_INIT_PHASE_MASK;
    iVar6 = FUN_80081134(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)spawnConfig->tableKeyType,uVar9,uVar12,uVar14,piVar16,param_14,
                         param_15,param_16);
    iVar6 = (int)(short)iVar6;
    if (iVar6 < 0) {
      expgfx_release((&gExpgfxSlotPoolBases)[local_56[0]],(int)local_56[0],(int)local_58,1,1);
    }
    else {
      iVar7 = (&DAT_8039b7b8)[iVar6 * 4];
      if (iVar7 == 0) {
        expgfx_release((&gExpgfxSlotPoolBases)[local_56[0]],(int)local_56[0],(int)local_58,1,1);
      }
      else if (*(short *)(iVar7 + 0xe) == -1) {
        expgfx_release((&gExpgfxSlotPoolBases)[local_56[0]],(int)local_56[0],(int)local_58,1,1);
      }
      else {
        *(short *)(iVar7 + 0xe) = *(short *)(iVar7 + 0xe) + 1;
        *(ushort *)(iVar7 + 0x14) = (ushort)spawnConfig->linkGroup;
        attachedSource = (ExpgfxAttachedSourceState *)spawnConfig->attachedSource;
        iVar13 = 0;
        if (attachedSource == (ExpgfxAttachedSourceState *)0x0) {
          slot->sourcePosY = spawnConfig->sourcePosYBits;
          slot->sourcePosZ = spawnConfig->sourcePosZBits;
          slot->sourcePosW = spawnConfig->sourcePosWBits;
          slot->sourcePosX = spawnConfig->sourcePosXBits;
          slot->sourceVecZ = spawnConfig->sourceVecZ;
          slot->sourceVecY = spawnConfig->sourceVecY;
          slot->sourceVecX = spawnConfig->sourceVecX;
        }
        else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_ATTACHED_SOURCE) != 0) {
          slot->sourcePosY = attachedSource->sourcePosYBits;
          slot->sourcePosZ = attachedSource->sourcePosZBits;
          slot->sourcePosW = attachedSource->sourcePosWBits;
          slot->sourcePosX = attachedSource->sourcePosXBits;
          slot->sourceVecZ = attachedSource->sourceVecZ;
          slot->sourceVecY = attachedSource->sourceVecY;
          slot->sourceVecX = attachedSource->sourceVecX;
          if (((slot->behaviorFlags & EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_A) != 0) ||
              ((slot->behaviorFlags & EXPGFX_BEHAVIOR_ADD_ATTACHED_VELOCITY_B) != 0)) {
            spawnConfig->velocityX = spawnConfig->velocityX + attachedSource->velocityX;
            spawnConfig->velocityY = spawnConfig->velocityY + attachedSource->velocityY;
            dVar19 = (double)spawnConfig->velocityZ;
            spawnConfig->velocityZ = (float)(dVar19 + (double)attachedSource->velocityZ);
          }
          iVar13 = attachedSource->tableKey1;
          attachedSource = (ExpgfxAttachedSourceState *)0x0;
        }
        iVar15 = (int)spawnConfig->tableKeyType;
        puVar10 = (undefined2 *)attachedSource;
        uVar3 = expgfx_addToTable(iVar7,(int)attachedSource,iVar13,iVar15);
        if ((short)uVar3 == -1) {
          uVar22 = FUN_80135810(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                sExpgfxInvalidTabIndex,puVar10,iVar13,iVar15,piVar16,
                                param_14,param_15,param_16);
          expgfx_release((&gExpgfxSlotPoolBases)[local_56[0]],(int)local_56[0],(int)local_58,1,1);
        }
        else {
          Expgfx_SetSlotTableIndex(slot, (u8)uVar3);
          iVar7 = spawnConfig->startPosXBits;
          slot->startPosX = iVar7;
          slot->posX = iVar7;
          iVar7 = spawnConfig->startPosYBits;
          slot->startPosY = iVar7;
          slot->posY = iVar7;
          iVar7 = spawnConfig->startPosZBits;
          slot->startPosZ = iVar7;
          slot->posZ = iVar7;
          slot->velocityX = spawnConfig->velocityX;
          slot->velocityY = spawnConfig->velocityY;
          slot->velocityZ = spawnConfig->velocityZ;
          slot->initialStateByte = spawnConfig->initialStateByte;
          puVar18[0x1b] = (short)spawnWords[1];
          slot->lifetimeFrame = (short)spawnWords[2];
          slot->lifetimeFrameLimit = (short)spawnWords[2];
          if ((double)lbl_803DFFD4 < (double)spawnConfig->scale) {
            FUN_80135810((double)spawnConfig->scale,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,sExpgfxScaleOverflow,puVar10,iVar13,iVar15,piVar16,param_14,
                         param_15,param_16);
          }
          dVar20 = (double)lbl_803DFFD0;
          dVar19 = dVar20 * (double)spawnConfig->scale;
          dVar21 = (double)(float)dVar19;
          if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_SCALE_FROM_ZERO) == 0) {
            if ((slot->renderFlags & EXPGFX_RENDER_SCALE_OVER_LIFETIME) == 0) {
              local_38 = (double)(longlong)(int)dVar19;
              slot->scaleCounter = (short)(int)dVar19;
              slot->scaleTarget = slot->scaleCounter;
              slot->scaleFrames = 0;
            }
            else {
              param_2 = (double)(longlong)(int)dVar19;
              uVar4 = (undefined2)(int)dVar19;
              slot->scaleCounter = uVar4;
              dVar20 = DOUBLE_803dffe0;
              local_48 = (double)CONCAT44(0x43300000,(int)slot->lifetimeFrameLimit ^ 0x80000000);
              iVar7 = (int)(dVar21 / (double)(float)(local_48 - DOUBLE_803dffe0));
              local_50 = (double)(longlong)iVar7;
              slot->scaleFrames = (short)iVar7;
              slot->scaleTarget = uVar4;
              local_40 = param_2;
              local_38 = param_2;
            }
          }
          else {
            slot->scaleCounter = 0;
            dVar20 = DOUBLE_803dffe0;
            local_50 = (double)CONCAT44(0x43300000,(int)slot->lifetimeFrameLimit ^ 0x80000000);
            iVar7 = (int)(dVar21 / (double)(float)(local_50 - DOUBLE_803dffe0));
            local_48 = (double)(longlong)iVar7;
            slot->scaleFrames = (short)iVar7;
            local_40 = (double)(longlong)(int)dVar19;
            slot->scaleTarget = (short)(int)dVar19;
          }
          if (((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_A) != 0) ||
             ((slot->behaviorFlags & EXPGFX_BEHAVIOR_COPY_CONFIG_SOURCE_B) != 0)) {
            slot->sourcePosY = spawnConfig->sourcePosYBits;
            slot->sourcePosZ = spawnConfig->sourcePosZBits;
            slot->sourcePosW = spawnConfig->sourcePosWBits;
            slot->sourcePosX = spawnConfig->sourcePosXBits;
            slot->sourceVecZ = spawnConfig->sourceVecZ;
            slot->sourceVecY = spawnConfig->sourceVecY;
            slot->sourceVecX = spawnConfig->sourceVecX;
          }
          slot->stateBits.bits.frameParity = gExpgfxFrameParityBit;
          if ((slot->renderFlags & EXPGFX_RENDER_BACKDATE_MOTION) != 0) {
            slot->renderFlags = slot->renderFlags ^ EXPGFX_RENDER_BACKDATE_MOTION;
            dVar21 = DOUBLE_803dffe0;
            param_4 = (double)lbl_803E009C;
            local_38 = (double)CONCAT44(0x43300000,(int)slot->lifetimeFrame ^ 0x80000000);
            *(float *)&slot->posX =
                 slot->velocityX *
                 (float)(param_4 * (double)(float)(local_38 - DOUBLE_803dffe0)) +
                 *(float *)&slot->posX;
            local_40 = (double)CONCAT44(0x43300000,(int)slot->lifetimeFrame ^ 0x80000000);
            *(float *)&slot->posY =
                 slot->velocityY * (float)(param_4 * (double)(float)(local_40 - dVar21)) +
                 *(float *)&slot->posY;
            param_2 = (double)slot->velocityZ;
            local_48 = (double)CONCAT44(0x43300000,(int)slot->lifetimeFrame ^ 0x80000000);
            *(float *)&slot->posZ =
                 (float)(param_2 * (double)(float)(param_4 * (double)(float)(local_48 - dVar21)) +
                        (double)*(float *)&slot->posZ);
            dVar20 = (double)lbl_803E00A0;
            slot->velocityX = (float)((double)slot->velocityX * dVar20);
            slot->velocityY = (float)((double)slot->velocityY * dVar20);
            slot->velocityZ = (float)((double)slot->velocityZ * dVar20);
          }
          if ((slot->renderFlags & EXPGFX_RENDER_AIM_AT_ACTOR) != 0) {
            iVar7 = FUN_80017a98();
            slot->renderFlags = slot->renderFlags ^ EXPGFX_RENDER_AIM_AT_ACTOR;
            dVar19 = DOUBLE_803dffe0;
            if ((slot->behaviorFlags & 1) == 0) {
              dVar21 = (double)(*(float *)(iVar7 + 0x18) -
                               (*(float *)&slot->startPosX +
                               *(float *)&attachedSource->sourcePosYBits));
              param_2 = (double)*(float *)(iVar7 + 0x20);
              fVar1 = (float)(param_2 -
                             (double)(*(float *)&slot->startPosZ +
                                     *(float *)&attachedSource->sourcePosWBits));
              dVar20 = (double)(float)(dVar21 * dVar21 + (double)(fVar1 * fVar1));
              if (((dVar20 < (double)lbl_803E00A4) &&
                  (dVar20 = (double)lbl_803DFFDC, dVar20 != (double)*(float *)(iVar7 + 0x24))) &&
                 (dVar20 != (double)*(float *)(iVar7 + 0x2c))) {
                local_38 = (double)CONCAT44(0x43300000,(int)slot->lifetimeFrame << 1 ^ 0x80000000);
                slot->velocityX =
                     slot->velocityX -
                     (float)(dVar21 / (double)(float)(local_38 - DOUBLE_803dffe0));
                local_40 = (double)CONCAT44(0x43300000,(int)slot->lifetimeFrame << 1 ^ 0x80000000);
                slot->velocityY =
                     slot->velocityY -
                     ((lbl_803E00A8 + *(float *)(iVar7 + 0x1c)) -
                     (*(float *)&slot->startPosY + *(float *)&attachedSource->sourcePosZBits)) /
                     (float)(local_40 - dVar19);
                dVar21 = (double)slot->velocityZ;
                param_2 = (double)*(float *)(iVar7 + 0x20);
                dVar20 = (double)(float)(param_2 - (double)(*(float *)&slot->startPosZ +
                                                *(float *)&attachedSource->sourcePosWBits));
                local_48 = (double)CONCAT44(0x43300000,(int)slot->lifetimeFrame << 1 ^ 0x80000000);
                slot->velocityZ =
                     (float)(dVar21 - (double)(float)(dVar20 / (double)(float)(local_48 - dVar19)));
                param_4 = dVar19;
              }
            }
            else {
              param_2 = (double)(*(float *)(iVar7 + 0x18) - *(float *)&slot->startPosX);
              fVar1 = *(float *)(iVar7 + 0x20) - *(float *)&slot->startPosZ;
              dVar20 = (double)(float)(param_2 * param_2 + (double)(fVar1 * fVar1));
              if (((dVar20 < (double)lbl_803E00A4) &&
                  (dVar20 = (double)lbl_803DFFDC, dVar20 != (double)*(float *)(iVar7 + 0x24))) &&
                 (dVar20 != (double)*(float *)(iVar7 + 0x2c))) {
                local_38 = (double)CONCAT44(0x43300000,(int)slot->lifetimeFrame << 1 ^ 0x80000000);
                slot->velocityX =
                     slot->velocityX +
                     (float)(param_2 / (double)(float)(local_38 - DOUBLE_803dffe0));
                local_40 = (double)CONCAT44(0x43300000,(int)slot->lifetimeFrame << 1 ^ 0x80000000);
                slot->velocityY =
                     slot->velocityY +
                     ((lbl_803E00A8 + *(float *)(iVar7 + 0x1c)) - *(float *)&slot->startPosY) /
                     (float)(local_40 - dVar19);
                param_2 = (double)slot->velocityZ;
                dVar20 = (double)(*(float *)(iVar7 + 0x20) - *(float *)&slot->startPosZ);
                local_48 = (double)CONCAT44(0x43300000,(int)slot->lifetimeFrame << 1 ^ 0x80000000);
                slot->velocityZ =
                     (float)(param_2 + (double)(float)(dVar20 / (double)(float)(local_48 - dVar19)));
                dVar21 = dVar19;
              }
            }
          }
          if (iVar6 == 1) {
            DAT_803ddef0 = DAT_803ddef0 + 1;
            DAT_803ddef8 = DAT_803ddef4 / DAT_803ddef0;
          }
          slot->colorByte0 = (char)((uint)spawnConfig->colorByte0Hi >> 8);
          slot->colorByte1 = (char)((uint)spawnConfig->colorByte1Hi >> 8);
          slot->colorByte2 = (char)((uint)spawnConfig->colorByte2Hi >> 8);
          if ((spawnConfig->renderFlags & EXPGFX_RENDER_OVERRIDE_COLORS) != 0) {
            *(char *)((int)puVar18 + 0x1f) = (char)(spawnConfig->overrideColor0 >> 8);
            *(char *)((int)puVar18 + 0x2f) = (char)(spawnConfig->overrideColor1 >> 8);
            *(char *)((int)puVar18 + 0x3f) = (char)(spawnConfig->overrideColor2 >> 8);
          }
          *(undefined *)(puVar18 + 6) = 0xff;
          *(undefined *)((int)puVar18 + 0xd) = 0xff;
          *(undefined *)(puVar18 + 7) = 0xff;
          puVar18[4] = 0;
          puVar18[5] = 0;
          puVar18[0xc] = 0;
          puVar18[0xd] = 0;
          puVar18[0x14] = 0;
          puVar18[0x15] = 0;
          puVar18[0x1c] = 0;
          puVar18[0x1d] = 0;
          if ((slot->renderFlags & EXPGFX_RENDER_INIT_QUAD) != 0) {
            expgfx_initSlotQuad(puVar18);
          }
          pbVar11 = &gExpgfxPoolSourceModes + local_56[0];
          *pbVar11 = (spawnConfig->behaviorFlags & EXPGFX_BEHAVIOR_SOURCE_MODE_FLAG) != 0;
          if ((*pbVar11 != 0) &&
              ((spawnConfig->behaviorFlags & EXPGFX_BEHAVIOR_TRACK_POOL_SOURCE) == 0)) {
            *pbVar11 = *pbVar11 + 1;
          }
          (&gExpgfxPoolBoundsTemplateIds)[local_56[0]] = param_12;
          FUN_802420e0((uint)slot,EXPGFX_SLOT_SIZE);
          DAT_803ddeec = (undefined2 *)slot;
        }
      }
    }
  }
  FUN_80286878();
  return;
}

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

  expgfxBase = lbl_8039AB58;
  asm {
    bl expgfx_initialise
  }
  poolActiveMasks = (u32 *)(expgfxBase + EXPGFX_POOL_ACTIVE_MASKS_OFFSET);
  poolActiveCounts = expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET;
  poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
  poolFrameFlags = gExpgfxStaticPoolFrameFlags;
  poolSourceModes = expgfxBase + EXPGFX_POOL_SOURCE_MODES_OFFSET;
  poolSourceIds = (u32 *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET);
  groupIndex = EXPGFX_POOL_GROUP_COUNT;
  do {
    poolActiveMasks[0] = 0;
    poolActiveCounts[0] = 0;
    poolSlotTypeIds[0] = -1;
    poolFrameFlags[0] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[0] = 0;
    poolSourceIds[0] = 0;
    poolActiveMasks[1] = 0;
    poolActiveCounts[1] = 0;
    poolSlotTypeIds[1] = -1;
    poolFrameFlags[1] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[1] = 0;
    poolSourceIds[1] = 0;
    poolActiveMasks[2] = 0;
    poolActiveCounts[2] = 0;
    poolSlotTypeIds[2] = -1;
    poolFrameFlags[2] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[2] = 0;
    poolSourceIds[2] = 0;
    poolActiveMasks[3] = 0;
    poolActiveCounts[3] = 0;
    poolSlotTypeIds[3] = -1;
    poolFrameFlags[3] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[3] = 0;
    poolSourceIds[3] = 0;
    poolActiveMasks[4] = 0;
    poolActiveCounts[4] = 0;
    poolSlotTypeIds[4] = -1;
    poolFrameFlags[4] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[4] = 0;
    poolSourceIds[4] = 0;
    poolActiveMasks[5] = 0;
    poolActiveCounts[5] = 0;
    poolSlotTypeIds[5] = -1;
    poolFrameFlags[5] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[5] = 0;
    poolSourceIds[5] = 0;
    poolActiveMasks[6] = 0;
    poolActiveCounts[6] = 0;
    poolSlotTypeIds[6] = -1;
    poolFrameFlags[6] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[6] = 0;
    poolSourceIds[6] = 0;
    poolActiveMasks[7] = 0;
    poolActiveCounts[7] = 0;
    poolSlotTypeIds[7] = -1;
    poolFrameFlags[7] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    poolSourceModes[7] = 0;
    poolSourceIds[7] = 0;
    poolActiveMasks = poolActiveMasks + 8;
    poolActiveCounts = poolActiveCounts + 8;
    poolSlotTypeIds = poolSlotTypeIds + 8;
    poolFrameFlags = poolFrameFlags + 8;
    poolSourceModes = poolSourceModes + 8;
    poolSourceIds = poolSourceIds + 8;
    groupIndex = groupIndex - 1;
  } while (groupIndex != 0);
  *(u32 *)(expgfxBase + 0x1014) = 0;
  *(u32 *)(expgfxBase + 0x1010) = 0;
  *(u32 *)(expgfxBase + 0x101c) = 0;
  *(u32 *)(expgfxBase + 0x1018) = 0;
  lbl_803DD258 = 1;
  resourceIndex = 0;
  resourceEntry = (ExpgfxResourceEntry *)(expgfxBase + EXPGFX_RESOURCE_TABLE_OFFSET);
  do {
    if (resourceEntry->resource != (void *)0x0) {
      fn_80054308(resourceEntry->resource);
    }
    resourceEntry->resource = (void *)0x0;
    resourceEntry->word8 = 0;
    resourceEntry->word4 = 0;
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
  u32 *slotPoolBases;
  int poolIndex;

  asm {
    bl expgfx_initialise
  }
  poolIndex = 0;
  slotPoolBases = &gExpgfxSlotPoolBases;
  do {
    fn_80023800(*slotPoolBases);
    slotPoolBases = slotPoolBases + 1;
    poolIndex = poolIndex + 1;
  } while (poolIndex < EXPGFX_POOL_COUNT);
  return;
}
