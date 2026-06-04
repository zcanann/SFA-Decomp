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
extern void lightmap_queueExternalRenderEntry(uint slotPoolBase,int poolIndex,float *position);
extern uint FUN_8005e558();
extern u8 fn_8005E97C(float minX,float maxX,float minY,float maxY,float minZ,float maxZ,
                      ExpgfxBounds *boundsTemplate);
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
extern void trackIntersect_drawColorBand(void);
extern int FUN_80080f40();
extern undefined4 FUN_80080f84();
extern undefined4 FUN_80080f8c();
extern undefined4 FUN_80081130();
extern int FUN_80081134();
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
extern undefined8 FUN_80286830();
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

extern ExpgfxBounds gExpgfxBoundsTemplates[];
extern s16 gExpgfxPoolSlotTypeIds[];
extern u8 gExpgfxPoolFrameFlags[];
extern undefined2 DAT_803105a8;
extern undefined4 DAT_80397420;
extern int DAT_8039b7b8;
extern ExpgfxBounds gExpgfxPoolBounds[];
extern int DAT_8039c138;
extern undefined4 DAT_8039c13c;
extern undefined4 DAT_8039c140;
extern short DAT_8039c144;
extern undefined4 DAT_8039c146;
extern u8 gExpgfxPoolSourceModes[];
extern u32 gExpgfxPoolSourceIds[];
extern undefined4 DAT_8039c7c8;
extern undefined4 DAT_8039c7cc;
extern u8 gExpgfxPoolBoundsTemplateIds[];
extern s8 gExpgfxPoolActiveCounts[];
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
extern u8 gExpgfxUpdatingActivePools;
extern u8 lbl_803DD253;
extern u8 gExpgfxRenderResetPending;
extern volatile f32 timeDelta;
extern volatile f32 gExpgfxFrameTimerA;
extern volatile f32 gExpgfxFrameTimerB;
extern volatile f32 gExpgfxFrameTimerC;
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
extern f32 gExpgfxYVelocityPositiveLimit;
extern f32 gExpgfxYVelocityFastStep;
extern f32 gExpgfxYVelocitySlowStep;
extern f32 gExpgfxYVelocityNegativeLimit;
extern f32 gExpgfxSlotMotionStep;
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
  return &gExpgfxBoundsTemplates[templateIndex];
}

static inline ExpgfxBounds *Expgfx_GetPoolBounds(int poolIndex) {
  return &gExpgfxPoolBounds[poolIndex];
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
#pragma scheduling off
#pragma peephole off
void expgfxRemove(uint slotPoolBase,int poolIndex,int slotIndex,int skipTextureFree,int flushSlot)
{
  u8 *expgfxBase;
  ExpgfxSlot *slot;
  u32 *poolActiveMask;
  u32 *expTabResources;
  u16 *expTabRefCount;
  s8 *poolActiveCountPtr;
  u32 activeBit;
  u32 inactiveBitMask;
  u32 expTabOffset;

  expgfxBase = gExpgfxRuntimeData;
  activeBit = 1 << slotIndex;
  poolActiveMask = (u32 *)(expgfxBase + EXPGFX_POOL_ACTIVE_MASKS_OFFSET + poolIndex * sizeof(u32));
  if ((activeBit & *poolActiveMask) == 0) {
    return;
  }

  slot = (ExpgfxSlot *)(slotPoolBase + slotIndex * EXPGFX_SLOT_SIZE);
  slot->behaviorFlags = 0;

  if (skipTextureFree == 0) {
    expTabResources = (u32 *)(expgfxBase + EXPGFX_EXPTAB_TEXTURE_RESOURCE_OFFSET);
    expTabOffset = Expgfx_GetSlotTableIndex(slot) << EXPGFX_TABLE_ENTRY_SHIFT;
    if (*(u32 *)((u8 *)expTabResources + expTabOffset) != 0) {
      gExpgfxTextureFreeInProgress = 1;
      expTabOffset = Expgfx_GetSlotTableIndex(slot) << EXPGFX_TABLE_ENTRY_SHIFT;
      textureFree((void *)*(u32 *)((u8 *)expTabResources + expTabOffset));
      gExpgfxTextureFreeInProgress = 0;
    }

    expTabOffset = Expgfx_GetSlotTableIndex(slot) << EXPGFX_TABLE_ENTRY_SHIFT;
    expTabRefCount = (u16 *)(expgfxBase + EXPGFX_EXPTAB_REFCOUNT_OFFSET + expTabOffset);
    if (*expTabRefCount != 0) {
      (*expTabRefCount)--;
      if (*expTabRefCount == 0) {
        *(u32 *)((u8 *)expTabResources + expTabOffset) = 0;
        *(u32 *)(expgfxBase + EXPGFX_EXPTAB_OFFSET + expTabOffset) = 0;
      }
    } else {
      debugPrintf(sExpgfxMismatchInAddRemove);
    }
  }

  slot->sequenceId = EXPGFX_INVALID_SEQUENCE_ID;
  if ((u8)flushSlot != 0) {
    DCFlushRange(slot, EXPGFX_SLOT_SIZE);
  }

  inactiveBitMask = ~activeBit;
  *poolActiveMask = *poolActiveMask & inactiveBitMask;
  poolActiveCountPtr = (s8 *)(expgfxBase + poolIndex);
  poolActiveCountPtr += EXPGFX_POOL_ACTIVE_COUNTS_OFFSET;
  (*poolActiveCountPtr)--;
  if (*poolActiveCountPtr == 0) {
    gExpgfxStaticPoolSlotTypeIds[poolIndex] = EXPGFX_INVALID_SLOT_TYPE;
  }
}
#pragma peephole reset
#pragma scheduling reset

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
#pragma scheduling off
#pragma peephole off
void expgfxRemoveAll(void)
{
  u8 *expgfxBase;
  ExpgfxSlot *slot;
  u32 *slotPoolBases;
  u32 *poolActiveMasks;
  s8 *poolActiveCountPtrs;
  s16 *poolSlotTypeIds;
  u16 *expTabRefCount;
  ExpgfxTableEntry *expTabEntry;
  u32 activeBit;
  u32 inactiveBitMask;
  u32 expTabOffset;
  int poolIndex;
  int slotIndex;

  expgfxBase = gExpgfxRuntimeData;
  poolIndex = 0;
  slotPoolBases = (u32 *)(expgfxBase + EXPGFX_SLOT_POOL_BASES_OFFSET);
  poolActiveMasks = (u32 *)(expgfxBase + EXPGFX_POOL_ACTIVE_MASKS_OFFSET);
  poolActiveCountPtrs = (s8 *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
  poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;

  while (poolIndex < EXPGFX_POOL_COUNT) {
    slot = (ExpgfxSlot *)*slotPoolBases;
    slotIndex = 0;
    while (slotIndex < EXPGFX_SLOTS_PER_POOL) {
      activeBit = 1 << slotIndex;
      if ((activeBit & *poolActiveMasks) != 0) {
        expTabOffset = Expgfx_GetSlotTableIndex(slot) << EXPGFX_TABLE_ENTRY_SHIFT;
        expTabEntry = (ExpgfxTableEntry *)(expgfxBase + EXPGFX_EXPTAB_OFFSET + expTabOffset);
        if ((expTabEntry->resource != 0) && (expTabEntry->resource != 0)) {
          gExpgfxTextureFreeInProgress = 1;
          expTabOffset = Expgfx_GetSlotTableIndex(slot) << EXPGFX_TABLE_ENTRY_SHIFT;
          expTabEntry = (ExpgfxTableEntry *)(expgfxBase + EXPGFX_EXPTAB_OFFSET + expTabOffset);
          textureFree((void *)expTabEntry->resource);
          gExpgfxTextureFreeInProgress = 0;
        }

        expTabOffset = Expgfx_GetSlotTableIndex(slot) << EXPGFX_TABLE_ENTRY_SHIFT;
        expTabEntry = (ExpgfxTableEntry *)(expgfxBase + EXPGFX_EXPTAB_OFFSET + expTabOffset);
        expTabRefCount = &expTabEntry->refCount;
        if (*expTabRefCount != 0) {
          (*expTabRefCount)--;
          if (*expTabRefCount == 0) {
            expTabEntry->resource = 0;
            expTabEntry->sourceId = 0;
          }
        } else {
          debugPrintf(sExpgfxMismatchInAddRemove);
        }

        slot->sequenceId = EXPGFX_INVALID_SEQUENCE_ID;
        inactiveBitMask = ~activeBit;
        *poolActiveMasks = *poolActiveMasks & inactiveBitMask;
      }

      slot = (ExpgfxSlot *)((u8 *)slot + EXPGFX_SLOT_SIZE);
      slotIndex++;
    }

    *poolActiveCountPtrs = 0;
    *poolSlotTypeIds = EXPGFX_INVALID_SLOT_TYPE;
    DCFlushRange((void *)*slotPoolBases, EXPGFX_POOL_BYTES);
    slotPoolBases++;
    poolActiveMasks++;
    poolActiveCountPtrs++;
    poolSlotTypeIds++;
    poolIndex++;
  }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: expgfxGetSlot
 * EN v1.0 Address: 0x8009B3BC
 * EN v1.0 Size: 792b
 * EN v1.1 Address: 0x8009B648
 * EN v1.1 Size: 792b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int expgfxGetSlot(short *poolIndexOut,short *slotIndexOut,short slotType,
                       int preferredPoolIndex,uint sourceId)
{
  u8 *expgfxBase;
  s8 *poolActiveCounts;
  u32 *poolSourceIds;
  u32 *poolActiveMasks;
  s16 *poolSlotTypeIds;
  u32 activeBit;
  int foundPool;
  int foundPoolIndex;
  int poolIndex;
  int slotIndex;

  expgfxBase = gExpgfxRuntimeData;
  poolActiveCounts = (s8 *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
  poolSourceIds = (u32 *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET);
  poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
  foundPool = 0;
  foundPoolIndex = EXPGFX_INVALID_POOL_INDEX;

  for (poolIndex = 0; poolIndex < EXPGFX_POOL_COUNT; poolIndex++) {
    if ((poolSourceIds[poolIndex] == sourceId) &&
        (poolSlotTypeIds[poolIndex] == slotType) &&
        (poolActiveCounts[poolIndex] < EXPGFX_SLOTS_PER_POOL)) {
      foundPoolIndex = (s16)poolIndex;
      foundPool = 1;
      break;
    }
  }

  if (foundPool) {
    poolIndex = (s16)foundPoolIndex;
    poolActiveMasks = (u32 *)(expgfxBase + EXPGFX_POOL_ACTIVE_MASKS_OFFSET);
    for (slotIndex = 0; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++) {
      activeBit = 1 << slotIndex;
      if ((activeBit & poolActiveMasks[poolIndex]) == 0) {
        *slotIndexOut = (s16)slotIndex;
        *poolIndexOut = (s16)poolIndex;
        poolActiveMasks[poolIndex] |= activeBit;
        poolActiveCounts[poolIndex]++;
        return 1;
      }
    }
  }

  foundPool = 0;
  if (preferredPoolIndex == EXPGFX_INVALID_POOL_INDEX) {
    for (poolIndex = 0; poolIndex < EXPGFX_POOL_COUNT - 1; poolIndex++) {
      if (poolActiveCounts[poolIndex] <= 0) {
        foundPoolIndex = (s16)poolIndex;
        foundPool = 1;
        poolActiveCounts[poolIndex] = 0;
        break;
      }
    }
  } else if (poolActiveCounts[preferredPoolIndex] < EXPGFX_SLOTS_PER_POOL) {
    foundPoolIndex = (s16)preferredPoolIndex;
    foundPool = 1;
  }

  if (!foundPool) {
    return EXPGFX_INVALID_POOL_INDEX;
  }

  poolIndex = (s16)foundPoolIndex;
  poolActiveMasks = (u32 *)(expgfxBase + EXPGFX_POOL_ACTIVE_MASKS_OFFSET);
  for (slotIndex = 0; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++) {
    activeBit = 1 << slotIndex;
    if ((activeBit & poolActiveMasks[poolIndex]) == 0) {
      *slotIndexOut = (s16)slotIndex;
      *poolIndexOut = (s16)poolIndex;
      poolActiveMasks[poolIndex] |= activeBit;
      poolSlotTypeIds[poolIndex] = slotType;
      poolActiveCounts[poolIndex]++;
      return 1;
    }
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
  u8 *staticBase;
  ExpgfxSlot *slot;
  ExpgfxTableEntry *entry;
  ExpgfxQuadVertex *quad;
  ExpgfxQuadTemplateVertex *template;
  u32 resource;
  u32 behaviorFlags;
  s16 texS0;
  s16 texT0;
  s16 texS1;
  s16 texT1;
  f32 step;

  slot = (ExpgfxSlot *)slotPtr;
  staticBase = gExpgfxStaticData;
  entry = Expgfx_GetTableEntry(Expgfx_GetSlotTableIndex(slot));
  resource = entry->resource;

  slot->stateBits.bits.frameParity = 0;
  slot->stateBits.bits.quadReady = 1;

  behaviorFlags = slot->behaviorFlags;
  if ((behaviorFlags & EXPGFX_BEHAVIOR_USE_QUAD_TEMPLATE_A) != 0) {
    template = (ExpgfxQuadTemplateVertex *)(staticBase + EXPGFX_STATIC_QUAD_TEMPLATE_A_OFFSET);
  } else {
    template = (ExpgfxQuadTemplateVertex *)(staticBase + EXPGFX_STATIC_QUAD_TEMPLATE_B_OFFSET);
  }

  if ((behaviorFlags & EXPGFX_BEHAVIOR_BOUNCE_LOW_Y_VELOCITY) != 0 &&
      slot->velocityY < gExpgfxYVelocityPositiveLimit) {
    if ((behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 &&
        slot->velocityY < gExpgfxYVelocityPositiveLimit) {
      slot->velocityY -= gExpgfxYVelocityFastStep * timeDelta;
    } else {
      slot->velocityY -= gExpgfxYVelocitySlowStep * timeDelta;
    }
  } else if ((behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 &&
             slot->velocityY > gExpgfxYVelocityNegativeLimit) {
    slot->velocityY += gExpgfxYVelocityFastStep * timeDelta;
  } else if ((behaviorFlags & EXPGFX_BEHAVIOR_ADD_HIGH_Y_VELOCITY) != 0 &&
             slot->velocityY > gExpgfxYVelocityNegativeLimit) {
    slot->velocityY += gExpgfxYVelocitySlowStep * timeDelta;
  }

  step = gExpgfxSlotMotionStep;
  *(f32 *)&slot->posX += slot->velocityX * step;
  *(f32 *)&slot->posY += slot->velocityY * step;
  *(f32 *)&slot->posZ += slot->velocityZ * step;

  if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_SCALE_FROM_ZERO) != 0) {
    slot->scaleCounter =
        (int)((f32)(u16)slot->scaleFrames * step + (f32)(u16)slot->scaleCounter);
  } else if ((slot->renderFlags & EXPGFX_RENDER_SCALE_OVER_LIFETIME) != 0) {
    slot->scaleCounter =
        (int)((f32)(u16)slot->scaleCounter - (f32)(u16)slot->scaleFrames * step);
  }

  if (resource == 0) {
    debugPrintf((char *)(staticBase + EXPGFX_STATIC_NO_TEXTURE_STRING_OFFSET));
    return;
  }

  texS0 = EXPGFX_QUAD_TEXCOORD_MAX;
  texT0 = EXPGFX_QUAD_TEXCOORD_MAX;
  texS1 = 0;
  texT1 = 0;
  if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX1_T) != 0) {
    texS1 = EXPGFX_QUAD_TEXCOORD_MAX;
    texS0 = 0;
  }
  if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX0_T) != 0) {
    texT1 = EXPGFX_QUAD_TEXCOORD_MAX;
    texT0 = 0;
  }

  quad = (ExpgfxQuadVertex *)slot;
  quad[0].x = template[0].x;
  quad[0].y = template[0].y;
  quad[0].z = template[0].z;
  quad[0].texS = texS0;
  quad[0].texT = texT0;
  quad[1].x = template[1].x;
  quad[1].y = template[1].y;
  quad[1].z = template[1].z;
  quad[1].texS = texS1;
  quad[1].texT = texT0;
  quad[2].x = template[2].x;
  quad[2].y = template[2].y;
  quad[2].z = template[2].z;
  quad[2].texS = texS1;
  quad[2].texT = texT1;
  quad[3].x = template[3].x;
  quad[3].y = template[3].y;
  quad[3].z = template[3].z;
  quad[3].texS = texS0;
  quad[3].texT = texT1;
}
#pragma peephole reset
#pragma scheduling reset

extern void *Obj_GetPlayerObject(void);
extern void *getTrickyObject(void);
extern int getSkyStructField24C(void);
extern void fn_800897D4(int skyStruct, f32 *x, f32 *y, f32 *z);
extern f32 *Camera_GetViewRotationMatrix(void);
extern void getAmbientColor(int skyStruct, u8 *r, u8 *g, u8 *b);
extern f32 fn_80138F78(void *tricky);
extern f32 fn_8029610C(void *player);
extern void *getCache(void);
extern void copyToCache(void *dst, void *src, int blockCount);
extern void memcpyToCache(void *dst, void *src, int blockCount);
extern void cacheFn_800229c4(int wait);
extern void *Camera_GetCurrentViewSlot(void);
extern u32 randomGetRange(int min, int max);
extern void mathFn_80021ac8(void *params, void *vec);
extern int coordsToMapCell(f32 x, f32 z);
extern void Obj_RotateLocalOffsetByYaw(void *offset, f32 *out, u8 yaw);
extern void Sfx_PlayFromObject(void *obj, int sfxId);
extern f32 sqrtf(f32 x);
extern u8 framesThisStep;
extern undefined4 *gWaterfxInterface;
extern u16 gExpgfxPhaseAngleA;
extern u16 gExpgfxPhaseAngleB;
extern f32 lbl_803DF38C;
extern f32 lbl_803DF390;
extern f32 lbl_803DF3B0;
extern f32 lbl_803DF3C8;
extern f32 lbl_803DF3CC;
extern f32 lbl_803DF3D0;
extern f32 lbl_803DF3D4;
extern f32 lbl_803DF3D8;
extern f32 lbl_803DF3DC;
extern f32 lbl_803DF3E0;
extern f32 lbl_803DF3E4;
extern f32 lbl_803DF3E8;
extern f32 lbl_803DF3EC;
extern f32 lbl_803DF3F0;
extern f32 lbl_803DF3F4;
extern f32 lbl_803DF3F8;
extern f32 lbl_803DF3FC;
extern f32 lbl_803DF400;
extern f32 lbl_803DF404;
extern f32 lbl_803DF408;
extern f32 lbl_803DF40C;
extern f32 lbl_803DF410;

typedef void (*ExpgfxSfxMoveFn)(void *obj, int soundHandle, void *params, int flags, int a,
                                int b);
typedef void (*ExpgfxWaterRippleFnA)(f32 x, f32 y, f32 z, f32 w, int a, int b);
typedef void (*ExpgfxWaterRippleFnB)(f32 x, f32 y, f32 z, f32 radius, int a);

typedef struct ExpgfxRotateParams {
  s16 angleX;
  s16 angleY;
  s16 angleZ;
  f32 scale;
  f32 x;
  f32 y;
  f32 z;
} ExpgfxRotateParams;

/*
 * --INFO--
 *
 * Function: expgfx_updateActivePools
 * EN v1.0 Address: 0x8009B9C8
 * EN v1.0 Size: 9252b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void expgfx_updateActivePools(u8 sourceMode, int sourceId, int resetSourceFrameState)
{
  u8 *staticBase;
  u8 *runtimeBase;
  int next;
  ExpgfxBounds *bounds;
  f32 *maxYPtr;
  f32 *minZPtr;
  f32 *maxZPtr;
  s16 slotIdx;
  ExpgfxSlot *slot;
  ExpgfxQuadTemplateVertex *template;
  s16 texT1;
  s16 texT0;
  s16 texS1;
  u8 *nextBuf;
  void *player;
  void *tricky;
  int pool;
  int sky;
  f32 *minYPtr;
  u8 *srcObj;
  u32 resource;
  s16 texS0;
  s8 *scan;
  int batch;
  int curPool;
  u32 *maskPtr;
  void *cache;
  u8 *curCache;
  u8 *curPoolBuf;
  f32 *maxXPtr;
  int pool4;
  u8 parity;
  u8 prefetched;
  int ambRPlus1;
  int ambGPlus1;
  int ambBPlus1;
  u8 ambScaledR;
  u8 ambScaledG;
  u8 ambScaledB;
  ExpgfxRotateParams rot;
  f32 vecBuf[3];
  f32 camDir[3];
  f32 rotPos[3];
  f32 srcVel[3];
  u8 ambB8;
  u8 ambG8;
  u8 ambR8;
  f32 trickyRange;
  f32 playerRange;
  f32 boundsMax;
  f32 boundsMin;
  f32 prevX;
  f32 prevY;
  f32 prevZ;
  f32 workA;
  f32 workB;
  f32 attractRatio;
  f32 camScale;

  staticBase = gExpgfxStaticData;
  runtimeBase = gExpgfxRuntimeData;
  attractRatio = lbl_803DF354;
  trickyRange = lbl_803DF35C;
  playerRange = trickyRange;
  player = Obj_GetPlayerObject();
  tricky = getTrickyObject();
  cache = getCache();
  gExpgfxPhaseAngleA += (int)(lbl_803DF3C8 * timeDelta);
  gExpgfxPhaseAngleB += (int)(lbl_803DF3CC * timeDelta);
  sky = getSkyStructField24C();
  fn_800897D4(sky, &camDir[0], &camDir[1], &camDir[2]);
  PSMTXMultVec((void *)Camera_GetViewRotationMatrix(), (void *)camDir, (void *)camDir);
  camScale = -camDir[2];
  if (camScale < lbl_803DF3D0) {
    camScale = lbl_803DF3D0;
  }
  getAmbientColor(sky, &ambR8, &ambG8, &ambB8);
  ambScaledR = (int)((f32)ambR8 * camScale);
  ambScaledG = (int)((f32)ambG8 * camScale);
  ambScaledB = (int)((f32)ambB8 * camScale);

  pool = 0;
  scan = (s8 *)(runtimeBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
  for (batch = 8; batch != 0; batch--) {
    switch (scan[0]) { case 0: break; default: goto foundFirst; }
    pool++;
    switch (scan[1]) { case 0: break; default: goto foundFirst; }
    pool++;
    switch (scan[2]) { case 0: break; default: goto foundFirst; }
    pool++;
    switch (scan[3]) { case 0: break; default: goto foundFirst; }
    pool++;
    switch (scan[4]) { case 0: break; default: goto foundFirst; }
    pool++;
    switch (scan[5]) { case 0: break; default: goto foundFirst; }
    pool++;
    switch (scan[6]) { case 0: break; default: goto foundFirst; }
    pool++;
    switch (scan[7]) { case 0: break; default: goto foundFirst; }
    pool++;
    switch (scan[8]) { case 0: break; default: goto foundFirst; }
    pool++;
    switch (scan[9]) { case 0: break; default: goto foundFirst; }
    scan += 10;
    pool++;
  }
  pool = -1;
foundFirst:
  if (pool != -1) {
    copyToCache(cache,
                (void *)*(u32 *)((runtimeBase + (pool << 2)) + EXPGFX_SLOT_POOL_BASES_OFFSET),
                0x7e);
    parity = 1;
    curCache = cache;
    Camera_GetCurrentViewSlot();
    if (tricky != NULL) {
      trickyRange = fn_80138F78(tricky);
    }
    if (player != NULL) {
      playerRange = fn_8029610C(player);
    }
    prefetched = 0;
    ambRPlus1 = ambScaledR + 1;
    ambGPlus1 = ambScaledG + 1;
    ambBPlus1 = ambScaledB + 1;
    boundsMin = lbl_803DF3D4;
    boundsMax = lbl_803DF3D8;
    while (pool > -1) {
      bounds = (ExpgfxBounds *)(runtimeBase + pool * 0x18 + EXPGFX_POOL_BOUNDS_OFFSET);
      bounds->minX = boundsMin;
      maxXPtr = &bounds->maxX;
      *maxXPtr = boundsMax;
      minYPtr = &bounds->minY;
      *minYPtr = boundsMin;
      maxYPtr = &bounds->maxY;
      *maxYPtr = boundsMax;
      minZPtr = &bounds->minZ;
      *minZPtr = boundsMin;
      maxZPtr = &bounds->maxZ;
      *maxZPtr = boundsMax;
      curPool = pool;
      next = pool + 1;
      scan = (s8 *)(runtimeBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET + next);
      if (next < EXPGFX_POOL_COUNT) {
        do {
          switch (*scan) { case 0: break; default: goto foundNext; }
          scan++;
          next++;
        } while (next < EXPGFX_POOL_COUNT);
      }
      next = -1;
    foundNext:
      slot = (ExpgfxSlot *)curCache;
      if (next > -1) {
        nextBuf = (u8 *)cache + (u32)parity * 0x1000;
        copyToCache(nextBuf,
                    (void *)*(u32 *)((runtimeBase + (next << 2)) + EXPGFX_SLOT_POOL_BASES_OFFSET),
                    0x7e);
        curCache = nextBuf;
        prefetched = 1;
      }
      parity ^= 1;
      cacheFn_800229c4(prefetched);
      slot--;
      pool4 = pool << 2;
      maskPtr = (u32 *)(runtimeBase + pool4);
      maskPtr = (u32 *)((u8 *)maskPtr + EXPGFX_POOL_ACTIVE_MASKS_OFFSET);
      curPoolBuf = (u8 *)cache + (u32)parity * 0x1000;
      for (slotIdx = 0; slotIdx < EXPGFX_SLOTS_PER_POOL; slotIdx++) {
        ExpgfxQuadVertex *quad;
        ExpgfxTableEntry *entry;
        u32 phase;

        slot++;
        if ((1 << slotIdx & *maskPtr) == 0) {
          continue;
        }
        if (slot->sequenceId == -1) {
          continue;
        }
        entry = (ExpgfxTableEntry *)(runtimeBase + EXPGFX_EXPTAB_OFFSET +
                                     (((u32)slot->encodedTableIndex >> 1) &
                                      EXPGFX_SLOT_TABLE_INDEX_MASK) *
                                         EXPGFX_TABLE_ENTRY_SIZE);
        srcObj = (u8 *)entry->sourceId;
        resource = entry->resource;
        slot->stateBits.bits.frameParity = 0;
        slot->stateBits.bits.quadReady = 1;
        if ((slot->behaviorFlags & 0x800) == 0) {
          slot->lifetimeFrame -= framesThisStep;
        }
        phase = slot->stateBits.bits.initPhase;
        if (phase == 2) {
          slot->stateBits.bits.initPhase = 1;
          continue;
        }
        if (phase == 1) {
          expgfxRemove((uint)curPoolBuf, curPool, slotIdx, 0, 0);
          continue;
        }
        if (slot->lifetimeFrame <= 0 || slot->lifetimeFrame > slot->lifetimeFrameLimit) {
          slot->stateBits.bits.initPhase = 2;
          continue;
        }
        if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_USE_QUAD_TEMPLATE_A) != 0) {
          template =
              (ExpgfxQuadTemplateVertex *)(staticBase + EXPGFX_STATIC_QUAD_TEMPLATE_A_OFFSET);
        } else {
          template =
              (ExpgfxQuadTemplateVertex *)(staticBase + EXPGFX_STATIC_QUAD_TEMPLATE_B_OFFSET);
        }
        if ((slot->behaviorFlags & 0x20000) != 0 &&
            (slot->renderFlags & 0x30000000) == 0) {
          rot.x = lbl_803DF35C;
          rot.y = lbl_803DF35C;
          rot.z = lbl_803DF35C;
          rot.scale = lbl_803DF354;
          rot.angleZ = (s16)(int)((f32)slot->sourceVecZ * timeDelta);
          rot.angleY = (s16)(int)((f32)slot->sourceVecY * timeDelta);
          rot.angleX = (s16)(int)((f32)slot->sourceVecX * timeDelta);
          mathFn_80021ac8(&rot, (f32 *)&slot->posX);
        }
        if ((slot->renderFlags & 0x30000000) != 0) {
          workB = lbl_803DF3DC;
          workA = workB;
          if ((slot->renderFlags & 0x10000000) != 0 && player != NULL && srcObj != NULL &&
              playerRange > lbl_803DF3E0) {
            vecBuf[0] = *(f32 *)((u8 *)player + 0x18) -
                        (*(f32 *)&slot->startPosX + *(f32 *)(srcObj + 0xc));
            vecBuf[2] = *(f32 *)((u8 *)player + 0x20) -
                        (*(f32 *)&slot->startPosZ + *(f32 *)(srcObj + 0x14));
            workB = vecBuf[0] * vecBuf[0] + vecBuf[2] * vecBuf[2];
            attractRatio = playerRange / workB;
          }
          if (workB > lbl_803DF3B0 && (slot->renderFlags & 0x20000000) != 0 &&
              tricky != NULL && srcObj != NULL && trickyRange > lbl_803DF3E0) {
            vecBuf[0] = *(f32 *)((u8 *)tricky + 0x18) -
                        (*(f32 *)&slot->startPosX + *(f32 *)(srcObj + 0xc));
            vecBuf[2] = *(f32 *)((u8 *)tricky + 0x20) -
                        (*(f32 *)&slot->startPosZ + *(f32 *)(srcObj + 0x14));
            workA = vecBuf[0] * vecBuf[0] + vecBuf[2] * vecBuf[2];
            attractRatio = trickyRange / workB;
          }
          if (workA < workB) {
            workB = workA;
          }
          if (workB < lbl_803DF3B0) {
            if ((slot->renderFlags & 0x10000000) != 0) {
              slot->renderFlags ^= 0x10000000;
            }
            if ((slot->renderFlags & 0x20000000) != 0) {
              slot->renderFlags ^= 0x20000000;
            }
            if ((slot->behaviorFlags & 0x8000000) != 0) {
              slot->behaviorFlags ^= 0x8000000;
            }
            slot->lifetimeFrame = (s16)randomGetRange(0, 0x28) + 0xdc;
            slot->lifetimeFrameLimit = (s16)randomGetRange(0, 0x28) + 0xdc;
            slot->behaviorFlags |= 0x1000;
            slot->renderFlags |= 0x40000000;
            slot->velocityX = -(vecBuf[0] * attractRatio);
            slot->velocityZ = -(vecBuf[2] * attractRatio);
          }
        } else {
          if ((slot->renderFlags & 0x10000) != 0) {
            slot->velocityX = lbl_803DF3E4 * slot->velocityX + slot->velocityX;
            slot->velocityY = lbl_803DF3E4 * slot->velocityY + slot->velocityY;
            slot->velocityZ = lbl_803DF3E4 * slot->velocityZ + slot->velocityZ;
          } else if ((slot->renderFlags & 0x20000) != 0) {
            slot->velocityX = lbl_803DF3E8 * slot->velocityX + slot->velocityX;
            slot->velocityY = lbl_803DF3E8 * slot->velocityY + slot->velocityY;
            slot->velocityZ = lbl_803DF3E8 * slot->velocityZ + slot->velocityZ;
          } else if ((slot->renderFlags & 0x40000) != 0) {
            slot->velocityX = lbl_803DF3EC * slot->velocityX + slot->velocityX;
            slot->velocityY = lbl_803DF3EC * slot->velocityY + slot->velocityY;
            slot->velocityZ = lbl_803DF3EC * slot->velocityZ + slot->velocityZ;
          } else if ((slot->renderFlags & 0x80000) != 0) {
            slot->velocityX = lbl_803DF3F0 * slot->velocityX;
            slot->velocityY = lbl_803DF3F0 * slot->velocityY;
            slot->velocityZ = lbl_803DF3F0 * slot->velocityZ;
          }
          if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_BOUNCE_LOW_Y_VELOCITY) != 0 &&
              slot->velocityY < gExpgfxYVelocityPositiveLimit) {
            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 &&
                slot->velocityY < gExpgfxYVelocityPositiveLimit) {
              slot->velocityY -= gExpgfxYVelocityFastStep * timeDelta;
            } else {
              slot->velocityY -= gExpgfxYVelocitySlowStep * timeDelta;
            }
          } else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FAST_Y_RESPONSE) != 0 &&
                     slot->velocityY > gExpgfxYVelocityNegativeLimit) {
            slot->velocityY += gExpgfxYVelocityFastStep * timeDelta;
          } else if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_ADD_HIGH_Y_VELOCITY) != 0 &&
                     slot->velocityY > gExpgfxYVelocityNegativeLimit) {
            slot->velocityY += gExpgfxYVelocitySlowStep * timeDelta;
          }
          if ((slot->renderFlags & EXPGFX_BEHAVIOR_BOUNCE_LOW_Y_VELOCITY) != 0) {
            f32 zero = lbl_803DF35C;
            if (slot->velocityY * timeDelta + *(f32 *)&slot->posY < zero) {
              slot->velocityX = zero;
              slot->velocityY = zero;
              slot->velocityZ = zero;
              slot->sourceVecX = 0;
              slot->sourceVecY = 0;
              slot->sourceVecZ = 0;
              if ((slot->behaviorFlags & 0x4000000) != 0) {
                slot->behaviorFlags ^= 0x4000000;
              }
              if ((slot->behaviorFlags & 0x20000) != 0) {
                slot->behaviorFlags ^= 0x20000;
              }
              slot->behaviorFlags |= 0x8000000;
              if ((slot->behaviorFlags & 0x1000000) != 0) {
                slot->behaviorFlags ^= 0x1000000;
              }
              if ((slot->behaviorFlags & 8) != 0) {
                slot->behaviorFlags ^= 8;
              }
              if ((slot->behaviorFlags & 0x80000000) != 0) {
                slot->behaviorFlags ^= 0x80000000;
              }
              slot->renderFlags ^= 0x40000000;
            }
          }
          if ((slot->behaviorFlags & 0xf020) != 0 &&
              slot->velocityY * timeDelta + *(f32 *)&slot->posY < lbl_803DF35C) {
            u32 rnd;
            f32 fade;

            rnd = randomGetRange(0, 5);
            slot->velocityY =
                slot->velocityY * -(lbl_803DF3E4 * (f32)(int)rnd + lbl_803DF38C);
            if (slot->velocityY > lbl_803DF390) {
              slot->velocityY = lbl_803DF390;
            }
            rot.scale = lbl_803DF354;
            rot.angleZ = 0;
            rot.angleY = 0;
            rot.angleX = 0;
            if (srcObj != NULL) {
              rot.x = *(f32 *)&slot->posX + *(f32 *)(srcObj + 0xc);
              rot.y = *(f32 *)&slot->posY + *(f32 *)(srcObj + 0x10);
              rot.z = *(f32 *)&slot->posZ + *(f32 *)(srcObj + 0x14);
            } else {
              rot.x = *(f32 *)&slot->posX + *(f32 *)&slot->sourcePosY;
              rot.y = *(f32 *)&slot->posY + *(f32 *)&slot->sourcePosZ;
              rot.z = *(f32 *)&slot->posZ + *(f32 *)&slot->sourcePosW;
            }
            gExpgfxFrameParityBit = 1;
            if ((slot->behaviorFlags & 0x20) != 0 &&
                (slot->renderFlags & 0x40000000) == 0) {
              slot->velocityX *= gExpgfxSlotMotionStep;
              slot->velocityZ *= gExpgfxSlotMotionStep;
              slot->behaviorFlags ^= 0x20;
              if (slot->soundHandle != -1) {
                (*(ExpgfxSfxMoveFn *)(*gPartfxInterface + 8))(srcObj, slot->soundHandle, &rot,
                                                              0x200001, -1, 0);
                slot->soundHandle = -1;
              }
            } else if ((slot->behaviorFlags & 0x1000) != 0) {
              slot->velocityX *= lbl_803DF358;
              slot->velocityZ *= lbl_803DF358;
              slot->scaleCounter =
                  (int)((f32)(u16)slot->scaleCounter * lbl_803DF3F4);
              slot->behaviorFlags ^= 0x1000;
            } else if ((slot->behaviorFlags & 0x2000) != 0) {
              slot->velocityX *= lbl_803DF358;
              slot->velocityZ *= lbl_803DF358;
              slot->scaleCounter =
                  (int)((f32)(u16)slot->scaleCounter * lbl_803DF3F4);
              slot->behaviorFlags ^= 0x2000;
              slot->behaviorFlags |= 0x1000;
            } else if ((slot->behaviorFlags & 0x4000) != 0) {
              slot->velocityX *= lbl_803DF358;
              slot->velocityZ *= lbl_803DF358;
              slot->scaleCounter =
                  (int)((f32)(u16)slot->scaleCounter * lbl_803DF3F4);
              slot->behaviorFlags ^= 0x4000;
              slot->behaviorFlags |= 0x2000;
              if (slot->soundHandle != -1) {
                (*(ExpgfxSfxMoveFn *)(*gPartfxInterface + 8))(srcObj, slot->soundHandle, &rot,
                                                              0x200001, -1, 0);
              }
              slot->soundHandle = -1;
            } else if ((slot->behaviorFlags & 0x8000) != 0) {
              slot->velocityX = slot->velocityX * (gExpgfxSlotMotionStep - slot->velocityX);
              slot->velocityZ = slot->velocityZ * (gExpgfxSlotMotionStep - slot->velocityZ);
              slot->scaleCounter =
                  (int)((f32)(u16)slot->scaleCounter * lbl_803DF3F4);
              slot->behaviorFlags ^= 0x8000;
              slot->behaviorFlags |= 0x4000;
              if (slot->soundHandle != -1) {
                (*(ExpgfxSfxMoveFn *)(*gPartfxInterface + 8))(srcObj, slot->soundHandle, &rot,
                                                              0x200001, -1, 0);
              }
            }
            gExpgfxFrameParityBit = 0;
          } else if ((slot->behaviorFlags & 0x10000000) != 0 &&
                     slot->velocityY * timeDelta + *(f32 *)&slot->posY < lbl_803DF35C) {
            if (slot->soundHandle != -1) {
              rot.scale = lbl_803DF354;
              rot.angleZ = 0;
              rot.angleY = 0;
              rot.angleX = 0;
              if ((slot->behaviorFlags & 1) == 0 && srcObj != NULL) {
                rot.x = *(f32 *)&slot->posX + *(f32 *)(srcObj + 0x18);
                rot.y = *(f32 *)(srcObj + 0x1c);
                rot.z = *(f32 *)&slot->posZ + *(f32 *)(srcObj + 0x20);
              } else {
                rot.x = *(f32 *)&slot->posX;
                rot.y = lbl_803DF35C;
                rot.z = *(f32 *)&slot->posZ;
              }
              gExpgfxFrameParityBit = 1;
              (*(ExpgfxWaterRippleFnA *)(*gWaterfxInterface + 0x14))(rot.x, rot.y, rot.z,
                                                                     lbl_803DF35C, 0, 4);
              (*(ExpgfxWaterRippleFnB *)(*gWaterfxInterface + 0x10))(rot.x, rot.y, rot.z,
                                                                     gExpgfxSlotMotionStep, 0);
              if (srcObj != NULL &&
                  coordsToMapCell(*(f32 *)(srcObj + 0xc), *(f32 *)(srcObj + 0x14)) == 0x10) {
                Sfx_PlayFromObject(srcObj, 0x285);
              }
              slot->soundHandle = -1;
              slot->behaviorFlags |= 0x10000000;
              slot->lifetimeFrame = 0;
              gExpgfxFrameParityBit = 0;
            }
          } else if ((slot->behaviorFlags & 0xf020) == 0 &&
                     (slot->behaviorFlags & 0x10000000) == 0 && slot->soundHandle != -1) {
            rot.scale = lbl_803DF354;
            rot.angleZ = 0;
            rot.angleY = 0;
            rot.angleX = 0;
            if ((slot->behaviorFlags & 1) == 0 && srcObj != NULL) {
              rot.x = *(f32 *)&slot->posX + *(f32 *)(srcObj + 0xc);
              rot.y = *(f32 *)&slot->posY + *(f32 *)(srcObj + 0x10);
              rot.z = *(f32 *)&slot->posZ + *(f32 *)(srcObj + 0x14);
            } else {
              rot.x = *(f32 *)&slot->posX;
              rot.y = *(f32 *)&slot->posY;
              rot.z = *(f32 *)&slot->posZ;
            }
            gExpgfxFrameParityBit = 1;
            (*(ExpgfxSfxMoveFn *)(*gPartfxInterface + 8))(srcObj, slot->soundHandle, &rot,
                                                          0x200001, -1, 0);
            gExpgfxFrameParityBit = 0;
          }
          if ((slot->behaviorFlags & 0x80000000) != 0 && randomGetRange(0, 4) == 1) {
            slot->velocityX +=
                lbl_803DF3F8 - (f32)(int)randomGetRange(0, 9) / lbl_803DF3FC;
            slot->velocityZ +=
                lbl_803DF3F8 - (f32)(int)randomGetRange(0, 9) / lbl_803DF3FC;
          }
          if ((slot->renderFlags & 0x100000) != 0 && randomGetRange(0, 10) == 1) {
            if ((f32)slot->lifetimeFrame < (f32)slot->lifetimeFrameLimit) {
              slot->velocityX +=
                  lbl_803DF400 * (f32)(int)randomGetRange(-800, 800) + lbl_803DF3E8;
              slot->velocityY +=
                  lbl_803DF400 * (f32)(int)randomGetRange(-800, 800) + lbl_803DF3E8;
              slot->velocityZ +=
                  lbl_803DF400 * (f32)(int)randomGetRange(-800, 800) + lbl_803DF3E8;
            }
          }
          if ((slot->behaviorFlags & 0x400) != 0) {
            if ((f32)slot->lifetimeFrame < lbl_803DF38C * (f32)slot->lifetimeFrameLimit) {
              f32 boost = lbl_803DF404;
              slot->behaviorFlags ^= 0x400;
              slot->velocityX *= boost;
              slot->velocityY *= boost;
              slot->velocityZ *= boost;
            }
          }
          if ((slot->renderFlags & 0x200000) != 0) {
            prevX = *(f32 *)&slot->posX;
            prevY = *(f32 *)&slot->posY;
            prevZ = *(f32 *)&slot->posZ;
          }
          *(f32 *)&slot->posX += slot->velocityX * timeDelta;
          *(f32 *)&slot->posY += slot->velocityY * timeDelta;
          *(f32 *)&slot->posZ += slot->velocityZ * timeDelta;
          if ((slot->behaviorFlags & 0x100000) != 0) {
            slot->scaleCounter = (int)((f32)(u16)slot->scaleFrames * timeDelta +
                                       (f32)(u16)slot->scaleCounter);
          } else if ((slot->renderFlags & 0x2000) != 0) {
            slot->scaleCounter = slot->scaleCounter - slot->scaleFrames * framesThisStep;
          }
        }
        quad = (ExpgfxQuadVertex *)slot;
        if (resource != 0) {
          u8 *attached;

          texT0 = 0;
          texT1 = 0;
          texS0 = 0;
          texS1 = 0;
          if (resource != 0) {
            texS0 = 0x80;
            texT0 = 0x80;
            texS1 = 0;
            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX1_T) != 0) {
              texS1 = 0x80;
              texS0 = 0;
            }
            if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX0_T) != 0) {
              texT1 = 0x80;
              texT0 = 0;
            }
          }
          if ((slot->renderFlags & 0x20) != 0) {
            int colR;
            int colG;
            int colB;
            f32 ratio;

            ratio = (f32)slot->lifetimeFrame / (f32)slot->lifetimeFrameLimit;
            colR = (int)(ratio * (f32)(quad[1].alpha - slot->colorByte0) +
                         (f32)slot->colorByte0);
            colG = (int)(ratio * (f32)(quad[2].alpha - slot->colorByte1) +
                         (f32)slot->colorByte1);
            colB = (int)(ratio * (f32)(quad[3].alpha - slot->colorByte2) +
                         (f32)slot->colorByte2);
            if ((slot->renderFlags & 0x1000000) != 0) {
              quad[0].colorR = (s16)colR * (ambR8 + 1) >> 8;
              quad[0].colorG = (s16)colG * (ambG8 + 1) >> 8;
              quad[0].colorB = (s16)colB * (ambB8 + 1) >> 8;
            } else if ((slot->renderFlags & 0x800000) != 0) {
              quad[0].colorR = (u32)((s16)colR * ambRPlus1) >> 8;
              quad[0].colorG = (u32)((s16)colG * ambGPlus1) >> 8;
              quad[0].colorB = (u32)((s16)colB * ambBPlus1) >> 8;
            } else {
              quad[0].colorR = colR;
              quad[0].colorG = colG;
              quad[0].colorB = colB;
            }
          } else if ((slot->renderFlags & 0x1000000) != 0) {
            quad[0].colorR = ambR8;
            quad[0].colorG = ambG8;
            quad[0].colorB = ambB8;
          } else if ((slot->renderFlags & 0x800000) != 0) {
            quad[0].colorR = ambScaledR;
            quad[0].colorG = ambScaledG;
            quad[0].colorB = ambScaledB;
          }
          if ((slot->renderFlags & 0x200000) != 0) {
            f32 sx;
            f32 sy;
            f32 sz;
            f32 dirX;
            f32 dirY;
            f32 dirZ;
            f32 prevDX;
            f32 prevDY;
            f32 prevDZ;
            f32 normSq;
            f32 norm;
            f32 axisX;
            f32 axisY;
            f32 axisZ;
            s16 baseX;
            s16 baseY;
            s16 baseZ;

            sx = lbl_803DF35C;
            sy = sx;
            sz = sx;
            if ((slot->behaviorFlags & 1) == 0) {
              if (srcObj != NULL) {
                sx = *(f32 *)(srcObj + 0x18);
                sy = *(f32 *)(srcObj + 0x1c);
                sz = *(f32 *)(srcObj + 0x20);
              } else {
                sx = *(f32 *)&slot->sourcePosY;
                sy = *(f32 *)&slot->sourcePosZ;
                sz = *(f32 *)&slot->sourcePosW;
              }
            }
            dirX = sx - *(f32 *)&slot->posX;
            dirY = sy - *(f32 *)&slot->posY;
            dirZ = sz - *(f32 *)&slot->posZ;
            prevDX = prevX - *(f32 *)&slot->posX;
            prevDY = prevY - *(f32 *)&slot->posY;
            prevDZ = prevZ - *(f32 *)&slot->posZ;
            workA = prevDY * dirZ - prevDZ * dirY;
            workB = -(prevDX * dirZ - prevDZ * dirX);
            attractRatio = prevDX * dirY - prevDY * dirX;
            normSq = attractRatio * attractRatio + (workA * workA + workB * workB);
            if (lbl_803DF35C != normSq) {
              norm = sqrtf(normSq);
            } else {
              norm = lbl_803DF354;
            }
            axisX = lbl_803DF408 * (workA / norm);
            axisY = lbl_803DF408 * (workB / norm);
            axisZ = lbl_803DF408 * (attractRatio / norm);
            attractRatio = lbl_803DF40C / (lbl_803DF410 * (f32)(u16)slot->scaleTarget);
            baseX = (s16)(int)axisX;
            quad[0].x = baseX;
            baseY = (s16)(int)axisY;
            quad[0].y = baseY;
            baseZ = (s16)(int)axisZ;
            quad[0].z = baseZ;
            quad[0].texS = texS0;
            quad[0].texT = texT0;
            quad[1].x = (s16)(int)(attractRatio * (*(f32 *)&slot->posX - prevX) + axisX);
            quad[1].y = (s16)(int)(attractRatio * (*(f32 *)&slot->posY - prevY) + axisY);
            quad[1].z = (s16)(int)(attractRatio * (*(f32 *)&slot->posZ - prevZ) + axisZ);
            quad[1].texS = texS1;
            quad[1].texT = texT0;
            quad[2].x = (s16)(int)(attractRatio * (*(f32 *)&slot->posX - prevX) - axisX);
            quad[2].y = (s16)(int)(attractRatio * (*(f32 *)&slot->posY - prevY) - axisY);
            quad[2].z = (s16)(int)(attractRatio * (*(f32 *)&slot->posZ - prevZ) - axisZ);
            quad[2].texS = texS1;
            quad[2].texT = texT1;
            quad[3].x = -baseX;
            quad[3].y = -baseY;
            quad[3].z = -baseZ;
            quad[3].texS = texS0;
            quad[3].texT = texT1;
          } else if ((slot->behaviorFlags & 0x4000000) != 0 &&
                     (slot->renderFlags & 0x30000000) == 0) {
            rot.x = lbl_803DF35C;
            rot.y = lbl_803DF35C;
            rot.z = lbl_803DF35C;
            slot->sourceVecX = slot->sourceVecX + framesThisStep * (int)*(f32 *)&slot->sourcePosY;
            slot->sourceVecY = slot->sourceVecY + framesThisStep * (int)*(f32 *)&slot->sourcePosZ;
            slot->sourceVecZ = slot->sourceVecZ + framesThisStep * (int)*(f32 *)&slot->sourcePosW;
            rot.scale = lbl_803DF354;
            vecBuf[0] = (f32)template[0].x;
            vecBuf[1] = (f32)template[0].y;
            vecBuf[2] = (f32)template[0].z;
            rot.angleZ = 0;
            rot.angleY = 0;
            rot.angleX = slot->sourceVecX;
            mathFn_80021ac8(&rot, vecBuf);
            rot.angleZ = slot->sourceVecY;
            rot.angleY = slot->sourceVecZ;
            rot.angleX = 0;
            mathFn_80021ac8(&rot, vecBuf);
            quad[0].x = (s16)(int)vecBuf[0];
            quad[0].y = (s16)(int)vecBuf[1];
            quad[0].z = (s16)(int)vecBuf[2];
            quad[0].texS = texS0;
            quad[0].texT = texT0;
            vecBuf[0] = (f32)template[1].x;
            vecBuf[1] = (f32)template[1].y;
            vecBuf[2] = (f32)template[1].z;
            rot.angleZ = 0;
            rot.angleY = 0;
            rot.angleX = slot->sourceVecX;
            mathFn_80021ac8(&rot, vecBuf);
            rot.angleZ = slot->sourceVecY;
            rot.angleY = slot->sourceVecZ;
            rot.angleX = 0;
            mathFn_80021ac8(&rot, vecBuf);
            quad[1].x = (s16)(int)vecBuf[0];
            quad[1].y = (s16)(int)vecBuf[1];
            quad[1].z = (s16)(int)vecBuf[2];
            quad[1].texS = texS1;
            quad[1].texT = texT0;
            vecBuf[0] = (f32)template[2].x;
            vecBuf[1] = (f32)template[2].y;
            vecBuf[2] = (f32)template[2].z;
            rot.angleZ = 0;
            rot.angleY = 0;
            rot.angleX = slot->sourceVecX;
            mathFn_80021ac8(&rot, vecBuf);
            rot.angleZ = slot->sourceVecY;
            rot.angleY = slot->sourceVecZ;
            rot.angleX = 0;
            mathFn_80021ac8(&rot, vecBuf);
            quad[2].x = (s16)(int)vecBuf[0];
            quad[2].y = (s16)(int)vecBuf[1];
            quad[2].z = (s16)(int)vecBuf[2];
            quad[2].texS = texS1;
            quad[2].texT = texT1;
            vecBuf[0] = (f32)template[3].x;
            vecBuf[1] = (f32)template[3].y;
            vecBuf[2] = (f32)template[3].z;
            rot.angleZ = 0;
            rot.angleY = 0;
            rot.angleX = slot->sourceVecX;
            mathFn_80021ac8(&rot, vecBuf);
            rot.angleZ = slot->sourceVecY;
            rot.angleY = slot->sourceVecZ;
            rot.angleX = 0;
            mathFn_80021ac8(&rot, vecBuf);
            quad[3].x = (s16)(int)vecBuf[0];
            quad[3].y = (s16)(int)vecBuf[1];
            quad[3].z = (s16)(int)vecBuf[2];
            quad[3].texS = texS0;
            quad[3].texT = texT1;
          } else if ((slot->renderFlags & 0x20) != 0) {
            quad[0].x = template[0].x;
            quad[0].y = template[0].y;
            quad[0].z = template[0].z;
            quad[0].texS = texS0;
            quad[0].texT = texT0;
            quad[1].x = template[1].x;
            quad[1].y = template[1].y;
            quad[1].z = template[1].z;
            quad[1].texS = texS1;
            quad[1].texT = texT0;
            quad[2].x = template[2].x;
            quad[2].y = template[2].y;
            quad[2].z = template[2].z;
            quad[2].texS = texS1;
            quad[2].texT = texT1;
            quad[3].x = template[3].x;
            quad[3].y = template[3].y;
            quad[3].z = template[3].z;
            quad[3].texS = texS0;
            quad[3].texT = texT1;
          } else if ((slot->renderFlags & 0x100) != 0) {
            quad[0].x = template[0].x;
            quad[0].y = template[0].y;
            quad[0].y = quad[0].y << 3;
            quad[0].z = template[0].z;
            quad[0].texS = texS0;
            quad[0].texT = texT0;
            quad[1].x = template[1].x;
            quad[1].y = template[1].y;
            quad[1].y = quad[1].y << 3;
            quad[1].z = template[1].z;
            quad[1].texS = texS1;
            quad[1].texT = texT0;
            quad[2].x = template[2].x;
            quad[2].y = template[2].y;
            quad[2].y = quad[2].y << 3;
            quad[2].z = template[2].z;
            quad[2].texS = texS1;
            quad[2].texT = texT1;
            quad[3].x = template[3].x;
            quad[3].y = template[3].y;
            quad[3].y = quad[3].y << 3;
            quad[3].z = template[3].z;
            quad[3].texS = texS0;
            quad[3].texT = texT1;
          } else if ((slot->renderFlags & 0x400) != 0) {
            quad[0].z = template[0].x;
            quad[0].z = quad[0].z << 5;
            quad[0].y = template[0].y;
            quad[0].x = template[0].z;
            quad[0].texS = texS0;
            quad[0].texT = texT0;
            quad[1].z = template[1].x;
            quad[1].z = quad[1].z << 5;
            quad[1].y = template[1].y;
            quad[1].x = template[1].z;
            quad[1].texS = texS1;
            quad[1].texT = texT0;
            quad[2].z = template[2].x;
            quad[2].z = quad[2].z << 5;
            quad[2].y = template[2].y;
            quad[2].x = template[2].z;
            quad[2].texS = texS1;
            quad[2].texT = texT1;
            quad[3].z = template[3].x;
            quad[3].z = quad[3].z << 5;
            quad[3].y = template[3].y;
            quad[3].x = template[3].z;
            quad[3].texS = texS0;
            quad[3].texT = texT1;
          } else if ((slot->renderFlags & 0x200) != 0) {
            quad[0].x = template[0].x;
            quad[0].x = quad[0].x << 5;
            quad[0].y = template[0].y;
            quad[0].z = template[0].z;
            quad[0].texS = texS0;
            quad[0].texT = texT0;
            quad[1].x = template[1].x;
            quad[1].x = quad[1].x << 5;
            quad[1].y = template[1].y;
            quad[1].z = template[1].z;
            quad[1].texS = texS1;
            quad[1].texT = texT0;
            quad[2].x = template[2].x;
            quad[2].x = quad[2].x << 5;
            quad[2].y = template[2].y;
            quad[2].z = template[2].z;
            quad[2].texS = texS1;
            quad[2].texT = texT1;
            quad[3].x = template[3].x;
            quad[3].x = quad[3].x << 5;
            quad[3].y = template[3].y;
            quad[3].z = template[3].z;
            quad[3].texS = texS0;
            quad[3].texT = texT1;
          } else {
            quad[0].x = template[0].x;
            quad[0].y = template[0].y;
            quad[0].z = template[0].z;
            quad[0].texS = texS0;
            quad[0].texT = texT0;
            quad[1].x = template[1].x;
            quad[1].y = template[1].y;
            quad[1].z = template[1].z;
            quad[1].texS = texS1;
            quad[1].texT = texT0;
            quad[2].x = template[2].x;
            quad[2].y = template[2].y;
            quad[2].z = template[2].z;
            quad[2].texS = texS1;
            quad[2].texT = texT1;
            quad[3].x = template[3].x;
            quad[3].y = template[3].y;
            quad[3].z = template[3].z;
            quad[3].texS = texS0;
            quad[3].texT = texT1;
          }
          attached = (u8 *)((ExpgfxTableEntry *)(runtimeBase + EXPGFX_EXPTAB_OFFSET +
                                                 (((u32)slot->encodedTableIndex >> 1) &
                                                  EXPGFX_SLOT_TABLE_INDEX_MASK) *
                                                     EXPGFX_TABLE_ENTRY_SIZE))
                         ->attachedKey1;
          rot.x = lbl_803DF35C;
          rot.y = lbl_803DF35C;
          rot.z = lbl_803DF35C;
          rot.scale = lbl_803DF354;
          if ((slot->behaviorFlags & 0x20000) != 0 &&
              (slot->renderFlags & 0x30000000) == 0) {
            rot.x = *(f32 *)&slot->posX;
            rot.y = *(f32 *)&slot->posY;
            rot.z = *(f32 *)&slot->posZ;
          }
          rot.angleZ = 0;
          rot.angleY = 0;
          rot.angleX = 0;
          if ((slot->behaviorFlags & 0x4000000) == 0 && (slot->behaviorFlags & 4) != 0) {
            if (srcObj != NULL) {
              rot.angleX = *(s16 *)srcObj;
              rot.angleY = *(s16 *)(srcObj + 2);
              rot.angleZ = *(s16 *)(srcObj + 4);
            } else {
              rot.angleX = slot->sourceVecX;
              rot.angleY = slot->sourceVecY;
              rot.angleZ = slot->sourceVecZ;
            }
          }
          rotPos[0] = *(f32 *)&slot->posX;
          rotPos[1] = *(f32 *)&slot->posY;
          rotPos[2] = *(f32 *)&slot->posZ;
          if ((u16)(rot.angleZ | rot.angleX | rot.angleY) != 0) {
            mathFn_80021ac8(&rot, rotPos);
          }
          if ((slot->behaviorFlags & 1) == 0) {
            if (srcObj == NULL) {
              srcVel[0] = *(f32 *)&slot->sourcePosY;
              srcVel[1] = *(f32 *)&slot->sourcePosZ;
              srcVel[2] = *(f32 *)&slot->sourcePosW;
              if (attached != NULL) {
                Obj_RotateLocalOffsetByYaw(&slot->sourcePosY, srcVel, *(attached + 0x35));
              }
            } else {
              srcVel[0] = *(f32 *)(srcObj + 0x18);
              srcVel[1] = *(f32 *)(srcObj + 0x1c);
              srcVel[2] = *(f32 *)(srcObj + 0x20);
            }
          } else {
            srcVel[0] = lbl_803DF35C;
            srcVel[1] = lbl_803DF35C;
            srcVel[2] = lbl_803DF35C;
          }
          rot.angleZ = 0;
          rot.angleY = 0;
          rot.angleX = 0;
          rot.x = srcVel[0] + rotPos[0];
          rot.y = srcVel[1] + rotPos[1];
          rot.z = srcVel[2] + rotPos[2];
          if ((slot->behaviorFlags & 0x20000) != 0 &&
              (slot->behaviorFlags & 0x4000000) == 0 &&
              (slot->renderFlags & 0x30000000) == 0) {
            rot.x = rot.x + *(f32 *)&slot->sourcePosY;
            rot.y = rot.y + *(f32 *)&slot->sourcePosZ;
            rot.z = rot.z + *(f32 *)&slot->sourcePosW;
          }
          slot->renderX = rot.x;
          slot->renderY = rot.y;
          slot->renderZ = rot.z;
          if (rot.x < bounds->minX) {
            bounds->minX = rot.x;
          }
          if (rot.x > *maxXPtr) {
            *maxXPtr = rot.x;
          }
          if (rot.y < *minYPtr) {
            *minYPtr = rot.y;
          }
          if (rot.y > *maxYPtr) {
            *maxYPtr = rot.y;
          }
          if (rot.z < *minZPtr) {
            *minZPtr = rot.z;
          }
          if (rot.z > *maxZPtr) {
            *maxZPtr = rot.z;
          }
        } else {
          debugPrintf((char *)(staticBase + EXPGFX_STATIC_NO_TEXTURE_STRING_OFFSET));
        }
      }
      memcpyToCache((void *)*(u32 *)((runtimeBase + pool4) + EXPGFX_SLOT_POOL_BASES_OFFSET),
                    curPoolBuf, 0x7e);
      prefetched = 1;
      pool = next;
    }
    cacheFn_800229c4(0);
  }
}
#pragma peephole reset
#pragma scheduling reset

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
#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
int expgfx_addToTable(uint resourceHandle,uint sourceId,uint attachedTableKey,s16 resourceId)
{
  ExpgfxTableEntry *entry;
  ExpgfxTableEntry *freeScan;
  u16 *refCount;
  int tableIndex;
  int freeIndex;

  tableIndex = 0;
  entry = gExpgfxTableEntries;
  freeScan = entry;
  for (; tableIndex < EXPGFX_EXPTAB_ENTRY_COUNT; entry++, tableIndex++) {
    if ((entry->refCount != 0) && (entry->resource == resourceHandle) &&
        (entry->sourceId == sourceId) && (entry->attachedKey1 == attachedTableKey)) {
      refCount = &gExpgfxTableEntries[tableIndex].refCount;
      if (*refCount >= EXPGFX_REFCOUNT_OVERFLOW) {
        debugPrintf(sExpgfxAddToTableUsageOverflow);
        return EXPGFX_INVALID_TABLE_INDEX;
      }
      (*refCount)++;
      return (s16)tableIndex;
    }
  }

  for (freeIndex = 0; freeIndex < EXPGFX_EXPTAB_ENTRY_COUNT; freeScan++, freeIndex++) {
    if (freeScan->refCount == 0) {
      gExpgfxTableEntries[freeIndex].refCount = 1;
      gExpgfxTableEntries[freeIndex].resource = resourceHandle;
      gExpgfxTableEntries[freeIndex].sourceId = sourceId;
      gExpgfxTableEntries[freeIndex].attachedKey1 = attachedTableKey;
      gExpgfxTableEntries[freeIndex].resourceId = resourceId;
      return (s16)freeIndex;
    }
  }

  debugPrintf(sExpgfxExpTabIsFull);
  return EXPGFX_INVALID_TABLE_INDEX;
}
#pragma peephole reset
#pragma scheduling reset
#pragma dont_inline reset

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
  ExpgfxTrackedSourceFrameMask *mask;
  u32 bit;
  u32 highBits;
  int result;
  u32 *poolSourceIds;
  int poolIndex;
  u8 *poolFrameFlags;
  int signedPoolIndex;

  result = EXPGFX_SOURCE_FRAME_STATE_NONE;
  lbl_803DD253 = 0;
  poolIndex = 0;
  source = (ExpgfxSourceObject *)sourceObject;
  poolSourceIds = gExpgfxTrackedPoolSourceIds;
  poolFrameFlags = gExpgfxStaticPoolFrameFlags;

  while ((s16)poolIndex < EXPGFX_POOL_COUNT) {
    if ((source->objType == EXPGFX_SOURCE_OBJTYPE_MATCH_ALL) ||
        (*poolSourceIds == (u32)sourceObject)) {
      signedPoolIndex = (s16)poolIndex;
      bit = 1 << (signedPoolIndex >> 1);
      highBits = (u32)((s32)bit >> 31);
      mask = &gExpgfxTrackedSourceFrameMasks[signedPoolIndex & 1];
      if ((CONCAT44(mask->high, mask->low) & CONCAT44(highBits, bit)) != 0) {
        *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_B;
        if ((s8)result == EXPGFX_SOURCE_FRAME_STATE_A) {
          result = EXPGFX_SOURCE_FRAME_STATE_MIXED;
        } else {
          result = EXPGFX_SOURCE_FRAME_STATE_B;
        }
      }
      else {
        *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_A;
        if ((s8)result == EXPGFX_SOURCE_FRAME_STATE_B) {
          result = EXPGFX_SOURCE_FRAME_STATE_MIXED;
        } else {
          result = EXPGFX_SOURCE_FRAME_STATE_A;
        }
      }
    }
    else {
      *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_NONE;
    }
    poolSourceIds++;
    poolFrameFlags++;
    poolIndex++;
  }

  return result;
}
#pragma peephole reset
#pragma scheduling reset

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
#pragma scheduling off
#pragma peephole off
void expgfx_renderSourcePools(int sourceId,int sourceMode)
{
  u8 *expgfxBase;
  ExpgfxBounds *boundsTemplate;
  s8 *poolActiveCounts;
  u32 *poolSourceIds;
  u8 *poolSourceModes;
  u8 *poolBoundsTemplateIds;
  ExpgfxBounds *poolBounds;
  u32 *slotPoolBases;
  int poolIndex;

  expgfxBase = gExpgfxRuntimeData;
  poolIndex = 0;
  poolActiveCounts = (s8 *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
  poolSourceIds = (u32 *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET);
  poolSourceModes = expgfxBase + EXPGFX_POOL_SOURCE_MODES_OFFSET;
  poolBoundsTemplateIds = expgfxBase + EXPGFX_POOL_BOUNDS_TEMPLATE_IDS_OFFSET;
  poolBounds = (ExpgfxBounds *)(expgfxBase + EXPGFX_POOL_BOUNDS_OFFSET);
  slotPoolBases = (u32 *)(expgfxBase + EXPGFX_SLOT_POOL_BASES_OFFSET);

  while (poolIndex < EXPGFX_POOL_COUNT) {
    if ((*poolActiveCounts != 0) && (*poolSourceIds == (u32)sourceId) &&
        (*poolSourceModes == sourceMode + EXPGFX_POOL_SOURCE_MODE_SOURCE_OFFSET)) {
      boundsTemplate =
          (ExpgfxBounds *)(gExpgfxStaticData + *poolBoundsTemplateIds * EXPGFX_BOUNDS_TEMPLATE_SIZE);
      if (fn_8005E97C(poolBounds->minX - playerMapOffsetX,poolBounds->maxX - playerMapOffsetX,
                      poolBounds->minY,poolBounds->maxY,poolBounds->minZ - playerMapOffsetZ,
                      poolBounds->maxZ - playerMapOffsetZ,boundsTemplate) != 0) {
        drawGlow(*slotPoolBases,poolIndex);
      }
    }
    poolActiveCounts++;
    poolSourceIds++;
    poolSourceModes++;
    poolBoundsTemplateIds++;
    poolBounds++;
    slotPoolBases++;
    poolIndex++;
  }
}
#pragma peephole reset
#pragma scheduling reset

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
extern void expgfx_updateResourceEntries(int unused);
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
    sourceObject = (ExpgfxSourceObject *)tabEntry->sourceId;
    texture = tabEntry->resource;
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
      } else if ((behavior & EXPGFX_BEHAVIOR_BILLBOARD_USE_PITCH) != 0) {
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

  if (gExpgfxRenderResetPending != 0) {
    expgfx_updateResourceEntries(0);
    gExpgfxRenderResetPending = 0;
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

  currentMatrix = Camera_GetViewMatrix();
  poolIndex = 0;
  poolActiveCounts = (char *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
  poolSourceModes = expgfxBase + EXPGFX_POOL_SOURCE_MODES_OFFSET;
  poolBoundsTemplateIds = expgfxBase + EXPGFX_POOL_BOUNDS_TEMPLATE_IDS_OFFSET;
  poolBounds = (ExpgfxBounds *)(expgfxBase + EXPGFX_POOL_BOUNDS_OFFSET);
  poolSourceIds = (u32 *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET);
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
        lightmap_queueExternalRenderEntry(*slotPoolBases,poolIndex,queuePosition);
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
#pragma scheduling off
#pragma peephole off
void expgfx_free(u32 sourceId)
{
  u8 *expgfxBase;
  ExpgfxRuntimeDataLayout *runtime;
  ExpgfxSlot *slot;
  ExpgfxTableEntry *tableEntry;
  u32 *slotPoolBases;
  u32 *poolSourceIds;
  s8 *poolActiveCounts;
  s16 *poolSlotTypeIds;
  u8 *poolFrameFlags;
  u32 tableOffset;
  int poolIndex;
  int slotIndex;

  runtime = EXPGFX_RUNTIME_DATA;
  expgfxBase = (u8 *)runtime;
  if (sourceId == 0) {
    return;
  }

  poolIndex = 0;
  slotPoolBases = runtime->slotPoolBases;
  poolSourceIds = runtime->poolSourceIds;
  poolActiveCounts = runtime->poolActiveCounts;
  poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
  poolFrameFlags = gExpgfxStaticPoolFrameFlags;

  while (poolIndex < EXPGFX_POOL_COUNT) {
    slot = (ExpgfxSlot *)*slotPoolBases;
    if (*poolSourceIds == sourceId) {
      for (slotIndex = 0; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++) {
        if (slot != NULL) {
          tableOffset = Expgfx_GetSlotTableIndex(slot) << EXPGFX_TABLE_ENTRY_SHIFT;
          tableEntry = (ExpgfxTableEntry *)(expgfxBase + EXPGFX_EXPTAB_OFFSET + tableOffset);
          if (tableEntry->sourceId == sourceId) {
            expgfxRemove(*slotPoolBases, poolIndex, slotIndex, 0, 1);
          }
        }
        slot = (ExpgfxSlot *)((u8 *)slot + EXPGFX_SLOT_SIZE);
        if (*poolActiveCounts == 0) {
          *poolSlotTypeIds = EXPGFX_INVALID_SLOT_TYPE;
        }
      }
      *poolSourceIds = 0;
      *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_NONE;
    }

    poolSourceIds++;
    slotPoolBases++;
    poolActiveCounts++;
    poolSlotTypeIds++;
    poolFrameFlags++;
    poolIndex++;
  }
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
  u8 *staticBase;
  u8 *expgfxBase;
  ExpgfxSlot *slot;
  ExpgfxResourceEntry *resourceEntry;
  u32 *slotPoolBases;
  u32 *poolActiveMasks;
  s8 *poolActiveCounts;
  s16 *poolSlotTypeIds;
  u32 *poolSourceIds;
  u8 *poolFrameFlags;
  u16 *refCount;
  u32 activeBit;
  u32 inactiveBitMask;
  u32 tableOffset;
  int poolIndex;
  int slotIndex;
  int resourceIndex;

  staticBase = gExpgfxStaticData;
  expgfxBase = gExpgfxRuntimeData;
  poolIndex = 0;
  slotPoolBases = (u32 *)(expgfxBase + EXPGFX_SLOT_POOL_BASES_OFFSET);
  poolActiveMasks = (u32 *)(expgfxBase + EXPGFX_POOL_ACTIVE_MASKS_OFFSET);
  poolActiveCounts = (s8 *)(expgfxBase + EXPGFX_POOL_ACTIVE_COUNTS_OFFSET);
  poolSlotTypeIds = (s16 *)(staticBase + EXPGFX_STATIC_POOL_SLOT_TYPE_IDS_OFFSET);
  poolSourceIds = (u32 *)(expgfxBase + EXPGFX_POOL_SOURCE_IDS_OFFSET);
  poolFrameFlags = staticBase + EXPGFX_STATIC_POOL_FRAME_FLAGS_OFFSET;

  while (poolIndex < EXPGFX_POOL_COUNT) {
    slot = (ExpgfxSlot *)*slotPoolBases;
    for (slotIndex = 0; slotIndex < EXPGFX_SLOTS_PER_POOL; slotIndex++) {
      activeBit = 1 << slotIndex;
      if ((*poolActiveMasks & activeBit) != 0) {
        tableOffset = Expgfx_GetSlotTableIndex(slot) << EXPGFX_TABLE_ENTRY_SHIFT;
        if (*(u32 *)(expgfxBase + EXPGFX_EXPTAB_TEXTURE_RESOURCE_OFFSET + tableOffset) != 0) {
          gExpgfxTextureFreeInProgress = 1;
          tableOffset = Expgfx_GetSlotTableIndex(slot) << EXPGFX_TABLE_ENTRY_SHIFT;
          textureFree((void *)*(u32 *)(expgfxBase + EXPGFX_EXPTAB_TEXTURE_RESOURCE_OFFSET + tableOffset));
          gExpgfxTextureFreeInProgress = 0;
        }

        tableOffset = Expgfx_GetSlotTableIndex(slot) << EXPGFX_TABLE_ENTRY_SHIFT;
        refCount = (u16 *)(expgfxBase + EXPGFX_EXPTAB_REFCOUNT_OFFSET + tableOffset);
        if (*refCount != 0) {
          (*refCount)--;
          if (*refCount == 0) {
            *(u32 *)(expgfxBase + EXPGFX_EXPTAB_TEXTURE_RESOURCE_OFFSET + tableOffset) = 0;
            *(u32 *)(expgfxBase + EXPGFX_EXPTAB_OFFSET + tableOffset) = 0;
          }
        } else {
          debugPrintf((char *)(staticBase + EXPGFX_STATIC_MISMATCH_ADD_REMOVE_STRING_OFFSET));
        }

        slot->sequenceId = EXPGFX_INVALID_SEQUENCE_ID;
        inactiveBitMask = ~activeBit;
        *poolActiveMasks = *poolActiveMasks & inactiveBitMask;
      }

      slot = (ExpgfxSlot *)((u8 *)slot + EXPGFX_SLOT_SIZE);
    }

    *poolActiveCounts = 0;
    *poolSlotTypeIds = EXPGFX_INVALID_SLOT_TYPE;
    *poolSourceIds = 0;
    *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_NONE;
    DCFlushRange((void *)*slotPoolBases, EXPGFX_POOL_BYTES);

    slotPoolBases++;
    poolActiveMasks++;
    poolActiveCounts++;
    poolSlotTypeIds++;
    poolSourceIds++;
    poolFrameFlags++;
    poolIndex++;
  }

  resourceEntry = (ExpgfxResourceEntry *)expgfxBase;
  resourceIndex = 0;
  while (resourceIndex < EXPGFX_RESOURCE_TABLE_COUNT) {
    gExpgfxTextureFreeInProgress = 1;
    if (resourceEntry->resource != NULL) {
      textureFree(resourceEntry->resource);
    }
    gExpgfxTextureFreeInProgress = 0;
    resourceEntry->resource = NULL;
    resourceEntry->resourceId = 0;
    resourceEntry->evictionScore = 0;
    resourceEntry->wordC = 0;
    resourceIndex++;
    resourceEntry++;
  }
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

  renderMode = renderModeSetOrGet(EXPGFX_INVALID_SLOT_TYPE);
  if ((short)renderMode != 1) {
    frameValue = gExpgfxFrameTimerA + (frameStep = timeDelta);
    gExpgfxFrameTimerA = frameValue;
    if (frameValue >= lbl_803DF418) {
      gExpgfxFrameTimerA = lbl_803DF35C;
    }
    frameValue = gExpgfxFrameTimerB + frameStep;
    gExpgfxFrameTimerB = frameValue;
    if (frameValue >= lbl_803DF384) {
      gExpgfxFrameTimerB = lbl_803DF35C;
    }
    frameValue = gExpgfxFrameTimerC + frameStep;
    gExpgfxFrameTimerC = frameValue;
    if (frameValue >= lbl_803DF354) {
      gExpgfxFrameTimerC = lbl_803DF35C;
    }
    gExpgfxUpdatingActivePools = 1;
    expgfx_updateActivePools((u8)sourceMode,sourceId,0);
    gExpgfxUpdatingActivePools = 0;
    poolIndex = EXPGFX_POOL_COUNT;
    while ((u8)poolIndex > 0) {
      poolIndex--;
      gExpgfxStaticPoolFrameFlags[(u8)poolIndex] = EXPGFX_SOURCE_FRAME_STATE_NONE;
    }
    (*(code *)(*gPartfxInterface + 0xc))(0);
    gExpgfxRenderResetPending = 1;
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
extern int expgfx_acquireResourceEntry(int resourceId);
extern void *Obj_GetPlayerObject(void);
extern f32 lbl_803DF350;
extern f32 lbl_803DF41C;
extern f32 lbl_803DF420;
extern f32 lbl_803DF424;
extern f32 lbl_803DF428;
extern int gExpgfxLastAddedSlot;
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
  int resourceTableIndex;
  int expTabIndex;
  int attachedTableKey;
  uint trackedMaskPair;
  uint bit;
  uint maskHighWord;
  uint maskLowWord;
  uint inverseBit;
  short poolIndex;
  short slotIndex;
  int texS1 = 0;
  int texS0 = 0;
  int texT0 = 0;
  int texT1 = 0;
  f32 scaleVal;
  u8 *poolSourceModesByte;
  u8 modeFlag;
  uint *slotPoolBases;
  u32 *trackedFrameMasks;
  ExpgfxQuadVertex *quadVertices;

  expgfxBase = gExpgfxRuntimeData;
  poolIndex = 0;
  slotIndex = 0;
  texS1 = 0;
  texS0 = 0;
  texT0 = 0;
  texT1 = 0;
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
  quadVertices = (ExpgfxQuadVertex *)slot;
  gExpgfxSequenceCounter = gExpgfxSequenceCounter + 1;
  if ((short)EXPGFX_SEQUENCE_COUNTER_MAX < (short)gExpgfxSequenceCounter) {
    gExpgfxSequenceCounter = 0;
  }
  slot->sequenceId = gExpgfxSequenceCounter;
  slot->behaviorFlags = config->behaviorFlags;
  slot->renderFlags = config->renderFlags;
  slot->stateBits.value = slot->stateBits.value & ~EXPGFX_SLOT_STATE_INIT_PHASE_MASK;

  resourceTableIndex = (int)(short)expgfx_acquireResourceEntry(config->textureId);
  if (resourceTableIndex < 0) {
    expgfxRemove(slotPoolBases[(int)poolIndex], (int)poolIndex, (int)slotIndex, 1, 1);
    return EXPGFX_INVALID_POOL_INDEX;
  }
  resourceHandle =
      (ExpgfxResourceHandle *)*(u32 *)(expgfxBase + (resourceTableIndex << EXPGFX_TABLE_ENTRY_SHIFT));
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
    texS1 = 0;
    texS0 = 0;
  }
  if ((behaviorFlags & EXPGFX_BEHAVIOR_FLIP_TEX0_T) != 0) {
    texT1 = 0;
    texT0 = 0;
  }

  attachedSource = (ExpgfxAttachedSourceState *)config->attachedSource;
  attachedTableKey = 0;
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
    attachedTableKey = attachedSource->tableKey1;
    attachedSource = NULL;
  }

  expTabIndex = expgfx_addToTable((uint)resourceHandle, (uint)attachedSource, attachedTableKey,
                                     config->textureId);
  if ((short)expTabIndex == EXPGFX_INVALID_TABLE_INDEX) {
    debugPrintf(sExpgfxInvalidTabIndex);
    expgfxRemove(slotPoolBases[(int)poolIndex], (int)poolIndex, (int)slotIndex, 1, 1);
    return EXPGFX_INVALID_POOL_INDEX;
  }
  Expgfx_SetSlotTableIndex(slot, (u8)expTabIndex);

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
  quadVertices[3].pad06 = (s16)config->quadVertex3Pad06;
  slot->lifetimeFrame = (s16)config->lifetimeFrames;
  slot->lifetimeFrameLimit = (s16)config->lifetimeFrames;

  if (config->scale > lbl_803DF354) {
    debugPrintf(sExpgfxScaleOverflow);
  }
  scaleVal = lbl_803DF350 * config->scale;

  if ((slot->behaviorFlags & EXPGFX_BEHAVIOR_SCALE_FROM_ZERO) != 0) {
    slot->scaleCounter = 0;
    slot->scaleFrames = (int)(scaleVal / (f32)(s32)slot->lifetimeFrameLimit);
    slot->scaleTarget = (int)scaleVal;
  } else if ((slot->renderFlags & EXPGFX_RENDER_SCALE_OVER_LIFETIME) != 0) {
    slot->scaleCounter = (int)scaleVal;
    slot->scaleFrames = (int)(scaleVal / (f32)(s32)slot->lifetimeFrameLimit);
    slot->scaleTarget = slot->scaleCounter;
  } else {
    slot->scaleCounter = (int)scaleVal;
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
    quadVertices[1].alpha = (u8)((int)config->overrideColor0 >> 8);
    quadVertices[2].alpha = (u8)((int)config->overrideColor1 >> 8);
    quadVertices[3].alpha = (u8)((int)config->overrideColor2 >> 8);
  }

  quadVertices[0].colorR = 0xff;
  quadVertices[0].colorG = 0xff;
  quadVertices[0].colorB = 0xff;

  quadVertices[0].texS = (s16)texS0;
  quadVertices[0].texT = (s16)texT0;
  quadVertices[1].texS = (s16)texS1;
  quadVertices[1].texT = (s16)texT0;
  quadVertices[2].texS = (s16)texS1;
  quadVertices[2].texT = (s16)texT1;
  quadVertices[3].texS = (s16)texS0;
  quadVertices[3].texT = (s16)texT1;

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
  gExpgfxLastAddedSlot = (int)slot;
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
#pragma scheduling off
#pragma peephole off
void expgfx_onMapSetup(void)
{
  ExpgfxRuntimeDataLayout *runtime;
  ExpgfxResourceEntry *resourceEntry;
  ExpgfxTrackedSourceFrameMask *trackedFrameMasks;
  u32 *poolActiveMasks;
  s8 *poolActiveCounts;
  u8 *poolSourceModes;
  u32 *poolSourceIds;
  s16 *poolSlotTypeIds;
  u8 *poolFrameFlags;
  int poolIndex;
  int resourceIndex;

  runtime = EXPGFX_RUNTIME_DATA;
  expgfxRemoveAll();

  poolActiveMasks = runtime->poolActiveMasks;
  poolActiveCounts = runtime->poolActiveCounts;
  poolSlotTypeIds = gExpgfxStaticPoolSlotTypeIds;
  poolFrameFlags = gExpgfxStaticPoolFrameFlags;
  poolSourceModes = runtime->poolSourceModes;
  poolSourceIds = runtime->poolSourceIds;

  for (poolIndex = 0; poolIndex < EXPGFX_POOL_COUNT; poolIndex++) {
    *poolActiveMasks = 0;
    *poolActiveCounts = 0;
    *poolSlotTypeIds = EXPGFX_INVALID_SLOT_TYPE;
    *poolFrameFlags = EXPGFX_SOURCE_FRAME_STATE_NONE;
    *poolSourceModes = EXPGFX_POOL_SOURCE_MODE_STANDALONE;
    *poolSourceIds = 0;

    poolActiveMasks++;
    poolActiveCounts++;
    poolSlotTypeIds++;
    poolFrameFlags++;
    poolSourceModes++;
    poolSourceIds++;
  }

  trackedFrameMasks = runtime->trackedSourceFrameMasks;
  trackedFrameMasks[0].low = 0;
  trackedFrameMasks[0].high = 0;
  trackedFrameMasks[1].low = 0;
  trackedFrameMasks[1].high = 0;

  gExpgfxTextureFreeInProgress = 1;
  resourceEntry = runtime->resourceTable;
  for (resourceIndex = 0; resourceIndex < EXPGFX_RESOURCE_TABLE_COUNT; resourceIndex++,
      resourceEntry++) {
    if (resourceEntry->resource != NULL) {
      textureFree(resourceEntry->resource);
    }
    resourceEntry->resource = NULL;
    resourceEntry->resourceId = 0;
    resourceEntry->evictionScore = 0;
    resourceEntry->wordC = 0;
  }
  gExpgfxTextureFreeInProgress = 0;
}
#pragma peephole reset
#pragma scheduling reset

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
  u32 *slotPoolBases;
  int poolIndex;

  expgfxRemoveAll();
  poolIndex = 0;
  slotPoolBases = gExpgfxSlotPoolBases;
  do {
    mm_free((void *)*slotPoolBases);
    slotPoolBases = slotPoolBases + 1;
    poolIndex = poolIndex + 1;
  } while (poolIndex < EXPGFX_POOL_COUNT);
  return;
}
#pragma peephole reset
#pragma scheduling reset
