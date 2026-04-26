#include "ghidra_import.h"
#include "dolphin/os/OSCache.h"
#include "main/expgfx.h"
#include "main/expgfx_internal.h"

extern undefined4 ABS();
extern int fn_8000F54C(void);
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
extern void fn_80247494(int matrix,float *src,float *dst);
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
extern undefined4 DAT_803dded0;
extern undefined4 DAT_803dded2;
extern undefined4 DAT_803dded4;
extern undefined4 DAT_803dded8;
extern undefined4 DAT_803ddee8;
extern undefined4 DAT_803ddeea;
extern undefined2* DAT_803ddeec;
extern undefined4 DAT_803ddef0;
extern undefined4 DAT_803ddef4;
extern undefined4 DAT_803ddef8;
extern undefined4 DAT_cc008000;
extern undefined lbl_8030F968[];
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
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc3f0;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 lbl_803DCDD8;
extern f32 lbl_803DCDDC;
extern f64 lbl_803DF378;
extern f32 lbl_803DF3B4;
extern f32 lbl_803DF3B8;
extern f32 lbl_803DF3BC;
extern f32 lbl_803DF3C0;
extern f32 lbl_803DF3C4;
extern f32 FLOAT_803ddedc;
extern f32 FLOAT_803ddee0;
extern f32 FLOAT_803ddee4;
extern f32 FLOAT_803dffd0;
extern f32 FLOAT_803dffd4;
extern f32 FLOAT_803dffd8;
extern f32 FLOAT_803dffdc;
extern f32 FLOAT_803e0004;
extern f32 FLOAT_803e000c;
extern f32 FLOAT_803e0010;
extern f32 FLOAT_803e0030;
extern f32 FLOAT_803e0034;
extern f32 FLOAT_803e0038;
extern f32 FLOAT_803e003c;
extern f32 FLOAT_803e0040;
extern f32 FLOAT_803e0044;
extern f32 FLOAT_803e0048;
extern f32 FLOAT_803e004c;
extern f32 FLOAT_803e0050;
extern f32 FLOAT_803e0054;
extern f32 FLOAT_803e0058;
extern f32 FLOAT_803e005c;
extern f32 FLOAT_803e0060;
extern f32 FLOAT_803e0064;
extern f32 FLOAT_803e0068;
extern f32 FLOAT_803e006c;
extern f32 FLOAT_803e0070;
extern f32 FLOAT_803e0074;
extern f32 FLOAT_803e0078;
extern f32 FLOAT_803e007c;
extern f32 FLOAT_803e0080;
extern f32 FLOAT_803e0084;
extern f32 FLOAT_803e0088;
extern f32 FLOAT_803e008c;
extern f32 FLOAT_803e0090;
extern f32 FLOAT_803e0094;
extern f32 FLOAT_803e0098;
extern f32 FLOAT_803e009c;
extern f32 FLOAT_803e00a0;
extern f32 FLOAT_803e00a4;
extern f32 FLOAT_803e00a8;
extern u8 lbl_8030F898[];
extern u8 lbl_8039AB58[];
extern u32 lbl_8039BA28[];
extern u32 lbl_8039BB68[];
extern u32 lbl_8039BD58;
extern s16 lbl_8030F8C8[];
extern int lbl_803DD258;
extern char sExpgfxAddToTableUsageOverflow[];
extern char sExpgfxExpTabIsFull[];
extern char sExpgfxInvalidTabIndex[];
extern char sExpgfxMismatchInAddRemove[];
extern char sExpgfxScaleOverflow[];
extern char sExpgfxNoTexture[];

#define EXPGFX_SLOT_TABLE_INDEX_OFFSET 0x8A

extern ExpgfxTableEntry gExpgfxTableEntries[];

typedef struct ExpgfxResourceEntry {
  void *resource;
  u32 word4;
  u32 word8;
  u32 wordC;
} ExpgfxResourceEntry;

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
  u8 stateBits;
  u8 colorByte0;
  u8 colorByte1;
  u8 colorByte2;
  u8 pad8F[0xA0 - 0x8F];
} ExpgfxSlot;

static inline ExpgfxTableEntry *Expgfx_GetTableEntry(int tableIndex) {
  return &gExpgfxTableEntries[tableIndex];
}

static inline u8 Expgfx_GetSlotTableIndex(const ExpgfxSlot *slot) {
  return slot->encodedTableIndex >> 1;
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
void expgfx_release(uint slotPoolBase,int poolIndex,int slotIndex,int freeTexture,int clearActive)
{
  u8 *expgfxBase;
  u32 *poolActiveMask;
  char *poolActiveCount;
  ExpgfxSlot *slot;
  uint activeMask;
  uint tableIndex;
  u16 *refCount;
  u32 *tableTextureResources;

  expgfxBase = lbl_8039AB58;
  activeMask = 1 << slotIndex;
  poolActiveMask = (u32 *)(expgfxBase + 0x10c0 + poolIndex * sizeof(u32));
  if ((activeMask & *poolActiveMask) != 0) {
    slot = (ExpgfxSlot *)(slotPoolBase + slotIndex * EXPGFX_SLOT_SIZE);
    slot->behaviorFlags = 0;
    if (freeTexture == 0) {
      tableTextureResources = (u32 *)(expgfxBase + 0x988);
      tableIndex = ((uint)slot->encodedTableIndex >> 1) * 4;
      if (tableTextureResources[tableIndex] != 0) {
        lbl_803DD258 = 1;
        fn_80054308((void *)tableTextureResources[((uint)slot->encodedTableIndex >> 1) * 4]);
        lbl_803DD258 = 0;
      }
      tableIndex = ((uint)slot->encodedTableIndex >> 1) * 4;
      refCount = (u16 *)(expgfxBase + 0x98c + tableIndex * sizeof(u32));
      if (*refCount == 0) {
        fn_801378A8(sExpgfxMismatchInAddRemove);
      }
      else {
        (*refCount)--;
        if (*refCount == 0) {
          tableTextureResources[tableIndex] = 0;
          *(u32 *)(expgfxBase + 0x980 + tableIndex * sizeof(u32)) = 0;
        }
      }
    }
    slot->sequenceId = -1;
    if ((clearActive & 0xff) != 0) {
      DCFlushRange(slot,EXPGFX_SLOT_SIZE);
    }
    *poolActiveMask &= ~activeMask;
    poolActiveCount = (char *)(expgfxBase + 0x1070 + poolIndex);
    (*poolActiveCount)--;
    if (*poolActiveCount == '\0') {
      lbl_8030F8C8[poolIndex] = -1;
    }
  }
  return;
}

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
  slotPoolBases = (uint *)(expgfxBase + 0x1200);
  poolActiveMasks = (uint *)(expgfxBase + 0x10c0);
  poolActiveCounts = (char *)(expgfxBase + 0x1070);
  poolSlotTypeIds = lbl_8030F8C8;
  do {
    slot = (ExpgfxSlot *)*slotPoolBases;
    slotIndex = 0;
    do {
      if ((1 << slotIndex & *poolActiveMasks) != 0) {
        if ((((ExpgfxTableEntry *)(expgfxBase + 0x980))[Expgfx_GetSlotTableIndex(slot)].
             textureOrResource != 0) &&
            (((ExpgfxTableEntry *)(expgfxBase + 0x980))[Expgfx_GetSlotTableIndex(slot)].
             textureOrResource != 0)) {
          lbl_803DD258 = 1;
          fn_80054308((void *)((ExpgfxTableEntry *)(expgfxBase + 0x980))
                          [Expgfx_GetSlotTableIndex(slot)].textureOrResource);
          lbl_803DD258 = 0;
        }
        tableIndex = Expgfx_GetSlotTableIndex(slot);
        tableEntry = &((ExpgfxTableEntry *)(expgfxBase + 0x980))[tableIndex];
        if (tableEntry->refCount != 0) {
          tableEntry->refCount = tableEntry->refCount + -1;
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
int expgfx_reserveSlot(short *param_1,undefined2 *param_2,short param_3,int param_4,uint param_5)
{
  bool bVar1;
  short sVar2;
  u8 *expgfxBase;
  char *poolActiveCounts;
  char *pcVar3;
  int iVar4;
  char *pcVar5;
  short *psVar6;
  uint *puVar7;
  int *piVar8;
  int iVar9;
  int iVar10;

  sVar2 = -1;
  bVar1 = false;
  iVar4 = 0;
  expgfxBase = lbl_8039AB58;
  piVar8 = (int *)(expgfxBase + 0xed0);
  psVar6 = lbl_8030F8C8;
  poolActiveCounts = (char *)(expgfxBase + 0x1070);
  pcVar3 = poolActiveCounts;
  iVar9 = 0x10;
  pcVar5 = pcVar3;
  do {
    if (((param_5 == *piVar8) && (param_3 == *psVar6)) && (*pcVar5 < EXPGFX_SLOTS_PER_POOL)) {
      sVar2 = (short)iVar4;
      bVar1 = true;
      break;
    }
    if (((param_5 == piVar8[1]) && (param_3 == psVar6[1])) &&
        (pcVar5[1] < EXPGFX_SLOTS_PER_POOL)) {
      sVar2 = (short)(iVar4 + 1);
      bVar1 = true;
      iVar4 = iVar4 + 1;
      break;
    }
    if (((param_5 == piVar8[2]) && (param_3 == psVar6[2])) &&
        (pcVar5[2] < EXPGFX_SLOTS_PER_POOL)) {
      sVar2 = (short)(iVar4 + 2);
      bVar1 = true;
      iVar4 = iVar4 + 2;
      break;
    }
    if (((param_5 == piVar8[3]) && (param_3 == psVar6[3])) &&
        (pcVar5[3] < EXPGFX_SLOTS_PER_POOL)) {
      sVar2 = (short)(iVar4 + 3);
      bVar1 = true;
      iVar4 = iVar4 + 3;
      break;
    }
    if (((param_5 == piVar8[4]) && (param_3 == psVar6[4])) &&
        (pcVar5[4] < EXPGFX_SLOTS_PER_POOL)) {
      sVar2 = (short)(iVar4 + 4);
      bVar1 = true;
      iVar4 = iVar4 + 4;
      break;
    }
    piVar8 = piVar8 + 5;
    psVar6 = psVar6 + 5;
    pcVar5 = pcVar5 + 5;
    iVar4 = iVar4 + 5;
    iVar9 = iVar9 + -1;
  } while (iVar9 != 0);
  if (bVar1) {
    iVar9 = 0;
    puVar7 = (uint *)(expgfxBase + 0x10c0) + sVar2;
    iVar10 = EXPGFX_SLOTS_PER_POOL;
    do {
      if ((1 << iVar9 & *puVar7) == 0) {
        *param_2 = (short)iVar9;
        *param_1 = sVar2;
        *puVar7 = *puVar7 | 1 << iVar9;
        poolActiveCounts[sVar2] = poolActiveCounts[sVar2] + '\x01';
        return 1;
      }
      iVar9 = iVar9 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
  }
  bVar1 = false;
  if (param_4 != -1) {
    if ((param_4 != -1) &&
        (iVar4 = param_4, poolActiveCounts[param_4] < EXPGFX_SLOTS_PER_POOL)) {
      sVar2 = (short)param_4;
      bVar1 = true;
    }
  }
  else {
    iVar4 = 0;
    iVar9 = EXPGFX_POOL_COUNT - 1;
    do {
      if (*pcVar3 < '\x01') {
        sVar2 = (short)iVar4;
        bVar1 = true;
        poolActiveCounts[iVar4] = 0;
        break;
      }
      pcVar3 = pcVar3 + 1;
      iVar4 = iVar4 + 1;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
  }
  if (bVar1) {
    iVar9 = 0;
    puVar7 = (uint *)(expgfxBase + 0x10c0) + sVar2;
    iVar10 = EXPGFX_SLOTS_PER_POOL;
    do {
      if ((1 << iVar9 & *puVar7) == 0) {
        *param_2 = (short)iVar9;
        *param_1 = sVar2;
        *puVar7 = *puVar7 | 1 << iVar9;
        lbl_8030F8C8[iVar4] = param_3;
        ((char *)(lbl_8039AB58 + 0x1070))[sVar2] =
             ((char *)(lbl_8039AB58 + 0x1070))[sVar2] + '\x01';
        return 1;
      }
      iVar9 = iVar9 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
  }
  return 0xffffffff;
}
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

  staticDataBase = lbl_8030F898;
  slot = (ExpgfxSlot *)slotPtr;
  tableEntry = Expgfx_GetTableEntry(Expgfx_GetSlotTableIndex(slot));
  texture = tableEntry->textureOrResource;
  slot->stateBits = slot->stateBits & 0xfe;
  slot->stateBits = slot->stateBits & 0xfd | 2;
  behaviorFlags = slot->behaviorFlags;
  if ((behaviorFlags & 0x8000000) == 0) {
    quadTemplate = (s16 *)(staticDataBase + 0x168);
  }
  else {
    quadTemplate = (s16 *)(staticDataBase + 0x150);
  }
  if ((behaviorFlags & 0x40000000) != 0) {
    if (slot->velocityY < lbl_803DF3B4) {
      if (((behaviorFlags & 0x1000000) == 0) || (lbl_803DF3B4 <= slot->velocityY)) {
        slot->velocityY = -(lbl_803DF3BC * lbl_803DB414 - slot->velocityY);
      }
      else {
        slot->velocityY = -(lbl_803DF3B8 * lbl_803DB414 - slot->velocityY);
      }
      goto LAB_8009ba84;
    }
  }
  if (((behaviorFlags & 0x1000000) == 0) || (slot->velocityY <= lbl_803DF3C0)) {
    if (((behaviorFlags & 8) != 0) && (lbl_803DF3C0 < slot->velocityY)) {
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
      if ((slot->behaviorFlags & 0x80) != 0) {
        tex1T = 0x80;
        tex1S = 0;
      }
      if ((slot->behaviorFlags & 0x40) != 0) {
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
int expgfx_addToTable(uint textureOrResource,uint key0,uint key1,s16 slotType)
{
  ExpgfxTableEntry *entry;
  ExpgfxTableEntry *entryBase;
  int tableIndex;
  int freeIndex;
  u16 refCount;
  
  tableIndex = 0;
  entryBase = Expgfx_GetTableEntry(0);
  entry = entryBase;
  for (; tableIndex < EXPGFX_POOL_COUNT; tableIndex++) {
    if (((entry->refCount != 0 && (entry->textureOrResource == textureOrResource)) &&
        (entry->key0 == key0)) && (entry->key1 == key1)) {
      entry = &gExpgfxTableEntries[tableIndex];
      refCount = entry->refCount;
      if (refCount >= 0xffff) {
        fn_801378A8(sExpgfxAddToTableUsageOverflow);
        return -1;
      }
      entry->refCount = refCount + 1;
      return (int)(short)tableIndex;
    }
    entry = entry + 1;
  }

  freeIndex = 0;
  entry = entryBase;
  for (; freeIndex < EXPGFX_POOL_COUNT; freeIndex++) {
    if (entry->refCount == 0) {
      entry = &gExpgfxTableEntries[freeIndex];
      entry->refCount = 1;
      entry->textureOrResource = textureOrResource;
      entry->key0 = key0;
      entry->key1 = key1;
      entry->slotType = slotType;
      return (int)(short)freeIndex;
    }
    entry = entry + 1;
  }

  fn_801378A8(sExpgfxExpTabIsFull);
  return -1;
}
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
int expgfx_updateSourceFrameFlags(void *sourceObject)
{
  u32 bit;
  s32 highBit;
  u32 *sourceMasks;
  u32 *poolSourceIds;
  u8 *poolFrameFlags;
  s8 aggregateState;
  int poolIndex;

  aggregateState = 0;
  lbl_803DD253 = 0;
  poolIndex = 0;
  poolSourceIds = lbl_8039BA28;
  poolFrameFlags = lbl_8030F968;
  while ((s16)poolIndex < EXPGFX_POOL_COUNT) {
    if ((*(s16 *)((u8 *)sourceObject + 0x46) == 0xd4) || (*poolSourceIds == (u32)sourceObject)) {
      bit = 1 << ((s16)poolIndex >> 1);
      highBit = (s32)bit >> 0x1f;
      sourceMasks = &lbl_8039BB68[((u32)(poolIndex & 1)) * 2];
      if (((bit & sourceMasks[1]) | (highBit & sourceMasks[0])) != 0) {
        *poolFrameFlags = 2;
        if (aggregateState == 1) {
          aggregateState = 3;
        }
        else {
          aggregateState = 2;
        }
      }
      else {
        *poolFrameFlags = 1;
        if (aggregateState == 2) {
          aggregateState = 3;
        }
        else {
          aggregateState = 1;
        }
      }
    }
    else {
      *poolFrameFlags = 0;
    }
    poolSourceIds = poolSourceIds + 1;
    poolFrameFlags = poolFrameFlags + 1;
    poolIndex = poolIndex + 1;
  }
  return aggregateState;
}
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
void fn_8009E004(void)
{
  expgfx_releaseSourceSlots();
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
  poolActiveCounts = (char *)(expgfxBase + 0x1070);
  poolSourceIds = (int *)(expgfxBase + 0xed0);
  poolSourceModes = expgfxBase + 0xe80;
  poolBoundsTemplateIds = expgfxBase + 0x1020;
  poolBounds = (ExpgfxBounds *)(expgfxBase + 0x200);
  slotPoolBases = (uint *)(expgfxBase + 0x1200);
  do {
    if (((*poolActiveCounts != '\0') && ((u32)*poolSourceIds == (u32)sourceId)) &&
       ((int)*poolSourceModes == sourceMode + 1)) {
      boundsTemplate = (ExpgfxBounds *)(lbl_8030F898 + (uint)*poolBoundsTemplateIds * 0x18);
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
 * Function: fn_8009ECE4
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
void fn_8009ECE4(void)
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
  currentMatrix = fn_8000F54C();
  poolIndex = 0;
  poolActiveCounts = (char *)(expgfxBase + 0x1070);
  poolSourceModes = expgfxBase + 0xe80;
  poolBoundsTemplateIds = expgfxBase + 0x1020;
  poolBounds = (ExpgfxBounds *)(expgfxBase + 0x200);
  poolSourceIds = (int *)(expgfxBase + 0xed0);
  poolSlotTypeIds = lbl_8030F8C8;
  slotPoolBases = (uint *)(expgfxBase + 0x1200);
  do {
    if ((*poolActiveCounts != '\0') && (*poolSourceModes == 0)) {
      boundsTemplate = (ExpgfxBounds *)(lbl_8030F898 + (uint)*poolBoundsTemplateIds * 0x18);
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
        fn_80247494(currentMatrix,queuePosition,queuePosition);
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
void fn_8009EEB8(void)
{
  expgfx_releaseSourceSlots();
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
void expgfx_releaseSourceSlots(int sourceId)
{
  char *poolActiveCounts;
  ExpgfxTableEntry *tableEntries;
  ExpgfxSlot *slot;
  int *poolSourceIds;
  s16 *poolSlotTypeIds;
  u8 *poolFrameFlags;
  uint *slotPoolBases;
  s16 invalidSlotType;
  int poolIndex;
  int slotIndex;

  if (sourceId != 0) {
    poolIndex = 0;
    tableEntries = (ExpgfxTableEntry *)(lbl_8039AB58 + 0x980);
    slotPoolBases = (uint *)(lbl_8039AB58 + 0x1200);
    poolSourceIds = (int *)(lbl_8039AB58 + 0xed0);
    poolActiveCounts = (char *)(lbl_8039AB58 + 0x1070);
    poolSlotTypeIds = lbl_8030F8C8;
    poolFrameFlags = lbl_8030F968;
    do {
      slot = (ExpgfxSlot *)*slotPoolBases;
      if (sourceId == *poolSourceIds) {
        slotIndex = 0;
        invalidSlotType = -1;
        do {
          if ((slot != (ExpgfxSlot *)0x0) &&
              (tableEntries[Expgfx_GetSlotTableIndex(slot)].key0 == sourceId)) {
            expgfx_release(*slotPoolBases,poolIndex,slotIndex,0,1);
          }
          slot = slot + 1;
          if (*poolActiveCounts == '\0') {
            *poolSlotTypeIds = invalidSlotType;
          }
          slotIndex = slotIndex + 1;
        } while (slotIndex < EXPGFX_SLOTS_PER_POOL);
        *poolSourceIds = 0;
        *poolFrameFlags = 0;
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

  staticDataBase = lbl_8030F898;
  expgfxBase = lbl_8039AB58;
  poolIndex = 0;
  slotPoolBases = (u32 *)(expgfxBase + 0x1200);
  poolActiveMasks = (u32 *)(expgfxBase + 0x10c0);
  poolActiveCounts = (char *)(expgfxBase + 0x1070);
  poolSlotTypeIds = (s16 *)(staticDataBase + 0x30);
  poolSourceIds = (int *)(expgfxBase + 0xed0);
  poolFrameFlags = staticDataBase + 0xd0;
  do {
    slot = (ExpgfxSlot *)*slotPoolBases;
    slotIndex = 0;
    do {
      activeBit = 1 << slotIndex;
      if ((*poolActiveMasks & activeBit) != 0) {
        if (((ExpgfxTableEntry *)(expgfxBase + 0x980))[Expgfx_GetSlotTableIndex(slot)].
            textureOrResource != 0) {
          lbl_803DD258 = 1;
          fn_80054308((void *)((ExpgfxTableEntry *)(expgfxBase + 0x980))
                          [Expgfx_GetSlotTableIndex(slot)].textureOrResource);
          lbl_803DD258 = 0;
        }
        tableEntry =
            (ExpgfxTableEntry *)(expgfxBase + 0x980 + (Expgfx_GetSlotTableIndex(slot) << 4));
        if (tableEntry->refCount != 0) {
          tableEntry->refCount = tableEntry->refCount - 1;
          if (tableEntry->refCount == 0) {
            tableEntry->textureOrResource = 0;
            tableEntry->key0 = 0;
          }
        }
        else {
          fn_801378A8((char *)(staticDataBase + 0x358));
        }
        *(s16 *)((u8 *)slot + 0x26) = -1;
        *poolActiveMasks = *poolActiveMasks & ~activeBit;
      }
      slot = slot + 1;
      slotIndex = slotIndex + 1;
    } while (slotIndex < EXPGFX_SLOTS_PER_POOL);
    *poolActiveCounts = 0;
    *poolSlotTypeIds = -1;
    *poolSourceIds = 0;
    *poolFrameFlags = 0;
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
void expgfx_updateFrameState(int sourceMode,int sourceId)
{
  int iVar1;
  byte bVar2;
  f32 frameStep;
  f32 frameValue;
  
  iVar1 = fn_80008B4C(-1);
  if ((short)iVar1 != 1) {
    frameValue = lbl_803DD25C;
    frameStep = lbl_803DB414;
    frameValue = frameValue + frameStep;
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
    bVar2 = EXPGFX_POOL_COUNT;
    while (bVar2 != 0) {
      bVar2 = bVar2 - 1;
      lbl_8030F968[bVar2] = 0;
    }
    (*(code *)(*lbl_803DCA88 + 0xc))(0);
    lbl_803DD254 = 1;
  }
  return;
}
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
      uVar12 = (&DAT_8039c7c8)[uVar2 * 2];
      uVar14 = (&DAT_8039c7cc)[uVar2 * 2];
      uVar8 = 1 << ((int)uVar3 >> 1);
      uVar9 = uVar14 | uVar8;
      (&DAT_8039c7cc)[uVar2 * 2] = uVar9;
      (&DAT_8039c7c8)[uVar2 * 2] = uVar12 | (int)uVar8 >> 0x1f;
    }
    else {
      uVar2 = uVar3 & 1;
      uVar12 = (&DAT_8039c7c8)[uVar2 * 2];
      uVar14 = (&DAT_8039c7cc)[uVar2 * 2];
      uVar8 = ~(1 << ((int)uVar3 >> 1));
      uVar9 = uVar14 & uVar8;
      (&DAT_8039c7cc)[uVar2 * 2] = uVar9;
      (&DAT_8039c7c8)[uVar2 * 2] = uVar12 & (int)uVar8 >> 0x1f;
    }
    piVar16 = &DAT_8039b7b8 + (uVar3 & 1) * 2;
    slot = Expgfx_GetSlot(uVar3, local_58);
    puVar18 = (undefined2 *)slot;
    DAT_803dded0 = DAT_803dded0 + 1;
    if (30000 < DAT_803dded0) {
      DAT_803dded0 = 0;
    }
    slot->sequenceId = DAT_803dded0;
    slot->behaviorFlags = spawnConfig->behaviorFlags;
    slot->renderFlags = spawnConfig->renderFlags;
    slot->stateBits = slot->stateBits & 0xf3;
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
          if ((double)FLOAT_803dffd4 < (double)spawnConfig->scale) {
            FUN_80135810((double)spawnConfig->scale,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,sExpgfxScaleOverflow,puVar10,iVar13,iVar15,piVar16,param_14,
                         param_15,param_16);
          }
          dVar20 = (double)FLOAT_803dffd0;
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
          slot->stateBits = DAT_803dded2 & 1 | slot->stateBits & 0xfe;
          if ((slot->renderFlags & EXPGFX_RENDER_BACKDATE_MOTION) != 0) {
            slot->renderFlags = slot->renderFlags ^ EXPGFX_RENDER_BACKDATE_MOTION;
            dVar21 = DOUBLE_803dffe0;
            param_4 = (double)FLOAT_803e009c;
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
            dVar20 = (double)FLOAT_803e00a0;
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
              if (((dVar20 < (double)FLOAT_803e00a4) &&
                  (dVar20 = (double)FLOAT_803dffdc, dVar20 != (double)*(float *)(iVar7 + 0x24))) &&
                 (dVar20 != (double)*(float *)(iVar7 + 0x2c))) {
                local_38 = (double)CONCAT44(0x43300000,(int)slot->lifetimeFrame << 1 ^ 0x80000000);
                slot->velocityX =
                     slot->velocityX -
                     (float)(dVar21 / (double)(float)(local_38 - DOUBLE_803dffe0));
                local_40 = (double)CONCAT44(0x43300000,(int)slot->lifetimeFrame << 1 ^ 0x80000000);
                slot->velocityY =
                     slot->velocityY -
                     ((FLOAT_803e00a8 + *(float *)(iVar7 + 0x1c)) -
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
              if (((dVar20 < (double)FLOAT_803e00a4) &&
                  (dVar20 = (double)FLOAT_803dffdc, dVar20 != (double)*(float *)(iVar7 + 0x24))) &&
                 (dVar20 != (double)*(float *)(iVar7 + 0x2c))) {
                local_38 = (double)CONCAT44(0x43300000,(int)slot->lifetimeFrame << 1 ^ 0x80000000);
                slot->velocityX =
                     slot->velocityX +
                     (float)(param_2 / (double)(float)(local_38 - DOUBLE_803dffe0));
                local_40 = (double)CONCAT44(0x43300000,(int)slot->lifetimeFrame << 1 ^ 0x80000000);
                slot->velocityY =
                     slot->velocityY +
                     ((FLOAT_803e00a8 + *(float *)(iVar7 + 0x1c)) - *(float *)&slot->startPosY) /
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
 * Function: fn_8009FCDC
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
void fn_8009FCDC(void)
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
  poolActiveMasks = (u32 *)(expgfxBase + 0x10c0);
  poolActiveCounts = expgfxBase + 0x1070;
  poolSlotTypeIds = lbl_8030F8C8;
  poolFrameFlags = lbl_8030F968;
  poolSourceModes = expgfxBase + 0xe80;
  poolSourceIds = (u32 *)(expgfxBase + 0xed0);
  groupIndex = 10;
  do {
    poolActiveMasks[0] = 0;
    poolActiveCounts[0] = 0;
    poolSlotTypeIds[0] = -1;
    poolFrameFlags[0] = 0;
    poolSourceModes[0] = 0;
    poolSourceIds[0] = 0;
    poolActiveMasks[1] = 0;
    poolActiveCounts[1] = 0;
    poolSlotTypeIds[1] = -1;
    poolFrameFlags[1] = 0;
    poolSourceModes[1] = 0;
    poolSourceIds[1] = 0;
    poolActiveMasks[2] = 0;
    poolActiveCounts[2] = 0;
    poolSlotTypeIds[2] = -1;
    poolFrameFlags[2] = 0;
    poolSourceModes[2] = 0;
    poolSourceIds[2] = 0;
    poolActiveMasks[3] = 0;
    poolActiveCounts[3] = 0;
    poolSlotTypeIds[3] = -1;
    poolFrameFlags[3] = 0;
    poolSourceModes[3] = 0;
    poolSourceIds[3] = 0;
    poolActiveMasks[4] = 0;
    poolActiveCounts[4] = 0;
    poolSlotTypeIds[4] = -1;
    poolFrameFlags[4] = 0;
    poolSourceModes[4] = 0;
    poolSourceIds[4] = 0;
    poolActiveMasks[5] = 0;
    poolActiveCounts[5] = 0;
    poolSlotTypeIds[5] = -1;
    poolFrameFlags[5] = 0;
    poolSourceModes[5] = 0;
    poolSourceIds[5] = 0;
    poolActiveMasks[6] = 0;
    poolActiveCounts[6] = 0;
    poolSlotTypeIds[6] = -1;
    poolFrameFlags[6] = 0;
    poolSourceModes[6] = 0;
    poolSourceIds[6] = 0;
    poolActiveMasks[7] = 0;
    poolActiveCounts[7] = 0;
    poolSlotTypeIds[7] = -1;
    poolFrameFlags[7] = 0;
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
  resourceEntry = (ExpgfxResourceEntry *)expgfxBase;
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
  } while (resourceIndex < 0x20);
  lbl_803DD258 = 0;
  return;
}
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: fn_8009FE7C
 * EN v1.0 Address: 0x8009FE7C
 * EN v1.0 Size: 84b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_8009FE7C(void)
{
  u32 *slotPoolBases;
  int poolIndex;

  asm {
    bl expgfx_initialise
  }
  poolIndex = 0;
  slotPoolBases = &lbl_8039BD58;
  do {
    fn_80023800(*slotPoolBases);
    slotPoolBases = slotPoolBases + 1;
    poolIndex = poolIndex + 1;
  } while (poolIndex < EXPGFX_POOL_COUNT);
  return;
}
