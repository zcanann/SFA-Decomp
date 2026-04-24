#include "ghidra_import.h"
#include "main/expgfx.h"
#include "main/expgfx_internal.h"

extern undefined4 ABS();
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
extern undefined4 FUN_8004812c();
extern undefined8 FUN_80053754();
extern int FUN_8005b024();
extern undefined4 FUN_8005d340();
extern undefined4 FUN_8005e1d8();
extern uint FUN_8005e558();
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
extern undefined8 FUN_80135810();
extern double FUN_80136594();
extern undefined4 FUN_802420e0();
extern undefined4 FUN_802475e4();
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
extern undefined2 gExpgfxSlotTypeIds;
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
extern int gExpgfxSlotSourceIds;
extern undefined4 DAT_8039c7c8;
extern undefined4 DAT_8039c7cc;
extern byte gExpgfxPoolBoundsTemplateIds;
extern char gExpgfxSlotActiveCounts;
extern char DAT_8039c829;
extern uint gExpgfxSlotActiveMasks;
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
extern f64 DOUBLE_803dffe0;
extern f64 DOUBLE_803dfff8;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc3f0;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
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
extern char sExpgfxAddToTableUsageOverflow[];
extern char sExpgfxExpTabIsFull[];
extern char sExpgfxInvalidTabIndex[];
extern char sExpgfxMismatchInAddRemove[];
extern char sExpgfxScaleOverflow[];
extern char sExpgfxNoTexture[];

#define EXPGFX_SLOT_TABLE_INDEX_OFFSET 0x8A

/*
 * Retail warning strings call this structure "exptab". The key fields are
 * still only partially understood, but the table's role and lifetime rules
 * are stable enough to stop treating it as raw integer arrays.
 */
typedef struct ExpgfxTableEntry {
  int key0;
  int key1;
  int textureOrResource;
  s16 refCount;
  s16 slotType;
} ExpgfxTableEntry;

typedef struct ExpgfxSlot {
  u8 pad00[0x40];
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

static ExpgfxTableEntry *Expgfx_GetTableEntry(int tableIndex) {
  return &((ExpgfxTableEntry *)&DAT_8039c138)[tableIndex];
}

static u8 Expgfx_GetSlotTableIndex(const ExpgfxSlot *slot) {
  return slot->encodedTableIndex >> 1;
}

static void Expgfx_SetSlotTableIndex(ExpgfxSlot *slot, u8 tableIndex) {
  slot->encodedTableIndex = (u8)((tableIndex << 1) | (slot->encodedTableIndex & 1));
}

static ExpgfxSlot *Expgfx_GetSlot(int poolIndex, int slotIndex) {
  return (ExpgfxSlot *)((&gExpgfxSlotPoolBases)[poolIndex] + slotIndex * EXPGFX_SLOT_SIZE);
}

static ExpgfxBounds *Expgfx_GetBoundsTemplate(int templateIndex) {
  return &((ExpgfxBounds *)&gExpgfxBoundsTemplates)[templateIndex];
}

static ExpgfxBounds *Expgfx_GetPoolBounds(int poolIndex) {
  return &((ExpgfxBounds *)&gExpgfxPoolBounds)[poolIndex];
}

static ExpgfxCurrentSource Expgfx_GetCurrentSource(void) {
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
 * EN v1.0 Address: 0x8009B254
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x8009B36C
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void expgfx_release(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                    undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                    undefined4 param_9,undefined4 param_10,int param_11,int param_12,uint param_13,
                    undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  ExpgfxTableEntry *tableEntry;
  ExpgfxSlot *slot;
  uint uVar1;
  int iVar2;
  char *pcVar4;
  uint uVar5;
  uint uVar6;
  uint *puVar7;
  undefined8 extraout_f1;
  undefined8 uVar8;
  
  uVar8 = FUN_80286838();
  iVar2 = (int)uVar8;
  puVar7 = &gExpgfxSlotActiveMasks + iVar2;
  if ((1 << param_11 & *puVar7) != 0) {
    slot = Expgfx_GetSlot(iVar2, param_11);
    slot->behaviorFlags = 0;
    if (param_12 == 0) {
      uVar5 = param_13;
      uVar8 = extraout_f1;
      tableEntry = Expgfx_GetTableEntry(Expgfx_GetSlotTableIndex(slot));
      if (tableEntry->textureOrResource != 0) {
        DAT_803dded8 = 1;
        uVar8 = FUN_80053754();
        DAT_803dded8 = 0;
      }
      uVar1 = Expgfx_GetSlotTableIndex(slot);
      if (tableEntry->refCount == 0) {
        FUN_80135810(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     sExpgfxMismatchInAddRemove,&tableEntry->refCount,uVar1 * 0x10,param_12,uVar5,
                     param_14,param_15,param_16);
      }
      else {
        tableEntry->refCount = tableEntry->refCount + -1;
        if (tableEntry->refCount == 0) {
          tableEntry->textureOrResource = 0;
          tableEntry->key0 = 0;
        }
      }
    }
    *(undefined2 *)((u8 *)slot + 0x4c) = 0xffff;
    if ((param_13 & 0xff) != 0) {
      FUN_802420e0((uint)slot,EXPGFX_SLOT_SIZE);
    }
    *puVar7 = *puVar7 & ~(1 << param_11);
    pcVar4 = &gExpgfxSlotActiveCounts + iVar2;
    *pcVar4 = *pcVar4 + -1;
    if (*pcVar4 == '\0') {
      (&gExpgfxSlotTypeIds)[iVar2] = 0xffff;
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: expgfx_initialise
 * EN v1.0 Address: 0x8009B454
 * EN v1.0 Size: 592b
 * EN v1.1 Address: 0x8009B4E0
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void expgfx_initialise(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                       undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  ExpgfxTableEntry *tableEntry;
  ExpgfxSlot *slot;
  uint uVar1;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined2 *puVar6;
  char *pcVar7;
  uint *puVar8;
  uint *puVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286830();
  iVar5 = 0;
  puVar9 = &gExpgfxSlotPoolBases;
  puVar8 = &gExpgfxSlotActiveMasks;
  pcVar7 = &gExpgfxSlotActiveCounts;
  puVar6 = &gExpgfxSlotTypeIds;
  do {
    uVar3 = *puVar9;
    iVar4 = 0;
    do {
      if ((1 << iVar4 & *puVar8) != 0) {
        slot = (ExpgfxSlot *)uVar3;
        tableEntry = Expgfx_GetTableEntry(Expgfx_GetSlotTableIndex(slot));
        if ((tableEntry->textureOrResource != 0) && (tableEntry->textureOrResource != 0)) {
          DAT_803dded8 = 1;
          uVar10 = FUN_80053754();
          DAT_803dded8 = 0;
        }
        uVar1 = Expgfx_GetSlotTableIndex(slot);
        if (tableEntry->refCount == 0) {
          uVar10 = FUN_80135810(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                sExpgfxMismatchInAddRemove,&tableEntry->refCount,
                                &tableEntry->key0,in_r6,in_r7,in_r8,in_r9,in_r10);
        }
        else {
          tableEntry->refCount = tableEntry->refCount + -1;
          if (tableEntry->refCount == 0) {
            tableEntry->textureOrResource = 0;
            tableEntry->key0 = 0;
          }
        }
        *(undefined2 *)((u8 *)slot + 0x4c) = 0xffff;
        *puVar8 = *puVar8 & ~(1 << iVar4);
      }
      uVar3 = uVar3 + EXPGFX_SLOT_SIZE;
      iVar4 = iVar4 + 1;
    } while (iVar4 < EXPGFX_SLOTS_PER_POOL);
    *pcVar7 = 0;
    *puVar6 = 0xffff;
    FUN_802420e0(*puVar9,EXPGFX_SLOTS_PER_POOL * EXPGFX_SLOT_SIZE);
    puVar9 = puVar9 + 1;
    puVar8 = puVar8 + 1;
    pcVar7 = pcVar7 + 1;
    puVar6 = puVar6 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < EXPGFX_POOL_COUNT);
  FUN_8028687c();
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
undefined4 expgfx_reserveSlot(short *param_1,undefined2 *param_2,short param_3,int param_4,
                              int param_5)
{
  bool bVar1;
  short sVar2;
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
  piVar8 = &gExpgfxSlotSourceIds;
  psVar6 = (short *)&gExpgfxSlotTypeIds;
  pcVar3 = &gExpgfxSlotActiveCounts;
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
    puVar7 = &gExpgfxSlotActiveMasks + sVar2;
    iVar10 = EXPGFX_SLOTS_PER_POOL;
    do {
      if ((1 << iVar9 & *puVar7) == 0) {
        *param_2 = (short)iVar9;
        *param_1 = sVar2;
        *puVar7 = *puVar7 | 1 << iVar9;
        (&gExpgfxSlotActiveCounts)[sVar2] = (&gExpgfxSlotActiveCounts)[sVar2] + '\x01';
        return 1;
      }
      iVar9 = iVar9 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
  }
  bVar1 = false;
  if (param_4 != -1) {
    if ((param_4 != -1) &&
        (iVar4 = param_4, (char)(&gExpgfxSlotActiveCounts)[param_4] < EXPGFX_SLOTS_PER_POOL)) {
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
        (&gExpgfxSlotActiveCounts)[iVar4] = 0;
        break;
      }
      pcVar3 = pcVar3 + 1;
      iVar4 = iVar4 + 1;
      iVar9 = iVar9 + -1;
    } while (iVar9 != 0);
  }
  if (bVar1) {
    iVar9 = 0;
    puVar7 = &gExpgfxSlotActiveMasks + sVar2;
    iVar10 = EXPGFX_SLOTS_PER_POOL;
    do {
      if ((1 << iVar9 & *puVar7) == 0) {
        *param_2 = (short)iVar9;
        *param_1 = sVar2;
        *puVar7 = *puVar7 | 1 << iVar9;
        (&gExpgfxSlotTypeIds)[iVar4] = param_3;
        (&gExpgfxSlotActiveCounts)[sVar2] = (&gExpgfxSlotActiveCounts)[sVar2] + '\x01';
        return 1;
      }
      iVar9 = iVar9 + 1;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
  }
  return 0xffffffff;
}

/*
 * --INFO--
 *
 * Function: FUN_8009b994
 * EN v1.0 Address: 0x8009B994
 * EN v1.0 Size: 1008b
 * EN v1.1 Address: 0x8009B960
 * EN v1.1 Size: 756b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009b994(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9)
{
  ExpgfxSlot *slot;
  ExpgfxTableEntry *tableEntry;
  double dVar1;
  undefined2 *puVar2;
  uint uVar3;
  undefined2 uVar4;
  int iVar5;
  undefined2 uVar6;
  undefined4 in_r8;
  undefined2 uVar7;
  undefined4 in_r9;
  undefined2 uVar8;
  undefined4 in_r10;
  double dVar9;
  double dVar10;
  undefined8 local_18;
  undefined8 local_8;
  
  slot = (ExpgfxSlot *)param_9;
  tableEntry = Expgfx_GetTableEntry(Expgfx_GetSlotTableIndex(slot));
  iVar5 = tableEntry->textureOrResource;
  slot->stateBits = slot->stateBits & 0xfe;
  slot->stateBits = slot->stateBits & 0xfd | 2;
  uVar3 = slot->behaviorFlags;
  if ((uVar3 & 0x8000000) == 0) {
    puVar2 = (undefined2 *)0x803105c0;
  }
  else {
    puVar2 = &DAT_803105a8;
  }
  if ((uVar3 & 0x40000000) != 0) {
    param_2 = (double)*(float *)(param_9 + 0x3a);
    if (param_2 < (double)FLOAT_803e0034) {
      if (((uVar3 & 0x1000000) == 0) || ((double)FLOAT_803e0034 <= param_2)) {
        param_2 = (double)FLOAT_803e003c;
        *(float *)(param_9 + 0x3a) =
             -(float)(param_2 * (double)FLOAT_803dc074 - (double)*(float *)(param_9 + 0x3a));
      }
      else {
        *(float *)(param_9 + 0x3a) =
             -(float)((double)FLOAT_803e0038 * (double)FLOAT_803dc074 - param_2);
      }
      goto LAB_8009ba84;
    }
  }
  if (((uVar3 & 0x1000000) == 0) ||
     (param_2 = (double)*(float *)(param_9 + 0x3a), param_2 <= (double)FLOAT_803e0040)) {
    if (((uVar3 & 8) != 0) &&
       (param_2 = (double)*(float *)(param_9 + 0x3a), (double)FLOAT_803e0040 < param_2)) {
      *(float *)(param_9 + 0x3a) =
           (float)((double)FLOAT_803e003c * (double)FLOAT_803dc074 + param_2);
    }
  }
  else {
    *(float *)(param_9 + 0x3a) = (float)((double)FLOAT_803e0038 * (double)FLOAT_803dc074 + param_2);
  }
LAB_8009ba84:
  dVar10 = (double)FLOAT_803e0044;
  *(float *)&slot->posX = (float)((double)slot->velocityX * dVar10 + (double)*(float *)&slot->posX);
  *(float *)&slot->posY = (float)((double)slot->velocityY * dVar10 + (double)*(float *)&slot->posY);
  dVar9 = (double)slot->velocityZ;
  *(float *)&slot->posZ = (float)(dVar9 * dVar10 + (double)*(float *)&slot->posZ);
  dVar1 = DOUBLE_803dfff8;
  if ((slot->behaviorFlags & 0x100000) == 0) {
    if ((slot->renderFlags & 0x2000) != 0) {
      uVar3 = 0x43300000;
      local_8 = (double)CONCAT44(0x43300000,(uint)(ushort)slot->scaleFrames);
      dVar9 = (double)(float)(local_8 - DOUBLE_803dfff8);
      slot->scaleCounter =
           (short)(int)-(float)(dVar9 * dVar10 -
                               (double)(float)((double)CONCAT44(0x43300000,(uint)(ushort)slot->scaleCounter) -
                                              DOUBLE_803dfff8));
      param_2 = dVar1;
    }
  }
  else {
    uVar3 = 0x43300000;
    local_18 = (double)CONCAT44(0x43300000,(uint)(ushort)slot->scaleFrames);
    dVar9 = (double)(float)(local_18 - DOUBLE_803dfff8);
    slot->scaleCounter =
         (short)(int)(dVar9 * dVar10 +
                     (double)(float)((double)CONCAT44(0x43300000,(uint)(ushort)slot->scaleCounter) -
                                    DOUBLE_803dfff8));
    param_2 = dVar1;
  }
  if (iVar5 != 0) {
    uVar6 = 0;
    uVar4 = 0;
    uVar8 = 0;
    uVar7 = 0;
    if (iVar5 != 0) {
      uVar8 = 0x80;
      uVar6 = 0x80;
      uVar7 = 0;
      if ((slot->behaviorFlags & 0x80) != 0) {
        uVar7 = 0x80;
        uVar8 = 0;
      }
      if ((slot->behaviorFlags & 0x40) != 0) {
        uVar4 = 0x80;
        uVar6 = 0;
      }
    }
    *param_9 = *puVar2;
    param_9[1] = puVar2[1];
    param_9[2] = puVar2[2];
    param_9[4] = uVar8;
    param_9[5] = uVar6;
    param_9[8] = puVar2[3];
    param_9[9] = puVar2[4];
    param_9[10] = puVar2[5];
    param_9[0xc] = uVar7;
    param_9[0xd] = uVar6;
    param_9[0x10] = puVar2[6];
    param_9[0x11] = puVar2[7];
    param_9[0x12] = puVar2[8];
    param_9[0x14] = uVar7;
    param_9[0x15] = uVar4;
    param_9[0x18] = puVar2[9];
    param_9[0x19] = puVar2[10];
    param_9[0x1a] = puVar2[0xb];
    param_9[0x1c] = uVar8;
    param_9[0x1d] = uVar4;
  }
  else {
    FUN_80135810(dVar9,param_2,dVar10,param_4,param_5,param_6,param_7,param_8,sExpgfxNoTexture,
                 &gExpgfxBoundsTemplates,puVar2,uVar3,0,in_r8,in_r9,in_r10);
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
 * EN v1.0 Address: 0x8009BD88
 * EN v1.0 Size: 484b
 * EN v1.1 Address: 0x8009E078
 * EN v1.1 Size: 536b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int expgfx_addToTable(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                      undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                      int param_9,int param_10,int param_11,undefined4 param_12)
{
  ExpgfxTableEntry *entry;
  ExpgfxTableEntry *entryBase;
  int iVar4;
  undefined4 in_r10;
  int iVar5;
  int iVar6;
  
  iVar4 = 0;
  entryBase = Expgfx_GetTableEntry(0);
  iVar5 = EXPGFX_POOL_COUNT;
  entry = entryBase;
  while ((((entry->refCount == 0 || (entry->textureOrResource != param_9)) || (entry->key0 != param_10)) ||
         (entry->key1 != param_11))) {
    entry = entry + 1;
    iVar4 = iVar4 + 1;
    iVar5 = iVar5 + -1;
    if (iVar5 == 0) {
      iVar5 = 0;
      iVar6 = EXPGFX_POOL_COUNT;
      do {
        if (entryBase->refCount == 0) {
          entryBase->refCount = 1;
          entryBase->textureOrResource = param_9;
          entryBase->key0 = param_10;
          entryBase->key1 = param_11;
          entryBase->slotType = (short)param_12;
          return (int)(short)iVar5;
        }
        entryBase = entryBase + 1;
        iVar5 = iVar5 + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
      FUN_80135810(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   sExpgfxExpTabIsFull,param_10,param_11,param_12,entry,entryBase,
                   iVar4,iVar5);
      return -1;
    }
  }
  if (entry->refCount == -1) {
    FUN_80135810(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 sExpgfxAddToTableUsageOverflow,&entry->refCount,param_11,param_12,entry,
                 Expgfx_GetTableEntry(0),iVar4,in_r10);
    return -1;
  }
  entry->refCount = entry->refCount + 1;
  return (int)(short)iVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_8009bf6c
 * EN v1.0 Address: 0x8009BF6C
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x8009E290
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009bf6c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  FUN_8009c11c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}

/*
 * --INFO--
 *
 * Function: expgfx_processCurrentSourceBounds
 * EN v1.0 Address: 0x8009BFCC
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x8009E2C0
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void expgfx_processCurrentSourceBounds(void)
{
  ExpgfxBounds *boundsTemplate;
  ExpgfxBounds *poolBounds;
  ExpgfxCurrentSource currentSource;
  uint uVar1;
  int poolIndex;
  byte *poolBoundsTemplateIds;
  byte *poolSourceModes;
  int *poolSourceIds;
  char *poolActiveCounts;
  
  currentSource = Expgfx_GetCurrentSource();
  poolIndex = 0;
  poolActiveCounts = &gExpgfxSlotActiveCounts;
  poolSourceIds = &gExpgfxSlotSourceIds;
  poolSourceModes = &gExpgfxPoolSourceModes;
  poolBoundsTemplateIds = &gExpgfxPoolBoundsTemplateIds;
  poolBounds = Expgfx_GetPoolBounds(0);
  do {
    if (((*poolActiveCounts != '\0') && (*poolSourceIds == currentSource.sourceId)) &&
       ((uint)*poolSourceModes == currentSource.sourceMode + 1U)) {
      boundsTemplate = Expgfx_GetBoundsTemplate(*poolBoundsTemplateIds);
      uVar1 = FUN_8005e558((double)(poolBounds->minX - FLOAT_803dda58),
                           (double)(poolBounds->maxX - FLOAT_803dda58),
                           (double)poolBounds->minY,(double)poolBounds->maxY,
                           (double)(poolBounds->minZ - FLOAT_803dda5c),
                           (double)(poolBounds->maxZ - FLOAT_803dda5c),(float *)boundsTemplate);
      if ((uVar1 & 0xff) != 0) {
        FUN_8009c0b4();
      }
    }
    poolActiveCounts = poolActiveCounts + 1;
    poolSourceIds = poolSourceIds + 1;
    poolSourceModes = poolSourceModes + 1;
    poolBoundsTemplateIds = poolBoundsTemplateIds + 1;
    poolBounds = poolBounds + 1;
    poolIndex = poolIndex + 1;
  } while (poolIndex < EXPGFX_POOL_COUNT);
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8009c0b4
 * EN v1.0 Address: 0x8009C0B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009E3C8
 * EN v1.1 Size: 2984b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009c0b4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8009c0b8
 * EN v1.0 Address: 0x8009C0B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009EF70
 * EN v1.1 Size: 468b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009c0b8(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8009c0bc
 * EN v1.0 Address: 0x8009C0BC
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x8009F144
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009c0bc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  FUN_8009c11c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8009c11c
 * EN v1.0 Address: 0x8009C11C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009F164
 * EN v1.1 Size: 260b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009c11c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8009c120
 * EN v1.0 Address: 0x8009C120
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8009F268
 * EN v1.1 Size: 464b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8009c120(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: expgfx_updateFrameState
 * EN v1.0 Address: 0x8009C124
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x8009F438
 * EN v1.1 Size: 288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void expgfx_updateFrameState(undefined8 param_1,undefined8 param_2,double param_3,double param_4,
                             double param_5,double param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  byte bVar2;
  double dVar3;
  double dVar4;
  
  iVar1 = FUN_80006714(-1);
  if ((short)iVar1 != 1) {
    dVar4 = (double)FLOAT_803dc074;
    FLOAT_803ddedc = (float)((double)FLOAT_803ddedc + dVar4);
    if (FLOAT_803e0098 <= FLOAT_803ddedc) {
      FLOAT_803ddedc = FLOAT_803dffdc;
    }
    FLOAT_803ddee0 = (float)((double)FLOAT_803ddee0 + dVar4);
    if (FLOAT_803e0004 <= FLOAT_803ddee0) {
      FLOAT_803ddee0 = FLOAT_803dffdc;
    }
    FLOAT_803ddee4 = (float)((double)FLOAT_803ddee4 + dVar4);
    dVar3 = (double)FLOAT_803ddee4;
    if ((double)FLOAT_803dffd4 <= dVar3) {
      FLOAT_803ddee4 = FLOAT_803dffdc;
    }
    DAT_803dd430 = 1;
    FUN_8009bd84(dVar3,dVar4,param_3,param_4,param_5,param_6,param_7,param_8);
    DAT_803dd430 = 0;
    bVar2 = EXPGFX_POOL_COUNT;
    while (bVar2 != 0) {
      bVar2 = bVar2 - 1;
      (&gExpgfxPoolFrameFlags)[bVar2] = 0;
    }
    (**(code **)(*DAT_803dd708 + 0xc))(0);
    DAT_803dded4 = 1;
  }
  return;
}

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
  ExpgfxSlot *slot;
  float fVar1;
  uint uVar2;
  uint uVar3;
  undefined2 uVar4;
  int *piVar5;
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
  undefined2 *puVar17;
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
  piVar5 = (int *)((ulonglong)uVar22 >> 0x20);
  local_56[0] = 0;
  local_58 = 0;
  dVar19 = extraout_f1;
  iVar6 = FUN_800176d0();
  if ((iVar6 == 0) &&
     (iVar6 = expgfx_reserveSlot(local_56,&local_58,param_11,(int)uVar22,*piVar5), iVar6 != -1)) {
    uVar3 = (uint)local_56[0];
    if ((int)uVar3 < EXPGFX_POOL_COUNT) {
      (&gExpgfxSlotSourceIds)[uVar3] = *piVar5;
    }
    if (((int)uVar3 < EXPGFX_POOL_COUNT) && ((piVar5[0x11] & 0x40000U) != 0)) {
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
    puVar18[0x13] = DAT_803dded0;
    slot->behaviorFlags = piVar5[0x11];
    slot->renderFlags = piVar5[0x12];
    slot->stateBits = slot->stateBits & 0xf3;
    iVar6 = FUN_80081134(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int)*(short *)((int)piVar5 + 0x42),uVar9,uVar12,uVar14,piVar16,param_14,
                         param_15,param_16);
    iVar6 = (int)(short)iVar6;
    if (iVar6 < 0) {
      expgfx_release(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (&gExpgfxSlotPoolBases)[local_56[0]],(int)local_56[0],(int)local_58,1,1,
                     param_14,
                     param_15,param_16);
    }
    else {
      iVar7 = (&DAT_8039b7b8)[iVar6 * 4];
      if (iVar7 == 0) {
        expgfx_release(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (&gExpgfxSlotPoolBases)[local_56[0]],(int)local_56[0],(int)local_58,1,1,
                       param_14,
                       param_15,param_16);
      }
      else if (*(short *)(iVar7 + 0xe) == -1) {
        expgfx_release(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (&gExpgfxSlotPoolBases)[local_56[0]],(int)local_56[0],(int)local_58,1,1,
                       param_14,
                       param_15,param_16);
      }
      else {
        *(short *)(iVar7 + 0xe) = *(short *)(iVar7 + 0xe) + 1;
        *(ushort *)(iVar7 + 0x14) = (ushort)*(byte *)((int)piVar5 + 0x61);
        puVar17 = (undefined2 *)*piVar5;
        iVar13 = 0;
        if (puVar17 == (undefined2 *)0x0) {
          *(int *)(puVar18 + 0x26) = piVar5[6];
          *(int *)(puVar18 + 0x28) = piVar5[7];
          *(int *)(puVar18 + 0x2a) = piVar5[8];
          *(int *)(puVar18 + 0x24) = piVar5[5];
          puVar18[0x22] = *(undefined2 *)(piVar5 + 4);
          puVar18[0x21] = *(undefined2 *)((int)piVar5 + 0xe);
          puVar18[0x20] = *(undefined2 *)(piVar5 + 3);
        }
        else if ((slot->behaviorFlags & 0x200000) != 0) {
          *(undefined4 *)(puVar18 + 0x26) = *(undefined4 *)(puVar17 + 0xc);
          *(undefined4 *)(puVar18 + 0x28) = *(undefined4 *)(puVar17 + 0xe);
          *(undefined4 *)(puVar18 + 0x2a) = *(undefined4 *)(puVar17 + 0x10);
          *(undefined4 *)(puVar18 + 0x24) = *(undefined4 *)(puVar17 + 4);
          puVar18[0x22] = puVar17[2];
          puVar18[0x21] = puVar17[1];
          puVar18[0x20] = *puVar17;
          if (((slot->behaviorFlags & 2) != 0) || ((slot->behaviorFlags & 4) != 0)) {
            piVar5[9] = (int)((float)piVar5[9] + *(float *)(puVar17 + 0x12));
            piVar5[10] = (int)((float)piVar5[10] + *(float *)(puVar17 + 0x14));
            dVar19 = (double)(float)piVar5[0xb];
            piVar5[0xb] = (int)(float)(dVar19 + (double)*(float *)(puVar17 + 0x16));
          }
          if (puVar17 != (undefined2 *)0x0) {
            iVar13 = *(int *)(puVar17 + 0x18);
          }
          puVar17 = (undefined2 *)0x0;
        }
        iVar15 = (int)*(short *)((int)piVar5 + 0x42);
        puVar10 = puVar17;
        uVar3 = expgfx_addToTable(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                  iVar7,(int)puVar17,iVar13,iVar15);
        if ((short)uVar3 == -1) {
          uVar22 = FUN_80135810(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                sExpgfxInvalidTabIndex,puVar10,iVar13,iVar15,piVar16,
                                param_14,param_15,param_16);
          expgfx_release(uVar22,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (&gExpgfxSlotPoolBases)[local_56[0]],(int)local_56[0],(int)local_58,1,1,
                         param_14,
                         param_15,param_16);
        }
        else {
          Expgfx_SetSlotTableIndex(slot, (u8)uVar3);
          iVar7 = piVar5[0xc];
          slot->startPosX = iVar7;
          slot->posX = iVar7;
          iVar7 = piVar5[0xd];
          slot->startPosY = iVar7;
          slot->posY = iVar7;
          iVar7 = piVar5[0xe];
          slot->startPosZ = iVar7;
          slot->posZ = iVar7;
          slot->velocityX = (float)piVar5[9];
          slot->velocityY = (float)piVar5[10];
          slot->velocityZ = (float)piVar5[0xb];
          *(undefined *)((int)puVar18 + 0xf) = *(undefined *)(piVar5 + 0x18);
          puVar18[0x1b] = (short)piVar5[1];
          puVar18[3] = (short)piVar5[2];
          puVar18[0xb] = (short)piVar5[2];
          if ((double)FLOAT_803dffd4 < (double)(float)piVar5[0xf]) {
            FUN_80135810((double)(float)piVar5[0xf],param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,sExpgfxScaleOverflow,puVar10,iVar13,iVar15,piVar16,
                         param_14,param_15,param_16);
          }
          dVar20 = (double)FLOAT_803dffd0;
          dVar19 = dVar20 * (double)(float)piVar5[0xf];
          dVar21 = (double)(float)dVar19;
          if ((slot->behaviorFlags & 0x100000) == 0) {
            if ((slot->renderFlags & 0x2000) == 0) {
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
              local_48 = (double)CONCAT44(0x43300000,(int)(short)puVar18[0xb] ^ 0x80000000);
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
            local_50 = (double)CONCAT44(0x43300000,(int)(short)puVar18[0xb] ^ 0x80000000);
            iVar7 = (int)(dVar21 / (double)(float)(local_50 - DOUBLE_803dffe0));
            local_48 = (double)(longlong)iVar7;
            slot->scaleFrames = (short)iVar7;
            local_40 = (double)(longlong)(int)dVar19;
            slot->scaleTarget = (short)(int)dVar19;
          }
          if (((slot->behaviorFlags & 0x20000) != 0) ||
             ((slot->behaviorFlags & 0x4000000) != 0)) {
            *(int *)(puVar18 + 0x26) = piVar5[6];
            *(int *)(puVar18 + 0x28) = piVar5[7];
            *(int *)(puVar18 + 0x2a) = piVar5[8];
            *(int *)(puVar18 + 0x24) = piVar5[5];
            puVar18[0x22] = *(undefined2 *)(piVar5 + 4);
            puVar18[0x21] = *(undefined2 *)((int)piVar5 + 0xe);
            puVar18[0x20] = *(undefined2 *)(piVar5 + 3);
          }
          slot->stateBits = DAT_803dded2 & 1 | slot->stateBits & 0xfe;
          if ((slot->renderFlags & 8) != 0) {
            slot->renderFlags = slot->renderFlags ^ 8;
            dVar21 = DOUBLE_803dffe0;
            param_4 = (double)FLOAT_803e009c;
            local_38 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] ^ 0x80000000);
            *(float *)(puVar18 + 0x2c) =
                 *(float *)(puVar18 + 0x38) *
                 (float)(param_4 * (double)(float)(local_38 - DOUBLE_803dffe0)) +
                 *(float *)(puVar18 + 0x2c);
            local_40 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] ^ 0x80000000);
            *(float *)(puVar18 + 0x2e) =
                 *(float *)(puVar18 + 0x3a) * (float)(param_4 * (double)(float)(local_40 - dVar21))
                 + *(float *)(puVar18 + 0x2e);
            param_2 = (double)*(float *)(puVar18 + 0x3c);
            local_48 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] ^ 0x80000000);
            *(float *)(puVar18 + 0x30) =
                 (float)(param_2 * (double)(float)(param_4 * (double)(float)(local_48 - dVar21)) +
                        (double)*(float *)(puVar18 + 0x30));
            dVar20 = (double)FLOAT_803e00a0;
            *(float *)(puVar18 + 0x38) = (float)((double)*(float *)(puVar18 + 0x38) * dVar20);
            *(float *)(puVar18 + 0x3a) = (float)((double)*(float *)(puVar18 + 0x3a) * dVar20);
            *(float *)(puVar18 + 0x3c) = (float)((double)*(float *)(puVar18 + 0x3c) * dVar20);
          }
          if ((slot->renderFlags & 0x10) != 0) {
            iVar7 = FUN_80017a98();
            slot->renderFlags = slot->renderFlags ^ 0x10;
            dVar19 = DOUBLE_803dffe0;
            if ((*(uint *)(puVar18 + 0x3e) & 1) == 0) {
              dVar21 = (double)(*(float *)(iVar7 + 0x18) -
                               (*(float *)(puVar18 + 0x32) + *(float *)(puVar17 + 6)));
              param_2 = (double)*(float *)(iVar7 + 0x20);
              fVar1 = (float)(param_2 -
                             (double)(*(float *)(puVar18 + 0x36) + *(float *)(puVar17 + 10)));
              dVar20 = (double)(float)(dVar21 * dVar21 + (double)(fVar1 * fVar1));
              if (((dVar20 < (double)FLOAT_803e00a4) &&
                  (dVar20 = (double)FLOAT_803dffdc, dVar20 != (double)*(float *)(iVar7 + 0x24))) &&
                 (dVar20 != (double)*(float *)(iVar7 + 0x2c))) {
                local_38 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] << 1 ^ 0x80000000);
                *(float *)(puVar18 + 0x38) =
                     *(float *)(puVar18 + 0x38) -
                     (float)(dVar21 / (double)(float)(local_38 - DOUBLE_803dffe0));
                local_40 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] << 1 ^ 0x80000000);
                *(float *)(puVar18 + 0x3a) =
                     *(float *)(puVar18 + 0x3a) -
                     ((FLOAT_803e00a8 + *(float *)(iVar7 + 0x1c)) -
                     (*(float *)(puVar18 + 0x34) + *(float *)(puVar17 + 8))) /
                     (float)(local_40 - dVar19);
                dVar21 = (double)*(float *)(puVar18 + 0x3c);
                param_2 = (double)*(float *)(iVar7 + 0x20);
                dVar20 = (double)(float)(param_2 - (double)(*(float *)(puVar18 + 0x36) +
                                                *(float *)(puVar17 + 10)));
                local_48 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] << 1 ^ 0x80000000);
                *(float *)(puVar18 + 0x3c) =
                     (float)(dVar21 - (double)(float)(dVar20 / (double)(float)(local_48 - dVar19)));
                param_4 = dVar19;
              }
            }
            else {
              param_2 = (double)(*(float *)(iVar7 + 0x18) - *(float *)(puVar18 + 0x32));
              fVar1 = *(float *)(iVar7 + 0x20) - *(float *)(puVar18 + 0x36);
              dVar20 = (double)(float)(param_2 * param_2 + (double)(fVar1 * fVar1));
              if (((dVar20 < (double)FLOAT_803e00a4) &&
                  (dVar20 = (double)FLOAT_803dffdc, dVar20 != (double)*(float *)(iVar7 + 0x24))) &&
                 (dVar20 != (double)*(float *)(iVar7 + 0x2c))) {
                local_38 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] << 1 ^ 0x80000000);
                *(float *)(puVar18 + 0x38) =
                     *(float *)(puVar18 + 0x38) +
                     (float)(param_2 / (double)(float)(local_38 - DOUBLE_803dffe0));
                local_40 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] << 1 ^ 0x80000000);
                *(float *)(puVar18 + 0x3a) =
                     *(float *)(puVar18 + 0x3a) +
                     ((FLOAT_803e00a8 + *(float *)(iVar7 + 0x1c)) - *(float *)(puVar18 + 0x34)) /
                     (float)(local_40 - dVar19);
                param_2 = (double)*(float *)(puVar18 + 0x3c);
                dVar20 = (double)(*(float *)(iVar7 + 0x20) - *(float *)(puVar18 + 0x36));
                local_48 = (double)CONCAT44(0x43300000,(int)(short)puVar18[3] << 1 ^ 0x80000000);
                *(float *)(puVar18 + 0x3c) =
                     (float)(param_2 + (double)(float)(dVar20 / (double)(float)(local_48 - dVar19)));
                dVar21 = dVar19;
              }
            }
          }
          if (iVar6 == 1) {
            DAT_803ddef0 = DAT_803ddef0 + 1;
            DAT_803ddef8 = DAT_803ddef4 / DAT_803ddef0;
          }
          *(char *)(puVar18 + 0x46) = (char)((ushort)*(undefined2 *)(piVar5 + 0x16) >> 8);
          *(char *)((int)puVar18 + 0x8d) = (char)((ushort)*(undefined2 *)((int)piVar5 + 0x5a) >> 8);
          *(char *)(puVar18 + 0x47) = (char)((ushort)*(undefined2 *)(piVar5 + 0x17) >> 8);
          if ((piVar5[0x12] & 0x20U) != 0) {
            *(char *)((int)puVar18 + 0x1f) = (char)((uint)piVar5[0x13] >> 8);
            *(char *)((int)puVar18 + 0x2f) = (char)((uint)piVar5[0x14] >> 8);
            *(char *)((int)puVar18 + 0x3f) = (char)((uint)piVar5[0x15] >> 8);
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
          if ((*(uint *)(puVar18 + 0x40) & 2) != 0) {
            FUN_8009b994(dVar20,param_2,dVar21,param_4,param_5,param_6,param_7,param_8,puVar18);
          }
          pbVar11 = &gExpgfxPoolSourceModes + local_56[0];
          *pbVar11 = (piVar5[0x11] & 0x20000000U) != 0;
          if ((*pbVar11 != 0) && ((piVar5[0x11] & 0x40000U) == 0)) {
            *pbVar11 = *pbVar11 + 1;
          }
          (&gExpgfxPoolBoundsTemplateIds)[local_56[0]] = param_12;
          FUN_802420e0((uint)puVar18,EXPGFX_SLOT_SIZE);
          DAT_803ddeec = puVar18;
        }
      }
    }
  }
  FUN_80286878();
  return;
}
