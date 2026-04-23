#include "ghidra_import.h"
#include "main/objHitReact.h"
#include "main/unknown/autos/placeholder_8002F604.h"

extern bool FUN_8000b5f0();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_80013e4c();
extern undefined4 FUN_80013ee8();
extern int FUN_80036868();
extern undefined4 FUN_8007d858();
extern undefined4 FUN_8009a468();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286888();

extern undefined4 DAT_802c2280;
extern undefined4 DAT_802c2284;
extern undefined4 DAT_802c2288;
extern undefined4 DAT_802c228c;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803df590;
extern f32 FLOAT_803df598;

typedef struct ObjHitReactEntry {
  s16 clearVolumeA;
  s16 clearVolumeB;
  s16 reactionAnim;
  u8 pad06[2];
  s8 hitFxMode;
  u8 pad09[3];
  f32 cooldown;
  u8 pad10[4];
} ObjHitReactEntry;

/*
 * --INFO--
 *
 * Function: objHitReact_update
 * EN v1.0 Address: 0x8003549C
 * EN v1.0 Size: 652b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u8 objHitReact_update(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                      undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                      undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,
                      float *param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint object;
  int iVar2;
  bool bVar3;
  int *piVar4;
  undefined4 hitFxFlags;
  u8 reactionState;
  float *pfVar6;
  undefined4 *puVar7;
  float *pfVar8;
  ObjHitReactEntry *reactEntry;
  undefined4 *puVar11;
  undefined8 uVar10;
  int local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined2 local_34;
  undefined2 local_32;
  undefined2 local_30;
  float local_2c;
  float local_28;
  undefined4 uStack_24;
  float local_20[8];

  uVar10 = FUN_8028683c();
  object = (uint)((ulonglong)uVar10 >> 0x20);
  local_44 = DAT_802c2280;
  local_40 = DAT_802c2284;
  local_3c = DAT_802c2288;
  local_38 = DAT_802c228c;
  reactionState = (u8)param_12;
  if (reactionState != 0) {
    FUN_8007d858();
    param_2 = (double)FLOAT_803dc074;
    iVar2 = ObjAnim_AdvanceCurrentMove((double)*param_13,param_2);
    if (iVar2 != 0) {
      FUN_8007d858();
      reactionState = 0;
    }
  }
  hitFxFlags = 0;
  pfVar6 = &local_28;
  puVar7 = &uStack_24;
  pfVar8 = local_20;
  iVar2 = FUN_80036868(object,(undefined4 *)0x0,&local_48,(uint *)0x0,pfVar6,puVar7,pfVar8);
  if (iVar2 != 0) {
    local_28 = local_28 + FLOAT_803dda58;
    local_20[0] = local_20[0] + FLOAT_803dda5c;
    local_2c = FLOAT_803df598;
    local_30 = 0;
    local_32 = 0;
    local_34 = 0;
    local_48 = (int)*(char *)(*(int *)(**(int **)(*(int *)(object + 0x7c) + *(char *)(object + 0xad) * 4) +
                                       0x58) + local_48 * 0x18 + 0x16);
    if ((int)(param_11 & 0xff) <= local_48) {
      FUN_8007d858();
      local_48 = 0;
    }
    reactEntry = (ObjHitReactEntry *)((int)uVar10 + local_48 * sizeof(ObjHitReactEntry));
    if (iVar2 != 0x11) {
      if ((reactEntry->clearVolumeA != -1) &&
          (bVar3 = FUN_8000b5f0(object,reactEntry->clearVolumeA), !bVar3)) {
        FUN_8000bb38(object,reactEntry->clearVolumeA);
      }
      if ((reactEntry->clearVolumeB != -1) &&
          (bVar3 = FUN_8000b5f0(object,reactEntry->clearVolumeB), !bVar3)) {
        FUN_8000bb38(object,reactEntry->clearVolumeB);
      }
      if (reactEntry->hitFxMode == 1) {
        piVar4 = (int *)FUN_80013ee8(0x5a);
        hitFxFlags = 0x401;
        pfVar6 = (float *)-1;
        puVar7 = &local_44;
        puVar11 = (undefined4 *)*piVar4;
        (*(code *)puVar11[1])(0,1,&local_34);
        pfVar8 = (float *)puVar11;
        if (piVar4 != (int *)0x0) {
          FUN_80013e4c((undefined *)piVar4);
        }
      }
      else {
        hitFxFlags = 0;
        FUN_8009a468(object,&local_34,1,(int *)0x0);
      }
    }
    if ((reactionState == 0) && (reactEntry->reactionAnim != -1)) {
      ObjAnim_SetCurrentMove((double)FLOAT_803df590,param_2,param_3,param_4,param_5,param_6,param_7,
                             param_8,object,(int)reactEntry->reactionAnim,0,hitFxFlags,
                             (undefined4)pfVar6,(undefined4)puVar7,(undefined4)pfVar8,param_16);
      *param_13 = reactEntry->cooldown;
    }
  }
  FUN_80286888();
  return reactionState;
}
