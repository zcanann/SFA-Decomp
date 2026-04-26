#include "ghidra_import.h"
#include "main/dll/backpack.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80017688();
extern undefined4 FUN_80017698();
extern double FUN_80017708();
extern uint FUN_80017760();
extern undefined4 FUN_80017a78();
extern undefined4 FUN_80017a88();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern int FUN_80017b00();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern undefined4 FUN_80037180();
extern undefined4 FUN_8003735c();
extern int FUN_80037584();
extern undefined8 FUN_80037844();
extern undefined4 FUN_80037bd4();
extern undefined4 FUN_80037ce0();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80081110();
extern undefined4 FUN_80163bbc();
extern undefined4 FUN_80163e44();
extern double FUN_80293900();

extern undefined4 DAT_80320ed8;
extern undefined4 DAT_803dc9a8;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd728;
extern undefined4* DAT_803dd738;
extern f64 DOUBLE_803e3c08;
extern f64 DOUBLE_803e3c28;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e3bf4;
extern f32 FLOAT_803e3c00;
extern f32 FLOAT_803e3c1c;
extern f32 FLOAT_803e3c30;
extern f32 FLOAT_803e3c34;
extern f32 FLOAT_803e3c38;
extern f32 FLOAT_803e3c3c;
extern f32 FLOAT_803e3c40;
extern f32 FLOAT_803e3c44;
extern f32 FLOAT_803e3c48;
extern f32 FLOAT_803e3c4c;
extern f32 FLOAT_803e3c50;
extern f32 FLOAT_803e3c54;
extern f32 FLOAT_803e3c58;
extern f32 FLOAT_803e3c5c;
extern f32 FLOAT_803e3c60;
extern f32 FLOAT_803e3c64;
extern f32 FLOAT_803e3c68;
extern f32 FLOAT_803e3c70;
extern f32 FLOAT_803e3c74;
extern f32 FLOAT_803e3c78;
extern f32 FLOAT_803e3c7c;
extern f32 FLOAT_803e3c80;
extern f32 FLOAT_803e3c84;
extern f32 FLOAT_803e3c88;
extern f32 FLOAT_803e3c8c;
extern f32 FLOAT_803e3c90;

/*
 * --INFO--
 *
 * Function: FUN_801641b0
 * EN v1.0 Address: 0x801641B0
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x8016445C
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801641b0(int param_1,undefined4 param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(undefined *)(iVar1 + 0x278) = 6;
  *(undefined4 *)(iVar1 + 0x290) = param_2;
  *(float *)(iVar1 + 0x294) = FLOAT_803dc074 * FLOAT_803e3c30;
  ObjHits_DisableObject(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801641f0
 * EN v1.0 Address: 0x801641F0
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x8016449C
 * EN v1.1 Size: 148b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801641f0(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar1 + 0x278) == '\x01') {
    ObjHits_EnableObject(param_1);
    *(undefined *)(iVar1 + 0x278) = 2;
    *(byte *)(iVar1 + 0x27a) = *(byte *)(iVar1 + 0x27a) | 3;
    if (*(short *)(param_1 + 0x46) == 0x4c1) {
      *(float *)(iVar1 + 0x2a0) = FLOAT_803e3c34;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016425c
 * EN v1.0 Address: 0x8016425C
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x80164530
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016425c(int param_1)
{
  short sVar1;
  int iVar2;
  int iVar3;
  int unaff_r30;
  int local_18;
  int local_14 [2];
  
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x4ba) {
    unaff_r30 = 0x4b9;
  }
  else if (sVar1 < 0x4ba) {
    if (sVar1 == 0x3fb) {
      unaff_r30 = 0x3fd;
    }
    else if ((sVar1 < 0x3fb) && (sVar1 == 0x39d)) {
      unaff_r30 = 0x28d;
    }
  }
  else if (sVar1 == 0x4c1) {
    unaff_r30 = 0x4be;
  }
  iVar2 = FUN_80017b00(local_14,&local_18);
  for (; local_14[0] < local_18; local_14[0] = local_14[0] + 1) {
    iVar3 = *(int *)(iVar2 + local_14[0] * 4);
    if (unaff_r30 == *(short *)(iVar3 + 0x46)) {
      (**(code **)(**(int **)(iVar3 + 0x68) + 0x20))(iVar3,param_1);
    }
  }
  FUN_80037180(param_1,3);
  FUN_80037180(param_1,0x31);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80164354
 * EN v1.0 Address: 0x80164354
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8016462C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80164354(int param_1)
{
  char in_r8;
  
  if ('\0' < in_r8) {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016437c
 * EN v1.0 Address: 0x8016437C
 * EN v1.0 Size: 2268b
 * EN v1.1 Address: 0x8016465C
 * EN v1.1 Size: 1936b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016437c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  char cVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  float *pfVar5;
  uint uVar6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  uint local_88;
  int local_84;
  uint uStack_80;
  int iStack_7c;
  longlong local_78;
  undefined8 local_70;
  undefined4 local_68;
  uint uStack_64;
  undefined8 local_60;
  
  fVar2 = FLOAT_803e3c58;
  iVar7 = *(int *)(param_9 + 0x5c);
  cVar1 = *(char *)(iVar7 + 0x278);
  if (cVar1 == '\0') {
    if (*(float *)(iVar7 + 0x26c) <= *(float *)(param_9 + 4)) {
      *(undefined *)(iVar7 + 0x278) = 1;
    }
    else {
      *(float *)(param_9 + 4) = *(float *)(iVar7 + 0x270) * FLOAT_803dc074 + *(float *)(param_9 + 4)
      ;
    }
  }
  else if (cVar1 == '\x01') {
    iVar4 = ObjHits_GetPriorityHit((int)param_9,&local_84,&iStack_7c,&uStack_80);
    if (iVar4 != 0) {
      ObjHits_EnableObject((int)param_9);
      *(undefined *)(iVar7 + 0x278) = 2;
      *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 3;
      if (param_9[0x23] == 0x4c1) {
        *(float *)(iVar7 + 0x2a0) = FLOAT_803e3c34;
      }
    }
  }
  else if (cVar1 == '\x02') {
    iVar4 = FUN_80017a98();
    dVar13 = (double)(*(float *)(param_9 + 6) - *(float *)(iVar4 + 0xc));
    dVar12 = (double)(*(float *)(param_9 + 10) - *(float *)(iVar4 + 0x14));
    dVar11 = (double)(float)(dVar13 * dVar13 + (double)(float)(dVar12 * dVar12));
    iVar4 = FUN_80017a90();
    if ((iVar4 != 0) && (*(short *)(iVar4 + 0x46) == 0x24)) {
      if (dVar11 < (double)FLOAT_803e3c38) {
        (**(code **)(**(int **)(iVar4 + 0x68) + 0x28))(iVar4,param_9,0,1);
      }
      dVar10 = (double)(*(float *)(param_9 + 6) - *(float *)(iVar4 + 0xc));
      dVar9 = (double)(*(float *)(param_9 + 10) - *(float *)(iVar4 + 0x14));
      dVar8 = (double)(float)(dVar10 * dVar10 + (double)(float)(dVar9 * dVar9));
      if (dVar8 < dVar11) {
        dVar11 = dVar8;
        dVar12 = dVar9;
        dVar13 = dVar10;
      }
    }
    dVar11 = FUN_80293900(dVar11);
    local_78 = (longlong)(int)dVar11;
    *(short *)(iVar7 + 0x268) = (short)(int)dVar11;
    dVar10 = (double)(*(float *)(param_9 + 6) - *(float *)(iVar7 + 0x288));
    dVar9 = (double)(*(float *)(param_9 + 10) - *(float *)(iVar7 + 0x28c));
    dVar8 = FUN_80293900((double)(float)(dVar10 * dVar10 + (double)(float)(dVar9 * dVar9)));
    local_70 = (double)(longlong)(int)dVar8;
    *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) & 0xf7;
    fVar3 = FLOAT_803e3c40;
    fVar2 = FLOAT_803e3c3c;
    dVar11 = DOUBLE_803e3c28;
    uStack_64 = (uint)*(ushort *)(iVar7 + 0x268);
    if ((FLOAT_803e3c3c <= (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e3c28)) ||
       (uStack_64 == 0)) {
      uVar6 = (int)dVar8 & 0xffff;
      local_60 = (double)CONCAT44(0x43300000,uVar6);
      if ((FLOAT_803e3bf4 < (float)(local_60 - DOUBLE_803e3c28)) && (uVar6 != 0)) {
        local_60 = (double)CONCAT44(0x43300000,uVar6);
        dVar11 = (double)(FLOAT_803e3bf4 * (float)(local_60 - DOUBLE_803e3c28));
        *(float *)(param_9 + 0x12) = *(float *)(param_9 + 0x12) - (float)(dVar10 / dVar11);
        *(float *)(param_9 + 0x16) = *(float *)(param_9 + 0x16) - (float)(dVar9 / dVar11);
      }
    }
    else {
      *(float *)(param_9 + 0x12) =
           *(float *)(param_9 + 0x12) -
           (float)(dVar13 / (double)(FLOAT_803e3c40 *
                                    ((float)((double)CONCAT44(0x43300000,uStack_64) -
                                            DOUBLE_803e3c28) - FLOAT_803e3c3c)));
      local_70 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar7 + 0x268));
      *(float *)(param_9 + 0x16) =
           *(float *)(param_9 + 0x16) -
           (float)(dVar12 / (double)(fVar3 * ((float)(local_70 - dVar11) - fVar2)));
      fVar2 = FLOAT_803e3c44;
      local_78 = (longlong)(int)(FLOAT_803e3c44 * *(float *)(param_9 + 0x12));
      *(short *)(iVar7 + 0x27c) = (short)(int)(FLOAT_803e3c44 * *(float *)(param_9 + 0x12));
      local_60 = (double)(longlong)(int)(fVar2 * *(float *)(param_9 + 0x16));
      *(short *)(iVar7 + 0x27e) = (short)(int)(fVar2 * *(float *)(param_9 + 0x16));
      *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 8;
    }
    local_68 = 0x43300000;
    FUN_80163e44(param_9,iVar7);
    (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,iVar7);
    *(float *)(iVar7 + 0x2a0) = *(float *)(iVar7 + 0x2a0) - FLOAT_803dc074;
    if (FLOAT_803e3c00 <= *(float *)(iVar7 + 0x2a0)) {
      iVar4 = ObjHits_GetPriorityHit((int)param_9,&local_84,&iStack_7c,&uStack_80);
      if ((iVar4 != 0) && (*(short *)(local_84 + 0x46) != param_9[0x23])) {
        if (param_9[0x23] == 0x4ba) {
          *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 3;
          *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) & 0xef;
          *(undefined *)(iVar7 + 0x278) = 3;
          *(float *)(iVar7 + 0x270) = FLOAT_803e3c48;
          *(float *)(iVar7 + 0x2a0) = FLOAT_803e3c4c;
          FUN_80017a78((int)param_9,1);
        }
        else {
          *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
        }
      }
    }
    else {
      *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
    }
  }
  else if (cVar1 == '\x03') {
    iVar4 = FUN_80017a98();
    dVar11 = FUN_80017708((float *)(iVar4 + 0x18),(float *)(param_9 + 0xc));
    if ((double)FLOAT_803e3c50 <= dVar11) {
      *(float *)(iVar7 + 0x270) = *(float *)(iVar7 + 0x270) - FLOAT_803dc074;
      *(float *)(iVar7 + 0x2a0) = *(float *)(iVar7 + 0x2a0) - FLOAT_803dc074;
      if (FLOAT_803e3c00 <= *(float *)(iVar7 + 0x2a0)) {
        if (FLOAT_803e3c00 < *(float *)(iVar7 + 0x270)) {
          iVar4 = ObjHits_GetPriorityHit((int)param_9,&local_84,&iStack_7c,&uStack_80);
          if ((iVar4 != 0) && (*(short *)(local_84 + 0x46) != param_9[0x23])) {
            *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
          }
        }
        else {
          *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
        }
      }
      else {
        *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
      }
    }
    else {
      *(undefined2 *)(iVar7 + 0x298) = 0x195;
      *(undefined2 *)(iVar7 + 0x29a) = 0;
      *(float *)(iVar7 + 0x29c) = FLOAT_803e3c30;
      FUN_80037bd4(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar4,0x7000a,
                   (uint)param_9,iVar7 + 0x298,in_r7,in_r8,in_r9,in_r10);
      *(undefined *)(iVar7 + 0x278) = 4;
    }
    FUN_80163bbc(param_9,iVar7);
    (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,iVar7);
  }
  else if (cVar1 == '\x04') {
    while (iVar4 = FUN_80037584((int)param_9,&local_88,(uint *)0x0,(uint *)0x0), iVar4 != 0) {
      if (local_88 == 0x7000b) {
        FUN_80017688(0x194);
        FUN_80006824((uint)param_9,0x49);
        *(byte *)(iVar7 + 0x27a) = *(byte *)(iVar7 + 0x27a) | 7;
      }
    }
  }
  else if (cVar1 == '\x06') {
    pfVar5 = *(float **)(iVar7 + 0x290);
    dVar12 = (double)(*pfVar5 - *(float *)(param_9 + 6));
    dVar13 = (double)(pfVar5[1] - *(float *)(param_9 + 8));
    dVar8 = (double)(pfVar5[2] - *(float *)(param_9 + 10));
    dVar11 = FUN_80293900((double)(float)(dVar8 * dVar8 +
                                         (double)(float)(dVar12 * dVar12 +
                                                        (double)(float)(dVar13 * dVar13))));
    *(float *)(iVar7 + 0x294) = FLOAT_803dc074 * FLOAT_803e3c30 + *(float *)(iVar7 + 0x294);
    fVar2 = FLOAT_803e3c54;
    *(float *)(param_9 + 0x12) =
         FLOAT_803e3c54 * (float)(dVar12 / dVar11) * *(float *)(iVar7 + 0x294);
    *(float *)(param_9 + 0x14) = fVar2 * (float)(dVar13 / dVar11) * *(float *)(iVar7 + 0x294);
    *(float *)(param_9 + 0x16) = fVar2 * (float)(dVar8 / dVar11) * *(float *)(iVar7 + 0x294);
    dVar11 = FUN_80017708((float *)(param_9 + 6),*(float **)(iVar7 + 0x290));
    FUN_80017a88((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
    dVar12 = FUN_80017708((float *)(param_9 + 6),*(float **)(iVar7 + 0x290));
    fVar2 = FLOAT_803e3c30;
    if (dVar11 < dVar12) {
      *(float *)(param_9 + 6) =
           (**(float **)(iVar7 + 0x290) - *(float *)(param_9 + 6)) * FLOAT_803e3c30 +
           *(float *)(param_9 + 6);
      *(float *)(param_9 + 8) =
           (*(float *)(*(int *)(iVar7 + 0x290) + 4) - *(float *)(param_9 + 8)) * fVar2 +
           *(float *)(param_9 + 8);
      *(float *)(param_9 + 10) =
           (*(float *)(*(int *)(iVar7 + 0x290) + 8) - *(float *)(param_9 + 10)) * fVar2 +
           *(float *)(param_9 + 10);
    }
  }
  else if (cVar1 == '\a') {
    for (uVar6 = 0; (int)(uVar6 & 0xffff) < (int)FLOAT_803dc074; uVar6 = uVar6 + 1) {
      *(float *)(param_9 + 4) = *(float *)(param_9 + 4) * fVar2;
    }
    *(undefined4 *)(param_9 + 6) = **(undefined4 **)(iVar7 + 0x290);
    *(undefined4 *)(param_9 + 8) = *(undefined4 *)(*(int *)(iVar7 + 0x290) + 4);
    *(undefined4 *)(param_9 + 10) = *(undefined4 *)(*(int *)(iVar7 + 0x290) + 8);
  }
  else {
    dVar11 = (double)*(float *)(iVar7 + 0x270);
    if ((double)FLOAT_803e3c00 < dVar11) {
      *(float *)(iVar7 + 0x270) = (float)(dVar11 - (double)FLOAT_803dc074);
    }
    else {
      FUN_80017ac8(dVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80164c58
 * EN v1.0 Address: 0x80164C58
 * EN v1.0 Size: 924b
 * EN v1.1 Address: 0x80164DEC
 * EN v1.1 Size: 772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80164c58(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  char cVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined auStack_58 [4];
  undefined4 uStack_54;
  uint uStack_50;
  int iStack_4c;
  undefined8 local_48;
  undefined4 local_40;
  uint uStack_3c;
  longlong local_38;
  longlong local_30;
  
  iVar5 = *(int *)(param_9 + 0x5c);
  cVar1 = *(char *)(iVar5 + 0x278);
  if (cVar1 == '\0') {
    iVar4 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_58);
    if (iVar4 != 0) {
      if (*(float *)(iVar5 + 0x26c) <= *(float *)(param_9 + 4)) {
        *(undefined *)(iVar5 + 0x278) = 1;
      }
      else {
        *(float *)(param_9 + 4) =
             *(float *)(iVar5 + 0x270) * FLOAT_803dc074 + *(float *)(param_9 + 4);
      }
    }
  }
  else if (cVar1 == '\x01') {
    iVar4 = (**(code **)(*DAT_803dd6d8 + 0x24))(auStack_58);
    if (iVar4 != 0) {
      iVar4 = *(int *)(iVar5 + 0x284);
      if (iVar4 == 0) {
        iVar4 = FUN_80017a98();
      }
      fVar2 = *(float *)(param_9 + 6) - *(float *)(iVar4 + 0xc);
      fVar3 = *(float *)(param_9 + 10) - *(float *)(iVar4 + 0x14);
      dVar6 = FUN_80293900((double)(fVar2 * fVar2 + fVar3 * fVar3));
      local_48 = (double)(longlong)(int)dVar6;
      *(short *)(iVar5 + 0x268) = (short)(int)dVar6;
      if (*(ushort *)(iVar5 + 0x268) < *(ushort *)(iVar5 + 0x26a)) {
        *(undefined *)(iVar5 + 0x278) = 2;
        *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
        ObjHits_EnableObject((int)param_9);
      }
    }
  }
  else if (cVar1 == '\x02') {
    iVar4 = *(int *)(iVar5 + 0x284);
    if (iVar4 == 0) {
      iVar4 = FUN_80017a98();
    }
    dVar8 = (double)(*(float *)(param_9 + 6) - *(float *)(iVar4 + 0xc));
    dVar7 = (double)(*(float *)(param_9 + 10) - *(float *)(iVar4 + 0x14));
    dVar6 = FUN_80293900((double)(float)(dVar8 * dVar8 + (double)(float)(dVar7 * dVar7)));
    local_48 = (double)(longlong)(int)dVar6;
    *(short *)(iVar5 + 0x268) = (short)(int)dVar6;
    fVar3 = FLOAT_803e3c5c;
    dVar6 = DOUBLE_803e3c28;
    fVar2 = FLOAT_803e3c1c;
    uStack_3c = (uint)*(ushort *)(iVar5 + 0x268);
    if ((float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e3c28) <= FLOAT_803e3c5c) {
      *(float *)(param_9 + 0x12) = -(FLOAT_803e3c1c * *(float *)(param_9 + 0x12));
      *(float *)(param_9 + 0x16) = -(fVar2 * *(float *)(param_9 + 0x16));
    }
    else {
      *(float *)(param_9 + 0x12) =
           *(float *)(param_9 + 0x12) -
           (float)(dVar8 / (double)(FLOAT_803e3c5c *
                                   (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e3c28)
                                   ));
      local_48 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar5 + 0x268));
      *(float *)(param_9 + 0x16) =
           *(float *)(param_9 + 0x16) - (float)(dVar7 / (double)(fVar3 * (float)(local_48 - dVar6)))
      ;
      fVar2 = FLOAT_803e3c44;
      local_38 = (longlong)(int)(FLOAT_803e3c44 * *(float *)(param_9 + 0x12));
      *(short *)(iVar5 + 0x27c) = (short)(int)(FLOAT_803e3c44 * *(float *)(param_9 + 0x12));
      local_30 = (longlong)(int)(fVar2 * *(float *)(param_9 + 0x16));
      *(short *)(iVar5 + 0x27e) = (short)(int)(fVar2 * *(float *)(param_9 + 0x16));
    }
    local_40 = 0x43300000;
    FUN_80163e44(param_9,iVar5);
    (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,iVar5);
    iVar4 = ObjHits_GetPriorityHit((int)param_9,&uStack_54,&iStack_4c,&uStack_50);
    if (iVar4 != 0) {
      FUN_80017698(0x642,1);
      *(byte *)(iVar5 + 0x27a) = *(byte *)(iVar5 + 0x27a) | 7;
    }
  }
  else {
    dVar6 = (double)*(float *)(iVar5 + 0x270);
    if ((double)FLOAT_803e3c00 < dVar6) {
      *(float *)(iVar5 + 0x270) = (float)(dVar6 - (double)FLOAT_803dc074);
    }
    else {
      FUN_80017ac8(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80164ff4
 * EN v1.0 Address: 0x80164FF4
 * EN v1.0 Size: 624b
 * EN v1.1 Address: 0x801650F0
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80164ff4(uint param_1)
{
  short sVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar4 + 0x27a) & 1) != 0) {
    sVar1 = *(short *)(param_1 + 0x46);
    if (sVar1 == 0x4ba) {
LAB_80165148:
      iVar3 = 0x14;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x34d,0,2,0xffffffff,0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    else {
      if (sVar1 < 0x4ba) {
        if (sVar1 == 0x39d) goto LAB_80165148;
      }
      else if (sVar1 == 0x4c1) goto LAB_80165148;
      iVar3 = 0x14;
      do {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x32e,0,2,0xffffffff,0);
        iVar3 = iVar3 + -1;
      } while (iVar3 != 0);
    }
    FUN_80006824(param_1,0x27d);
    *(byte *)(iVar4 + 0x27a) = *(byte *)(iVar4 + 0x27a) & 0xfe;
  }
  if ((*(byte *)(iVar4 + 0x27a) & 2) == 0) goto LAB_80165284;
  sVar1 = *(short *)(param_1 + 0x46);
  if (sVar1 == 0x4ba) {
LAB_80165218:
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x34c,0,2,0xffffffff,0);
  }
  else {
    if (sVar1 < 0x4ba) {
      if (sVar1 == 0x39d) goto LAB_80165218;
    }
    else if (sVar1 == 0x4c1) goto LAB_80165218;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x32d,0,2,0xffffffff,0);
  }
  *(byte *)(iVar4 + 0x27a) = *(byte *)(iVar4 + 0x27a) & 0xfd;
LAB_80165284:
  if ((*(byte *)(iVar4 + 0x27a) & 4) != 0) {
    *(undefined *)(param_1 + 0x36) = 0;
    *(undefined *)(iVar4 + 0x278) = 5;
    *(float *)(iVar4 + 0x270) = FLOAT_803e3c60;
    ObjHits_DisableObject(param_1);
    *(byte *)(iVar4 + 0x27a) = *(byte *)(iVar4 + 0x27a) & 0xfb;
  }
  if (((*(byte *)(iVar4 + 0x27a) & 0x10) != 0) && ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    ObjHits_SetHitVolumeSlot(param_1,0x1f,1,0);
    bVar2 = *(char *)(iVar4 + 0x27b) + 1;
    *(byte *)(iVar4 + 0x27b) = bVar2;
    if ((uint)bVar2 % 6 == 0) {
      FUN_80081110(param_1,1,3,0,(undefined4 *)0x0);
    }
    else {
      FUN_80081110(param_1,1,0,0,(undefined4 *)0x0);
    }
    FUN_800068c4(param_1,0x451);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80165264
 * EN v1.0 Address: 0x80165264
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x80165390
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80165264(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9)
{
  if (param_9[0x23] == 0x39d) {
    FUN_80164c58(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  else {
    FUN_8016437c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  FUN_80164ff4((uint)param_9);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016531c
 * EN v1.0 Address: 0x8016531C
 * EN v1.0 Size: 416b
 * EN v1.1 Address: 0x801653D8
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016531c(int param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined4 *)(iVar2 + 0x288) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(iVar2 + 0x28c) = *(undefined4 *)(param_1 + 0x14);
  *(short *)(iVar2 + 0x26a) = (short)(int)(FLOAT_803e3c64 * *(float *)(param_2 + 0x1c));
  *(undefined *)(iVar2 + 0x279) = *(undefined *)(param_2 + 0x1b);
  *(undefined4 *)(iVar2 + 0x26c) = *(undefined4 *)(param_1 + 8);
  uVar1 = FUN_80017760(200,500);
  *(float *)(iVar2 + 0x270) =
       *(float *)(iVar2 + 0x26c) /
       (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e3c08);
  *(undefined4 *)(iVar2 + 0x284) = 0;
  *(float *)(param_1 + 8) = FLOAT_803e3c68;
  (**(code **)(*DAT_803dd728 + 4))(iVar2,0,0x40000,1);
  (**(code **)(*DAT_803dd728 + 8))(iVar2,1,&DAT_80320ed8,&DAT_803dc9a8,8);
  (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar2);
  *(undefined *)(iVar2 + 0x278) = 0;
  uVar1 = FUN_80017760(0xfffffed4,300);
  *(float *)(iVar2 + 0x2a0) =
       FLOAT_803e3c4c + (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) - DOUBLE_803e3c08);
  FUN_8003735c(param_1,3);
  FUN_8003735c(param_1,0x31);
  ObjHits_DisableObject(param_1);
  FUN_80037ce0(param_1,1);
  if (*(short *)(param_1 + 0x46) == 0x4ba) {
    *(byte *)(iVar2 + 0x27a) = *(byte *)(iVar2 + 0x27a) | 0x10;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801654bc
 * EN v1.0 Address: 0x801654BC
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x80165584
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801654bc(int param_1,int param_2)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    (**(code **)(*DAT_803dd738 + 0x4c))(param_1,(int)*(short *)(iVar1 + 0x3f0),0xffffffff,0);
    (**(code **)(*DAT_803dd70c + 0x58))(param_1,param_2,0x3c,10,0);
    FUN_80017698((int)*(short *)(iVar1 + 0x3f2),1);
    *(undefined *)(iVar1 + 0x405) = 0;
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80165570
 * EN v1.0 Address: 0x80165570
 * EN v1.0 Size: 884b
 * EN v1.1 Address: 0x80165634
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80165570(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  int iVar2;
  double dVar3;
  undefined8 uVar4;
  double dVar5;
  double dVar6;
  
  iVar2 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  *(undefined *)((int)param_10 + 0x34d) = 3;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    ObjHits_DisableObject(param_9);
    *(float *)(param_9 + 0x24) = -*(float *)(param_9 + 0x24);
    *(float *)(param_9 + 0x28) = *(float *)(param_9 + 0x28) + FLOAT_803e3c70;
    *(float *)(param_9 + 0x2c) = -*(float *)(param_9 + 0x2c);
    FUN_800305f8((double)FLOAT_803e3c74,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,3,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(iVar2 + 0x44) = FLOAT_803e3c78;
  }
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6d) = 0;
  *param_10 = *param_10 | 0x4000;
  fVar1 = FLOAT_803e3c7c;
  *(float *)(param_9 + 0x24) = *(float *)(param_9 + 0x24) * FLOAT_803e3c7c;
  *(float *)(param_9 + 0x28) = FLOAT_803e3c80 * (*(float *)(param_9 + 0x28) - FLOAT_803e3c84);
  *(float *)(param_9 + 0x2c) = *(float *)(param_9 + 0x2c) * fVar1;
  dVar5 = (double)*(float *)(param_9 + 0x28);
  dVar6 = (double)*(float *)(param_9 + 0x2c);
  FUN_80017a88((double)*(float *)(param_9 + 0x24),dVar5,dVar6,param_9);
  if (*(float *)(param_9 + 0xc) < *(float *)(iVar2 + 0x48)) {
    *(float *)(param_9 + 0xc) = *(float *)(iVar2 + 0x48);
    *(float *)(param_9 + 0x24) = FLOAT_803e3c88 * -*(float *)(param_9 + 0x24);
  }
  if (*(float *)(iVar2 + 0x4c) < *(float *)(param_9 + 0xc)) {
    *(float *)(param_9 + 0xc) = *(float *)(iVar2 + 0x4c);
    *(float *)(param_9 + 0x24) = FLOAT_803e3c88 * -*(float *)(param_9 + 0x24);
  }
  if (*(float *)(param_9 + 0x10) < *(float *)(iVar2 + 0x5c)) {
    *(float *)(param_9 + 0x10) = *(float *)(iVar2 + 0x5c);
    *(float *)(param_9 + 0x28) = FLOAT_803e3c88 * -*(float *)(param_9 + 0x28);
  }
  if (*(float *)(iVar2 + 0x58) < *(float *)(param_9 + 0x10)) {
    *(float *)(param_9 + 0x10) = *(float *)(iVar2 + 0x58);
    *(float *)(param_9 + 0x28) = FLOAT_803e3c88 * -*(float *)(param_9 + 0x28);
  }
  if (*(float *)(param_9 + 0x14) < *(float *)(iVar2 + 0x54)) {
    *(float *)(param_9 + 0x14) = *(float *)(iVar2 + 0x54);
    *(float *)(param_9 + 0x2c) = FLOAT_803e3c88 * -*(float *)(param_9 + 0x2c);
  }
  if (*(float *)(iVar2 + 0x50) < *(float *)(param_9 + 0x14)) {
    *(float *)(param_9 + 0x14) = *(float *)(iVar2 + 0x50);
    *(float *)(param_9 + 0x2c) = FLOAT_803e3c88 * -*(float *)(param_9 + 0x2c);
  }
  dVar3 = (double)*(float *)(param_9 + 0x98);
  if ((double)FLOAT_803e3c8c == dVar3) {
    uVar4 = FUN_80037844(dVar3,dVar5,dVar6,param_4,param_5,param_6,param_7,param_8,0,3,param_9,
                         0xe0000,param_9,param_14,param_15,param_16);
    FUN_80017ac8(uVar4,dVar5,dVar6,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  else {
    *(char *)(param_9 + 0x36) = -1 - (char)(int)((double)FLOAT_803e3c90 * dVar3);
  }
  return 0;
}
