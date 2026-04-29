#include "ghidra_import.h"
#include "main/dll/staffAction.h"

extern uint FUN_80017690();
extern int FUN_80017728();
extern undefined4 FUN_80017740();
extern uint FUN_80017760();
extern undefined4 FUN_8001776c();
extern undefined4 FUN_80017784();
extern undefined4 FUN_80017788();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_RegisterActiveHitVolumeObject();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_EnableObject();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8003b870();
extern int FUN_80063a68();
extern undefined4 FUN_80063a74();
extern void trackDolphin_buildSweptBounds(uint *boundsOut,float *startPoints,float *endPoints,
                                          float *radii,int pointCount);
extern undefined4 FUN_80166f2c();
extern int FUN_8028683c();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern undefined4 FUN_80293bc4();
extern undefined4 FUN_80293f80();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd728;
extern undefined4* DAT_803dd738;
extern f64 DOUBLE_803e3cb0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e3c70;
extern f32 FLOAT_803e3c74;
extern f32 FLOAT_803e3c8c;
extern f32 FLOAT_803e3c9c;
extern f32 FLOAT_803e3ca0;
extern f32 FLOAT_803e3ca4;
extern f32 FLOAT_803e3ca8;
extern f32 FLOAT_803e3cb8;
extern f32 FLOAT_803e3cbc;
extern f32 FLOAT_803e3cc0;
extern f32 FLOAT_803e3cc4;
extern f32 FLOAT_803e3cc8;

/*
 * --INFO--
 *
 * Function: FUN_801659b8
 * EN v1.0 Address: 0x801659B8
 * EN v1.0 Size: 1212b
 * EN v1.1 Address: 0x80165A38
 * EN v1.1 Size: 1068b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_801659b8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  
  iVar3 = *(int *)(*(int *)(param_9 + 0x5c) + 0x40c);
  iVar1 = FUN_80017a98();
  *(undefined *)((int)param_10 + 0x34d) = 1;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(float *)(iVar3 + 0x60) = FLOAT_803e3c9c;
    ObjHits_EnableObject((int)param_9);
    dVar4 = (double)FUN_80293bc4();
    *(float *)(param_9 + 0x12) = (float)(-(double)*(float *)(iVar3 + 0x60) * dVar4);
    *(float *)(param_9 + 0x14) = FLOAT_803e3c74;
    dVar4 = (double)FUN_80293f80();
    *(float *)(param_9 + 0x16) = (float)(-(double)*(float *)(iVar3 + 0x60) * dVar4);
    *param_10 = *param_10 | 0x2004000;
    FUN_800305f8((double)FLOAT_803e3c74,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(iVar3 + 0x44) = FLOAT_803e3ca0;
  }
  ObjHits_SetHitVolumeSlot((int)param_9,9,1,-1);
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6c) = 9;
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6d) = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,param_10 + 1);
  if (*(char *)(iVar3 + 0x90) == '\x06') {
    if ((*(byte *)(iVar3 + 0x92) & 1) == 0) {
      uVar2 = 0;
    }
    else {
      uVar2 = 2;
      if ((ushort)DAT_803dc070 < *(ushort *)(iVar3 + 0x8e)) {
        *(ushort *)(iVar3 + 0x8e) = *(ushort *)(iVar3 + 0x8e) - (ushort)DAT_803dc070;
      }
      else {
        *(byte *)(iVar3 + 0x92) = *(byte *)(iVar3 + 0x92) & 0xfe;
      }
    }
  }
  else if ((((iVar1 == 0) || (*(float *)(iVar1 + 0x18) < *(float *)(iVar3 + 0x48))) ||
           (*(float *)(iVar3 + 0x4c) < *(float *)(iVar1 + 0x18))) ||
          (((*(float *)(iVar1 + 0x1c) < *(float *)(iVar3 + 0x5c) ||
            (*(float *)(iVar3 + 0x58) < *(float *)(iVar1 + 0x1c))) ||
           ((*(float *)(iVar1 + 0x20) < *(float *)(iVar3 + 0x54) ||
            (*(float *)(iVar3 + 0x50) < *(float *)(iVar1 + 0x20))))))) {
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  if (uVar2 == 1) {
    if ((ushort)DAT_803dc070 < *(ushort *)(iVar3 + 0x8c)) {
      *(ushort *)(iVar3 + 0x8c) = *(ushort *)(iVar3 + 0x8c) - (ushort)DAT_803dc070;
    }
    else {
      uVar2 = FUN_80017760((int)*(float *)(iVar3 + 0x48),(int)*(float *)(iVar3 + 0x4c));
      *(float *)(iVar3 + 100) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3cb0);
      uVar2 = FUN_80017760((int)*(float *)(iVar3 + 0x5c),(int)*(float *)(iVar3 + 0x58));
      *(float *)(iVar3 + 0x68) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3cb0);
      uVar2 = FUN_80017760((int)*(float *)(iVar3 + 0x54),(int)*(float *)(iVar3 + 0x50));
      *(float *)(iVar3 + 0x6c) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3cb0);
      uVar2 = FUN_80017760(300,600);
      *(short *)(iVar3 + 0x8c) = (short)uVar2;
    }
    in_f31 = (double)*(float *)(iVar3 + 100);
    in_f30 = (double)*(float *)(iVar3 + 0x68);
    in_f29 = (double)*(float *)(iVar3 + 0x6c);
    in_f28 = (double)FLOAT_803e3ca8;
  }
  else if (uVar2 == 0) {
    in_f31 = (double)*(float *)(iVar1 + 0xc);
    in_f30 = (double)(*(float *)(iVar1 + 0x10) - FLOAT_803e3c70);
    in_f29 = (double)*(float *)(iVar1 + 0x14);
    in_f28 = (double)FLOAT_803e3ca4;
    uVar2 = FUN_80017690(0x698);
    if (uVar2 != 0) {
      in_f28 = -(double)FLOAT_803e3ca4;
    }
  }
  else if (uVar2 < 3) {
    in_f31 = (double)*(float *)(iVar3 + 0x70);
    in_f30 = (double)*(float *)(iVar3 + 0x74);
    in_f29 = (double)*(float *)(iVar3 + 0x78);
    in_f28 = (double)FLOAT_803e3ca4;
  }
  FUN_80166e9c(in_f31,in_f30,in_f29,in_f28,(int)param_9);
  if (*(char *)(iVar3 + 0x90) == '\x06') {
    if ((*(byte *)(iVar3 + 0x92) >> 2 & 1) == 0) {
      FUN_8016693c((int)param_9,iVar3);
    }
    else {
      FUN_801660c0((int)param_9,iVar3);
    }
  }
  else {
    FUN_801661ec(param_9,iVar3);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80165e74
 * EN v1.0 Address: 0x80165E74
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x80165E64
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80165e74(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  double dVar2;
  
  iVar1 = *(int *)(*(int *)(param_9 + 0x5c) + 0x40c);
  *(undefined *)((int)param_10 + 0x34d) = 1;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(float *)(iVar1 + 0x60) = FLOAT_803e3c9c;
    ObjHits_EnableObject((int)param_9);
    dVar2 = (double)FUN_80293bc4();
    *(float *)(param_9 + 0x12) = (float)(-(double)*(float *)(iVar1 + 0x60) * dVar2);
    *(float *)(param_9 + 0x14) = FLOAT_803e3c74;
    dVar2 = (double)FUN_80293f80();
    *(float *)(param_9 + 0x16) = (float)(-(double)*(float *)(iVar1 + 0x60) * dVar2);
    *param_10 = *param_10 | 0x2004000;
    FUN_800305f8((double)FLOAT_803e3c74,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(iVar1 + 0x44) = FLOAT_803e3c74;
  }
  ObjHits_SetHitVolumeSlot((int)param_9,9,1,-1);
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6c) = 9;
  *(undefined *)(*(int *)(param_9 + 0x2a) + 0x6d) = 1;
  ObjHits_RegisterActiveHitVolumeObject(param_9);
  (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,param_10 + 1);
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    if (*(char *)(iVar1 + 0x90) == '\x06') {
      if ((*(byte *)(iVar1 + 0x92) >> 2 & 1) == 0) {
        FUN_8016693c((int)param_9,iVar1);
      }
      else {
        FUN_801660c0((int)param_9,iVar1);
      }
    }
    else {
      FUN_801661ec(param_9,iVar1);
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801660c0
 * EN v1.0 Address: 0x801660C0
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x80165FE8
 * EN v1.1 Size: 336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801660c0(int param_1,int param_2)
{
  float fVar1;
  int iVar2;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  uint auStack_9c [6];
  float afStack_84 [16];
  float local_44;
  undefined local_30;
  
  local_b8 = FLOAT_803e3cb8;
  *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) - FLOAT_803e3c8c;
  fVar1 = FLOAT_803e3cbc;
  *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) * FLOAT_803e3cbc;
  *(float *)(param_1 + 0x28) = *(float *)(param_1 + 0x28) * fVar1;
  *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) * fVar1;
  local_a8 = *(float *)(param_1 + 0xc);
  local_a4 = *(float *)(param_1 + 0x10);
  local_a0 = *(float *)(param_1 + 0x14);
  local_b4 = local_a8 + *(float *)(param_1 + 0x24);
  local_b0 = local_a4 + *(float *)(param_1 + 0x28);
  local_ac = local_a0 + *(float *)(param_1 + 0x2c);
  local_44 = FLOAT_803e3c74;
  local_30 = 3;
  trackDolphin_buildSweptBounds(auStack_9c,&local_a8,&local_b4,&local_b8,1);
  FUN_80063a74(param_1,auStack_9c,0,'\x01');
  iVar2 = FUN_80063a68();
  if (iVar2 == 0) {
    *(float *)(param_1 + 0xc) = local_b4;
    *(float *)(param_1 + 0x10) = local_b0;
    *(float *)(param_1 + 0x14) = local_ac;
  }
  else {
    *(byte *)(param_2 + 0x92) = *(byte *)(param_2 + 0x92) & 0xfb;
    FUN_80166c6c(param_1,param_2,afStack_84,&local_b4);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801661ec
 * EN v1.0 Address: 0x801661EC
 * EN v1.0 Size: 1872b
 * EN v1.1 Address: 0x80166138
 * EN v1.1 Size: 1976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801661ec(short *param_1,int param_2)
{
  byte bVar1;
  int iVar2;
  
  FUN_80017a88((double)*(float *)(param_1 + 0x12),(double)*(float *)(param_1 + 0x14),
               (double)*(float *)(param_1 + 0x16),(int)param_1);
  bVar1 = *(byte *)(param_2 + 0x90);
  if (bVar1 == 3) {
    if (*(float *)(param_2 + 0x48) <= *(float *)(param_1 + 6)) {
      if (*(float *)(param_1 + 6) <= *(float *)(param_2 + 0x4c)) {
        if (*(float *)(param_2 + 0x5c) <= *(float *)(param_1 + 8)) {
          if (*(float *)(param_2 + 0x58) < *(float *)(param_1 + 8)) {
            *(float *)(param_1 + 8) = *(float *)(param_2 + 0x58);
            if ((*(byte *)(param_2 + 0x91) & 0x10) != 0) {
              *(undefined4 *)(param_1 + 0x16) = *(undefined4 *)(param_1 + 0x14);
              *(undefined *)(param_2 + 0x90) = 4;
            }
            *(float *)(param_1 + 0x14) = FLOAT_803e3c74;
          }
        }
        else {
          *(float *)(param_1 + 8) = *(float *)(param_2 + 0x5c);
          if ((*(byte *)(param_2 + 0x91) & 0x20) != 0) {
            *(float *)(param_1 + 0x16) = -*(float *)(param_1 + 0x14);
            *(undefined *)(param_2 + 0x90) = 5;
          }
          *(float *)(param_1 + 0x14) = FLOAT_803e3c74;
        }
      }
      else {
        *(float *)(param_1 + 6) = *(float *)(param_2 + 0x4c);
        if ((*(byte *)(param_2 + 0x91) & 2) != 0) {
          *(undefined4 *)(param_1 + 0x16) = *(undefined4 *)(param_1 + 0x12);
          *(undefined *)(param_2 + 0x90) = 1;
        }
        *(float *)(param_1 + 0x12) = FLOAT_803e3c74;
      }
    }
    else {
      *(float *)(param_1 + 6) = *(float *)(param_2 + 0x48);
      if ((*(byte *)(param_2 + 0x91) & 1) != 0) {
        *(float *)(param_1 + 0x16) = -*(float *)(param_1 + 0x12);
        *(undefined *)(param_2 + 0x90) = 0;
      }
      *(float *)(param_1 + 0x12) = FLOAT_803e3c74;
    }
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      if (*(float *)(param_2 + 0x5c) <= *(float *)(param_1 + 8)) {
        if (*(float *)(param_1 + 8) <= *(float *)(param_2 + 0x58)) {
          if (*(float *)(param_1 + 10) <= *(float *)(param_2 + 0x50)) {
            if (*(float *)(param_1 + 10) < *(float *)(param_2 + 0x54)) {
              *(float *)(param_1 + 10) = *(float *)(param_2 + 0x54);
              if ((*(byte *)(param_2 + 0x91) & 8) != 0) {
                *(undefined4 *)(param_1 + 0x12) = *(undefined4 *)(param_1 + 0x16);
                *(undefined *)(param_2 + 0x90) = 3;
              }
              *(float *)(param_1 + 0x16) = FLOAT_803e3c74;
            }
          }
          else {
            *(float *)(param_1 + 10) = *(float *)(param_2 + 0x50);
            if ((*(byte *)(param_2 + 0x91) & 4) != 0) {
              *(float *)(param_1 + 0x12) = -*(float *)(param_1 + 0x16);
              *(undefined *)(param_2 + 0x90) = 2;
            }
            *(float *)(param_1 + 0x16) = FLOAT_803e3c74;
          }
        }
        else {
          *(float *)(param_1 + 8) = *(float *)(param_2 + 0x58);
          if ((*(byte *)(param_2 + 0x91) & 0x10) != 0) {
            *(float *)(param_1 + 0x12) = -*(float *)(param_1 + 0x14);
            *(undefined *)(param_2 + 0x90) = 4;
          }
          *(float *)(param_1 + 0x14) = FLOAT_803e3c74;
        }
      }
      else {
        *(float *)(param_1 + 8) = *(float *)(param_2 + 0x5c);
        if ((*(byte *)(param_2 + 0x91) & 0x20) != 0) {
          *(undefined4 *)(param_1 + 0x12) = *(undefined4 *)(param_1 + 0x14);
          *(undefined *)(param_2 + 0x90) = 5;
        }
        *(float *)(param_1 + 0x14) = FLOAT_803e3c74;
      }
    }
    else if (bVar1 == 0) {
      if (*(float *)(param_2 + 0x5c) <= *(float *)(param_1 + 8)) {
        if (*(float *)(param_1 + 8) <= *(float *)(param_2 + 0x58)) {
          if (*(float *)(param_1 + 10) <= *(float *)(param_2 + 0x50)) {
            if (*(float *)(param_1 + 10) < *(float *)(param_2 + 0x54)) {
              *(float *)(param_1 + 10) = *(float *)(param_2 + 0x54);
              if ((*(byte *)(param_2 + 0x91) & 8) != 0) {
                *(float *)(param_1 + 0x12) = -*(float *)(param_1 + 0x16);
                *(undefined *)(param_2 + 0x90) = 3;
              }
              *(float *)(param_1 + 0x16) = FLOAT_803e3c74;
            }
          }
          else {
            *(float *)(param_1 + 10) = *(float *)(param_2 + 0x50);
            if ((*(byte *)(param_2 + 0x91) & 4) != 0) {
              *(undefined4 *)(param_1 + 0x12) = *(undefined4 *)(param_1 + 0x16);
              *(undefined *)(param_2 + 0x90) = 2;
            }
            *(float *)(param_1 + 0x16) = FLOAT_803e3c74;
          }
        }
        else {
          *(float *)(param_1 + 8) = *(float *)(param_2 + 0x58);
          if ((*(byte *)(param_2 + 0x91) & 0x10) != 0) {
            *(undefined4 *)(param_1 + 0x12) = *(undefined4 *)(param_1 + 0x14);
            *(undefined *)(param_2 + 0x90) = 4;
          }
          *(float *)(param_1 + 0x14) = FLOAT_803e3c74;
        }
      }
      else {
        *(float *)(param_1 + 8) = *(float *)(param_2 + 0x5c);
        if ((*(byte *)(param_2 + 0x91) & 0x20) != 0) {
          *(float *)(param_1 + 0x12) = -*(float *)(param_1 + 0x14);
          *(undefined *)(param_2 + 0x90) = 5;
        }
        *(float *)(param_1 + 0x14) = FLOAT_803e3c74;
      }
    }
    else if (*(float *)(param_2 + 0x48) <= *(float *)(param_1 + 6)) {
      if (*(float *)(param_1 + 6) <= *(float *)(param_2 + 0x4c)) {
        if (*(float *)(param_2 + 0x5c) <= *(float *)(param_1 + 8)) {
          if (*(float *)(param_2 + 0x58) < *(float *)(param_1 + 8)) {
            *(float *)(param_1 + 8) = *(float *)(param_2 + 0x58);
            if ((*(byte *)(param_2 + 0x91) & 0x10) != 0) {
              *(float *)(param_1 + 0x16) = -*(float *)(param_1 + 0x14);
              *(undefined *)(param_2 + 0x90) = 4;
            }
            *(float *)(param_1 + 0x14) = FLOAT_803e3c74;
          }
        }
        else {
          *(float *)(param_1 + 8) = *(float *)(param_2 + 0x5c);
          if ((*(byte *)(param_2 + 0x91) & 0x20) != 0) {
            *(undefined4 *)(param_1 + 0x16) = *(undefined4 *)(param_1 + 0x14);
            *(undefined *)(param_2 + 0x90) = 5;
          }
          *(float *)(param_1 + 0x14) = FLOAT_803e3c74;
        }
      }
      else {
        *(float *)(param_1 + 6) = *(float *)(param_2 + 0x4c);
        if ((*(byte *)(param_2 + 0x91) & 2) != 0) {
          *(float *)(param_1 + 0x16) = -*(float *)(param_1 + 0x12);
          *(undefined *)(param_2 + 0x90) = 1;
        }
        *(float *)(param_1 + 0x12) = FLOAT_803e3c74;
      }
    }
    else {
      *(float *)(param_1 + 6) = *(float *)(param_2 + 0x48);
      if ((*(byte *)(param_2 + 0x91) & 1) != 0) {
        *(undefined4 *)(param_1 + 0x16) = *(undefined4 *)(param_1 + 0x12);
        *(undefined *)(param_2 + 0x90) = 0;
      }
      *(float *)(param_1 + 0x12) = FLOAT_803e3c74;
    }
  }
  else if (bVar1 == 5) {
    if (*(float *)(param_2 + 0x48) <= *(float *)(param_1 + 6)) {
      if (*(float *)(param_1 + 6) <= *(float *)(param_2 + 0x4c)) {
        if (*(float *)(param_1 + 10) <= *(float *)(param_2 + 0x50)) {
          if (*(float *)(param_1 + 10) < *(float *)(param_2 + 0x54)) {
            *(float *)(param_1 + 10) = *(float *)(param_2 + 0x54);
            if ((*(byte *)(param_2 + 0x91) & 8) != 0) {
              *(float *)(param_1 + 0x14) = -*(float *)(param_1 + 0x16);
              *(undefined *)(param_2 + 0x90) = 3;
            }
            *(float *)(param_1 + 0x16) = FLOAT_803e3c74;
          }
        }
        else {
          *(float *)(param_1 + 10) = *(float *)(param_2 + 0x50);
          if ((*(byte *)(param_2 + 0x91) & 4) != 0) {
            *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_1 + 0x16);
            *(undefined *)(param_2 + 0x90) = 2;
          }
          *(float *)(param_1 + 0x16) = FLOAT_803e3c74;
        }
      }
      else {
        *(float *)(param_1 + 6) = *(float *)(param_2 + 0x4c);
        if ((*(byte *)(param_2 + 0x91) & 2) != 0) {
          *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_1 + 0x12);
          *(undefined *)(param_2 + 0x90) = 1;
        }
        *(float *)(param_1 + 0x12) = FLOAT_803e3c74;
      }
    }
    else {
      *(float *)(param_1 + 6) = *(float *)(param_2 + 0x48);
      if ((*(byte *)(param_2 + 0x91) & 1) != 0) {
        *(float *)(param_1 + 0x14) = -*(float *)(param_1 + 0x12);
        *(undefined *)(param_2 + 0x90) = 0;
      }
      *(float *)(param_1 + 0x12) = FLOAT_803e3c74;
    }
  }
  else if (bVar1 < 5) {
    if (*(float *)(param_2 + 0x48) <= *(float *)(param_1 + 6)) {
      if (*(float *)(param_1 + 6) <= *(float *)(param_2 + 0x4c)) {
        if (*(float *)(param_1 + 10) <= *(float *)(param_2 + 0x50)) {
          if (*(float *)(param_1 + 10) < *(float *)(param_2 + 0x54)) {
            *(float *)(param_1 + 10) = *(float *)(param_2 + 0x54);
            if ((*(byte *)(param_2 + 0x91) & 8) != 0) {
              *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_1 + 0x16);
              *(undefined *)(param_2 + 0x90) = 3;
            }
            *(float *)(param_1 + 0x16) = FLOAT_803e3c74;
          }
        }
        else {
          *(float *)(param_1 + 10) = *(float *)(param_2 + 0x50);
          if ((*(byte *)(param_2 + 0x91) & 4) != 0) {
            *(float *)(param_1 + 0x14) = -*(float *)(param_1 + 0x16);
            *(undefined *)(param_2 + 0x90) = 2;
          }
          *(float *)(param_1 + 0x16) = FLOAT_803e3c74;
        }
      }
      else {
        *(float *)(param_1 + 6) = *(float *)(param_2 + 0x4c);
        if ((*(byte *)(param_2 + 0x91) & 2) != 0) {
          *(float *)(param_1 + 0x14) = -*(float *)(param_1 + 0x12);
          *(undefined *)(param_2 + 0x90) = 1;
        }
        *(float *)(param_1 + 0x12) = FLOAT_803e3c74;
      }
    }
    else {
      *(float *)(param_1 + 6) = *(float *)(param_2 + 0x48);
      if ((*(byte *)(param_2 + 0x91) & 1) != 0) {
        *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_1 + 0x12);
        *(undefined *)(param_2 + 0x90) = 0;
      }
      *(float *)(param_1 + 0x12) = FLOAT_803e3c74;
    }
  }
  bVar1 = *(byte *)(param_2 + 0x90);
  if (bVar1 == 3) {
    *param_1 = 0x4000;
    iVar2 = FUN_80017728();
    param_1[1] = (short)iVar2 + 0x4000;
    param_1[2] = 0x4000;
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      *param_1 = 0;
      iVar2 = FUN_80017728();
      param_1[1] = (short)iVar2 + 0x4000;
      param_1[2] = 0x4000;
    }
    else if (bVar1 == 0) {
      *param_1 = 0;
      iVar2 = FUN_80017728();
      param_1[1] = (short)iVar2 + 0x4000;
      param_1[2] = -0x4000;
    }
    else {
      *param_1 = 0x4000;
      iVar2 = FUN_80017728();
      param_1[1] = (short)iVar2 + 0x4000;
      param_1[2] = -0x4000;
    }
  }
  else if (bVar1 == 5) {
    iVar2 = FUN_80017728();
    *param_1 = (short)iVar2 + -0x8000;
    param_1[1] = 0;
    param_1[2] = 0;
  }
  else if (bVar1 < 5) {
    iVar2 = FUN_80017728();
    *param_1 = (short)iVar2 + -0x8000;
    param_1[1] = 0;
    param_1[2] = -0x8000;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016693c
 * EN v1.0 Address: 0x8016693C
 * EN v1.0 Size: 816b
 * EN v1.1 Address: 0x801668F0
 * EN v1.1 Size: 1020b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016693c(int param_1,int param_2)
{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  uint auStack_cc [6];
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_74;
  undefined local_60;
  
  dVar4 = FUN_80293900((double)(*(float *)(param_1 + 0x2c) * *(float *)(param_1 + 0x2c) +
                               *(float *)(param_1 + 0x24) * *(float *)(param_1 + 0x24) +
                               *(float *)(param_1 + 0x28) * *(float *)(param_1 + 0x28)));
  dVar6 = (double)FLOAT_803e3c74;
  iVar3 = 0;
  local_74 = FLOAT_803e3c74;
  local_60 = 3;
  local_d8 = *(float *)(param_1 + 0xc);
  local_d4 = *(float *)(param_1 + 0x10);
  local_d0 = *(float *)(param_1 + 0x14);
  local_e4 = local_d8 + *(float *)(param_1 + 0x24);
  local_e0 = local_d4 + *(float *)(param_1 + 0x28);
  local_dc = local_d0 + *(float *)(param_1 + 0x2c);
  local_e8 = FLOAT_803e3cb8;
  trackDolphin_buildSweptBounds(auStack_cc,&local_d8,&local_e4,&local_e8,1);
  FUN_80063a74(param_1,auStack_cc,0,'\x01');
  dVar7 = (double)FLOAT_803e3c8c;
  while ((dVar6 < dVar4 && (iVar3 = iVar3 + 1, iVar3 < 10))) {
    local_d8 = *(float *)(param_1 + 0xc);
    local_d4 = *(float *)(param_1 + 0x10);
    local_d0 = *(float *)(param_1 + 0x14);
    fVar1 = (float)(dVar7 - (double)(float)(dVar6 / dVar4));
    local_e4 = *(float *)(param_1 + 0x24) * fVar1 + local_d8;
    local_e0 = *(float *)(param_1 + 0x28) * fVar1 + local_d4;
    local_dc = *(float *)(param_1 + 0x2c) * fVar1 + local_d0;
    iVar2 = FUN_80063a68();
    if (iVar2 == 0) {
      *(float *)(param_1 + 0xc) = local_e4;
      *(float *)(param_1 + 0x10) = local_e0;
      *(float *)(param_1 + 0x14) = local_dc;
      dVar6 = dVar4;
    }
    else {
      dVar5 = FUN_80293900((double)((local_dc - local_d0) * (local_dc - local_d0) +
                                   (local_e4 - local_d8) * (local_e4 - local_d8) +
                                   (local_e0 - local_d4) * (local_e0 - local_d4)));
      dVar6 = (double)(float)(dVar6 + dVar5);
      FUN_80166c6c(param_1,param_2,&local_b4,&local_e4);
    }
  }
  local_d8 = *(float *)(param_1 + 0xc);
  local_d4 = *(float *)(param_1 + 0x10);
  local_d0 = *(float *)(param_1 + 0x14);
  local_e4 = -(FLOAT_803e3cc0 * *(float *)(param_2 + 0x7c) - local_d8);
  local_e0 = -(FLOAT_803e3cc0 * *(float *)(param_2 + 0x80) - local_d4);
  local_dc = -(FLOAT_803e3cc0 * *(float *)(param_2 + 0x84) - local_d0);
  local_74 = FLOAT_803e3c74;
  local_60 = 3;
  iVar3 = FUN_80063a68();
  if (iVar3 == 0) {
    local_d8 = local_e4;
    local_d4 = local_e0;
    local_d0 = local_dc;
    local_e4 = -*(float *)(param_1 + 0x24);
    local_e0 = -*(float *)(param_1 + 0x28);
    local_dc = -*(float *)(param_1 + 0x2c);
    FUN_80017784(&local_e4);
    local_e4 = FLOAT_803e3cc4 * local_e4 + local_d8;
    local_e0 = FLOAT_803e3cc4 * local_e0 + local_d4;
    local_dc = FLOAT_803e3cc4 * local_dc + local_d0;
    local_74 = FLOAT_803e3c74;
    local_60 = 3;
    iVar3 = FUN_80063a68();
    fVar1 = FLOAT_803e3cc8;
    if (iVar3 == 0) {
      *(float *)(param_1 + 0x24) = FLOAT_803e3cc8 * *(float *)(param_2 + 0x7c);
      *(float *)(param_1 + 0x28) = fVar1 * *(float *)(param_2 + 0x80);
      *(float *)(param_1 + 0x2c) = fVar1 * *(float *)(param_2 + 0x84);
      *(byte *)(param_2 + 0x92) = *(byte *)(param_2 + 0x92) & 0xfb | 4;
    }
    else {
      FUN_80166c6c(param_1,param_2,&local_b4,&local_e4);
    }
  }
  else if ((((local_b4 == *(float *)(param_2 + 0x7c)) && (local_b0 == *(float *)(param_2 + 0x80)))
           && (local_ac == *(float *)(param_2 + 0x84))) && (local_a8 == *(float *)(param_2 + 0x88)))
  {
    *(float *)(param_1 + 0xc) = local_e4;
    *(float *)(param_1 + 0x10) = local_e0;
    *(float *)(param_1 + 0x14) = local_dc;
  }
  else {
    FUN_80166c6c(param_1,param_2,&local_b4,&local_e4);
  }
  *(byte *)(param_2 + 0x92) = *(byte *)(param_2 + 0x92) & 0xf7 | 8;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80166c6c
 * EN v1.0 Address: 0x80166C6C
 * EN v1.0 Size: 560b
 * EN v1.1 Address: 0x80166CEC
 * EN v1.1 Size: 528b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80166c6c(int param_1,int param_2,float *param_3,float *param_4)
{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  
  dVar2 = (double)FLOAT_803e3cb8;
  dVar5 = (double)*(float *)(param_1 + 0xc);
  dVar10 = (double)(float)(dVar2 * (double)*(float *)(param_2 + 0x7c) + dVar5);
  dVar6 = (double)*(float *)(param_1 + 0x10);
  dVar9 = (double)(float)(dVar2 * (double)*(float *)(param_2 + 0x80) + dVar6);
  dVar7 = (double)*(float *)(param_1 + 0x14);
  dVar8 = (double)(float)(dVar2 * (double)*(float *)(param_2 + 0x84) + dVar7);
  dVar3 = (double)(float)(dVar2 * (double)*(float *)(param_1 + 0x24) + dVar5);
  dVar4 = (double)(float)(dVar2 * (double)*(float *)(param_1 + 0x28) + dVar6);
  dVar2 = (double)(float)(dVar2 * (double)*(float *)(param_1 + 0x2c) + dVar7);
  dVar11 = (double)(float)(dVar6 * (double)(float)(dVar8 - dVar2) +
                          (double)(float)(dVar9 * (double)(float)(dVar2 - dVar7) +
                                         (double)(float)(dVar4 * (double)(float)(dVar7 - dVar8))));
  dVar7 = (double)(float)(dVar7 * (double)(float)(dVar10 - dVar3) +
                         (double)(float)(dVar8 * (double)(float)(dVar3 - dVar5) +
                                        (double)(float)(dVar2 * (double)(float)(dVar5 - dVar10))));
  dVar3 = (double)(float)(dVar5 * (double)(float)(dVar9 - dVar4) +
                         (double)(float)(dVar10 * (double)(float)(dVar4 - dVar6) +
                                        (double)(float)(dVar3 * (double)(float)(dVar6 - dVar9))));
  dVar2 = FUN_80293900((double)(float)(dVar3 * dVar3 +
                                      (double)(float)(dVar11 * dVar11 +
                                                     (double)(float)(dVar7 * dVar7))));
  if ((double)FLOAT_803e3c74 < dVar2) {
    dVar2 = (double)(float)((double)FLOAT_803e3c8c / dVar2);
    dVar11 = (double)(float)(dVar11 * dVar2);
    dVar7 = (double)(float)(dVar7 * dVar2);
    dVar3 = (double)(float)(dVar3 * dVar2);
  }
  local_98 = (float)dVar11;
  local_94 = (float)dVar7;
  local_90 = (float)dVar3;
  local_8c = -(float)(dVar8 * dVar3 +
                     (double)(float)(dVar10 * dVar11 + (double)(float)(dVar9 * dVar7)));
  FUN_80017788(&local_98,param_3,&local_88);
  FUN_80017784(&local_88);
  fVar1 = FLOAT_803e3c9c;
  *(float *)(param_1 + 0x24) = FLOAT_803e3c9c * local_88;
  *(float *)(param_1 + 0x28) = fVar1 * local_84;
  *(float *)(param_1 + 0x2c) = fVar1 * local_80;
  *(float *)(param_2 + 0x7c) = *param_3;
  *(float *)(param_2 + 0x80) = param_3[1];
  *(float *)(param_2 + 0x84) = param_3[2];
  *(float *)(param_2 + 0x88) = param_3[3];
  *(float *)(param_1 + 0xc) = *param_4 + *(float *)(param_2 + 0x7c);
  *(float *)(param_1 + 0x10) = param_4[1] + *(float *)(param_2 + 0x80);
  *(float *)(param_1 + 0x14) = param_4[2] + *(float *)(param_2 + 0x84);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80166e9c
 * EN v1.0 Address: 0x80166E9C
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x80166EFC
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80166e9c(double param_1,double param_2,double param_3,double param_4,int param_5)
{
  byte bVar1;
  int iVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  iVar2 = *(int *)(*(int *)(param_5 + 0xb8) + 0x40c);
  if ((*(byte *)(iVar2 + 0x92) >> 2 & 1) == 0) {
    dVar6 = (double)(float)(param_1 - (double)*(float *)(param_5 + 0xc));
    dVar5 = (double)(float)(param_2 - (double)*(float *)(param_5 + 0x10));
    dVar4 = (double)(float)(param_3 - (double)*(float *)(param_5 + 0x14));
    dVar3 = FUN_80293900((double)(float)(dVar4 * dVar4 +
                                        (double)(float)(dVar6 * dVar6 +
                                                       (double)(float)(dVar5 * dVar5))));
    if ((double)FLOAT_803e3c74 <= dVar3) {
      dVar3 = (double)(float)((double)*(float *)(iVar2 + 0x60) / dVar3);
      dVar6 = (double)(float)(dVar6 * dVar3);
      dVar5 = (double)(float)(dVar5 * dVar3);
      dVar4 = (double)(float)(dVar4 * dVar3);
    }
    dVar6 = (double)(float)(param_4 * (double)(float)(dVar6 - (double)*(float *)(param_5 + 0x24)) +
                           (double)*(float *)(param_5 + 0x24));
    dVar5 = (double)(float)(param_4 * (double)(float)(dVar5 - (double)*(float *)(param_5 + 0x28)) +
                           (double)*(float *)(param_5 + 0x28));
    dVar3 = (double)(float)(param_4 * (double)(float)(dVar4 - (double)*(float *)(param_5 + 0x2c)) +
                           (double)*(float *)(param_5 + 0x2c));
    bVar1 = *(byte *)(iVar2 + 0x90);
    if (bVar1 < 4) {
      if (bVar1 < 2) {
        dVar6 = (double)FLOAT_803e3c74;
        dVar4 = FUN_80293900((double)(float)(dVar5 * dVar5 + (double)(float)(dVar3 * dVar3)));
        if (dVar4 != (double)FLOAT_803e3c74) {
          dVar4 = (double)(float)((double)*(float *)(iVar2 + 0x60) / dVar4);
          dVar5 = (double)(float)(dVar5 * dVar4);
          dVar3 = (double)(float)(dVar3 * dVar4);
        }
      }
      else {
        dVar3 = (double)FLOAT_803e3c74;
        dVar4 = FUN_80293900((double)(float)(dVar6 * dVar6 + (double)(float)(dVar5 * dVar5)));
        if (dVar4 != (double)FLOAT_803e3c74) {
          dVar4 = (double)(float)((double)*(float *)(iVar2 + 0x60) / dVar4);
          dVar6 = (double)(float)(dVar6 * dVar4);
          dVar5 = (double)(float)(dVar5 * dVar4);
        }
      }
    }
    else if (bVar1 == 6) {
      dVar4 = (double)(float)(dVar3 * (double)*(float *)(iVar2 + 0x84) +
                             (double)(float)(dVar6 * (double)*(float *)(iVar2 + 0x7c) +
                                            (double)(float)(dVar5 * (double)*(float *)(iVar2 + 0x80)
                                                           )));
      dVar6 = -(double)(float)(dVar4 * (double)*(float *)(iVar2 + 0x7c) - dVar6);
      dVar5 = -(double)(float)(dVar4 * (double)*(float *)(iVar2 + 0x80) - dVar5);
      dVar3 = -(double)(float)(dVar4 * (double)*(float *)(iVar2 + 0x84) - dVar3);
      dVar4 = FUN_80293900((double)(float)(dVar3 * dVar3 +
                                          (double)(float)(dVar6 * dVar6 +
                                                         (double)(float)(dVar5 * dVar5))));
      if (dVar4 != (double)FLOAT_803e3c74) {
        dVar4 = (double)(float)((double)*(float *)(iVar2 + 0x60) / dVar4);
        dVar6 = (double)(float)(dVar6 * dVar4);
        dVar5 = (double)(float)(dVar5 * dVar4);
        dVar3 = (double)(float)(dVar3 * dVar4);
      }
    }
    else if (bVar1 < 6) {
      dVar5 = (double)FLOAT_803e3c74;
      dVar4 = FUN_80293900((double)(float)(dVar6 * dVar6 + (double)(float)(dVar3 * dVar3)));
      if (dVar4 != (double)FLOAT_803e3c74) {
        dVar4 = (double)(float)((double)*(float *)(iVar2 + 0x60) / dVar4);
        dVar6 = (double)(float)(dVar6 * dVar4);
        dVar3 = (double)(float)(dVar3 * dVar4);
      }
    }
    *(float *)(param_5 + 0x24) = (float)dVar6;
    *(float *)(param_5 + 0x28) = (float)dVar5;
    *(float *)(param_5 + 0x2c) = (float)dVar3;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016716c
 * EN v1.0 Address: 0x8016716C
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x80167138
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016716c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  undefined4 uVar1;
  undefined8 uVar2;
  
  uVar1 = *(undefined4 *)(param_9 + 0xb8);
  uVar2 = ObjGroup_RemoveObject(param_9,3);
  if (*(int *)(param_9 + 200) != 0) {
    FUN_80017ac8(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(param_9 + 200));
    *(undefined4 *)(param_9 + 200) = 0;
  }
  (**(code **)(*DAT_803dd738 + 0x40))(param_9,uVar1,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8016725c
 * EN v1.0 Address: 0x8016725C
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x801671AC
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016725c(void)
{
  int iVar1;
  int iVar2;
  char in_r8;
  double dVar3;
  float afStack_58 [12];
  float local_28;
  undefined4 local_24;
  float local_20;
  
  iVar1 = FUN_8028683c();
  iVar2 = *(int *)(*(int *)(iVar1 + 0xb8) + 0x40c);
  if ((in_r8 != '\0') && (*(int *)(iVar1 + 0xf4) == 0)) {
    if ((*(char *)(iVar2 + 0x90) == '\x06') && ((*(byte *)(iVar2 + 0x92) >> 3 & 1) != 0)) {
      if ((*(byte *)(iVar2 + 0x92) >> 2 & 1) == 0) {
        FUN_80166f2c((float *)(iVar2 + 4),(float *)(iVar1 + 0x24),(float *)(iVar2 + 0x7c));
      }
      dVar3 = (double)*(float *)(iVar1 + 8);
      FUN_80017740(dVar3,dVar3,dVar3,afStack_58);
      FUN_8001776c(afStack_58,(float *)(iVar2 + 4),afStack_58);
      local_28 = *(float *)(iVar1 + 0xc) - FLOAT_803dda58;
      local_24 = *(undefined4 *)(iVar1 + 0x10);
      local_20 = *(float *)(iVar1 + 0x14) - FLOAT_803dda5c;
      FUN_8003b870(afStack_58);
      FUN_8003b818(iVar1);
      FUN_8003b870(0);
    }
    else {
      FUN_8003b818(iVar1);
    }
  }
  FUN_80286888();
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_80166F28(void) {}

/* 8b "li r3, N; blr" returners. */
int fn_80166C7C(void) { return 0x4a4; }
int fn_80166C84(void) { return 0x49; }
