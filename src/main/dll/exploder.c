#include "ghidra_import.h"
#include "main/dll/exploder.h"

extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80017748();
extern undefined4 FUN_80017a98();
extern undefined8 ObjGroup_RemoveObject();
extern int FUN_800620e8();
extern byte FUN_80063a68();
extern undefined4 FUN_80063a74();
extern void trackDolphin_buildSweptBounds(uint *boundsOut,float *startPoints,float *endPoints,
                                          float *radii,int pointCount);
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_803ad3f0;
extern undefined4 DAT_803ad3f4;
extern undefined4 DAT_803ad3f8;
extern undefined4 DAT_803ad3fc;
extern undefined4* DAT_803dd6fc;
extern undefined4 DAT_803de740;
extern f64 DOUBLE_803e4600;
extern f32 FLOAT_803e45d0;
extern f32 FLOAT_803e45e8;
extern f32 FLOAT_803e45f0;
extern f32 FLOAT_803e460c;

/*
 * --INFO--
 *
 * Function: FUN_801826e8
 * EN v1.0 Address: 0x801826E8
 * EN v1.0 Size: 764b
 * EN v1.1 Address: 0x80182754
 * EN v1.1 Size: 776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801826e8(void)
{
  float fVar1;
  int *piVar2;
  int iVar3;
  byte bVar4;
  int iVar5;
  uint auStack_110 [6];
  float local_f8;
  int local_f4;
  int local_f0;
  float local_c8;
  int local_c4 [11];
  undefined4 local_98 [16];
  float local_58 [4];
  undefined local_48 [4];
  undefined local_44;
  int local_3c [5];
  undefined4 local_28;
  uint uStack_24;
  
  piVar2 = (int *)FUN_80286840();
  iVar5 = piVar2[0x15];
  iVar3 = FUN_800620e8(piVar2 + 0x20,piVar2 + 3,(float *)0x1,(int *)0x0,piVar2,1,0xffffffff,0xff,0);
  if (iVar3 == 0) {
    if ((*(uint *)(iVar5 + 0x48) >> 4 != 0) && (*(char *)(iVar5 + 0x70) == '\0')) {
      local_c8 = (float)piVar2[3];
      local_c4[0] = piVar2[4];
      local_c4[1] = piVar2[5];
      local_f8 = (float)piVar2[0x20];
      local_f4 = piVar2[0x21];
      local_f0 = piVar2[0x22];
      uStack_24 = (int)*(short *)(iVar5 + 0x5a) ^ 0x80000000;
      local_28 = 0x43300000;
      local_58[0] = (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e4600);
      local_48[0] = 0xff;
      local_44 = 3;
      trackDolphin_buildSweptBounds(auStack_110,&local_f8,&local_c8,local_58,1);
      FUN_80063a74(piVar2,auStack_110,(uint)*(ushort *)(iVar5 + 0xb2),'\x01');
      bVar4 = FUN_80063a68();
      if (bVar4 != 0) {
        if ((bVar4 & 1) == 0) {
          if ((bVar4 & 2) == 0) {
            if ((bVar4 & 4) == 0) {
              iVar3 = 3;
            }
            else {
              iVar3 = 2;
            }
          }
          else {
            iVar3 = 1;
          }
        }
        else {
          iVar3 = 0;
        }
        *(undefined *)(iVar5 + 0xac) = local_48[iVar3];
        *(float *)(iVar5 + 0x3c) = (&local_c8)[iVar3 * 3];
        *(int *)(iVar5 + 0x40) = local_c4[iVar3 * 3];
        *(int *)(iVar5 + 0x44) = local_c4[iVar3 * 3 + 1];
        DAT_803ad3f0 = local_98[iVar3 * 4];
        DAT_803ad3f4 = local_98[iVar3 * 4 + 1];
        DAT_803ad3f8 = local_98[iVar3 * 4 + 2];
        DAT_803ad3fc = local_98[iVar3 * 4 + 3];
        if (local_3c[iVar3] == 0) {
          *(byte *)(iVar5 + 0xad) = *(byte *)(iVar5 + 0xad) | 1;
          piVar2[3] = *(int *)(iVar5 + 0x3c);
          piVar2[4] = *(int *)(iVar5 + 0x40);
          piVar2[5] = *(int *)(iVar5 + 0x44);
          *(int *)(iVar5 + 0x10) = piVar2[0x20];
          *(int *)(iVar5 + 0x14) = piVar2[0x21];
          *(int *)(iVar5 + 0x18) = piVar2[0x22];
          fVar1 = FLOAT_803e45d0;
          piVar2[9] = (int)FLOAT_803e45d0;
          piVar2[10] = (int)fVar1;
          piVar2[0xb] = (int)fVar1;
        }
        else {
          *(byte *)(iVar5 + 0xad) = *(byte *)(iVar5 + 0xad) | 2;
          piVar2[3] = *(int *)(iVar5 + 0x3c);
          piVar2[4] = *(int *)(iVar5 + 0x40);
          piVar2[5] = *(int *)(iVar5 + 0x44);
          *(int *)(iVar5 + 0x10) = piVar2[0x20];
          *(int *)(iVar5 + 0x14) = piVar2[0x21];
          *(int *)(iVar5 + 0x18) = piVar2[0x22];
          fVar1 = FLOAT_803e45d0;
          piVar2[9] = (int)FLOAT_803e45d0;
          piVar2[10] = (int)fVar1;
          piVar2[0xb] = (int)fVar1;
        }
      }
    }
  }
  else {
    *(byte *)(iVar5 + 0xad) = *(byte *)(iVar5 + 0xad) | 1;
    *(int *)(iVar5 + 0x10) = piVar2[0x20];
    *(int *)(iVar5 + 0x14) = piVar2[0x21];
    *(int *)(iVar5 + 0x18) = piVar2[0x22];
    fVar1 = FLOAT_803e45d0;
    piVar2[9] = (int)FLOAT_803e45d0;
    piVar2[10] = (int)fVar1;
    piVar2[0xb] = (int)fVar1;
  }
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801829e4
 * EN v1.0 Address: 0x801829E4
 * EN v1.0 Size: 120b
 * EN v1.1 Address: 0x80182A5C
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801829e4(int param_1)
{
  ushort *puVar1;
  int iVar2;
  ushort local_28 [4];
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  puVar1 = (ushort *)FUN_80017a98();
  *(undefined *)(iVar2 + 6) = 0;
  *(undefined *)(iVar2 + 5) = 0;
  *(undefined *)(iVar2 + 9) = 1;
  *(float *)(param_1 + 0x28) = FLOAT_803e45f0;
  *(float *)(param_1 + 0x2c) = FLOAT_803e460c;
  local_1c = FLOAT_803e45d0;
  local_18 = FLOAT_803e45d0;
  local_14 = FLOAT_803e45d0;
  local_20 = FLOAT_803e45e8;
  local_28[2] = 0;
  local_28[1] = 0;
  local_28[0] = *puVar1;
  FUN_80017748(local_28,(float *)(param_1 + 0x24));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80182a5c
 * EN v1.0 Address: 0x80182A5C
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x80182AF4
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80182a5c(int param_1)
{
  (**(code **)(*DAT_803dd6fc + 0x18))();
  FUN_80006b0c(DAT_803de740);
  ObjGroup_RemoveObject(param_1,0x10);
  return;
}
