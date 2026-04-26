#include "ghidra_import.h"
#include "main/dll/dll_10B.h"

extern undefined4 FUN_80006824();
extern int FUN_80006a10();
extern uint FUN_80017730();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 FUN_8014ccb8();
extern undefined4 FUN_8014d164();
extern undefined4 FUN_8014d3d0();
extern undefined4 FUN_80154af4();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247ef8();
extern double FUN_80247f90();
extern undefined4 FUN_80247fb0();
extern double FUN_80293900();
extern undefined4 FUN_80293f8c();
extern byte FUN_80294ca8();

extern undefined4 DAT_803dc938;
extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e3640;
extern f64 DOUBLE_803e3660;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e3628;
extern f32 FLOAT_803e362c;
extern f32 FLOAT_803e3638;
extern f32 FLOAT_803e363c;
extern f32 FLOAT_803e3648;
extern f32 FLOAT_803e364c;
extern f32 FLOAT_803e3650;
extern f32 FLOAT_803e3654;
extern f32 FLOAT_803e365c;
extern f32 FLOAT_803e3668;
extern f32 FLOAT_803e366c;
extern f32 FLOAT_803e3678;
extern f32 FLOAT_803e367c;
extern f32 FLOAT_803e3680;
extern f32 FLOAT_803e3684;
extern f32 FLOAT_803e3688;
extern f32 FLOAT_803e368c;
extern f32 FLOAT_803e3690;
extern f32 FLOAT_803e3698;
extern f32 FLOAT_803e369c;
extern f32 FLOAT_803e36a0;

/*
 * --INFO--
 *
 * Function: FUN_80154870
 * EN v1.0 Address: 0x80154870
 * EN v1.0 Size: 792b
 * EN v1.1 Address: 0x80154A30
 * EN v1.1 Size: 748b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80154870(ushort *param_1,undefined4 *param_2)
{
  int iVar1;
  char cVar3;
  uint uVar2;
  float *pfVar4;
  double dVar5;
  float local_38;
  float local_34;
  float local_30;
  undefined8 local_28;
  undefined4 local_20;
  uint uStack_1c;
  undefined8 local_18;
  
  pfVar4 = (float *)*param_2;
  *(undefined *)((int)param_2 + 0x33b) = 0;
  *(undefined *)(*(int *)(param_1 + 0x2a) + 0x70) = 0;
  if ((param_2[0xb7] & 0x2000) != 0) {
    iVar1 = FUN_80006a10((double)(float)param_2[0xbf],pfVar4);
    if ((((iVar1 != 0) || (pfVar4[4] != 0.0)) &&
        (cVar3 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar4), cVar3 != '\0')) &&
       (cVar3 = (**(code **)(*DAT_803dd71c + 0x8c))
                          ((double)FLOAT_803e3648,*param_2,param_1,&DAT_803dc938,0xffffffff),
       cVar3 != '\0')) {
      param_2[0xb7] = param_2[0xb7] & 0xffffdfff;
    }
    local_38 = pfVar4[0x1a] - *(float *)(param_1 + 6);
    local_34 = FLOAT_803e3628;
    local_30 = pfVar4[0x1c] - *(float *)(param_1 + 10);
    FUN_8014ccb8((double)FLOAT_803e3638,(double)FLOAT_803e364c,(double)FLOAT_803e364c,(int)param_1,
                 (int)param_2,&local_38,'\x01');
    param_2[0xc9] = (float)param_2[0xc9] + FLOAT_803dc074;
    if (FLOAT_803e3650 < (float)param_2[0xc9]) {
      param_2[0xb9] = param_2[0xb9] & 0xfffeffff;
      param_2[0xc9] = FLOAT_803e3628;
    }
  }
  local_28 = CONCAT44(0x43300000,(uint)*(byte *)((int)param_2 + 0x33a));
  dVar5 = (double)FUN_80293f8c();
  uStack_1c = (int)(short)param_1[1] ^ 0x80000000;
  local_20 = 0x43300000;
  iVar1 = (int)-(float)((double)FLOAT_803e3654 * dVar5 -
                       (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e3640));
  local_18 = (longlong)iVar1;
  param_1[1] = (ushort)iVar1;
  FUN_8014d164((double)FLOAT_803e365c,(double)FLOAT_803e362c,param_1,(int)param_2,0xf,'\0');
  if ((param_2[0xb7] & 0x40000000) != 0) {
    if (DOUBLE_803e3660 <= (double)*(float *)(param_1 + 0x4c)) {
      uVar2 = FUN_80017760(0,0x3c);
    }
    else {
      uVar2 = FUN_80017760(0,200);
    }
    if ((uVar2 & 0xff) == 0) {
      if ((double)*(float *)(param_1 + 0x4c) <= DOUBLE_803e3660) {
        FUN_80006824((uint)param_1,0x24c);
        param_2[0xc2] = FLOAT_803e366c;
      }
      else {
        FUN_80006824((uint)param_1,0x24b);
        param_2[0xc2] = FLOAT_803e3668;
      }
    }
  }
  *(char *)((int)param_2 + 0x33a) = *(char *)((int)param_2 + 0x33a) + '\x01';
  local_18 = CONCAT44(0x43300000,(uint)*(byte *)((int)param_2 + 0x33a));
  dVar5 = (double)FUN_80293f8c();
  uStack_1c = (int)(short)param_1[1] ^ 0x80000000;
  local_20 = 0x43300000;
  iVar1 = (int)((double)FLOAT_803e3654 * dVar5 +
               (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e3640));
  local_28 = (longlong)iVar1;
  param_1[1] = (ushort)iVar1;
  FUN_80154af4(param_1,(int)param_2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80154b88
 * EN v1.0 Address: 0x80154B88
 * EN v1.0 Size: 1028b
 * EN v1.1 Address: 0x80154D1C
 * EN v1.1 Size: 948b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80154b88(ushort *param_1,undefined4 *param_2)
{
  float fVar1;
  int iVar2;
  char cVar3;
  byte bVar4;
  float *pfVar5;
  double dVar6;
  float local_38;
  float local_34;
  float local_30;
  undefined8 local_28;
  undefined4 local_20;
  uint uStack_1c;
  undefined8 local_18;
  
  pfVar5 = (float *)*param_2;
  if ((param_2[0xb7] & 0x80000000) != 0) {
    FUN_80006824((uint)param_1,0x4c0);
  }
  if ((((param_2[0xb7] & 0x2000) != 0) &&
      (((iVar2 = FUN_80006a10((double)FLOAT_803e3628,pfVar5), iVar2 != 0 || (pfVar5[4] != 0.0)) &&
       (cVar3 = (**(code **)(*DAT_803dd71c + 0x90))(pfVar5), cVar3 != '\0')))) &&
     (cVar3 = (**(code **)(*DAT_803dd71c + 0x8c))
                        ((double)FLOAT_803e3648,*param_2,param_1,&DAT_803dc938,0xffffffff),
     cVar3 != '\0')) {
    param_2[0xb7] = param_2[0xb7] & 0xffffdfff;
  }
  ObjHits_SetHitVolumeSlot((int)param_1,0xe,1,0);
  iVar2 = FUN_80017a98();
  bVar4 = FUN_80294ca8(iVar2);
  local_38 = *(float *)(param_2[0xa7] + 0xc) - *(float *)(param_1 + 6);
  local_34 = FLOAT_803e3628;
  local_30 = *(float *)(param_2[0xa7] + 0x14) - *(float *)(param_1 + 10);
  if ((param_2[0xd0] != 0) && (iVar2 = FUN_80017a98(), param_2[0xd0] == iVar2)) {
    param_2[0xb9] = param_2[0xb9] | 0x10000;
    param_2[0xc9] = FLOAT_803e3628;
  }
  local_28 = CONCAT44(0x43300000,(uint)*(byte *)((int)param_2 + 0x33a));
  dVar6 = (double)FUN_80293f8c();
  uStack_1c = (int)(short)param_1[1] ^ 0x80000000;
  local_20 = 0x43300000;
  iVar2 = (int)-(float)((double)FLOAT_803e3654 * dVar6 -
                       (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e3640));
  local_18 = (longlong)iVar2;
  param_1[1] = (ushort)iVar2;
  fVar1 = FLOAT_803e3628;
  if (bVar4 == 0) {
    *(float *)(param_1 + 0x12) = FLOAT_803e3628;
    *(float *)(param_1 + 0x16) = fVar1;
    FUN_8014d3d0((short *)param_1,param_2,10,0);
  }
  else {
    FUN_8014ccb8((double)FLOAT_803e3638,(double)FLOAT_803e364c,(double)FLOAT_803e364c,(int)param_1,
                 (int)param_2,&local_38,'\x01');
    FUN_8014d164((double)FLOAT_803e365c,(double)FLOAT_803e362c,param_1,(int)param_2,0xf,'\0');
  }
  fVar1 = FLOAT_803e3628;
  if ((param_2[0xb7] & 0x40000000) != 0) {
    if (FLOAT_803e3628 == (float)param_2[0xca]) {
      if (bVar4 == 0) {
        if (*(float *)(param_1 + 0x4c) <= FLOAT_803e363c) {
          param_2[0xca] = FLOAT_803e367c;
        }
        else {
          param_2[0xca] = FLOAT_803e3678;
          *(char *)((int)param_2 + 0x33b) = *(char *)((int)param_2 + 0x33b) + '\x01';
        }
      }
      else if ((double)*(float *)(param_1 + 0x4c) <= DOUBLE_803e3660) {
        FUN_80006824((uint)param_1,0x24c);
        param_2[0xc2] = FLOAT_803e366c;
      }
      else {
        FUN_80006824((uint)param_1,0x24b);
        param_2[0xc2] = FLOAT_803e3668;
      }
    }
    else {
      param_2[0xca] = (float)param_2[0xca] - FLOAT_803dc074;
      if ((float)param_2[0xca] <= fVar1) {
        param_2[0xca] = fVar1;
        if ((double)*(float *)(param_1 + 0x4c) <= DOUBLE_803e3660) {
          FUN_80006824((uint)param_1,0x24c);
          param_2[0xc2] = FLOAT_803e364c;
        }
        else {
          FUN_80006824((uint)param_1,0x24b);
          param_2[0xc2] = FLOAT_803e3668;
        }
      }
    }
  }
  *(char *)((int)param_2 + 0x33a) = *(char *)((int)param_2 + 0x33a) + '\x01';
  local_18 = CONCAT44(0x43300000,(uint)*(byte *)((int)param_2 + 0x33a));
  dVar6 = (double)FUN_80293f8c();
  uStack_1c = (int)(short)param_1[1] ^ 0x80000000;
  local_20 = 0x43300000;
  iVar2 = (int)((double)FLOAT_803e3654 * dVar6 +
               (double)(float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e3640));
  local_28 = (longlong)iVar2;
  param_1[1] = (ushort)iVar2;
  FUN_80154af4(param_1,(int)param_2);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80154f8c
 * EN v1.0 Address: 0x80154F8C
 * EN v1.0 Size: 224b
 * EN v1.1 Address: 0x801550D0
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80154f8c(int param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  
  *(float *)(param_2 + 0x2ac) = FLOAT_803e3680;
  *(undefined4 *)(param_2 + 0x2e4) = 0x8000009;
  *(float *)(param_2 + 0x308) = FLOAT_803e3668;
  *(float *)(param_2 + 0x300) = FLOAT_803e364c;
  *(float *)(param_2 + 0x304) = FLOAT_803e3684;
  *(undefined *)(param_2 + 800) = 0;
  fVar1 = FLOAT_803e3688;
  *(float *)(param_2 + 0x314) = FLOAT_803e3688;
  *(undefined *)(param_2 + 0x321) = 1;
  *(float *)(param_2 + 0x318) = FLOAT_803e362c;
  *(undefined *)(param_2 + 0x322) = 0;
  *(float *)(param_2 + 0x31c) = fVar1;
  fVar1 = FLOAT_803e3628;
  *(float *)(param_2 + 0x324) = FLOAT_803e3628;
  *(float *)(param_2 + 0x328) = fVar1;
  *(undefined4 *)(param_2 + 0x32c) = *(undefined4 *)(param_1 + 0x10);
  uVar2 = FUN_80017760(0,0xff);
  *(char *)(param_2 + 0x33a) = (char)uVar2;
  *(undefined *)(param_2 + 0x33b) = 0;
  *(float *)(param_2 + 0x330) = FLOAT_803e368c;
  uVar2 = FUN_80017760(0x32,0x4b);
  *(float *)(param_2 + 0x2fc) =
       FLOAT_803e3690 * (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e3640);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8015506c
 * EN v1.0 Address: 0x8015506C
 * EN v1.0 Size: 604b
 * EN v1.1 Address: 0x801551B8
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8015506c(int param_1,int param_2,undefined2 *param_3,float *param_4)
{
  int iVar1;
  uint uVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0 [2];
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float afStack_88 [3];
  float local_7c [2];
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float afStack_64 [3];
  float local_58;
  float local_54;
  float local_50;
  
  local_70 = *(float *)(param_2 + 0x360);
  local_6c = *(float *)(param_2 + 0x358);
  local_68 = *(float *)(param_2 + 0x364);
  FUN_80247eb8(&local_70,(float *)(param_1 + 0xc),afStack_64);
  dVar3 = FUN_80247f90(afStack_64,(float *)(param_2 + 0x344));
  local_70 = (float)((double)*(float *)(param_2 + 0x344) * dVar3 + (double)*(float *)(param_1 + 0xc)
                    );
  dVar6 = (double)*(float *)(param_1 + 0x10);
  local_6c = (float)((double)*(float *)(param_2 + 0x348) * dVar3 + dVar6);
  local_68 = (float)((double)*(float *)(param_2 + 0x34c) * dVar3 +
                    (double)*(float *)(param_1 + 0x14));
  local_ac = FLOAT_803e3698;
  local_a8 = FLOAT_803e369c;
  local_a4 = FLOAT_803e3698;
  FUN_80247fb0(&local_ac,(float *)(param_2 + 0x344),local_7c);
  FUN_80247ef8(local_7c,local_7c);
  if (FLOAT_803e3698 == local_7c[0]) {
    local_7c[0] = (*(float *)(param_1 + 0x14) - *(float *)(param_2 + 0x364)) / local_74;
  }
  else {
    local_7c[0] = (*(float *)(param_1 + 0xc) - *(float *)(param_2 + 0x360)) / local_7c[0];
  }
  dVar5 = (double)local_7c[0];
  iVar1 = *(int *)(param_2 + 0x29c);
  local_58 = *(float *)(iVar1 + 0xc);
  local_54 = FLOAT_803e36a0 + *(float *)(iVar1 + 0x10);
  local_50 = *(float *)(iVar1 + 0x14);
  local_94 = *(float *)(param_2 + 0x360);
  local_90 = *(float *)(param_2 + 0x358);
  local_8c = *(float *)(param_2 + 0x364);
  FUN_80247eb8(&local_94,&local_58,afStack_88);
  dVar3 = FUN_80247f90(afStack_88,(float *)(param_2 + 0x344));
  local_94 = (float)((double)*(float *)(param_2 + 0x344) * dVar3 + (double)local_58);
  dVar4 = (double)local_54;
  local_90 = (float)((double)*(float *)(param_2 + 0x348) * dVar3 + dVar4);
  local_8c = (float)((double)*(float *)(param_2 + 0x34c) * dVar3 + (double)local_50);
  local_b8 = FLOAT_803e3698;
  local_b4 = FLOAT_803e369c;
  local_b0 = FLOAT_803e3698;
  FUN_80247fb0(&local_b8,(float *)(param_2 + 0x344),local_a0);
  FUN_80247ef8(local_a0,local_a0);
  if (FLOAT_803e3698 == local_a0[0]) {
    local_a0[0] = (local_50 - *(float *)(param_2 + 0x364)) / local_98;
  }
  else {
    local_a0[0] = (local_58 - *(float *)(param_2 + 0x360)) / local_a0[0];
  }
  dVar5 = (double)(float)(dVar5 - (double)local_a0[0]);
  dVar3 = (double)(float)(dVar6 - dVar4);
  uVar2 = FUN_80017730();
  iVar1 = (uVar2 & 0xffff) - (uint)*(ushort *)(param_1 + 2);
  if (0x8000 < iVar1) {
    iVar1 = iVar1 + -0xffff;
  }
  if (iVar1 < -0x8000) {
    iVar1 = iVar1 + 0xffff;
  }
  if (iVar1 < 0) {
    iVar1 = -iVar1;
  }
  *param_3 = (short)iVar1;
  dVar3 = FUN_80293900((double)(float)(dVar5 * dVar5 + (double)(float)(dVar3 * dVar3)));
  *param_4 = (float)dVar3;
  return;
}
