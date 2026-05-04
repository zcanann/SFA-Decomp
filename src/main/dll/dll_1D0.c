#include "ghidra_import.h"
#include "main/dll/dll_1D0.h"

extern undefined4 FUN_800066e0();
extern void* FUN_800069a8();
extern int FUN_80006a64();
extern undefined8 FUN_80006a68();
extern uint FUN_80017760();
extern undefined8 ObjHits_SetHitVolumeSlot();
extern double FUN_80293900();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd6f8;
extern undefined4* DAT_803dd6fc;
extern undefined4* DAT_803dd708;
extern f32 lbl_803E5E60;
extern f32 lbl_803E5E64;
extern f32 lbl_803E5E68;
extern f32 lbl_803E5E6C;
extern f32 lbl_803E5E70;
extern f32 lbl_803E5E74;

/*
 * --INFO--
 *
 * Function: FUN_801cd258
 * EN v1.0 Address: 0x801CD258
 * EN v1.0 Size: 464b
 * EN v1.1 Address: 0x801CD480
 * EN v1.1 Size: 232b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cd258(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  char cVar1;
  undefined uVar2;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar3;
  undefined8 uVar4;
  
  iVar3 = *(int *)(param_9 + 0x4c);
  if (*(char *)(iVar3 + 0x19) == '\0') {
    uVar2 = 1;
  }
  else {
    uVar2 = 3;
  }
  uVar4 = ObjHits_SetHitVolumeSlot(param_9,0xe,uVar2,0);
  cVar1 = *(char *)(iVar3 + 0x19);
  if (cVar1 == '\x01') {
    FUN_800066e0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,0x203
                 ,0,0,0,in_r9,in_r10);
  }
  else if (cVar1 == '\x02') {
    FUN_800066e0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,0x204
                 ,0,0,0,in_r9,in_r10);
  }
  else {
    FUN_800066e0(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,0x201
                 ,0,0,0,in_r9,in_r10);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cd428
 * EN v1.0 Address: 0x801CD428
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801CD568
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cd428(undefined4 param_1)
{
  (**(code **)(*DAT_803dd6fc + 0x18))();
  (**(code **)(*DAT_803dd6f8 + 0x18))(param_1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cd484
 * EN v1.0 Address: 0x801CD484
 * EN v1.0 Size: 596b
 * EN v1.1 Address: 0x801CD5BC
 * EN v1.1 Size: 592b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cd484(int param_1)
{
  float fVar1;
  undefined2 *puVar2;
  int iVar3;
  uint uVar4;
  char in_r8;
  int iVar5;
  double dVar6;
  undefined8 uVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined4 auStack_68 [2];
  short asStack_60 [4];
  short asStack_58 [4];
  float local_50;
  float local_4c;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  undefined auStack_2c [12];
  float local_20;
  float local_1c;
  float local_18;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  if (in_r8 == '\0') {
    *(undefined2 *)(iVar5 + 4) = 0;
    *(undefined *)(iVar5 + 10) = 0;
  }
  else if (*(char *)(iVar5 + 0xc) != '\0') {
    *(undefined *)(iVar5 + 10) = 1;
    puVar2 = FUN_800069a8();
    local_38 = *(float *)(puVar2 + 6) - *(float *)(param_1 + 0xc);
    local_34 = *(float *)(puVar2 + 8) - *(float *)(param_1 + 0x10);
    local_30 = *(float *)(puVar2 + 10) - *(float *)(param_1 + 0x14);
    dVar6 = FUN_80293900((double)(local_30 * local_30 + local_38 * local_38 + local_34 * local_34));
    if ((double)lbl_803E5E60 < dVar6) {
      fVar1 = (float)((double)lbl_803E5E64 / dVar6);
      local_38 = local_38 * fVar1;
      dVar12 = (double)local_38;
      local_34 = local_34 * fVar1;
      dVar11 = (double)local_34;
      local_30 = local_30 * fVar1;
      dVar10 = (double)local_30;
      dVar6 = (double)lbl_803E5E68;
      local_44 = (float)(dVar6 * dVar12) + *(float *)(param_1 + 0xc);
      local_40 = (float)(dVar6 * dVar11) + *(float *)(param_1 + 0x10);
      local_3c = (float)(dVar6 * dVar10) + *(float *)(param_1 + 0x14);
      dVar6 = (double)lbl_803E5E6C;
      dVar9 = (double)(float)(dVar6 * dVar12);
      dVar8 = (double)(float)(dVar6 * dVar11);
      local_50 = (float)(dVar9 + (double)*(float *)(puVar2 + 6));
      local_4c = (float)(dVar8 + (double)*(float *)(puVar2 + 8));
      local_48 = (float)(dVar6 * dVar10) + *(float *)(puVar2 + 10);
      FUN_80006a68(&local_44,asStack_58);
      uVar7 = FUN_80006a68(&local_50,asStack_60);
      iVar3 = FUN_80006a64(uVar7,dVar8,dVar9,dVar10,dVar11,dVar12,in_f7,in_f8,asStack_58,asStack_60,
                           auStack_68,(undefined *)0x0,0);
      if (iVar3 == 0) {
        *(undefined *)(iVar5 + 10) = 0;
        (**(code **)(*DAT_803dd6f8 + 0x14))(param_1);
      }
    }
    if (*(short *)(iVar5 + 4) < 1) {
      if (*(char *)(iVar5 + 10) != '\0') {
        local_20 = lbl_803E5E70;
        local_1c = lbl_803E5E74;
        local_18 = lbl_803E5E70;
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x1f7,auStack_2c,0x12,0xffffffff,0);
      }
      uVar4 = FUN_80017760(0xfffffff6,10);
      *(short *)(iVar5 + 4) = (short)uVar4 + 0x3c;
    }
    else {
      *(ushort *)(iVar5 + 4) = *(short *)(iVar5 + 4) - (ushort)DAT_803dc070;
    }
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void fn_801CD7D4(void) {}
void fn_801CD7D8(void) {}
