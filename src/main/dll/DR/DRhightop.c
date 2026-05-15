#include "ghidra_import.h"
#include "main/dll/DR/DRhightop.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006818();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80006920();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_80006c88();
extern uint GameBit_Get(int eventId);
extern uint FUN_80017730();
extern undefined4 FUN_8001774c();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017778();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern ushort ObjHits_IsObjectEnabled();
extern int ObjHits_GetPriorityHit();
extern undefined4 FUN_80053c20();
extern int FUN_8005b398();
extern undefined4 FUN_800632e8();
extern int FUN_8007f3c8();
extern undefined4 FUN_80081124();
extern undefined4 FUN_801ea854();
extern double FUN_801eac78();
extern undefined4 FUN_801ecdec();
extern undefined4 FUN_801ed004();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double FUN_80247f54();
extern double FUN_80247f90();
extern undefined4 FUN_80293130();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_8032916c;
extern undefined4 DAT_803adcf4;
extern undefined4 DAT_803add04;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcd24;
extern undefined4 DAT_803dcd34;
extern undefined4 DAT_803dcd38;
extern undefined4 DAT_803dcd3c;
extern undefined4 DAT_803dcd44;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd6ec;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd728;
extern f64 DOUBLE_803e6798;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803DCD30;
extern f32 lbl_803DCD40;
extern f32 lbl_803E6780;
extern f32 lbl_803E6784;
extern f32 lbl_803E678C;
extern f32 lbl_803E67A0;
extern f32 lbl_803E67A8;
extern f32 lbl_803E67AC;
extern f32 lbl_803E67B8;
extern f32 lbl_803E67D8;
extern f32 lbl_803E6800;
extern f32 lbl_803E6804;
extern f32 lbl_803E6808;
extern f32 lbl_803E680C;
extern f32 lbl_803E6810;
extern f32 lbl_803E6814;
extern f32 lbl_803E6818;
extern f32 lbl_803E681C;
extern f32 lbl_803E6820;
extern f32 lbl_803E6824;
extern f32 lbl_803E6834;
extern f32 lbl_803E6838;
extern f32 lbl_803E6840;
extern f32 lbl_803E6844;
extern f32 lbl_803E6848;
extern f32 lbl_803E684C;
extern f32 lbl_803E6850;
extern f32 lbl_803E6854;
extern f32 lbl_803E6858;
extern f32 lbl_803E685C;
extern f32 lbl_803E6860;
extern f32 lbl_803E6864;

/*
 * --INFO--
 *
 * Function: FUN_801eae4c
 * EN v1.0 Address: 0x801EAE4C
 * EN v1.0 Size: 628b
 * EN v1.1 Address: 0x801EAE8C
 * EN v1.1 Size: 620b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801eae4c(int param_1,int param_2)
{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  
  fVar1 = *(float *)(param_1 + 0xc) - *(float *)(param_2 + 0xc);
  fVar2 = *(float *)(param_1 + 0x14) - *(float *)(param_2 + 0x14);
  dVar8 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
  dVar8 = (double)(float)((double)lbl_803E6800 - dVar8);
  dVar9 = (double)lbl_803E6780;
  if ((double)*(float *)(param_2 + 0x3e4) != dVar9) {
    dVar7 = (double)(float)(dVar8 - (double)lbl_803E67A8);
    if ((dVar9 <= dVar7) && (dVar9 = dVar7, (double)lbl_803E67A0 < dVar7)) {
      dVar9 = (double)lbl_803E67A0;
    }
    dVar8 = (double)(float)(dVar8 + dVar9);
  }
  if (dVar8 < (double)lbl_803E6780) {
    dVar8 = (double)lbl_803E6780;
  }
  iVar4 = (**(code **)(*DAT_803dd6ec + 0x18))
                    (dVar8,param_2,param_2 + 0x28,*(undefined *)(param_2 + 0x5d),1,0);
  (**(code **)(*DAT_803dd6ec + 0x14))(param_1,param_2 + 0x28);
  (**(code **)(*DAT_803dd6ec + 0x2c))(param_2 + 0x28);
  if (iVar4 == 0) {
    uVar6 = FUN_80017730();
    iVar4 = (uVar6 & 0xffff) - (uint)*(ushort *)(param_2 + 0x40c);
    if (0x8000 < iVar4) {
      iVar4 = iVar4 + -0xffff;
    }
    if (iVar4 < -0x8000) {
      iVar4 = iVar4 + 0xffff;
    }
    iVar3 = iVar4 / 0xb6 + (iVar4 >> 0x1f);
    iVar3 = iVar3 - (iVar3 >> 0x1f);
    if (iVar3 < -0x41) {
      iVar3 = -0x41;
    }
    else if (0x41 < iVar3) {
      iVar3 = 0x41;
    }
    *(float *)(param_2 + 0x45c) =
         (float)((double)CONCAT44(0x43300000,-iVar3 ^ 0x80000000) - DOUBLE_803e6798);
    *(undefined2 *)(param_2 + 0x44c) = 0;
    *(float *)(param_2 + 0x45c) = *(float *)(param_2 + 0x45c) / lbl_803E6804;
    fVar1 = *(float *)(param_2 + 0x45c);
    fVar2 = lbl_803E6808;
    if ((lbl_803E6808 <= fVar1) && (fVar2 = fVar1, lbl_803E6784 < fVar1)) {
      fVar2 = lbl_803E6784;
    }
    *(float *)(param_2 + 0x45c) = fVar2;
    dVar8 = FUN_801eac78(param_1,param_2);
    if ((((double)*(float *)(param_2 + 0x49c) < -dVar8) || (0x2aaa < iVar4)) || (iVar4 < -0x2aaa)) {
      *(undefined4 *)(param_2 + 0x458) = 0;
    }
    else if (-dVar8 < (double)*(float *)(param_2 + 0x49c)) {
      *(undefined4 *)(param_2 + 0x458) = 0x100;
    }
    uVar5 = 1;
  }
  else {
    *(float *)(param_2 + 0x45c) = lbl_803E6780;
    uVar5 = 0;
  }
  return uVar5;
}

/*
 * --INFO--
 *
 * Function: FUN_801eb0c0
 * EN v1.0 Address: 0x801EB0C0
 * EN v1.0 Size: 876b
 * EN v1.1 Address: 0x801EB0F8
 * EN v1.1 Size: 908b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_801eb0c0(undefined2 *param_1,int param_2)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  undefined2 uVar4;
  double dVar5;
  float local_18 [3];
  
  if ((*(byte *)(param_2 + 0x428) >> 3 & 1) == 0) {
    uVar2 = 0;
  }
  else {
    iVar3 = FUN_8005b398((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8));
    fVar1 = lbl_803E6780;
    if (iVar3 < 0) {
      dVar5 = FUN_801eac78((int)param_1,param_2);
      iVar3 = (**(code **)(*DAT_803dd6ec + 0x18))
                        ((double)(float)((double)lbl_803DC074 * dVar5),param_2,param_2 + 0x28,
                         *(undefined *)(param_2 + 0x5d),1,0);
      (**(code **)(*DAT_803dd6ec + 0x14))(param_1,param_2 + 0x28);
      (**(code **)(*DAT_803dd6ec + 0x2c))(param_2 + 0x28);
      if (iVar3 == 0) {
        iVar3 = FUN_80017730();
        *param_1 = (short)iVar3;
        *(undefined4 *)(param_1 + 6) = *(undefined4 *)(param_2 + 0xc);
        *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_2 + 0x10);
        *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_2 + 0x14);
        (**(code **)(*DAT_803dd728 + 0x20))(param_1,param_2 + 0x178);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x10) = *(undefined4 *)(param_1 + 6);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x14) = *(undefined4 *)(param_1 + 8);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x18) = *(undefined4 *)(param_1 + 10);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x1c) = *(undefined4 *)(param_1 + 0xc);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x20) = *(undefined4 *)(param_1 + 0xe);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x24) = *(undefined4 *)(param_1 + 0x10);
        *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xfe;
        uVar2 = 0;
      }
      else {
        uVar2 = 0;
      }
    }
    else if ((*(byte *)(param_2 + 0x428) & 1) == 0) {
      *(float *)(param_2 + 0x494) = lbl_803E6780;
      *(float *)(param_2 + 0x498) = fVar1;
      dVar5 = FUN_801eac78((int)param_1,param_2);
      *(float *)(param_2 + 0x49c) = (float)-dVar5;
      iVar3 = (**(code **)(*DAT_803dd6ec + 0x18))
                        ((double)(-*(float *)(param_2 + 0x49c) * lbl_803DC074),param_2,
                         param_2 + 0x28,*(undefined *)(param_2 + 0x5d),1,0);
      (**(code **)(*DAT_803dd6ec + 0x14))(param_1,param_2 + 0x28);
      (**(code **)(*DAT_803dd6ec + 0x2c))(param_2 + 0x28);
      if (iVar3 == 0) {
        FUN_801ecdec(param_1,param_2);
        iVar3 = FUN_80017730();
        uVar4 = (undefined2)iVar3;
        *param_1 = uVar4;
        *(undefined2 *)(param_2 + 0x40e) = uVar4;
        *(undefined2 *)(param_2 + 0x40c) = uVar4;
        *(float *)(param_2 + 0x430) = lbl_803E680C;
        *(undefined4 *)(param_1 + 6) = *(undefined4 *)(param_2 + 0xc);
        *(undefined4 *)(param_1 + 8) = *(undefined4 *)(param_2 + 0x10);
        *(undefined4 *)(param_1 + 10) = *(undefined4 *)(param_2 + 0x14);
        (**(code **)(*DAT_803dd728 + 0x20))(param_1,param_2 + 0x178);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x10) = *(undefined4 *)(param_1 + 6);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x14) = *(undefined4 *)(param_1 + 8);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x18) = *(undefined4 *)(param_1 + 10);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x1c) = *(undefined4 *)(param_1 + 0xc);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x20) = *(undefined4 *)(param_1 + 0xe);
        *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x24) = *(undefined4 *)(param_1 + 0x10);
        if (*(char *)(param_2 + 0x434) == '\0') {
          FUN_800632e8((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                       (double)*(float *)(param_1 + 10),param_1,local_18,0);
          *(float *)(param_1 + 8) = *(float *)(param_1 + 8) - local_18[0];
          *(float *)(param_1 + 8) = *(float *)(param_1 + 8) + lbl_803E6810;
        }
        *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xfe | 1;
        uVar2 = 0;
      }
      else {
        uVar2 = 0;
      }
    }
    else {
      uVar2 = FUN_801eae4c((int)param_1,param_2);
      uVar2 = (-uVar2 | uVar2) >> 0x1f;
    }
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801eb42c
 * EN v1.0 Address: 0x801EB42C
 * EN v1.0 Size: 732b
 * EN v1.1 Address: 0x801EB484
 * EN v1.1 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801eb42c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)
{
  float fVar1;
  float fVar2;
  uint uVar3;
  short sVar4;
  undefined uVar5;
  
  if ((*(byte *)(param_10 + 0x428) >> 3 & 1) == 0) {
    *(undefined4 *)(param_10 + 0x38) = 0xffffffff;
    *(undefined4 *)(param_10 + 0x3c) = 0xffffffff;
    *(undefined4 *)(param_10 + 0x40) = 0xffffffff;
    *(undefined4 *)(param_10 + 0x44) = 0;
    DAT_803dcd24 = -1;
    uVar3 = GameBit_Get((int)**(short **)(param_10 + 0x60));
    if (uVar3 != 0) {
      *(byte *)(param_10 + 0x428) = *(byte *)(param_10 + 0x428) & 0xf7 | 8;
    }
    if ((*(byte *)(param_10 + 0x428) >> 3 & 1) != 0) {
      if ((*(byte *)(param_10 + 0x428) >> 1 & 1) == 0) {
        (**(code **)(*DAT_803dd6ec + 0x10))(param_9,param_10 + 0x28,*(undefined *)(param_10 + 0x5c))
        ;
      }
      else {
        FUN_801ed004(param_9);
      }
      (**(code **)(*DAT_803dd6ec + 0x28))(param_10 + 0x28);
    }
  }
  else {
    if ((*(byte *)(param_10 + 0x428) >> 1 & 1) == 0) {
      sVar4 = (**(code **)(*DAT_803dd6ec + 0x14))(param_9,param_10 + 0x28);
      sVar4 = *param_9 - sVar4;
      if (0x8000 < sVar4) {
        sVar4 = sVar4 + 1;
      }
      if (sVar4 < -0x8000) {
        sVar4 = sVar4 + -1;
      }
      uVar3 = (uint)sVar4;
      if ((int)uVar3 < 0) {
        uVar3 = -uVar3;
      }
      fVar1 = lbl_803DC074;
      if ((int)(((int)(uVar3 ^ (int)DAT_803dcd44) >> 1) - ((uVar3 ^ (int)DAT_803dcd44) & uVar3)) < 0
         ) {
        fVar1 = -lbl_803DC074;
      }
      *(float *)(param_10 + 0x68) = *(float *)(param_10 + 0x68) + fVar1;
      fVar1 = *(float *)(param_10 + 0x68);
      fVar2 = lbl_803E6780;
      if ((lbl_803E6780 <= fVar1) && (fVar2 = fVar1, lbl_803E6800 < fVar1)) {
        fVar2 = lbl_803E6800;
      }
      *(float *)(param_10 + 0x68) = fVar2;
      if ((double)lbl_803E6814 < (double)*(float *)(param_10 + 0x68)) {
        FUN_80006c88((double)*(float *)(param_10 + 0x68),param_2,param_3,param_4,param_5,param_6,
                     param_7,param_8,0x475);
      }
      (**(code **)(*DAT_803dd6ec + 0x2c))(param_10 + 0x28);
      uVar5 = (**(code **)(*DAT_803dd6ec + 0x34))(param_10 + 0x28);
      *(undefined *)(param_10 + 0x422) = uVar5;
      if ((*(char *)(param_10 + 0x422) == '\x01') && (DAT_803dcd24 == -1)) {
        DAT_803dcd24 = -1;
      }
      else {
        DAT_803dcd24 = (int)*(char *)(param_10 + 0x422);
        DAT_803add04 = *(undefined4 *)(param_10 + 0x44);
        DAT_803adcf4 = *(undefined4 *)(param_10 + 0x34);
      }
    }
    uVar3 = GameBit_Get((int)*(short *)(*(int *)(param_10 + 0x60) + 2));
    if (uVar3 != 0) {
      *(byte *)(param_10 + 0x428) = *(byte *)(param_10 + 0x428) & 0xf7;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801eb708
 * EN v1.0 Address: 0x801EB708
 * EN v1.0 Size: 648b
 * EN v1.1 Address: 0x801EB70C
 * EN v1.1 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801eb708(uint param_1,int param_2)
{
  float fVar1;
  float fVar2;
  double dVar3;
  uint uVar4;
  double dVar5;
  double dVar6;
  undefined8 local_28;
  undefined8 local_20;
  
  if ((*(byte *)(param_2 + 0x428) >> 5 & 1) != 0) {
    if (*(float *)(param_2 + 0x4bc) < lbl_803E6780) {
      FUN_8000680c(param_1,0x7f);
      if (*(float *)(param_2 + 0x464) <= lbl_803E67B8) {
        (**(code **)(*DAT_803dd6e8 + 0x60))();
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
        fVar2 = lbl_803E6824;
        *(float *)(param_2 + 0x464) = lbl_803E6824;
        *(float *)(param_2 + 0x468) = fVar2;
        *(float *)(param_2 + 0x46c) = fVar2;
      }
      else {
        uVar4 = randomGetRange(0,10);
        if (uVar4 == 0) {
          FUN_80006824(0,0x117);
        }
        FUN_80247edc((double)lbl_803E6820,(float *)(param_2 + 0x464),(float *)(param_2 + 0x464));
        if ((*(char *)(param_2 + 0x428) < '\0') && (*(float *)(param_2 + 0x464) < lbl_803E67B8)) {
          *(float *)(param_2 + 0x464) = lbl_803E67B8;
        }
      }
    }
    else {
      dVar6 = (double)lbl_803DC074;
      dVar5 = FUN_80247f54((float *)(param_2 + 0x494));
      dVar3 = DOUBLE_803e6798;
      local_20 = (double)CONCAT44(0x43300000,
                                  (int)(*(float *)(param_2 + 0x4c0) * (float)(dVar6 * dVar5)) ^
                                  0x80000000);
      *(float *)(param_2 + 0x4bc) =
           *(float *)(param_2 + 0x4bc) -
           (float)(dVar6 * (double)lbl_803DCD40 + (double)(float)(local_20 - DOUBLE_803e6798));
      fVar1 = lbl_803E67AC;
      fVar2 = lbl_803E6780;
      if (lbl_803E6780 != *(float *)(param_2 + 0x4c4)) {
        *(float *)(param_2 + 0x4bc) = lbl_803E67AC * lbl_803DC074 + *(float *)(param_2 + 0x4bc);
        local_28 = (double)CONCAT44(0x43300000,(int)(fVar1 * lbl_803DC074) ^ 0x80000000);
        *(float *)(param_2 + 0x4c4) = *(float *)(param_2 + 0x4c4) - (float)(local_28 - dVar3);
        fVar1 = *(float *)(param_2 + 0x4c4);
        if ((fVar2 <= fVar1) && (fVar2 = fVar1, lbl_803E6818 < fVar1)) {
          fVar2 = lbl_803E6818;
        }
        *(float *)(param_2 + 0x4c4) = fVar2;
        fVar2 = *(float *)(param_2 + 0x4bc);
        fVar1 = lbl_803E6780;
        if ((lbl_803E6780 <= fVar2) && (fVar1 = fVar2, *(float *)(param_2 + 0x4b8) < fVar2)) {
          fVar1 = *(float *)(param_2 + 0x4b8);
        }
        *(float *)(param_2 + 0x4bc) = fVar1;
      }
      if (*(float *)(param_2 + 0x4bc) < lbl_803E681C) {
        FUN_800068c4(param_1,0x44e);
      }
      (**(code **)(*DAT_803dd6e8 + 0x5c))((int)*(float *)(param_2 + 0x4bc));
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801eb990
 * EN v1.0 Address: 0x801EB990
 * EN v1.0 Size: 232b
 * EN v1.1 Address: 0x801EB96C
 * EN v1.1 Size: 236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801eb990(undefined2 *param_1)
{
  undefined2 uVar1;
  float fVar2;
  int iVar3;
  
  fVar2 = lbl_803E6780;
  iVar3 = *(int *)(param_1 + 0x5c);
  if ((*(byte *)(iVar3 + 0x428) >> 1 & 1) == 0) {
    *(float *)(iVar3 + 0x494) = lbl_803E6780;
    *(float *)(iVar3 + 0x498) = fVar2;
    *(float *)(iVar3 + 0x49c) = lbl_803E6834;
    *(byte *)(iVar3 + 0x428) = *(byte *)(iVar3 + 0x428) & 0x7f;
    *(float *)(iVar3 + 0x424) = fVar2;
    uVar1 = *param_1;
    *(undefined2 *)(iVar3 + 0x40e) = uVar1;
    *(undefined2 *)(iVar3 + 0x40c) = uVar1;
    *(float *)(iVar3 + 0x430) = lbl_803E680C;
  }
  ObjHits_EnableObject((int)param_1);
  (**(code **)(*DAT_803dd728 + 0x20))(param_1,iVar3 + 0x178);
  *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x10) = *(undefined4 *)(param_1 + 6);
  *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x14) = *(undefined4 *)(param_1 + 8);
  *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x18) = *(undefined4 *)(param_1 + 10);
  *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x1c) = *(undefined4 *)(param_1 + 0xc);
  *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x20) = *(undefined4 *)(param_1 + 0xe);
  *(undefined4 *)(*(int *)(param_1 + 0x2a) + 0x24) = *(undefined4 *)(param_1 + 0x10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801eba78
 * EN v1.0 Address: 0x801EBA78
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801EBA58
 * EN v1.1 Size: 532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801eba78(short *param_1,undefined4 param_2,int param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_801eba80
 * EN v1.0 Address: 0x801EBA80
 * EN v1.0 Size: 788b
 * EN v1.1 Address: 0x801EBC6C
 * EN v1.1 Size: 780b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801eba80(int param_1,int param_2)
{
  bool bVar1;
  ushort uVar3;
  int iVar2;
  int iVar4;
  uint uVar5;
  double dVar6;
  int local_38;
  uint uStack_34;
  int iStack_30;
  float afStack_2c [3];
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  iVar4 = *(int *)(param_1 + 0x54);
  uVar3 = ObjHits_IsObjectEnabled(param_1);
  if (uVar3 != 0) {
    if ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) {
      ObjHits_SetHitVolumeSlot(param_1,0x15,1,0);
    }
    else {
      ObjHits_ClearHitVolumes(param_1);
      ObjHits_SyncObjectPositionIfDirty(param_1);
    }
    iVar2 = ObjHits_GetPriorityHit(param_1,&local_38,&iStack_30,&uStack_34);
    if (iVar2 == 0x15) {
      if (*(float *)(param_2 + 0x3e4) == lbl_803E6780) {
        FUN_80247ef8((float *)(param_1 + 0x24),afStack_2c);
        dVar6 = FUN_80247f90(afStack_2c,(float *)(local_38 + 0x24));
        FUN_80247edc((double)(float)(dVar6 * (double)*(float *)(param_2 + 0x4ac) +
                                    (double)lbl_803E6784),(float *)(param_2 + 0x494),
                     (float *)(param_2 + 0x494));
        *(float *)(param_2 + 0x498) = *(float *)(param_2 + 0x498) * lbl_803E6840;
        *(float *)(param_2 + 0x3e4) = lbl_803E678C;
        *(float *)(param_2 + 0x3e0) = lbl_803E6784;
      }
    }
    else if (iVar2 < 0x15) {
      if ((iVar2 == 0xd) && ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0)) {
        *(int *)(param_2 + 0x42c) = local_38;
        *(float *)(param_2 + 0x3e0) = lbl_803E6784;
      }
    }
    else if ((iVar2 == 0x1d) && ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0)) {
      FUN_80053c20((double)lbl_803E6844,1);
      dVar6 = DOUBLE_803e6798;
      uStack_1c = DAT_803dcd38 ^ 0x80000000;
      local_20 = 0x43300000;
      *(float *)(param_2 + 0x3e4) =
           (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e6798);
      *(float *)(param_2 + 0x3e0) = lbl_803DCD30;
      uStack_14 = DAT_803dcd34 ^ 0x80000000;
      local_18 = 0x43300000;
      *(float *)(param_2 + 0x4c4) = (float)((double)CONCAT44(0x43300000,uStack_14) - dVar6);
    }
    local_38 = *(int *)(iVar4 + 0x50);
    if (((local_38 != 0) &&
        (*(int *)(param_2 + 0x42c) = local_38, *(float *)(param_2 + 0x3e4) == lbl_803E6780)) &&
       (iVar4 = FUN_8007f3c8((int *)&DAT_8032916c,0xc,(int)*(short *)(local_38 + 0x46)), iVar4 != -1
       )) {
      FUN_80081124((double)lbl_803E6848,param_1);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x551,0,4,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x552,0,4,0xffffffff,0);
      (**(code **)(*DAT_803dd708 + 8))(param_1,0x554,0,4,0xffffffff,0);
      uVar5 = 0x32 / DAT_803dc070;
      while (bVar1 = uVar5 != 0, uVar5 = uVar5 - 1, bVar1) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x553,0,2,0xffffffff,0);
      }
      *(float *)(param_2 + 0x3e4) = lbl_803E678C;
      *(float *)(param_2 + 0x3e0) = lbl_803E6784;
      if ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) {
        *(float *)(param_2 + 0x3e4) =
             (float)((double)CONCAT44(0x43300000,DAT_803dcd3c ^ 0x80000000) - DOUBLE_803e6798);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801ebd94
 * EN v1.0 Address: 0x801EBD94
 * EN v1.0 Size: 1104b
 * EN v1.1 Address: 0x801EBF78
 * EN v1.1 Size: 1056b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ebd94(short *param_1,int param_2)
{
  float fVar1;
  float fVar2;
  short sVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  undefined8 local_48;
  undefined8 local_40;
  
  iVar5 = param_2 + 0x178;
  (**(code **)(*DAT_803dd728 + 0x10))((double)lbl_803DC074,param_1,iVar5);
  (**(code **)(*DAT_803dd728 + 0x14))(param_1,iVar5);
  (**(code **)(*DAT_803dd728 + 0x18))((double)lbl_803DC074,param_1,iVar5);
  fVar1 = lbl_803E6854;
  dVar6 = DOUBLE_803e6798;
  iVar5 = 2;
  if (*(char *)(param_2 + 0x3d9) == '\0') {
    *(float *)(param_2 + 0x424) = *(float *)(param_2 + 0x424) + lbl_803DC074;
    fVar1 = *(float *)(param_2 + 0x424);
    fVar2 = lbl_803E6780;
    if ((lbl_803E6780 <= fVar1) && (fVar2 = fVar1, lbl_803E684C < fVar1)) {
      fVar2 = lbl_803E684C;
    }
    *(float *)(param_2 + 0x424) = fVar2;
    if (lbl_803E6850 <= *(float *)(param_2 + 0x424)) {
      if (-1 < *(char *)(param_2 + 0x428)) {
        *(float *)(param_2 + 0x584) = lbl_803E6780;
      }
      *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0x7f | 0x80;
    }
  }
  else {
    if (*(char *)(param_2 + 0x428) < '\0') {
      iVar5 = 0;
      local_48 = (double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000);
      *(float *)(param_2 + 0x58c) = lbl_803E6854 * (float)(local_48 - DOUBLE_803e6798);
      local_40 = (double)CONCAT44(0x43300000,(int)param_1[2] ^ 0x80000000);
      *(float *)(param_2 + 0x590) = fVar1 * (float)(local_40 - dVar6);
      *(undefined2 *)(param_2 + 0x588) = 0;
      *(undefined2 *)(param_2 + 0x58a) = 0;
      if ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) {
        FUN_80006b94((double)(*(float *)(param_2 + 0x424) * fVar1));
        FUN_800069bc();
        FUN_80006920((double)(*(float *)(param_2 + 0x424) / lbl_803E6858));
        FUN_80006824((uint)param_1,0x3bc);
        fVar1 = lbl_803E685C * *(float *)(param_2 + 0x424);
        if (lbl_803E67D8 < fVar1) {
          fVar1 = lbl_803E67D8;
        }
        FUN_80006818((double)lbl_803E67B8,(int)param_1,0x3bc,(byte)(int)fVar1);
      }
    }
    *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0x7f;
    *(float *)(param_2 + 0x424) = lbl_803E6780;
    *(undefined *)(param_2 + 0x4b4) = *(undefined *)(param_2 + 0x230);
  }
  fVar1 = lbl_803E6860;
  dVar6 = DOUBLE_803e6798;
  local_40 = (double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x588) ^ 0x80000000);
  *(short *)(param_2 + 0x588) =
       (short)(int)(lbl_803E6860 * lbl_803DC074 + (float)(local_40 - DOUBLE_803e6798));
  *(short *)(param_2 + 0x58a) =
       (short)(int)(fVar1 * lbl_803DC074 +
                   (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 0x58a) ^ 0x80000000
                                           ) - dVar6));
  dVar6 = (double)FUN_80293130((double)lbl_803E6864,(double)lbl_803DC074);
  *(float *)(param_2 + 0x58c) = (float)((double)*(float *)(param_2 + 0x58c) * dVar6);
  dVar6 = (double)FUN_80293130((double)lbl_803E6864,(double)lbl_803DC074);
  *(float *)(param_2 + 0x590) = (float)((double)*(float *)(param_2 + 0x590) * dVar6);
  dVar6 = (double)FUN_80293f90();
  *(float *)(param_2 + 0x594) = (float)((double)*(float *)(param_2 + 0x58c) * dVar6);
  dVar6 = (double)FUN_80293f90();
  *(float *)(param_2 + 0x598) = (float)((double)*(float *)(param_2 + 0x590) * dVar6);
  iVar4 = (int)*param_1 - (uint)*(ushort *)(param_2 + 0x40e);
  if (0x8000 < iVar4) {
    iVar4 = iVar4 + -0xffff;
  }
  if (iVar4 < -0x8000) {
    iVar4 = iVar4 + 0xffff;
  }
  *(short *)(param_2 + 0x40e) = *(short *)(param_2 + 0x40e) + (short)iVar4;
  *(short *)(param_2 + 0x40c) = *(short *)(param_2 + 0x40c) + (short)iVar4;
  param_1[1] = param_1[1] + (short)((int)*(short *)(param_2 + 0x310) >> iVar5);
  param_1[2] = param_1[2] + (short)((int)*(short *)(param_2 + 0x312) >> iVar5);
  sVar3 = param_1[1];
  if (sVar3 < -0x2000) {
    sVar3 = -0x2000;
  }
  else if (0x2000 < sVar3) {
    sVar3 = 0x2000;
  }
  param_1[1] = sVar3;
  sVar3 = param_1[2];
  if (sVar3 < -0x2000) {
    sVar3 = -0x2000;
  }
  else if (0x2000 < sVar3) {
    sVar3 = 0x2000;
  }
  param_1[2] = sVar3;
  return;
}
