#include "ghidra_import.h"
#include "main/dll/DR/DRcloudcage.h"
#include "main/dll/DR/DRhightop.h"

extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006818();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern undefined4 FUN_80006920();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_80006c88();
extern void gameTextShow(int p);
extern void doRumble(f32 strength);
extern void mtxRotateByVec3s(void *matrix, void *transform);
extern void Matrix_TransformPoint(void *matrix, double x, double y, double z, float *outX,
                                  float *outY, float *outZ);
extern f32 PSVECMag(void *vec);
extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
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
extern double SeekTwiceBeforeRead();
extern double FUN_80247f90();
extern undefined4 FUN_80293130();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();

extern undefined4 DAT_8032916c;
extern undefined4 DAT_803adcf4;
extern undefined4 DAT_803add04;
extern undefined4 DAT_803dc070;
extern u8 framesThisStep;
extern f32 oneOverTimeDelta;
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
extern undefined4 *gPartfxInterface;
extern f64 DOUBLE_803e6798;
extern f64 lbl_803E5B00;
extern f32 timeDelta;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803DCD30;
extern f32 lbl_803DCD40;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5AEC;
extern f32 lbl_803E5AF8;
extern f32 lbl_803E5B14;
extern f32 lbl_803E5B1C;
extern f32 lbl_803E5B20;
extern f32 lbl_803E5B2C;
extern f32 lbl_803E5B34;
extern f32 lbl_803E5B80;
extern f32 lbl_803E5B84;
extern f32 lbl_803E5B88;
extern f32 lbl_803E5B8C;
extern f32 lbl_803DC0D8;
extern void **gGameUIInterface;
extern void **gObjectTriggerInterface;
extern void PSVECScale(f32 *dst, f32 *src, f32 s);
extern void Sfx_KeepAliveLoopedObjectSound(uint obj, int sfxId);
extern void Sfx_StopObjectChannel(uint obj, int channel);
extern int Sfx_PlayFromObject(int obj, int sfxId);
extern f32 lbl_803E5BBC;
extern f32 lbl_803E5BC4;
extern f32 lbl_803E5BD8;
extern f32 lbl_803E5BDC;
extern f32 lbl_803E5BE0;
extern f32 lbl_803E5BE4;
extern f32 lbl_803E5BE8;
extern f32 lbl_803E5BEC;
extern f32 lbl_803E5BF0;
extern f32 lbl_803E5BF4;
extern f32 lbl_803E5BF8;
extern f32 lbl_803E5BFC;
extern f32 lbl_803E5C00;
extern f32 lbl_803E5C04;
extern f32 lbl_803E5C08;
extern f32 lbl_803E5C0C;
extern f32 lbl_803E5C10;
extern f32 lbl_803E5C14;
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
         (f32)(s32)(-iVar3);
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
 * Function: fn_801EAE4C
 * EN v1.0 Address: 0x801EAE4C
 * EN v1.0 Size: 648b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void fn_801EAE4C(short *param_9,int param_10)
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
      if (*(float *)(param_10 + 0x68) > lbl_803E6814) {
        gameTextShow(0x475);
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
 * Function: fn_801EB0D4
 * EN v1.0 Address: 0x801EB0D4
 * EN v1.0 Size: 608b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801EB0D4(uint param_1,int param_2)
{
  float fVar1;
  float fVar2;
  float v;
  uint uVar4;

  if ((*(byte *)(param_2 + 0x428) >> 5 & 1) != 0) {
    if (lbl_803E5AE8 <= *(float *)(param_2 + 0x4bc)) {
      v = (f32)(s32)(*(float *)(param_2 + 0x4c0) *
                     (timeDelta * PSVECMag((float *)(param_2 + 0x494))));
      *(float *)(param_2 + 0x4bc) =
           *(float *)(param_2 + 0x4bc) - (timeDelta * lbl_803DC0D8 + v);
      if (lbl_803E5AE8 != *(float *)(param_2 + 0x4c4)) {
        *(float *)(param_2 + 0x4bc) =
             lbl_803E5B14 * timeDelta + *(float *)(param_2 + 0x4bc);
        v = (f32)(s32)(lbl_803E5B14 * timeDelta);
        *(float *)(param_2 + 0x4c4) = *(float *)(param_2 + 0x4c4) - v;
        fVar2 = lbl_803E5AE8;
        fVar1 = *(float *)(param_2 + 0x4c4);
        if ((fVar2 <= fVar1) && (fVar2 = fVar1, lbl_803E5B80 < fVar1)) {
          fVar2 = lbl_803E5B80;
        }
        *(float *)(param_2 + 0x4c4) = fVar2;
        fVar2 = lbl_803E5AE8;
        fVar1 = *(float *)(param_2 + 0x4bc);
        if ((fVar2 <= fVar1) && (fVar2 = fVar1, *(float *)(param_2 + 0x4b8) < fVar1)) {
          fVar2 = *(float *)(param_2 + 0x4b8);
        }
        *(float *)(param_2 + 0x4bc) = fVar2;
      }
      if (*(float *)(param_2 + 0x4bc) < lbl_803E5B84) {
        Sfx_KeepAliveLoopedObjectSound(param_1,0x44e);
      }
      (*(void (**)(int))((char *)*gGameUIInterface + 0x5c))((s32)*(float *)(param_2 + 0x4bc));
    }
    else {
      Sfx_StopObjectChannel(param_1,0x7f);
      if (lbl_803E5B20 < *(float *)(param_2 + 0x464)) {
        uVar4 = randomGetRange(0,10);
        if (uVar4 == 0) {
          Sfx_PlayFromObject(0,0x117);
        }
        PSVECScale((float *)(param_2 + 0x464),(float *)(param_2 + 0x464),lbl_803E5B88);
        if ((*(byte *)(param_2 + 0x428) >> 7 & 1) != 0) {
          if (*(float *)(param_2 + 0x464) < lbl_803E5B20) {
            *(float *)(param_2 + 0x464) = lbl_803E5B20;
          }
        }
      }
      else {
        (*(void (**)(void))((char *)*gGameUIInterface + 0x60))();
        (*(void (**)(int, uint, int))((char *)*gObjectTriggerInterface + 0x48))
            (0,param_1,0xffffffff);
        fVar2 = lbl_803E5B8C;
        *(float *)(param_2 + 0x464) = lbl_803E5B8C;
        *(float *)(param_2 + 0x468) = fVar2;
        *(float *)(param_2 + 0x46c) = fVar2;
      }
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
 * Function: fn_801EB420
 * EN v1.0 Address: 0x801EB420
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x801EBA58
 * EN v1.1 Size: 532b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 fn_801EB420(short *param_1,undefined4 param_2,int param_3)
{
  typedef struct HightopMatrixSeed {
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 pad;
    f32 unused;
    f32 x;
    f32 y;
    f32 z;
  } HightopMatrixSeed;

  u8 triggerType;
  int i;
  int state;
  float matrix[16];
  HightopMatrixSeed transform;
  int intensity;
  double xSpeed;
  double ySpeed;
  double zSpeed;

  state = *(int *)(param_1 + 0x5c);
  *(void (**)(int *))(param_3 + 0xe8) = fn_801EB334;
  ObjHits_DisableObject((int)param_1);

  for (i = 0; i < (int)(uint)*(u8 *)(param_3 + 0x8b); i++) {
    triggerType = *(u8 *)(param_3 + i + 0x81);
    switch (triggerType) {
    case 2:
      if (param_1[0x23] != 0x16c && param_1[0x23] != 0x16f) {
        GameBit_Set(0x499, 1);
      }
      break;
    case 3:
      (**(code **)(*DAT_803dd6e8 + 0x60))();
      break;
    }
  }

  if (*(s8 *)(state + 0x421) == 2) {
    xSpeed = (double)(float)(oneOverTimeDelta *
                             (*(float *)(param_1 + 6) - *(float *)(state + 0x16c)));
    ySpeed = (double)(float)(oneOverTimeDelta *
                             (*(float *)(param_1 + 8) - *(float *)(state + 0x170)));
    zSpeed = (double)(float)(oneOverTimeDelta *
                             (*(float *)(param_1 + 10) - *(float *)(state + 0x174)));

    transform.unused = lbl_803E6784;
    transform.x = lbl_803E6780;
    transform.y = lbl_803E6780;
    transform.z = lbl_803E6780;
    transform.rotX = -*param_1;
    transform.rotY = 0;
    transform.rotZ = 0;
    mtxRotateByVec3s(matrix, &transform);
    Matrix_TransformPoint(matrix, xSpeed, ySpeed, zSpeed, (float *)(state + 0x494),
                          (float *)(state + 0x498), (float *)(state + 0x49c));

    *(s8 *)(state + 0x460) = *(s8 *)(state + 0x460) + (framesThisStep << 3);
    if (*(s8 *)(state + 0x460) > 0x46) {
      *(s8 *)(state + 0x460) = 0x46;
    }

    intensity = (int)(lbl_803E6838 * -*(float *)(state + 0x430));
    fn_801EA240((double)*(float *)(state + 0x49c), (int)param_1, state, intensity,
                state + 0x461, 4);
  }

  *(u8 *)(state + 0x428) &= 0xf7;
  return 0;
}

/*
 * --INFO--
 *
 * Function: fn_801EB634
 * EN v1.0 Address: 0x801EB634
 * EN v1.0 Size: 780b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801EB634(int param_1,int param_2)
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
           (f32)(s32)uStack_1c;
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
      while (uVar5 != 0) {
        uVar5 = uVar5 - 1;
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x553,0,2,0xffffffff,0);
      }
      *(float *)(param_2 + 0x3e4) = lbl_803E678C;
      *(float *)(param_2 + 0x3e0) = lbl_803E6784;
      if ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) {
        *(float *)(param_2 + 0x3e4) =
             (f32)(s32)(DAT_803dcd3c);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: fn_801EB940
 * EN v1.0 Address: 0x801EB940
 * EN v1.0 Size: 1056b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801EB940(short *param_1,int param_2)
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
      *(float *)(param_2 + 0x58c) = lbl_803E6854 * (f32)(s32)((int)param_1[1]);
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
  *(short *)(param_2 + 0x588) =
       (short)(int)(lbl_803E6860 * lbl_803DC074 + (f32)(s32)((int)*(short *)(param_2 + 0x588)));
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

/*
 * --INFO--
 *
 * Function: fn_801EBD60
 * EN v1.0 Address: 0x801EBD60
 * EN v1.0 Size: 1100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fn_801EBD60(int param_1,int param_2)
{
  typedef struct HightopPartfxTransform {
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    s16 pad;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
  } HightopPartfxTransform;

  u8 mode;
  s16 motionFrame;
  f32 speed;
  f32 target558;
  f32 target534;
  f32 target530;
  f32 target548;
  f32 target54c;
  f32 target540;
  f32 target544;
  HightopPartfxTransform effect;

  speed = sqrtf(*(f32 *)(param_2 + 0x49c) * *(f32 *)(param_2 + 0x49c) +
                *(f32 *)(param_2 + 0x494) * *(f32 *)(param_2 + 0x494) +
                *(f32 *)(param_2 + 0x498) * *(f32 *)(param_2 + 0x498));
  *(f32 *)(param_2 + 0x43c) -= timeDelta;
  target558 = *(f32 *)(param_2 + 0x43c);
  if (target558 < lbl_803E5AE8) {
    target558 = lbl_803E5AE8;
  } else if (target558 > lbl_803E5B1C) {
    target558 = lbl_803E5B1C;
  }
  *(f32 *)(param_2 + 0x43c) = target558;

  if ((*(u8 *)(param_2 + 0x428) & 0x80) != 0) {
    target558 = *(f32 *)(param_2 + 0x578);
    target534 = *(f32 *)(param_2 + 0x574);
    target530 = *(f32 *)(param_2 + 0x56c);
    target548 = *(f32 *)(param_2 + 0x57c);
    target54c = *(f32 *)(param_2 + 0x580);
    target540 = lbl_803E5B20;
    target544 = lbl_803E5AF8;
  } else {
    mode = *(u8 *)(param_2 + 0x4b4);
    if (mode == 9) {
      target558 = lbl_803E5BEC;
      target534 = lbl_803E5BF4;
      target530 = lbl_803E5C00;
      target548 = lbl_803E5C04;
      target54c = lbl_803E5C08;
      target540 = lbl_803E5B20;
      target544 = lbl_803E5C0C;
      if (speed > lbl_803E5B34) {
        effect.scale = lbl_803E5AEC;
        effect.rotZ = 0;
        effect.rotY = 0;
        effect.rotX = 0;
        effect.x = *(f32 *)(param_1 + 0xc);
        effect.y = lbl_803E5C10 + *(f32 *)(param_1 + 0x10);
        effect.z = *(f32 *)(param_1 + 0x14);
        (**(code **)(*gPartfxInterface + 8))(param_1,0x80a,&effect,1,0xffffffff,0);
      }
    } else if (mode == 0xd) {
      target558 = lbl_803E5BD8;
      target534 = lbl_803E5BDC;
      target530 = lbl_803E5B88;
      target548 = lbl_803E5BE0;
      target54c = lbl_803E5BE4;
      target540 = lbl_803E5BE8;
      target544 = lbl_803E5AF8;
      if (((*(u8 *)(param_2 + 0x428) >> 1 & 1) == 0) &&
          (*(f32 *)(param_2 + 0x43c) <= lbl_803E5AE8)) {
        *(f32 *)(param_2 + 0x43c) = (f32)(s32)randomGetRange(5,10);
        if (PSVECMag((void *)(param_1 + 0x24)) > lbl_803E5BC4) {
          doRumble((f32)(s32)randomGetRange(1,3));
        }
      }
      if (speed > lbl_803E5BEC) {
        (**(code **)(*gPartfxInterface + 8))(param_1,0x80b,0,2,0xffffffff,0);
      }
    } else {
      target558 = lbl_803E5BF0;
      target534 = lbl_803E5BF4;
      target530 = lbl_803E5BF8;
      target548 = lbl_803E5BFC;
      target54c = lbl_803E5BE4;
      target540 = lbl_803E5BE8;
      target544 = lbl_803E5AF8;
    }

    motionFrame = *(s16 *)(param_2 + 0x44c);
    if (((motionFrame >= 0x1e) && (motionFrame <= 0x3c)) ||
        ((motionFrame >= 0x12c) && (motionFrame <= 0x14a))) {
      target558 *= lbl_803E5B20;
      target534 *= lbl_803E5B2C;
      target530 += lbl_803E5B20;
      if (target530 < lbl_803E5AE8) {
        target530 = lbl_803E5AE8;
      } else if (target530 > lbl_803E5B88) {
        target530 = lbl_803E5B88;
      }
    }
  }

  if ((*(u8 *)(param_2 + 0x428) >> 1 & 1) != 0) {
    target558 = lbl_803E5AF8;
  }
  if (target558 < lbl_803E5BD8) {
    target558 = lbl_803E5BD8;
  } else if (target558 > lbl_803E5AEC) {
    target558 = lbl_803E5AEC;
  }

  *(f32 *)(param_2 + 0x558) += timeDelta * (lbl_803E5C14 * (target558 - *(f32 *)(param_2 + 0x558)));
  *(f32 *)(param_2 + 0x534) += timeDelta * (lbl_803E5BBC * (target534 - *(f32 *)(param_2 + 0x534)));
  *(f32 *)(param_2 + 0x530) += timeDelta * (lbl_803E5C14 * (target530 - *(f32 *)(param_2 + 0x530)));
  *(f32 *)(param_2 + 0x548) += timeDelta * (lbl_803E5B20 * (target548 - *(f32 *)(param_2 + 0x548)));
  *(f32 *)(param_2 + 0x54c) += timeDelta * (lbl_803E5B20 * (target54c - *(f32 *)(param_2 + 0x54c)));
  *(f32 *)(param_2 + 0x540) += timeDelta * (lbl_803E5B20 * (target540 - *(f32 *)(param_2 + 0x540)));
  *(f32 *)(param_2 + 0x544) += timeDelta * (lbl_803E5B20 * (target544 - *(f32 *)(param_2 + 0x544)));
}

extern undefined4 *gPathControlInterface;
extern f32 lbl_803E5AE8;
extern f32 lbl_803E5B9C;
extern f32 lbl_803E5B74;

typedef struct HightopFlags {
    u8 resetLatch : 1;
    u8 flags : 7;
} HightopFlags;

#pragma scheduling off
#pragma peephole off
void fn_801EB334(int *obj) {
    int *state = *(int **)((char *)obj + 0xb8);
    if ((u32)((*(u8 *)((char *)state + 0x428) >> 1) & 1) == 0) {
        s16 sv;
        f32 fz = lbl_803E5AE8;
        *(f32 *)((char *)state + 0x494) = fz;
        *(f32 *)((char *)state + 0x498) = fz;
        *(f32 *)((char *)state + 0x49c) = lbl_803E5B9C;
        ((HightopFlags *)((char *)state + 0x428))->resetLatch = 0;
        *(f32 *)((char *)state + 0x424) = fz;
        sv = *(s16 *)obj;
        *(s16 *)((char *)state + 0x40e) = sv;
        *(s16 *)((char *)state + 0x40c) = sv;
        *(f32 *)((char *)state + 0x430) = lbl_803E5B74;
    }
    ObjHits_EnableObject(obj);
    (*(void (**)(int *, char *))((char *)*gPathControlInterface + 32))(obj, (char *)state + 0x178);
    *(f32 *)((char *)*(int **)((char *)obj + 0x54) + 0x10) = *(f32 *)((char *)obj + 0xc);
    *(f32 *)((char *)*(int **)((char *)obj + 0x54) + 0x14) = *(f32 *)((char *)obj + 0x10);
    *(f32 *)((char *)*(int **)((char *)obj + 0x54) + 0x18) = *(f32 *)((char *)obj + 0x14);
    *(f32 *)((char *)*(int **)((char *)obj + 0x54) + 0x1c) = *(f32 *)((char *)obj + 0x18);
    *(f32 *)((char *)*(int **)((char *)obj + 0x54) + 0x20) = *(f32 *)((char *)obj + 0x1c);
    *(f32 *)((char *)*(int **)((char *)obj + 0x54) + 0x24) = *(f32 *)((char *)obj + 0x20);
}
#pragma peephole reset
#pragma scheduling reset
