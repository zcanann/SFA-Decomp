#include "ghidra_import.h"
#include "main/dll/DR/DRbarrelplace.h"

extern bool FUN_800067f0();
extern undefined4 FUN_80006818();
extern undefined4 FUN_80006824();
extern undefined4 FUN_80006920();
extern undefined4 FUN_800069bc();
extern undefined4 FUN_80006b94();
extern undefined4 FUN_80017778();
extern undefined4 FUN_800723a0();
extern int FUN_8007f3c8();
extern undefined4 FUN_801ebd94();
extern double FUN_80247f54();

extern undefined4 DAT_8032919c;
extern f64 DOUBLE_803e6798;
extern f32 lbl_803DC078;
extern f32 lbl_803E6780;
extern f32 lbl_803E6784;
extern f32 lbl_803E6790;
extern f32 lbl_803E67C0;
extern f32 lbl_803E6820;
extern f32 lbl_803E6824;
extern f32 lbl_803E683C;
extern f32 lbl_803E6854;
extern f32 lbl_803E685C;
extern f32 lbl_803E6898;
extern f32 lbl_803E68E4;

/*
 * --INFO--
 *
 * Function: FUN_801ed428
 * EN v1.0 Address: 0x801ED428
 * EN v1.0 Size: 1140b
 * EN v1.1 Address: 0x801ED5CC
 * EN v1.1 Size: 1172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ed428(short *param_1)
{
  int iVar1;
  float fVar2;
  float fVar3;
  short sVar4;
  float fVar5;
  bool bVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  float afStack_68 [2];
  undefined4 local_60;
  uint uStack_5c;
  longlong local_58;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  longlong local_40;
  
  iVar8 = *(int *)(param_1 + 0x5c);
  iVar7 = **(int **)(param_1 + 0x2a);
  if (*(int *)(param_1 + 0x60) == 0) {
    if (*(char *)(iVar8 + 0x421) == '\x02') {
      FUN_801ebd94(param_1,iVar8);
      *(short *)(iVar8 + 0x41c) = param_1[1];
      *(short *)(iVar8 + 0x41e) = param_1[2];
      dVar9 = DOUBLE_803e6798;
      uStack_5c = (int)param_1[1] ^ 0x80000000;
      local_60 = 0x43300000;
      iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e6798) +
                   *(float *)(iVar8 + 0x594));
      local_58 = (longlong)iVar1;
      param_1[1] = (short)iVar1;
      uStack_4c = (int)param_1[2] ^ 0x80000000;
      local_50 = 0x43300000;
      uStack_44 = *(uint *)(iVar8 + 0x410) ^ 0x80000000;
      local_48 = 0x43300000;
      iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack_4c) - dVar9) +
                   (float)((double)CONCAT44(0x43300000,uStack_44) - dVar9) +
                   *(float *)(iVar8 + 0x598));
      local_40 = (longlong)iVar1;
      param_1[2] = (short)iVar1;
    }
    if ((*(char *)(iVar8 + 0x3d9) == '\x04') || (*(char *)(iVar8 + 0x3d6) != '\0')) {
      *(float *)(param_1 + 0x14) =
           lbl_803DC078 * (*(float *)(param_1 + 8) - *(float *)(param_1 + 0x42));
      *(undefined4 *)(iVar8 + 0x498) = *(undefined4 *)(param_1 + 0x14);
    }
    if (((*(char *)(iVar8 + 0x3d6) != '\0') ||
        (((*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 8) != 0 &&
         (iVar7 = FUN_8007f3c8((int *)&DAT_8032919c,10,(int)*(short *)(iVar7 + 0x46)), iVar7 == -1))
        )) || ((*(int *)(iVar8 + 0x42c) != 0 && (*(float *)(iVar8 + 0x3e0) <= lbl_803E6784)))) {
      dVar9 = FUN_80247f54((float *)(param_1 + 0x12));
      if ((double)lbl_803E6784 < dVar9) {
        if ((*(byte *)(iVar8 + 0x428) >> 1 & 1) == 0) {
          FUN_80006b94((double)(float)((double)lbl_803E685C * dVar9));
        }
        *(float *)(iVar8 + 0x430) = *(float *)(iVar8 + 0x430) * lbl_803E6854;
        if ((param_1[0x23] == 0x72) || (param_1[0x23] == 0x38c)) {
          iVar7 = (int)((double)lbl_803E68E4 * dVar9);
          local_40 = (longlong)iVar7;
          if (iVar7 < 0x51) {
            if (iVar7 < 0x1e) {
              iVar7 = 0x1e;
            }
          }
          else {
            iVar7 = 0x50;
          }
          bVar6 = FUN_800067f0((int)param_1,0x20);
          if (!bVar6) {
            FUN_80006824((uint)param_1,0x3bc);
            FUN_80006818((double)lbl_803E67C0,(int)param_1,0x3bc,(byte)iVar7);
          }
        }
      }
      if (((*(byte *)(iVar8 + 0x428) >> 1 & 1) == 0) && ((double)lbl_803E685C < dVar9)) {
        FUN_800069bc();
        FUN_80006920((double)(float)(dVar9 * (double)lbl_803E6790));
      }
      fVar2 = lbl_803E6820;
      if (*(int *)(iVar8 + 0x42c) == 0) {
        *(float *)(param_1 + 0x12) =
             lbl_803E6820 *
             lbl_803DC078 * (*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40));
        *(float *)(param_1 + 0x16) =
             fVar2 * lbl_803DC078 * (*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44));
      }
      else {
        dVar9 = (double)lbl_803E6898;
        FUN_800723a0();
        sVar4 = *(short *)(*(int *)(iVar8 + 0x42c) + 0x46);
        if (((sVar4 == 0x38d) || (sVar4 == 0x38e)) || (sVar4 == 0x4d4)) {
          dVar9 = (double)lbl_803E6820;
        }
        *(float *)(param_1 + 0x12) =
             (float)(dVar9 * (double)(lbl_803DC078 *
                                     (*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40))));
        *(float *)(param_1 + 0x16) =
             (float)(dVar9 * (double)(lbl_803DC078 *
                                     (*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44))));
      }
      FUN_80017778((double)*(float *)(param_1 + 0x12),(double)lbl_803E6780,
                   (double)*(float *)(param_1 + 0x16),(float *)(iVar8 + 300),
                   (float *)(iVar8 + 0x494),afStack_68,(float *)(iVar8 + 0x49c));
    }
    fVar2 = *(float *)(iVar8 + 0x494);
    fVar3 = *(float *)(iVar8 + 0x47c);
    fVar5 = -fVar3;
    if ((fVar5 <= fVar2) && (fVar5 = fVar2, fVar3 < fVar2)) {
      fVar5 = fVar3;
    }
    *(float *)(iVar8 + 0x494) = fVar5;
    if ((*(float *)(iVar8 + 0x494) < lbl_803E6824) && (lbl_803E683C < *(float *)(iVar8 + 0x494))
       ) {
      *(float *)(iVar8 + 0x494) = lbl_803E6780;
    }
    fVar2 = *(float *)(iVar8 + 0x498);
    fVar3 = -*(float *)(iVar8 + 0x480);
    if ((fVar3 <= fVar2) && (fVar3 = fVar2, lbl_803E6784 < fVar2)) {
      fVar3 = lbl_803E6784;
    }
    *(float *)(iVar8 + 0x498) = fVar3;
    if ((*(float *)(iVar8 + 0x498) < lbl_803E6824) && (lbl_803E683C < *(float *)(iVar8 + 0x498))
       ) {
      *(float *)(iVar8 + 0x498) = lbl_803E6780;
    }
    fVar2 = *(float *)(iVar8 + 0x49c);
    fVar3 = *(float *)(iVar8 + 0x484);
    fVar5 = -fVar3;
    if ((fVar5 <= fVar2) && (fVar5 = fVar2, fVar3 < fVar2)) {
      fVar5 = fVar3;
    }
    *(float *)(iVar8 + 0x49c) = fVar5;
    if ((*(float *)(iVar8 + 0x49c) < lbl_803E6824) && (lbl_803E683C < *(float *)(iVar8 + 0x49c))
       ) {
      *(float *)(iVar8 + 0x49c) = lbl_803E6780;
    }
    *(undefined4 *)(iVar8 + 0x16c) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(iVar8 + 0x170) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(iVar8 + 0x174) = *(undefined4 *)(param_1 + 10);
    *(undefined4 *)(iVar8 + 0x42c) = 0;
  }
  return;
}
