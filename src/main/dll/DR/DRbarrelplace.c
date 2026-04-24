#include "ghidra_import.h"
#include "main/dll/DR/DRbarrelplace.h"

extern bool FUN_8000b598();
extern undefined4 FUN_8000b9bc();
extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000e69c();
extern undefined4 FUN_8000faf8();
extern undefined4 FUN_80014acc();
extern undefined4 FUN_80022790();
extern undefined4 FUN_8007d858();
extern int FUN_80080100();
extern undefined4 FUN_801ebf78();
extern double FUN_80247f54();

extern undefined4 DAT_8032919c;
extern f64 DOUBLE_803e6798;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803e6780;
extern f32 FLOAT_803e6784;
extern f32 FLOAT_803e6790;
extern f32 FLOAT_803e67c0;
extern f32 FLOAT_803e6820;
extern f32 FLOAT_803e6824;
extern f32 FLOAT_803e683c;
extern f32 FLOAT_803e6854;
extern f32 FLOAT_803e685c;
extern f32 FLOAT_803e6898;
extern f32 FLOAT_803e68e4;

/*
 * --INFO--
 *
 * Function: FUN_801ed5cc
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801ED5CC
 * EN v1.1 Size: 1172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ed5cc(short *param_1)
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
      FUN_801ebf78(param_1,iVar8);
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
           FLOAT_803dc078 * (*(float *)(param_1 + 8) - *(float *)(param_1 + 0x42));
      *(undefined4 *)(iVar8 + 0x498) = *(undefined4 *)(param_1 + 0x14);
    }
    if (((*(char *)(iVar8 + 0x3d6) != '\0') ||
        (((*(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 8) != 0 &&
         (iVar7 = FUN_80080100((int *)&DAT_8032919c,10,(int)*(short *)(iVar7 + 0x46)), iVar7 == -1))
        )) || ((*(int *)(iVar8 + 0x42c) != 0 && (*(float *)(iVar8 + 0x3e0) <= FLOAT_803e6784)))) {
      dVar9 = FUN_80247f54((float *)(param_1 + 0x12));
      if ((double)FLOAT_803e6784 < dVar9) {
        if ((*(byte *)(iVar8 + 0x428) >> 1 & 1) == 0) {
          FUN_80014acc((double)(float)((double)FLOAT_803e685c * dVar9));
        }
        *(float *)(iVar8 + 0x430) = *(float *)(iVar8 + 0x430) * FLOAT_803e6854;
        if ((param_1[0x23] == 0x72) || (param_1[0x23] == 0x38c)) {
          iVar7 = (int)((double)FLOAT_803e68e4 * dVar9);
          local_40 = (longlong)iVar7;
          if (iVar7 < 0x51) {
            if (iVar7 < 0x1e) {
              iVar7 = 0x1e;
            }
          }
          else {
            iVar7 = 0x50;
          }
          bVar6 = FUN_8000b598((int)param_1,0x20);
          if (!bVar6) {
            FUN_8000bb38((uint)param_1,0x3bc);
            FUN_8000b9bc((double)FLOAT_803e67c0,(int)param_1,0x3bc,(byte)iVar7);
          }
        }
      }
      if (((*(byte *)(iVar8 + 0x428) >> 1 & 1) == 0) && ((double)FLOAT_803e685c < dVar9)) {
        FUN_8000faf8();
        FUN_8000e69c((double)(float)(dVar9 * (double)FLOAT_803e6790));
      }
      fVar2 = FLOAT_803e6820;
      if (*(int *)(iVar8 + 0x42c) == 0) {
        *(float *)(param_1 + 0x12) =
             FLOAT_803e6820 *
             FLOAT_803dc078 * (*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40));
        *(float *)(param_1 + 0x16) =
             fVar2 * FLOAT_803dc078 * (*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44));
      }
      else {
        dVar9 = (double)FLOAT_803e6898;
        FUN_8007d858();
        sVar4 = *(short *)(*(int *)(iVar8 + 0x42c) + 0x46);
        if (((sVar4 == 0x38d) || (sVar4 == 0x38e)) || (sVar4 == 0x4d4)) {
          dVar9 = (double)FLOAT_803e6820;
        }
        *(float *)(param_1 + 0x12) =
             (float)(dVar9 * (double)(FLOAT_803dc078 *
                                     (*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40))));
        *(float *)(param_1 + 0x16) =
             (float)(dVar9 * (double)(FLOAT_803dc078 *
                                     (*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44))));
      }
      FUN_80022790((double)*(float *)(param_1 + 0x12),(double)FLOAT_803e6780,
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
    if ((*(float *)(iVar8 + 0x494) < FLOAT_803e6824) && (FLOAT_803e683c < *(float *)(iVar8 + 0x494))
       ) {
      *(float *)(iVar8 + 0x494) = FLOAT_803e6780;
    }
    fVar2 = *(float *)(iVar8 + 0x498);
    fVar3 = -*(float *)(iVar8 + 0x480);
    if ((fVar3 <= fVar2) && (fVar3 = fVar2, FLOAT_803e6784 < fVar2)) {
      fVar3 = FLOAT_803e6784;
    }
    *(float *)(iVar8 + 0x498) = fVar3;
    if ((*(float *)(iVar8 + 0x498) < FLOAT_803e6824) && (FLOAT_803e683c < *(float *)(iVar8 + 0x498))
       ) {
      *(float *)(iVar8 + 0x498) = FLOAT_803e6780;
    }
    fVar2 = *(float *)(iVar8 + 0x49c);
    fVar3 = *(float *)(iVar8 + 0x484);
    fVar5 = -fVar3;
    if ((fVar5 <= fVar2) && (fVar5 = fVar2, fVar3 < fVar2)) {
      fVar5 = fVar3;
    }
    *(float *)(iVar8 + 0x49c) = fVar5;
    if ((*(float *)(iVar8 + 0x49c) < FLOAT_803e6824) && (FLOAT_803e683c < *(float *)(iVar8 + 0x49c))
       ) {
      *(float *)(iVar8 + 0x49c) = FLOAT_803e6780;
    }
    *(undefined4 *)(iVar8 + 0x16c) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(iVar8 + 0x170) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(iVar8 + 0x174) = *(undefined4 *)(param_1 + 10);
    *(undefined4 *)(iVar8 + 0x42c) = 0;
  }
  return;
}
