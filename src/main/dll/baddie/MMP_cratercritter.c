#include "ghidra_import.h"
#include "main/dll/baddie/MMP_cratercritter.h"

extern double FUN_80021730();
extern undefined4 FUN_80021b8c();
extern double FUN_80293900();

extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803e306c;
extern f32 FLOAT_803e3084;
extern f32 FLOAT_803e30ac;
extern f32 FLOAT_803e30b0;
extern f32 FLOAT_803e30cc;
extern f32 FLOAT_803e3118;
extern f32 FLOAT_803e311c;

/*
 * --INFO--
 *
 * Function: FUN_8013d92c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8013D92C
 * EN v1.1 Size: 844b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013d92c(double param_1,short *param_2,int param_3,float *param_4,char param_5)
{
  float fVar1;
  float fVar2;
  int iVar3;
  float *pfVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  ushort local_58 [4];
  float local_50;
  float local_4c;
  float local_48;
  
  fVar1 = *(float *)(param_3 + 0x14);
  fVar2 = FLOAT_803e30b0;
  while( true ) {
    dVar5 = (double)fVar1;
    if (dVar5 <= (double)FLOAT_803e306c) break;
    fVar2 = (float)(dVar5 * (double)FLOAT_803dc074 + (double)fVar2);
    fVar1 = (float)(dVar5 + (double)(float)((double)FLOAT_803e30ac * (double)FLOAT_803dc074));
  }
  dVar6 = (double)(float)(param_1 + (double)fVar2);
  dVar8 = (double)(float)(dVar6 * dVar6);
  dVar5 = FUN_80021730(param_4,(float *)(param_2 + 0xc));
  if (dVar8 <= dVar5) {
    if (param_5 != '\0') {
      local_50 = *param_4 - *(float *)(param_2 + 0xc);
      local_4c = param_4[1] - *(float *)(param_2 + 0xe);
      local_48 = param_4[2] - *(float *)(param_2 + 0x10);
      local_58[0] = -*param_2;
      local_58[1] = 0;
      local_58[2] = 0;
      FUN_80021b8c(local_58,&local_50);
      if (FLOAT_803e306c < local_48) {
        fVar1 = FLOAT_803e30ac * FLOAT_803dc074 + *(float *)(param_3 + 0x14);
        if (fVar1 < FLOAT_803e306c) {
          fVar1 = FLOAT_803e306c;
        }
        *(float *)(param_3 + 0x14) = fVar1;
        return;
      }
    }
    if ((*(uint *)(param_3 + 0x54) & 0x10000000) == 0) {
      dVar6 = (double)((float)((double)FLOAT_803e3118 + dVar6) *
                      (float)((double)FLOAT_803e3118 + dVar6));
      iVar3 = *(int *)(param_2 + 0x5c);
      pfVar4 = *(float **)(iVar3 + 0x28);
      fVar1 = FLOAT_803e306c;
      if (pfVar4 == *(float **)(iVar3 + 0x6f0)) {
        fVar1 = *(float *)(iVar3 + 0x6f4) - *(float *)(param_2 + 0xc);
        fVar2 = *(float *)(iVar3 + 0x6fc) - *(float *)(param_2 + 0x10);
        dVar8 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
        dVar7 = (double)(float)((double)FLOAT_803dc078 * dVar8);
        dVar8 = FUN_80293900((double)((*pfVar4 - *(float *)(param_2 + 0xc)) *
                                      (*pfVar4 - *(float *)(param_2 + 0xc)) +
                                     (pfVar4[2] - *(float *)(param_2 + 0x10)) *
                                     (pfVar4[2] - *(float *)(param_2 + 0x10))));
        fVar1 = (float)((double)(float)((double)FLOAT_803dc078 * dVar8) - dVar7);
      }
      if ((dVar6 <= dVar5) || (fVar1 <= FLOAT_803e306c)) {
        if ((*(uint *)(param_3 + 0x54) & 0x100000) == 0) {
          fVar1 = FLOAT_803e30b0 * FLOAT_803dc074 + *(float *)(param_3 + 0x14);
          if (FLOAT_803e311c < fVar1) {
            fVar1 = FLOAT_803e311c;
          }
          *(float *)(param_3 + 0x14) = fVar1;
        }
        else {
          *(float *)(param_3 + 0x14) = FLOAT_803e30cc * FLOAT_803dc074 + *(float *)(param_3 + 0x14);
          if (FLOAT_803e311c < *(float *)(param_3 + 0x14)) {
            *(float *)(param_3 + 0x14) = FLOAT_803e311c;
          }
        }
      }
      else {
        fVar2 = *(float *)(param_3 + 0x14);
        if (fVar2 <= fVar1) {
          if (fVar1 <= FLOAT_803e311c) {
            fVar2 = FLOAT_803e30b0 * FLOAT_803dc074 + fVar2;
            if (fVar1 < fVar2) {
              fVar2 = fVar1;
            }
            *(float *)(param_3 + 0x14) = fVar2;
          }
          else {
            fVar2 = FLOAT_803e30b0 * FLOAT_803dc074 + fVar2;
            if (FLOAT_803e311c < fVar2) {
              fVar2 = FLOAT_803e311c;
            }
            *(float *)(param_3 + 0x14) = fVar2;
          }
        }
        else {
          fVar2 = FLOAT_803e30ac * FLOAT_803dc074 + fVar2;
          if (fVar2 < fVar1) {
            fVar2 = fVar1;
          }
          *(float *)(param_3 + 0x14) = fVar2;
        }
      }
    }
    else {
      *(float *)(param_3 + 0x14) = FLOAT_803e3084 * FLOAT_803dc074 + *(float *)(param_3 + 0x14);
      if (*(float *)(param_3 + 0x14) < FLOAT_803e306c) {
        *(float *)(param_3 + 0x14) = FLOAT_803e306c;
      }
    }
  }
  else {
    fVar1 = FLOAT_803e30ac * FLOAT_803dc074 + *(float *)(param_3 + 0x14);
    if (fVar1 < FLOAT_803e306c) {
      fVar1 = FLOAT_803e306c;
    }
    *(float *)(param_3 + 0x14) = fVar1;
  }
  return;
}
