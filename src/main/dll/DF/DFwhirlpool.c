#include "ghidra_import.h"
#include "main/dll/DF/DFwhirlpool.h"

extern int FUN_80021884();
extern double FUN_80293900();

extern f64 DOUBLE_803e5a88;
extern f32 FLOAT_803e5a94;
extern f32 FLOAT_803e5ab8;
extern f32 FLOAT_803e5abc;

/*
 * --INFO--
 *
 * Function: FUN_801c21a4
 * EN v1.0 Address: 0x801C21A4
 * EN v1.0 Size: 700b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801c21a4(int param_1)
{
  double dVar1;
  float fVar2;
  short sVar4;
  int iVar3;
  int iVar5;
  int iVar6;
  int iVar7;
  int *piVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  
  if ((*(byte *)(*(int *)(param_1 + 0x4c) + 0x18) & 1) == 0) {
    iVar6 = **(int **)(param_1 + 0xb8);
    if (iVar6 == 0) {
      return 0;
    }
    piVar8 = *(int **)(iVar6 + 0xb8);
  }
  else {
    piVar8 = *(int **)(param_1 + 0xb8);
    iVar6 = param_1;
    param_1 = *piVar8;
  }
  if ((piVar8[0xb] != 0) && (param_1 != 0)) {
    dVar12 = (double)(*(float *)(param_1 + 0xc) - *(float *)(iVar6 + 0xc));
    dVar11 = (double)(*(float *)(param_1 + 0x10) - *(float *)(iVar6 + 0x10));
    dVar10 = (double)(*(float *)(param_1 + 0x14) - *(float *)(iVar6 + 0x14));
    iVar5 = FUN_80021884();
    sVar4 = (short)iVar5;
    if (0x8000 < sVar4) {
      sVar4 = sVar4 + 1;
    }
    if (sVar4 < -0x8000) {
      sVar4 = sVar4 + -1;
    }
    *(short *)(piVar8 + 6) = sVar4;
    dVar9 = FUN_80293900((double)(float)(dVar10 * dVar10 +
                                        (double)(float)(dVar12 * dVar12 +
                                                       (double)(float)(dVar11 * dVar11))));
    iVar5 = piVar8[0xb];
    dVar1 = (double)CONCAT44(0x43300000,*(byte *)(iVar5 + 8) - 1 ^ 0x80000000) - DOUBLE_803e5a88;
    iVar7 = *(int *)(iVar5 + 4);
    *(float *)(iVar5 + 0x38) = FLOAT_803e5ab8;
    iVar5 = 0;
    while( true ) {
      iVar3 = *(byte *)((int *)piVar8[0xb] + 2) - 1;
      if (iVar3 <= iVar5) break;
      *(float *)(iVar7 + 0xc) = (float)(dVar9 / (double)(float)dVar1);
      iVar5 = iVar5 + 1;
      iVar7 = iVar7 + 0x24;
    }
    iVar3 = iVar3 * 0x34;
    *(float *)(*(int *)piVar8[0xb] + iVar3) = (float)dVar12;
    *(float *)(*(int *)piVar8[0xb] + iVar3 + 4) = (float)dVar11;
    *(float *)(*(int *)piVar8[0xb] + iVar3 + 8) = (float)dVar10;
    piVar8[1] = *(int *)(iVar6 + 0xc);
    piVar8[3] = *(int *)(iVar6 + 0x14);
    piVar8[2] = *(int *)(param_1 + 0xc);
    piVar8[4] = *(int *)(param_1 + 0x14);
    fVar2 = (float)piVar8[1];
    if ((float)piVar8[2] < fVar2) {
      piVar8[1] = piVar8[2];
      piVar8[2] = (int)fVar2;
    }
    fVar2 = (float)piVar8[3];
    if ((float)piVar8[4] < fVar2) {
      piVar8[3] = piVar8[4];
      piVar8[4] = (int)fVar2;
    }
    if ((float)piVar8[5] != FLOAT_803e5a94) {
      fVar2 = (float)piVar8[5] - *(float *)(iVar6 + 0x10);
      iVar6 = 0;
      for (iVar5 = 0; iVar5 < (int)(*(byte *)((int *)piVar8[0xb] + 2) - 1); iVar5 = iVar5 + 1) {
        iVar7 = *(int *)piVar8[0xb];
        if (*(float *)(iVar7 + iVar6 + 4) < fVar2) {
          *(float *)(iVar7 + iVar6 + 4) = fVar2;
        }
        iVar6 = iVar6 + 0x34;
      }
    }
    fVar2 = FLOAT_803e5abc;
    piVar8[1] = (int)((float)piVar8[1] - FLOAT_803e5abc);
    piVar8[3] = (int)((float)piVar8[3] - fVar2);
    piVar8[2] = (int)((float)piVar8[2] + fVar2);
    piVar8[4] = (int)((float)piVar8[4] + fVar2);
  }
  return 0;
}
