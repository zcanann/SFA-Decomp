// Function: FUN_801f1c84
// Entry: 801f1c84
// Size: 624 bytes

void FUN_801f1c84(int param_1)

{
  char cVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  undefined4 uVar5;
  undefined uVar9;
  int iVar6;
  float *pfVar7;
  uint uVar8;
  int iVar10;
  float fVar11;
  int iVar12;
  short *psVar13;
  int local_18 [3];
  
  psVar13 = *(short **)(param_1 + 0xb8);
  uVar5 = FUN_8002b9ec();
  if (*(char *)((int)psVar13 + 5) == '\0') {
    uVar9 = 0;
    if (((*(byte *)(param_1 + 0xaf) & 1) != 0) && (*(int *)(param_1 + 0xf8) == 0)) {
      *psVar13 = 0;
      psVar13[1] = 0x28;
      FUN_80014b3c(0,0x100);
      uVar9 = 1;
    }
    *(undefined *)((int)psVar13 + 5) = uVar9;
    if (*(char *)((int)psVar13 + 5) != '\0') {
      *(undefined *)(psVar13 + 3) = 1;
    }
    if (*(int *)(param_1 + 0xf8) == 0) {
      FUN_80035f20(param_1);
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      *(float *)(param_1 + 0x28) = -(FLOAT_803e5d84 * FLOAT_803db414 - *(float *)(param_1 + 0x28));
      *(float *)(param_1 + 0x10) =
           *(float *)(param_1 + 0x28) * FLOAT_803db414 + *(float *)(param_1 + 0x10);
      iVar6 = FUN_80065e50((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                           (double)*(float *)(param_1 + 0x14),param_1,local_18,0,1);
      fVar4 = FLOAT_803e5d8c;
      fVar3 = FLOAT_803e5d88;
      fVar11 = 0.0;
      iVar12 = 0;
      iVar10 = 0;
      if (0 < iVar6) {
        do {
          pfVar7 = *(float **)(local_18[0] + iVar10);
          if (*(char *)(pfVar7 + 5) != '\x0e') {
            fVar2 = *pfVar7;
            if ((*(float *)(param_1 + 0x10) < fVar2) &&
               ((fVar2 - fVar3 < *(float *)(param_1 + 0x10) || (iVar12 == 0)))) {
              fVar11 = pfVar7[4];
              *(float *)(param_1 + 0x10) = fVar2;
              *(float *)(param_1 + 0x28) = fVar4;
            }
          }
          iVar10 = iVar10 + 4;
          iVar12 = iVar12 + 1;
          iVar6 = iVar6 + -1;
        } while (iVar6 != 0);
      }
      if (fVar11 != 0.0) {
        iVar6 = *(int *)((int)fVar11 + 0x58);
        cVar1 = *(char *)(iVar6 + 0x10f);
        *(char *)(iVar6 + 0x10f) = cVar1 + '\x01';
        *(int *)(iVar6 + cVar1 * 4 + 0x100) = param_1;
      }
    }
  }
  else {
    FUN_80035f00(param_1);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    uVar8 = FUN_80014e70(0);
    if ((uVar8 & 0x100) != 0) {
      *(undefined *)(psVar13 + 3) = 0;
      FUN_80014b3c(0,0x100);
    }
    if (*(int *)(param_1 + 0xf8) == 1) {
      *(undefined *)((int)psVar13 + 5) = 2;
    }
    if ((*(char *)((int)psVar13 + 5) == '\x02') && (*(int *)(param_1 + 0xf8) == 0)) {
      *(undefined *)((int)psVar13 + 5) = 0;
      *(undefined *)(psVar13 + 3) = 0;
    }
    if (*(char *)(psVar13 + 3) != '\0') {
      FUN_800378c4(uVar5,0x100008,param_1,(int)psVar13[1] << 0x10 | (int)*psVar13 & 0xffffU);
    }
  }
  return;
}

