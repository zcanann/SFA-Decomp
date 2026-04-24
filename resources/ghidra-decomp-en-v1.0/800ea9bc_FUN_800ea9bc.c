// Function: FUN_800ea9bc
// Entry: 800ea9bc
// Size: 948 bytes

int FUN_800ea9bc(int param_1)

{
  char cVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  undefined4 uVar5;
  uint uVar6;
  int iVar7;
  float **ppfVar8;
  int iVar9;
  float fVar10;
  int iVar11;
  short *psVar12;
  undefined uVar13;
  float **local_18 [3];
  
  psVar12 = *(short **)(param_1 + 0xb8);
  *(undefined *)(psVar12 + 4) = 0;
  *(byte *)((int)psVar12 + 7) = *(byte *)((int)psVar12 + 7) & 0xfe;
  uVar5 = FUN_8002b9ec();
  if (*(char *)((int)psVar12 + 5) == '\0') {
    uVar13 = 0;
    if (((((*(byte *)(*(int *)(param_1 + 0x78) + (uint)*(byte *)(param_1 + 0xe4) * 5 + 4) & 0xf) ==
           6) && (uVar6 = FUN_80014b24(0), (uVar6 & 0x100) == 0)) &&
        ((*(byte *)(param_1 + 0xaf) & 1) != 0)) && (*(int *)(param_1 + 0xf8) == 0)) {
      *psVar12 = 0;
      FUN_80014b3c(0,0x100);
      uVar13 = 1;
    }
    *(undefined *)((int)psVar12 + 5) = uVar13;
    if (*(char *)((int)psVar12 + 5) != '\0') {
      *(byte *)((int)psVar12 + 7) = *(byte *)((int)psVar12 + 7) | 1;
      *(undefined *)(psVar12 + 3) = 1;
    }
    if (*(int *)(param_1 + 0xf8) == 0) {
      FUN_80035ea4(param_1);
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
      if ((*(byte *)((int)psVar12 + 7) & 2) == 0) {
        *(float *)(param_1 + 0x28) = -(FLOAT_803e06dc * FLOAT_803db414 - *(float *)(param_1 + 0x28))
        ;
        *(float *)(param_1 + 0x10) =
             *(float *)(param_1 + 0x28) * FLOAT_803db414 + *(float *)(param_1 + 0x10);
      }
      iVar7 = FUN_80065e50((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                           (double)*(float *)(param_1 + 0x14),param_1,local_18,0,1);
      fVar10 = 0.0;
      iVar11 = 0;
      ppfVar8 = local_18[0];
      iVar9 = iVar7;
      if (0 < iVar7) {
        do {
          if (*(char *)(*ppfVar8 + 5) != '\x0e') {
            fVar2 = **ppfVar8;
            if ((*(float *)(param_1 + 0x10) < fVar2) &&
               (fVar2 - FLOAT_803e06e0 < *(float *)(param_1 + 0x10))) {
              fVar10 = local_18[0][iVar11][4];
              *(float *)(param_1 + 0x10) = *local_18[0][iVar11];
              *(float *)(param_1 + 0x28) = FLOAT_803e06e4;
              break;
            }
          }
          ppfVar8 = ppfVar8 + 1;
          iVar11 = iVar11 + 1;
          iVar9 = iVar9 + -1;
        } while (iVar9 != 0);
      }
      fVar4 = FLOAT_803e06e8;
      fVar2 = FLOAT_803e06e4;
      iVar9 = 0;
      if (0 < iVar7) {
        do {
          fVar3 = *(float *)(param_1 + 0x10) - **(float **)((int)local_18[0] + iVar9);
          if (fVar3 < fVar2) {
            fVar3 = -fVar3;
          }
          if ((fVar3 < fVar4) &&
             (cVar1 = *(char *)(*(float **)((int)local_18[0] + iVar9) + 5),
             (int)(uint)*(byte *)(psVar12 + 4) < (int)cVar1)) {
            *(char *)(psVar12 + 4) = cVar1;
          }
          iVar9 = iVar9 + 4;
          iVar7 = iVar7 + -1;
        } while (iVar7 != 0);
      }
      if (fVar10 != 0.0) {
        iVar9 = *(int *)((int)fVar10 + 0x58);
        cVar1 = *(char *)(iVar9 + 0x10f);
        *(char *)(iVar9 + 0x10f) = cVar1 + '\x01';
        *(int *)(iVar9 + cVar1 * 4 + 0x100) = param_1;
      }
    }
  }
  else {
    FUN_80035e8c(param_1);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    uVar6 = FUN_80014e70(0);
    if ((uVar6 & 0x100) != 0) {
      if (((*(byte *)((int)psVar12 + 7) & 4) == 0) && (iVar9 = FUN_80295bf0(uVar5), iVar9 != 0)) {
        FUN_80014b3c(0,0x100);
        *(undefined *)(psVar12 + 3) = 0;
      }
      else {
        FUN_8000bb18(0,0x10a);
      }
    }
    if (*(int *)(param_1 + 0xf8) == 1) {
      *(undefined *)((int)psVar12 + 5) = 2;
    }
    if ((*(char *)((int)psVar12 + 5) == '\x02') && (*(int *)(param_1 + 0xf8) == 0)) {
      iVar9 = *(int *)(param_1 + 0xb8);
      *(undefined *)(iVar9 + 5) = 0;
      *(undefined *)(iVar9 + 6) = 0;
      if ((*(byte *)(iVar9 + 7) & 8) == 0) {
        *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803e06d8;
        FUN_800e8370(param_1);
        *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - FLOAT_803e06d8;
      }
    }
    if (*(char *)(psVar12 + 3) != '\0') {
      FUN_800378c4(uVar5,0x100008,param_1,(int)psVar12[1] << 0x10 | (int)*psVar12 & 0xffffU);
    }
  }
  return (int)*(char *)((int)psVar12 + 5);
}

