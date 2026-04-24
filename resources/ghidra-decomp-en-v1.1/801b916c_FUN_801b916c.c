// Function: FUN_801b916c
// Entry: 801b916c
// Size: 832 bytes

void FUN_801b916c(uint param_1)

{
  byte bVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  float *pfVar8;
  
  pfVar8 = *(float **)(param_1 + 0xb8);
  iVar4 = FUN_8002bac4();
  iVar7 = *(int *)(param_1 + 0x4c);
  bVar2 = false;
  iVar6 = 0;
  iVar3 = (int)*(char *)(*(int *)(param_1 + 0x58) + 0x10f);
  if (0 < iVar3) {
    do {
      if (*(int *)(*(int *)(param_1 + 0x58) + iVar6 + 0x100) == iVar4) {
        bVar2 = true;
        break;
      }
      iVar6 = iVar6 + 4;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  bVar1 = *(byte *)(pfVar8 + 1);
  if (bVar1 == 3) {
    *pfVar8 = *pfVar8 + FLOAT_803e57a8 * FLOAT_803dc074 +
                        FLOAT_803e57ac *
                        (float)((double)CONCAT44(0x43300000,
                                                 ((uint)(byte)((*pfVar8 < FLOAT_803e57a4) << 3) <<
                                                 0x1c) >> 0x1f ^ 0x80000000) - DOUBLE_803e57c0);
    if (FLOAT_803e57b0 < *pfVar8) {
      *pfVar8 = FLOAT_803e57b0;
    }
    *(float *)(param_1 + 0x10) = *pfVar8 * FLOAT_803dc074 + *(float *)(param_1 + 0x10);
    if (*(float *)(iVar7 + 0xc) < *(float *)(param_1 + 0x10)) {
      FUN_8000bb38(param_1,0x1f8);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar7 + 0xc);
      *(undefined *)(pfVar8 + 1) = 1;
      if (bVar2) {
        *(undefined *)((int)pfVar8 + 5) = 1;
        *(undefined *)((int)pfVar8 + 6) = 0;
      }
    }
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      FUN_8000b7dc(param_1,8);
      if (bVar2) {
        if ((*(char *)((int)pfVar8 + 6) != '\0') && (*(char *)((int)pfVar8 + 5) != '\0')) {
          FUN_8000bb38(param_1,0x113);
          *(undefined *)(pfVar8 + 1) = 4;
          *pfVar8 = FLOAT_803e57a4;
        }
      }
      else {
        *(undefined *)((int)pfVar8 + 6) = 1;
      }
      uVar5 = FUN_80020078((int)*(short *)(iVar7 + 0x20));
      if (uVar5 != 0) {
        FUN_8000bb38(param_1,0x113);
        *(undefined *)(pfVar8 + 1) = 4;
        *pfVar8 = FLOAT_803e57a4;
      }
    }
    else if (bVar1 != 0) {
      FUN_8000b7dc(param_1,8);
      if (*(char *)((int)pfVar8 + 5) == '\0') {
        uVar5 = FUN_80020078((int)*(short *)(iVar7 + 0x20));
        if (uVar5 == 0) {
          FUN_8000bb38(param_1,0x113);
          *(undefined *)(pfVar8 + 1) = 3;
          *pfVar8 = FLOAT_803e57a4;
          *(undefined *)((int)pfVar8 + 5) = 0;
          FUN_800201ac((int)*(short *)(iVar7 + 0x1e),0);
        }
      }
      else if (!bVar2) {
        FUN_8000bb38(param_1,0x113);
        *(undefined *)(pfVar8 + 1) = 3;
        *pfVar8 = FLOAT_803e57a4;
        *(undefined *)((int)pfVar8 + 5) = 0;
        FUN_800201ac((int)*(short *)(iVar7 + 0x1e),0);
      }
    }
  }
  else if (bVar1 < 5) {
    *pfVar8 = FLOAT_803e57b4 * FLOAT_803dc074 + *pfVar8;
    if (*pfVar8 < FLOAT_803e57b8) {
      *pfVar8 = FLOAT_803e57b8;
    }
    *(float *)(param_1 + 0x10) = *pfVar8 * FLOAT_803dc074 + *(float *)(param_1 + 0x10);
    if (*(float *)(param_1 + 0x10) < *(float *)(iVar7 + 0xc) - FLOAT_803e57bc) {
      FUN_8000bb38(param_1,0x1f8);
      *(float *)(param_1 + 0x10) = *(float *)(iVar7 + 0xc) - FLOAT_803e57bc;
      *(undefined *)(pfVar8 + 1) = 2;
      FUN_800201ac((int)*(short *)(iVar7 + 0x1e),1);
    }
    if ((*(char *)((int)pfVar8 + 5) == '\0') &&
       (uVar5 = FUN_80020078((int)*(short *)(iVar7 + 0x20)), uVar5 == 0)) {
      *(undefined *)(pfVar8 + 1) = 3;
      FUN_800201ac((int)*(short *)(iVar7 + 0x1e),0);
    }
  }
  return;
}

