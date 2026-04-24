// Function: FUN_801b8bb8
// Entry: 801b8bb8
// Size: 832 bytes

void FUN_801b8bb8(int param_1)

{
  byte bVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  float *pfVar7;
  
  pfVar7 = *(float **)(param_1 + 0xb8);
  iVar4 = FUN_8002b9ec();
  iVar6 = *(int *)(param_1 + 0x4c);
  bVar2 = false;
  iVar5 = 0;
  iVar3 = (int)*(char *)(*(int *)(param_1 + 0x58) + 0x10f);
  if (0 < iVar3) {
    do {
      if (*(int *)(*(int *)(param_1 + 0x58) + iVar5 + 0x100) == iVar4) {
        bVar2 = true;
        break;
      }
      iVar5 = iVar5 + 4;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  bVar1 = *(byte *)(pfVar7 + 1);
  if (bVar1 == 3) {
    *pfVar7 = *pfVar7 + FLOAT_803e4b10 * FLOAT_803db414 +
                        FLOAT_803e4b14 *
                        (float)((double)CONCAT44(0x43300000,
                                                 ((uint)(byte)((*pfVar7 < FLOAT_803e4b0c) << 3) <<
                                                 0x1c) >> 0x1f ^ 0x80000000) - DOUBLE_803e4b28);
    if (FLOAT_803e4b18 < *pfVar7) {
      *pfVar7 = FLOAT_803e4b18;
    }
    *(float *)(param_1 + 0x10) = *pfVar7 * FLOAT_803db414 + *(float *)(param_1 + 0x10);
    if (*(float *)(iVar6 + 0xc) < *(float *)(param_1 + 0x10)) {
      FUN_8000bb18(param_1,0x1f8);
      *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar6 + 0xc);
      *(undefined *)(pfVar7 + 1) = 1;
      if (bVar2) {
        *(undefined *)((int)pfVar7 + 5) = 1;
        *(undefined *)((int)pfVar7 + 6) = 0;
      }
    }
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      FUN_8000b7bc(param_1,8);
      if (bVar2) {
        if ((*(char *)((int)pfVar7 + 6) != '\0') && (*(char *)((int)pfVar7 + 5) != '\0')) {
          FUN_8000bb18(param_1,0x113);
          *(undefined *)(pfVar7 + 1) = 4;
          *pfVar7 = FLOAT_803e4b0c;
        }
      }
      else {
        *(undefined *)((int)pfVar7 + 6) = 1;
      }
      iVar3 = FUN_8001ffb4((int)*(short *)(iVar6 + 0x20));
      if (iVar3 != 0) {
        FUN_8000bb18(param_1,0x113);
        *(undefined *)(pfVar7 + 1) = 4;
        *pfVar7 = FLOAT_803e4b0c;
      }
    }
    else if (bVar1 != 0) {
      FUN_8000b7bc(param_1,8);
      if (*(char *)((int)pfVar7 + 5) == '\0') {
        iVar3 = FUN_8001ffb4((int)*(short *)(iVar6 + 0x20));
        if (iVar3 == 0) {
          FUN_8000bb18(param_1,0x113);
          *(undefined *)(pfVar7 + 1) = 3;
          *pfVar7 = FLOAT_803e4b0c;
          *(undefined *)((int)pfVar7 + 5) = 0;
          FUN_800200e8((int)*(short *)(iVar6 + 0x1e),0);
        }
      }
      else if (!bVar2) {
        FUN_8000bb18(param_1,0x113);
        *(undefined *)(pfVar7 + 1) = 3;
        *pfVar7 = FLOAT_803e4b0c;
        *(undefined *)((int)pfVar7 + 5) = 0;
        FUN_800200e8((int)*(short *)(iVar6 + 0x1e),0);
      }
    }
  }
  else if (bVar1 < 5) {
    *pfVar7 = FLOAT_803e4b1c * FLOAT_803db414 + *pfVar7;
    if (*pfVar7 < FLOAT_803e4b20) {
      *pfVar7 = FLOAT_803e4b20;
    }
    *(float *)(param_1 + 0x10) = *pfVar7 * FLOAT_803db414 + *(float *)(param_1 + 0x10);
    if (*(float *)(param_1 + 0x10) < *(float *)(iVar6 + 0xc) - FLOAT_803e4b24) {
      FUN_8000bb18(param_1,0x1f8);
      *(float *)(param_1 + 0x10) = *(float *)(iVar6 + 0xc) - FLOAT_803e4b24;
      *(undefined *)(pfVar7 + 1) = 2;
      FUN_800200e8((int)*(short *)(iVar6 + 0x1e),1);
    }
    if ((*(char *)((int)pfVar7 + 5) == '\0') &&
       (iVar3 = FUN_8001ffb4((int)*(short *)(iVar6 + 0x20)), iVar3 == 0)) {
      *(undefined *)(pfVar7 + 1) = 3;
      FUN_800200e8((int)*(short *)(iVar6 + 0x1e),0);
    }
  }
  return;
}

