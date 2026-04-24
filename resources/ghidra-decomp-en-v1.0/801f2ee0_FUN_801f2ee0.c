// Function: FUN_801f2ee0
// Entry: 801f2ee0
// Size: 452 bytes

void FUN_801f2ee0(int param_1)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  int iVar4;
  int iVar5;
  short *psVar6;
  int iVar7;
  
  iVar7 = *(int *)(param_1 + 0x4c);
  psVar6 = *(short **)(param_1 + 0xb8);
  *(char *)(psVar6 + 1) = *(char *)(psVar6 + 1) + -1;
  if (*(char *)(psVar6 + 1) < '\0') {
    *(undefined *)(psVar6 + 1) = 0;
  }
  fVar1 = FLOAT_803e5dcc;
  if ('\0' < *(char *)(*(int *)(param_1 + 0x58) + 0x10f)) {
    iVar4 = 0;
    for (iVar5 = 0; iVar5 < *(char *)(*(int *)(param_1 + 0x58) + 0x10f); iVar5 = iVar5 + 1) {
      if (fVar1 < *(float *)(*(int *)(*(int *)(param_1 + 0x58) + iVar4 + 0x100) + 0x10) -
                  *(float *)(param_1 + 0x10)) {
        *(undefined *)(psVar6 + 1) = 0x3c;
      }
      iVar4 = iVar4 + 4;
    }
  }
  bVar3 = false;
  if (((*psVar6 == -1) || (iVar4 = FUN_8001ffb4(), iVar4 != 0)) && (*(char *)(psVar6 + 1) != '\0'))
  {
    fVar2 = FLOAT_803e5dd0 + FLOAT_803e5dd4 + *(float *)(iVar7 + 0xc);
    fVar1 = *(float *)(param_1 + 0x10);
    if (fVar1 <= fVar2) {
      *(float *)(param_1 + 0x10) = FLOAT_803e5ddc * FLOAT_803db414 + fVar1;
      if (*(float *)(param_1 + 0x10) <= fVar2) {
        bVar3 = true;
      }
      else {
        *(float *)(param_1 + 0x10) = fVar2;
      }
    }
    else {
      *(float *)(param_1 + 0x10) = -(FLOAT_803e5dd8 * FLOAT_803db414 - fVar1);
      if (fVar2 < *(float *)(param_1 + 0x10)) {
        *(float *)(param_1 + 0x10) = fVar2;
      }
    }
  }
  else {
    *(float *)(param_1 + 0x10) = -(FLOAT_803e5de0 * FLOAT_803db414 - *(float *)(param_1 + 0x10));
    fVar1 = *(float *)(iVar7 + 0xc);
    if (fVar1 <= *(float *)(param_1 + 0x10)) {
      bVar3 = true;
    }
    else {
      *(float *)(param_1 + 0x10) = fVar1;
    }
  }
  if (bVar3) {
    FUN_8000bb18(param_1,0x7d);
  }
  else {
    FUN_8000b7bc(param_1,8);
  }
  return;
}

