// Function: FUN_801f3518
// Entry: 801f3518
// Size: 452 bytes

void FUN_801f3518(uint param_1)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  short *psVar7;
  int iVar8;
  
  iVar8 = *(int *)(param_1 + 0x4c);
  psVar7 = *(short **)(param_1 + 0xb8);
  *(char *)(psVar7 + 1) = *(char *)(psVar7 + 1) + -1;
  if (*(char *)(psVar7 + 1) < '\0') {
    *(undefined *)(psVar7 + 1) = 0;
  }
  fVar1 = FLOAT_803e6a64;
  if ('\0' < *(char *)(*(int *)(param_1 + 0x58) + 0x10f)) {
    iVar5 = 0;
    for (iVar6 = 0; iVar6 < *(char *)(*(int *)(param_1 + 0x58) + 0x10f); iVar6 = iVar6 + 1) {
      if (fVar1 < *(float *)(*(int *)(*(int *)(param_1 + 0x58) + iVar5 + 0x100) + 0x10) -
                  *(float *)(param_1 + 0x10)) {
        *(undefined *)(psVar7 + 1) = 0x3c;
      }
      iVar5 = iVar5 + 4;
    }
  }
  bVar3 = false;
  if ((((int)*psVar7 == 0xffffffff) || (uVar4 = FUN_80020078((int)*psVar7), uVar4 != 0)) &&
     (*(char *)(psVar7 + 1) != '\0')) {
    fVar2 = FLOAT_803e6a68 + FLOAT_803e6a6c + *(float *)(iVar8 + 0xc);
    fVar1 = *(float *)(param_1 + 0x10);
    if (fVar1 <= fVar2) {
      *(float *)(param_1 + 0x10) = FLOAT_803e6a74 * FLOAT_803dc074 + fVar1;
      if (*(float *)(param_1 + 0x10) <= fVar2) {
        bVar3 = true;
      }
      else {
        *(float *)(param_1 + 0x10) = fVar2;
      }
    }
    else {
      *(float *)(param_1 + 0x10) = -(FLOAT_803e6a70 * FLOAT_803dc074 - fVar1);
      if (fVar2 < *(float *)(param_1 + 0x10)) {
        *(float *)(param_1 + 0x10) = fVar2;
      }
    }
  }
  else {
    *(float *)(param_1 + 0x10) = -(FLOAT_803e6a78 * FLOAT_803dc074 - *(float *)(param_1 + 0x10));
    fVar1 = *(float *)(iVar8 + 0xc);
    if (fVar1 <= *(float *)(param_1 + 0x10)) {
      bVar3 = true;
    }
    else {
      *(float *)(param_1 + 0x10) = fVar1;
    }
  }
  if (bVar3) {
    FUN_8000bb38(param_1,0x7d);
  }
  else {
    FUN_8000b7dc(param_1,8);
  }
  return;
}

