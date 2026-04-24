// Function: FUN_8025efcc
// Entry: 8025efcc
// Size: 364 bytes

uint FUN_8025efcc(uint param_1)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  
  iVar7 = 8;
  uVar1 = param_1 >> 0x1f;
  iVar5 = 0;
  iVar6 = 1;
  uVar2 = 0;
  uVar3 = 0;
  do {
    if (uVar3 < 0x10) {
      uVar2 = uVar2 | (param_1 & 1 << uVar3) << (0x1f - uVar3) - iVar5;
      iVar5 = iVar5 + 1;
    }
    else if (uVar3 == 0x1f) {
      uVar2 = uVar2 | uVar1;
    }
    else {
      uVar2 = uVar2 | (param_1 & 1 << uVar3) >> iVar6;
      iVar6 = iVar6 + 2;
    }
    uVar4 = uVar3 + 1;
    if (uVar4 < 0x10) {
      uVar2 = uVar2 | (param_1 & 1 << uVar4) << (0x1f - uVar4) - iVar5;
      iVar5 = iVar5 + 1;
    }
    else if (uVar4 == 0x1f) {
      uVar2 = uVar2 | uVar1;
    }
    else {
      uVar2 = uVar2 | (param_1 & 1 << uVar4) >> iVar6;
      iVar6 = iVar6 + 2;
    }
    uVar4 = uVar3 + 2;
    if (uVar4 < 0x10) {
      uVar2 = uVar2 | (param_1 & 1 << uVar4) << (0x1f - uVar4) - iVar5;
      iVar5 = iVar5 + 1;
    }
    else if (uVar4 == 0x1f) {
      uVar2 = uVar2 | uVar1;
    }
    else {
      uVar2 = uVar2 | (param_1 & 1 << uVar4) >> iVar6;
      iVar6 = iVar6 + 2;
    }
    uVar4 = uVar3 + 3;
    if (uVar4 < 0x10) {
      uVar2 = uVar2 | (param_1 & 1 << uVar4) << (0x1f - uVar4) - iVar5;
      iVar5 = iVar5 + 1;
    }
    else if (uVar4 == 0x1f) {
      uVar2 = uVar2 | uVar1;
    }
    else {
      uVar2 = uVar2 | (param_1 & 1 << uVar4) >> iVar6;
      iVar6 = iVar6 + 2;
    }
    uVar3 = uVar3 + 4;
    iVar7 = iVar7 + -1;
  } while (iVar7 != 0);
  return uVar2;
}

