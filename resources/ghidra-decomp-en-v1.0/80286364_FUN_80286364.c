// Function: FUN_80286364
// Entry: 80286364
// Size: 224 bytes

undefined8 FUN_80286364(uint param_1,uint param_2,int param_3,uint param_4)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  bool bVar11;
  bool bVar12;
  
  iVar3 = countLeadingZeros(param_1);
  iVar8 = countLeadingZeros(param_2);
  if (param_1 == 0) {
    iVar3 = iVar8 + 0x20;
  }
  iVar8 = countLeadingZeros(param_3);
  iVar10 = countLeadingZeros(param_4);
  if (param_3 == 0) {
    iVar8 = iVar10 + 0x20;
  }
  if (iVar8 < iVar3) {
    return CONCAT44(param_1,param_2);
  }
  iVar10 = 0x40 - (iVar8 + 1);
  iVar8 = iVar3 + iVar10;
  iVar10 = (0x40 - iVar3) - iVar10;
  if (iVar10 < 0x20) {
    uVar6 = param_2 >> iVar10 | param_1 << 0x20 - iVar10;
    uVar5 = param_1 >> iVar10;
  }
  else {
    uVar6 = param_1 >> iVar10 + -0x20;
    uVar5 = 0;
  }
  if (iVar8 < 0x20) {
    uVar4 = param_1 << iVar8 | param_2 >> 0x20 - iVar8;
    param_2 = param_2 << iVar8;
  }
  else {
    uVar4 = param_2 << iVar8 + -0x20;
    param_2 = 0;
  }
  bVar11 = false;
  do {
    bVar12 = CARRY4(param_2,(uint)bVar11);
    uVar1 = param_2 + bVar11;
    bVar11 = CARRY4(param_2,uVar1);
    param_2 = param_2 + uVar1;
    uVar1 = (uint)(bVar12 || bVar11);
    bVar12 = CARRY4(uVar4,uVar1);
    uVar1 = uVar4 + uVar1;
    bVar11 = CARRY4(uVar4,uVar1);
    uVar4 = uVar4 + uVar1;
    uVar1 = (uint)(bVar12 || bVar11);
    uVar2 = uVar6 + uVar1;
    uVar7 = uVar6 + uVar2;
    uVar1 = uVar5 * 2 + (uint)(CARRY4(uVar6,uVar1) || CARRY4(uVar6,uVar2));
    uVar2 = (uint)(uVar7 < param_4) + param_3;
    uVar9 = uVar1 - uVar2;
    uVar5 = uVar1;
    uVar6 = uVar7;
    if (-1 < (int)uVar9) {
      uVar5 = uVar9;
      uVar6 = uVar7 - param_4;
    }
    bVar11 = -1 < (int)uVar9 || uVar2 <= uVar1;
    iVar10 = iVar10 + -1;
  } while (iVar10 != 0);
  return CONCAT44(uVar5,uVar6);
}

