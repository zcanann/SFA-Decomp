// Function: FUN_8028622c
// Entry: 8028622c
// Size: 312 bytes

undefined8 FUN_8028622c(uint param_1,uint param_2,uint param_3,uint param_4)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  int iVar10;
  uint uVar11;
  int iVar12;
  bool bVar13;
  bool bVar14;
  
  uVar3 = param_1 & 0x80000000;
  if (uVar3 != 0) {
    bVar13 = param_2 != 0;
    param_2 = -param_2;
    param_1 = -(bVar13 + param_1);
  }
  uVar4 = param_3 & 0x80000000;
  if (uVar4 != 0) {
    bVar13 = param_4 != 0;
    param_4 = -param_4;
    param_3 = -(bVar13 + param_3);
  }
  iVar5 = countLeadingZeros(param_1);
  iVar10 = countLeadingZeros(param_2);
  if (param_1 == 0) {
    iVar5 = iVar10 + 0x20;
  }
  iVar10 = countLeadingZeros(param_3);
  iVar12 = countLeadingZeros(param_4);
  if (param_3 == 0) {
    iVar10 = iVar12 + 0x20;
  }
  if (iVar10 < iVar5) {
    iVar10 = 0;
    iVar5 = 0;
  }
  else {
    iVar12 = 0x40 - (iVar10 + 1);
    iVar10 = iVar5 + iVar12;
    iVar12 = (0x40 - iVar5) - iVar12;
    if (iVar12 < 0x20) {
      uVar8 = param_2 >> iVar12 | param_1 << 0x20 - iVar12;
      uVar7 = param_1 >> iVar12;
    }
    else {
      uVar8 = param_1 >> iVar12 + -0x20;
      uVar7 = 0;
    }
    if (iVar10 < 0x20) {
      uVar6 = param_1 << iVar10 | param_2 >> 0x20 - iVar10;
      param_2 = param_2 << iVar10;
    }
    else {
      uVar6 = param_2 << iVar10 + -0x20;
      param_2 = 0;
    }
    bVar13 = false;
    do {
      bVar14 = CARRY4(param_2,(uint)bVar13);
      uVar1 = param_2 + bVar13;
      bVar13 = CARRY4(param_2,uVar1);
      param_2 = param_2 + uVar1;
      uVar1 = (uint)(bVar14 || bVar13);
      bVar14 = CARRY4(uVar6,uVar1);
      uVar1 = uVar6 + uVar1;
      bVar13 = CARRY4(uVar6,uVar1);
      uVar6 = uVar6 + uVar1;
      uVar1 = (uint)(bVar14 || bVar13);
      uVar2 = uVar8 + uVar1;
      uVar9 = uVar8 + uVar2;
      uVar1 = uVar7 * 2 + (uint)(CARRY4(uVar8,uVar1) || CARRY4(uVar8,uVar2));
      uVar2 = (uVar9 < param_4) + param_3;
      uVar11 = uVar1 - uVar2;
      uVar7 = uVar1;
      uVar8 = uVar9;
      if (-1 < (int)uVar11) {
        uVar7 = uVar11;
        uVar8 = uVar9 - param_4;
      }
      bVar13 = -1 < (int)uVar11 || uVar2 <= uVar1;
      iVar12 = iVar12 + -1;
    } while (iVar12 != 0);
    uVar7 = param_2 + bVar13;
    iVar10 = param_2 + uVar7;
    iVar5 = uVar6 * 2 + (uint)(CARRY4(param_2,(uint)bVar13) || CARRY4(param_2,uVar7));
    if (uVar3 != uVar4) {
      bVar13 = iVar10 != 0;
      iVar10 = -iVar10;
      iVar5 = -((uint)bVar13 + iVar5);
    }
  }
  return CONCAT44(iVar5,iVar10);
}

