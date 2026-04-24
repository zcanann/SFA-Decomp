// Function: FUN_80286990
// Entry: 80286990
// Size: 312 bytes

undefined8 FUN_80286990(uint param_1,uint param_2,uint param_3,uint param_4)

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
  uint uVar10;
  int iVar11;
  uint uVar12;
  int iVar13;
  bool bVar14;
  bool bVar15;
  
  uVar3 = param_1 & 0x80000000;
  if (uVar3 != 0) {
    bVar14 = param_2 != 0;
    param_2 = -param_2;
    param_1 = -(bVar14 + param_1);
  }
  uVar4 = param_3 & 0x80000000;
  if (uVar4 != 0) {
    bVar14 = param_4 != 0;
    param_4 = -param_4;
    param_3 = -(bVar14 + param_3);
  }
  iVar5 = countLeadingZeros(param_1);
  iVar11 = countLeadingZeros(param_2);
  if (param_1 == 0) {
    iVar5 = iVar11 + 0x20;
  }
  iVar11 = countLeadingZeros(param_3);
  iVar13 = countLeadingZeros(param_4);
  if (param_3 == 0) {
    iVar11 = iVar13 + 0x20;
  }
  if (iVar11 < iVar5) {
    iVar11 = 0;
    iVar5 = 0;
  }
  else {
    iVar13 = 0x40 - (iVar11 + 1);
    iVar11 = iVar5 + iVar13;
    iVar13 = (0x40 - iVar5) - iVar13;
    if (iVar13 < 0x20) {
      uVar9 = param_2 >> iVar13 | param_1 << 0x20 - iVar13;
      uVar8 = param_1 >> iVar13;
    }
    else {
      uVar9 = param_1 >> iVar13 + -0x20;
      uVar8 = 0;
    }
    if (iVar11 < 0x20) {
      uVar6 = param_1 << iVar11 | param_2 >> 0x20 - iVar11;
      uVar7 = param_2 << iVar11;
    }
    else {
      uVar6 = param_2 << iVar11 + -0x20;
      uVar7 = 0;
    }
    bVar14 = false;
    do {
      bVar15 = CARRY4(uVar7,(uint)bVar14);
      uVar1 = uVar7 + bVar14;
      bVar14 = CARRY4(uVar7,uVar1);
      uVar7 = uVar7 + uVar1;
      uVar1 = (uint)(bVar15 || bVar14);
      bVar15 = CARRY4(uVar6,uVar1);
      uVar1 = uVar6 + uVar1;
      bVar14 = CARRY4(uVar6,uVar1);
      uVar6 = uVar6 + uVar1;
      uVar1 = (uint)(bVar15 || bVar14);
      uVar2 = uVar9 + uVar1;
      uVar10 = uVar9 + uVar2;
      uVar1 = uVar8 * 2 + (uint)(CARRY4(uVar9,uVar1) || CARRY4(uVar9,uVar2));
      uVar2 = (uVar10 < param_4) + param_3;
      uVar12 = uVar1 - uVar2;
      uVar8 = uVar1;
      uVar9 = uVar10;
      if (-1 < (int)uVar12) {
        uVar8 = uVar12;
        uVar9 = uVar10 - param_4;
      }
      bVar14 = -1 < (int)uVar12 || uVar2 <= uVar1;
      iVar13 = iVar13 + -1;
    } while (iVar13 != 0);
    uVar8 = uVar7 + bVar14;
    iVar11 = uVar7 + uVar8;
    iVar5 = uVar6 * 2 + (uint)(CARRY4(uVar7,(uint)bVar14) || CARRY4(uVar7,uVar8));
    if (uVar3 != uVar4) {
      bVar14 = iVar11 != 0;
      iVar11 = -iVar11;
      iVar5 = -((uint)bVar14 + iVar5);
    }
  }
  return CONCAT44(iVar5,iVar11);
}

