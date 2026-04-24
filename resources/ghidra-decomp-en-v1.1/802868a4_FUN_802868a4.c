// Function: FUN_802868a4
// Entry: 802868a4
// Size: 236 bytes

undefined8 FUN_802868a4(uint param_1,uint param_2,int param_3,uint param_4)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  bool bVar12;
  bool bVar13;
  
  iVar3 = countLeadingZeros(param_1);
  iVar9 = countLeadingZeros(param_2);
  if (param_1 == 0) {
    iVar3 = iVar9 + 0x20;
  }
  iVar9 = countLeadingZeros(param_3);
  iVar11 = countLeadingZeros(param_4);
  if (param_3 == 0) {
    iVar9 = iVar11 + 0x20;
  }
  if (iVar3 <= iVar9) {
    iVar11 = 0x40 - (iVar9 + 1);
    iVar9 = iVar3 + iVar11;
    iVar11 = (0x40 - iVar3) - iVar11;
    if (iVar11 < 0x20) {
      uVar7 = param_2 >> iVar11 | param_1 << 0x20 - iVar11;
      uVar6 = param_1 >> iVar11;
    }
    else {
      uVar7 = param_1 >> iVar11 + -0x20;
      uVar6 = 0;
    }
    if (iVar9 < 0x20) {
      uVar4 = param_1 << iVar9 | param_2 >> 0x20 - iVar9;
      uVar5 = param_2 << iVar9;
    }
    else {
      uVar4 = param_2 << iVar9 + -0x20;
      uVar5 = 0;
    }
    bVar12 = false;
    do {
      bVar13 = CARRY4(uVar5,(uint)bVar12);
      uVar1 = uVar5 + bVar12;
      bVar12 = CARRY4(uVar5,uVar1);
      uVar5 = uVar5 + uVar1;
      uVar1 = (uint)(bVar13 || bVar12);
      bVar13 = CARRY4(uVar4,uVar1);
      uVar1 = uVar4 + uVar1;
      bVar12 = CARRY4(uVar4,uVar1);
      uVar4 = uVar4 + uVar1;
      uVar1 = (uint)(bVar13 || bVar12);
      uVar2 = uVar7 + uVar1;
      uVar8 = uVar7 + uVar2;
      uVar1 = uVar6 * 2 + (uint)(CARRY4(uVar7,uVar1) || CARRY4(uVar7,uVar2));
      uVar2 = (uint)(uVar8 < param_4) + param_3;
      uVar10 = uVar1 - uVar2;
      uVar6 = uVar1;
      uVar7 = uVar8;
      if (-1 < (int)uVar10) {
        uVar6 = uVar10;
        uVar7 = uVar8 - param_4;
      }
      bVar12 = -1 < (int)uVar10 || uVar2 <= uVar1;
      iVar11 = iVar11 + -1;
    } while (iVar11 != 0);
    uVar6 = uVar5 + bVar12;
    return CONCAT44(uVar4 * 2 + (uint)(CARRY4(uVar5,(uint)bVar12) || CARRY4(uVar5,uVar6)),
                    uVar5 + uVar6);
  }
  return 0;
}

