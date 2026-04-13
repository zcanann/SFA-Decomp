// Function: FUN_80243308
// Entry: 80243308
// Size: 412 bytes

uint FUN_80243308(uint param_1)

{
  bool bVar1;
  bool bVar2;
  uint uVar3;
  uint uVar4;
  ushort uVar6;
  int iVar5;
  
  uVar6 = FUN_80243618();
  if (uVar6 == 1) {
    uVar3 = param_1 & 0xffff;
    if ((0x1f < uVar3) && (uVar3 < 0xe0)) {
      return (uint)*(ushort *)((int)&PTR_caseD_0_8032d8e0 + uVar3 * 2);
    }
    uVar3 = param_1 & 0xffff;
    if ((0x889e < uVar3) && (uVar3 < 0x9873)) {
      uVar4 = param_1 & 0xff;
      bVar2 = false;
      bVar1 = false;
      if ((0x3f < uVar4) && (uVar4 < 0xfd)) {
        bVar1 = true;
      }
      if ((bVar1) && (uVar4 != 0x7f)) {
        bVar2 = true;
      }
      if (!bVar2) {
        return 0;
      }
      iVar5 = uVar4 - 0x40;
      if (0x3f < iVar5) {
        iVar5 = uVar4 - 0x41;
      }
      return (((int)uVar3 >> 8) + -0x88) * 0xbc + iVar5 + 0x2be;
    }
    uVar3 = param_1 & 0xffff;
    if ((0x813f < uVar3) && (uVar3 < 0x879e)) {
      uVar4 = param_1 & 0xff;
      bVar2 = false;
      bVar1 = false;
      if ((0x3f < uVar4) && (uVar4 < 0xfd)) {
        bVar1 = true;
      }
      if ((bVar1) && (uVar4 != 0x7f)) {
        bVar2 = true;
      }
      if (!bVar2) {
        return 0;
      }
      iVar5 = uVar4 - 0x40;
      if (0x3f < iVar5) {
        iVar5 = uVar4 - 0x41;
      }
      return (uint)*(ushort *)(&DAT_8032daa0 + ((((int)uVar3 >> 8) + -0x81) * 0xbc + iVar5) * 2);
    }
  }
  else {
    uVar3 = param_1 & 0xffff;
    if ((0x20 < uVar3) && (uVar3 < 0x100)) {
      return uVar3 - 0x20;
    }
  }
  return 0;
}

