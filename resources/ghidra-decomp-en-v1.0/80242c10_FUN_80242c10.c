// Function: FUN_80242c10
// Entry: 80242c10
// Size: 412 bytes

uint FUN_80242c10(uint param_1)

{
  bool bVar1;
  bool bVar2;
  uint uVar3;
  short sVar5;
  int iVar4;
  
  sVar5 = FUN_80242f20();
  if (sVar5 == 1) {
    uVar3 = param_1 & 0xffff;
    if ((0x1f < uVar3) && (uVar3 < 0xe0)) {
      return (uint)*(ushort *)((int)&PTR_caseD_0_8032cc88 + uVar3 * 2);
    }
    uVar3 = param_1 & 0xffff;
    if ((0x889e < uVar3) && (uVar3 < 0x9873)) {
      param_1 = param_1 & 0xff;
      bVar2 = false;
      bVar1 = false;
      if ((0x3f < param_1) && (param_1 < 0xfd)) {
        bVar1 = true;
      }
      if ((bVar1) && (param_1 != 0x7f)) {
        bVar2 = true;
      }
      if (!bVar2) {
        return 0;
      }
      iVar4 = param_1 - 0x40;
      if (0x3f < iVar4) {
        iVar4 = param_1 - 0x41;
      }
      return (((int)uVar3 >> 8) + -0x88) * 0xbc + iVar4 + 0x2be;
    }
    uVar3 = param_1 & 0xffff;
    if ((0x813f < uVar3) && (uVar3 < 0x879e)) {
      param_1 = param_1 & 0xff;
      bVar2 = false;
      bVar1 = false;
      if ((0x3f < param_1) && (param_1 < 0xfd)) {
        bVar1 = true;
      }
      if ((bVar1) && (param_1 != 0x7f)) {
        bVar2 = true;
      }
      if (!bVar2) {
        return 0;
      }
      iVar4 = param_1 - 0x40;
      if (0x3f < iVar4) {
        iVar4 = param_1 - 0x41;
      }
      return (uint)*(ushort *)(&DAT_8032ce48 + ((((int)uVar3 >> 8) + -0x81) * 0xbc + iVar4) * 2);
    }
  }
  else {
    param_1 = param_1 & 0xffff;
    if ((0x20 < param_1) && (param_1 < 0x100)) {
      return param_1 - 0x20;
    }
  }
  return 0;
}

