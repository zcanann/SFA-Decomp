// Function: FUN_80282288
// Entry: 80282288
// Size: 652 bytes

uint FUN_80282288(uint param_1,uint param_2,uint param_3)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  
  uVar3 = param_2 & 0xff;
  if (uVar3 == 0xff) {
    return 0;
  }
  uVar1 = param_3 & 0xff;
  if (uVar1 == 0xff) {
    uVar1 = param_1 & 0xff;
    if (uVar1 < 0x40) {
      iVar4 = uVar3 * 0x86 + -0x7fc31c40 + (param_1 & 0x1f);
      return (uint)*(byte *)(iVar4 + 0x43c0) << 7 | (uint)*(byte *)(iVar4 + 0x43e0);
    }
    if (uVar1 < 0x46) {
      if (*(byte *)(uVar3 * 0x86 + uVar1 + -0x7fc2d880) < 0x40) {
        uVar3 = 0;
      }
      else {
        uVar3 = 0x3fff;
      }
      return uVar3;
    }
    if ((0x5f < uVar1) && (uVar1 < 0x66)) {
      return 0;
    }
    if ((param_1 - 0x80 & 0xff) < 2) {
      iVar4 = (param_2 & 0xff) * 0x86 + -0x7fc31c40 + (param_1 & 0xfe);
      return (uint)*(byte *)(iVar4 + 0x43c0) << 7 | (uint)*(byte *)(iVar4 + 0x43c1);
    }
    if ((param_1 - 0x84 & 0xff) < 2) {
      iVar4 = (param_2 & 0xff) * 0x86 + -0x7fc31c40 + (param_1 & 0xfe);
      return (uint)*(byte *)(iVar4 + 0x43c0) << 7 | (uint)*(byte *)(iVar4 + 0x43c1);
    }
    return (uint)*(byte *)((param_2 & 0xff) * 0x86 + (param_1 & 0xff) + -0x7fc2d880) << 7;
  }
  uVar2 = param_1 & 0xff;
  if (uVar2 < 0x40) {
    iVar4 = uVar1 * 0x860 + -0x7fc31c40 + uVar3 * 0x86 + (param_1 & 0x1f);
    return (uint)*(byte *)(iVar4 + 0xc0) << 7 | (uint)*(byte *)(iVar4 + 0xe0);
  }
  if (uVar2 < 0x46) {
    if (*(byte *)(uVar1 * 0x860 + uVar3 * 0x86 + uVar2 + -0x7fc31b80) < 0x40) {
      uVar3 = 0;
    }
    else {
      uVar3 = 0x3fff;
    }
    return uVar3;
  }
  if ((0x5f < uVar2) && (uVar2 < 0x66)) {
    return 0;
  }
  if ((param_1 - 0x80 & 0xff) < 2) {
    iVar4 = (param_3 & 0xff) * 0x860 + -0x7fc31c40 + (param_2 & 0xff) * 0x86 + (param_1 & 0xfe);
    return (uint)*(byte *)(iVar4 + 0xc0) << 7 | (uint)*(byte *)(iVar4 + 0xc1);
  }
  if ((param_1 - 0x84 & 0xff) < 2) {
    iVar4 = (param_3 & 0xff) * 0x860 + -0x7fc31c40 + (param_2 & 0xff) * 0x86 + (param_1 & 0xfe);
    return (uint)*(byte *)(iVar4 + 0xc0) << 7 | (uint)*(byte *)(iVar4 + 0xc1);
  }
  return (uint)*(byte *)((param_3 & 0xff) * 0x860 + (param_2 & 0xff) * 0x86 + (param_1 & 0xff) +
                        -0x7fc31b80) << 7;
}

