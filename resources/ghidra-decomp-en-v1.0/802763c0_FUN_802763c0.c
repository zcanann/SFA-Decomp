// Function: FUN_802763c0
// Entry: 802763c0
// Size: 128 bytes

uint FUN_802763c0(uint param_1,uint param_2)

{
  uint uVar1;
  int iVar2;
  
  if (((param_2 & 0xffff) != 0xffff) && (iVar2 = FUN_80275058(param_2), iVar2 != 0)) {
    uVar1 = param_1 >> 0x10;
    if (uVar1 < 0x7f) {
      param_1 = (param_1 & 0xffff) *
                ((uint)*(byte *)(iVar2 + uVar1 + 1) - (uint)*(byte *)(iVar2 + uVar1)) +
                (uint)*(byte *)(iVar2 + uVar1) * 0x10000;
    }
    else {
      param_1 = (uint)*(byte *)(iVar2 + uVar1) << 0x10;
    }
  }
  return param_1;
}

