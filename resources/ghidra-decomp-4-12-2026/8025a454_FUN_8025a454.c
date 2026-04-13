// Function: FUN_8025a454
// Entry: 8025a454
// Size: 356 bytes

void FUN_8025a454(int param_1,uint *param_2)

{
  int iVar1;
  uint uVar2;
  
  if (param_1 == 3) {
    iVar1 = 1;
    uVar2 = *(uint *)(DAT_803dd210 + 0xb4) & 0xffffff00 | (uint)*(byte *)((int)param_2 + 3);
  }
  else if (param_1 < 3) {
    if (param_1 == 1) {
      iVar1 = 1;
      uVar2 = (uint)*(byte *)((int)param_2 + 2) << 8 | *(uint *)(DAT_803dd210 + 0xb4) & 0xff |
              (uint)*(byte *)((int)param_2 + 1) << 0x10 | (uint)*(byte *)param_2 << 0x18;
    }
    else if (param_1 < 1) {
      if (param_1 < 0) {
        return;
      }
      iVar1 = 0;
      uVar2 = (uint)*(byte *)((int)param_2 + 2) << 8 | *(uint *)(DAT_803dd210 + 0xb0) & 0xff |
              (uint)*(byte *)((int)param_2 + 1) << 0x10 | (uint)*(byte *)param_2 << 0x18;
    }
    else {
      iVar1 = 0;
      uVar2 = *(uint *)(DAT_803dd210 + 0xb0) & 0xffffff00 | (uint)*(byte *)((int)param_2 + 3);
    }
  }
  else if (param_1 == 5) {
    iVar1 = 1;
    uVar2 = *param_2;
  }
  else {
    if (4 < param_1) {
      return;
    }
    iVar1 = 0;
    uVar2 = *param_2;
  }
  DAT_cc008000._0_1_ = 0x10;
  DAT_cc008000 = iVar1 + 0x100c;
  DAT_cc008000 = uVar2;
  *(undefined2 *)(DAT_803dd210 + 2) = 1;
  *(uint *)(DAT_803dd210 + iVar1 * 4 + 0xb0) = uVar2;
  return;
}

