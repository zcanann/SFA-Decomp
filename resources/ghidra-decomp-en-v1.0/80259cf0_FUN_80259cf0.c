// Function: FUN_80259cf0
// Entry: 80259cf0
// Size: 356 bytes

void FUN_80259cf0(int param_1,uint *param_2)

{
  int iVar1;
  uint uVar2;
  
  if (param_1 == 3) {
    iVar1 = 1;
    uVar2 = *(uint *)(DAT_803dc5a8 + 0xb4) & 0xffffff00 | (uint)*(byte *)((int)param_2 + 3);
  }
  else if (param_1 < 3) {
    if (param_1 == 1) {
      iVar1 = 1;
      uVar2 = (uint)*(byte *)((int)param_2 + 2) << 8 | *(uint *)(DAT_803dc5a8 + 0xb4) & 0xff |
              (uint)*(byte *)((int)param_2 + 1) << 0x10 | (uint)*(byte *)param_2 << 0x18;
    }
    else if (param_1 < 1) {
      if (param_1 < 0) {
        return;
      }
      iVar1 = 0;
      uVar2 = (uint)*(byte *)((int)param_2 + 2) << 8 | *(uint *)(DAT_803dc5a8 + 0xb0) & 0xff |
              (uint)*(byte *)((int)param_2 + 1) << 0x10 | (uint)*(byte *)param_2 << 0x18;
    }
    else {
      iVar1 = 0;
      uVar2 = *(uint *)(DAT_803dc5a8 + 0xb0) & 0xffffff00 | (uint)*(byte *)((int)param_2 + 3);
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
  write_volatile_1(DAT_cc008000,0x10);
  write_volatile_4(0xcc008000,iVar1 + 0x100c);
  write_volatile_4(0xcc008000,uVar2);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 1;
  *(uint *)(DAT_803dc5a8 + iVar1 * 4 + 0xb0) = uVar2;
  return;
}

