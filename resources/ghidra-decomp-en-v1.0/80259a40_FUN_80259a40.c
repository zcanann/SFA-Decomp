// Function: FUN_80259a40
// Entry: 80259a40
// Size: 328 bytes

void FUN_80259a40(int param_1,int param_2)

{
  int iVar1;
  
  if (param_2 == 0x10) {
    iVar1 = 4;
    goto LAB_80259ae4;
  }
  if (param_2 < 0x10) {
    if (param_2 == 4) {
      iVar1 = 2;
      goto LAB_80259ae4;
    }
    if (param_2 < 4) {
      if (param_2 == 2) {
        iVar1 = 1;
        goto LAB_80259ae4;
      }
      if ((param_2 < 2) && (0 < param_2)) {
        iVar1 = 0;
        goto LAB_80259ae4;
      }
    }
    else if (param_2 == 8) {
      iVar1 = 3;
      goto LAB_80259ae4;
    }
  }
  else {
    if (param_2 == 0x40) {
      iVar1 = 6;
      goto LAB_80259ae4;
    }
    if (param_2 < 0x40) {
      if (param_2 == 0x20) {
        iVar1 = 5;
        goto LAB_80259ae4;
      }
    }
    else if (param_2 == 0x80) {
      iVar1 = 7;
      goto LAB_80259ae4;
    }
  }
  iVar1 = 0;
LAB_80259ae4:
  write_volatile_1(DAT_cc008000,0x10);
  write_volatile_4(0xcc008000,iVar1 * 0x10 + 0x600U | 0xf0000);
  write_volatile_4(0xcc008000,0);
  write_volatile_4(0xcc008000,0);
  write_volatile_4(0xcc008000,0);
  write_volatile_4(0xcc008000,*(undefined4 *)(param_1 + 0xc));
  write_volatile_4(0xcc008000,*(undefined4 *)(param_1 + 0x10));
  write_volatile_4(0xcc008000,*(undefined4 *)(param_1 + 0x14));
  write_volatile_4(0xcc008000,*(undefined4 *)(param_1 + 0x18));
  write_volatile_4(0xcc008000,*(undefined4 *)(param_1 + 0x1c));
  write_volatile_4(0xcc008000,*(undefined4 *)(param_1 + 0x20));
  write_volatile_4(0xcc008000,*(undefined4 *)(param_1 + 0x24));
  write_volatile_4(0xcc008000,*(undefined4 *)(param_1 + 0x28));
  write_volatile_4(0xcc008000,*(undefined4 *)(param_1 + 0x2c));
  write_volatile_4(0xcc008000,*(undefined4 *)(param_1 + 0x30));
  write_volatile_4(0xcc008000,*(undefined4 *)(param_1 + 0x34));
  write_volatile_4(0xcc008000,*(undefined4 *)(param_1 + 0x38));
  write_volatile_4(0xcc008000,*(undefined4 *)(param_1 + 0x3c));
  *(undefined2 *)(DAT_803dc5a8 + 2) = 1;
  return;
}

