// Function: FUN_8025cf48
// Entry: 8025cf48
// Size: 212 bytes

void FUN_8025cf48(undefined4 *param_1,int param_2)

{
  *(int *)(DAT_803dc5a8 + 0x420) = param_2;
  *(undefined4 *)(DAT_803dc5a8 + 0x424) = *param_1;
  *(undefined4 *)(DAT_803dc5a8 + 0x42c) = param_1[5];
  *(undefined4 *)(DAT_803dc5a8 + 0x434) = param_1[10];
  *(undefined4 *)(DAT_803dc5a8 + 0x438) = param_1[0xb];
  if (param_2 == 1) {
    *(undefined4 *)(DAT_803dc5a8 + 0x428) = param_1[3];
    *(undefined4 *)(DAT_803dc5a8 + 0x430) = param_1[7];
  }
  else {
    *(undefined4 *)(DAT_803dc5a8 + 0x428) = param_1[2];
    *(undefined4 *)(DAT_803dc5a8 + 0x430) = param_1[6];
  }
  write_volatile_1(DAT_cc008000,0x10);
  write_volatile_4(0xcc008000,0x61020);
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x424));
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x428));
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x42c));
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x430));
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x434));
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x438));
  write_volatile_4(0xcc008000,*(undefined4 *)(DAT_803dc5a8 + 0x420));
  *(undefined2 *)(DAT_803dc5a8 + 2) = 1;
  return;
}

