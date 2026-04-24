// Function: FUN_8025908c
// Entry: 8025908c
// Size: 104 bytes

void FUN_8025908c(undefined *param_1,uint param_2)

{
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,CONCAT11(param_1[3],*param_1) | 0x4f000000);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*(ushort *)(param_1 + 1) | 0x50000000);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,param_2 & 0xffffff | 0x51000000);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

