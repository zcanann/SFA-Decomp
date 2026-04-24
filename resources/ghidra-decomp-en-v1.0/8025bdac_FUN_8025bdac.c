// Function: FUN_8025bdac
// Entry: 8025bdac
// Size: 116 bytes

void FUN_8025bdac(int param_1,byte *param_2)

{
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,
                   (uint)*param_2 | (uint)param_2[3] << 0xc | 0x800000 |
                   (param_1 * 2 + 0xe0) * 0x1000000);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,
                   (uint)param_2[2] | (uint)param_2[1] << 0xc | 0x800000 |
                   (param_1 * 2 + 0xe1) * 0x1000000);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

