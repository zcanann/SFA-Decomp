// Function: FUN_8025bcc4
// Entry: 8025bcc4
// Size: 116 bytes

void FUN_8025bcc4(int param_1,byte *param_2)

{
  uint uVar1;
  
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,
                   (uint)*param_2 | (uint)param_2[3] << 0xc | (param_1 * 2 + 0xe0) * 0x1000000);
  write_volatile_1(DAT_cc008000,0x61);
  uVar1 = (uint)param_2[2] | (uint)param_2[1] << 0xc | (param_1 * 2 + 0xe1) * 0x1000000;
  write_volatile_4(0xcc008000,uVar1);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,uVar1);
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,uVar1);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

