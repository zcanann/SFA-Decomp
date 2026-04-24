// Function: FUN_8025c484
// Entry: 8025c484
// Size: 256 bytes

void FUN_8025c484(byte param_1,uint param_2,ushort *param_3)

{
  if (param_1 != 0) {
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,*param_3 & 0xfff | (param_3[1] & 0xfff) << 0xc | 0xe9000000);
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,param_3[2] & 0xfff | (param_3[3] & 0xfff) << 0xc | 0xea000000);
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,param_3[4] & 0xfff | (param_3[5] & 0xfff) << 0xc | 0xeb000000);
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,param_3[6] & 0xfff | (param_3[7] & 0xfff) << 0xc | 0xec000000);
    write_volatile_1(DAT_cc008000,0x61);
    write_volatile_4(0xcc008000,param_3[8] & 0xfff | (param_3[9] & 0xfff) << 0xc | 0xed000000);
  }
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,
                   (param_2 & 0xffff) + 0x156 & 0xfffbff | (uint)param_1 << 10 | 0xe8000000);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

