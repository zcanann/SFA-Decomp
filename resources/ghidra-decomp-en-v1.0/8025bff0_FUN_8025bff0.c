// Function: FUN_8025bff0
// Entry: 8025bff0
// Size: 80 bytes

void FUN_8025bff0(uint param_1,uint param_2,int param_3,int param_4,uint param_5)

{
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,
                   ((param_2 & 0xff | (param_5 & 0xff) << 8 | (param_1 & 0xffc7) << 0x10 |
                    param_4 << 0x13) & 0xff3fffff | param_3 << 0x16) & 0xffffff | 0xf3000000);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

