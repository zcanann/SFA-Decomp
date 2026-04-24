// Function: FUN_8025bc04
// Entry: 8025bc04
// Size: 192 bytes

void FUN_8025bc04(int param_1,uint param_2,int param_3,int param_4,uint param_5,int param_6)

{
  uint *puVar1;
  
  puVar1 = (uint *)(DAT_803dc5a8 + param_1 * 4 + 0x170);
  *puVar1 = (param_2 & 1) << 0x12 | *puVar1 & 0xfffbffff;
  if ((int)param_2 < 2) {
    *puVar1 = *puVar1 & 0xffcfffff | param_4 << 0x14;
    *puVar1 = *puVar1 & 0xfffcffff | param_3 << 0x10;
  }
  else {
    *puVar1 = (param_2 & 6) << 0x13 | *puVar1 & 0xffcfffff;
    *puVar1 = *puVar1 & 0xfffcffff | 0x30000;
  }
  *puVar1 = *puVar1 & 0xfff7ffff | (param_5 & 0xff) << 0x13;
  *puVar1 = *puVar1 & 0xff3fffff | param_6 << 0x16;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*puVar1);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

