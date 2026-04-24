// Function: FUN_8025bac0
// Entry: 8025bac0
// Size: 132 bytes

void FUN_8025bac0(int param_1,int param_2,int param_3,int param_4,int param_5)

{
  uint *puVar1;
  
  puVar1 = (uint *)(DAT_803dc5a8 + param_1 * 4 + 0x170);
  *puVar1 = *puVar1 & 0xffff1fff | param_2 << 0xd;
  *puVar1 = *puVar1 & 0xffffe3ff | param_3 << 10;
  *puVar1 = *puVar1 & 0xfffffc7f | param_4 << 7;
  *puVar1 = *puVar1 & 0xffffff8f | param_5 << 4;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*puVar1);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

