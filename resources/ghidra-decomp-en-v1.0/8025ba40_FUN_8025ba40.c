// Function: FUN_8025ba40
// Entry: 8025ba40
// Size: 128 bytes

void FUN_8025ba40(int param_1,int param_2,int param_3,int param_4,uint param_5)

{
  uint *puVar1;
  
  puVar1 = (uint *)(DAT_803dc5a8 + param_1 * 4 + 0x130);
  *puVar1 = *puVar1 & 0xffff0fff | param_2 << 0xc;
  *puVar1 = *puVar1 & 0xfffff0ff | param_3 << 8;
  *puVar1 = *puVar1 & 0xffffff0f | param_4 << 4;
  *puVar1 = *puVar1 & 0xfffffff0 | param_5;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*puVar1);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

