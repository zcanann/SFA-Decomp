// Function: FUN_8025bef8
// Entry: 8025bef8
// Size: 88 bytes

void FUN_8025bef8(int param_1,uint param_2,int param_3)

{
  uint *puVar1;
  
  puVar1 = (uint *)(DAT_803dc5a8 + param_1 * 4 + 0x170);
  *puVar1 = *puVar1 & 0xfffffffc | param_2;
  *puVar1 = *puVar1 & 0xfffffff3 | param_3 << 2;
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*puVar1);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

