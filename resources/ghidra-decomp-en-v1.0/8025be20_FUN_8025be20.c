// Function: FUN_8025be20
// Entry: 8025be20
// Size: 108 bytes

void FUN_8025be20(uint param_1,int param_2)

{
  uint *puVar1;
  
  puVar1 = (uint *)(DAT_803dc5a8 + ((int)param_1 >> 1) * 4 + 0x1b0);
  if ((param_1 & 1) == 0) {
    *puVar1 = *puVar1 & 0xfffffe0f | param_2 << 4;
  }
  else {
    *puVar1 = *puVar1 & 0xfff83fff | param_2 << 0xe;
  }
  write_volatile_1(DAT_cc008000,0x61);
  write_volatile_4(0xcc008000,*puVar1);
  *(undefined2 *)(DAT_803dc5a8 + 2) = 0;
  return;
}

