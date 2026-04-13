// Function: FUN_8029738c
// Entry: 8029738c
// Size: 32 bytes

uint FUN_8029738c(int param_1)

{
  uint uVar1;
  
  uVar1 = (uint)**(char **)(*(int *)(param_1 + 0xb8) + 0x35c);
  return (-uVar1 & ~uVar1) >> 0x1f;
}

