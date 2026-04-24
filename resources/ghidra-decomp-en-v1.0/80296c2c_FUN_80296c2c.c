// Function: FUN_80296c2c
// Entry: 80296c2c
// Size: 32 bytes

uint FUN_80296c2c(int param_1)

{
  uint uVar1;
  
  uVar1 = (uint)**(char **)(*(int *)(param_1 + 0xb8) + 0x35c);
  return (-uVar1 & ~uVar1) >> 0x1f;
}

