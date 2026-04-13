// Function: FUN_80296e34
// Entry: 80296e34
// Size: 32 bytes

uint FUN_80296e34(int param_1,undefined4 *param_2)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *param_2 = *(undefined4 *)(iVar1 + 0x7f8);
  uVar2 = *(uint *)(iVar1 + 0x7f8);
  return (-uVar2 | uVar2) >> 0x1f;
}

