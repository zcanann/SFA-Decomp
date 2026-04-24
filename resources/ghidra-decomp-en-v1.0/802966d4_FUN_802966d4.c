// Function: FUN_802966d4
// Entry: 802966d4
// Size: 32 bytes

uint FUN_802966d4(int param_1,undefined4 *param_2)

{
  int iVar1;
  uint uVar2;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *param_2 = *(undefined4 *)(iVar1 + 0x7f8);
  uVar2 = *(uint *)(iVar1 + 0x7f8);
  return (-uVar2 | uVar2) >> 0x1f;
}

