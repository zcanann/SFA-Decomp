// Function: FUN_802961d4
// Entry: 802961d4
// Size: 40 bytes

void FUN_802961d4(undefined2 *param_1,undefined2 param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  *param_1 = param_2;
  *(undefined2 *)(iVar1 + 0x478) = param_2;
  *(undefined2 *)(iVar1 + 0x484) = param_2;
  *(uint *)(iVar1 + 0x360) = *(uint *)(iVar1 + 0x360) | 0x800000;
  return;
}

