// Function: FUN_80016c50
// Entry: 80016c50
// Size: 48 bytes

void FUN_80016c50(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803dd648;
  iVar1 = DAT_803dd648 * 5;
  DAT_803dd648 = DAT_803dd648 + 1;
  (&DAT_8033b1a0)[iVar1] = 1;
  (&DAT_8033b1a4)[iVar2 * 5] = param_1;
  (&DAT_8033b1a8)[iVar2 * 5] = param_2;
  return;
}

