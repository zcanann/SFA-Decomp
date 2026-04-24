// Function: FUN_8022d48c
// Entry: 8022d48c
// Size: 32 bytes

void FUN_8022d48c(undefined4 *param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_2 + 0xb8);
  uVar1 = *(undefined4 *)(iVar2 + 0x4c);
  *param_1 = *(undefined4 *)(iVar2 + 0x48);
  param_1[1] = uVar1;
  param_1[2] = *(undefined4 *)(iVar2 + 0x50);
  return;
}

