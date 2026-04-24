// Function: FUN_8029656c
// Entry: 8029656c
// Size: 20 bytes

undefined FUN_8029656c(int param_1,undefined4 *param_2)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *param_2 = *(undefined4 *)(iVar1 + 0x77c);
  return *(undefined *)(iVar1 + 0x8c4);
}

