// Function: FUN_8027938c
// Entry: 8027938c
// Size: 20 bytes

undefined4 FUN_8027938c(int param_1)

{
  *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(param_1 + 0xf8);
  return *(undefined4 *)(*(int *)(param_1 + 0xf8) + 8);
}

