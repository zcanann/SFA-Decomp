// Function: FUN_80279af0
// Entry: 80279af0
// Size: 20 bytes

undefined4 FUN_80279af0(int param_1)

{
  *(undefined4 *)(param_1 + 0xfc) = *(undefined4 *)(param_1 + 0xf8);
  return *(undefined4 *)(*(int *)(param_1 + 0xf8) + 8);
}

