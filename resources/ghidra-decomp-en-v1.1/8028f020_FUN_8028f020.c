// Function: FUN_8028f020
// Entry: 8028f020
// Size: 52 bytes

void FUN_8028f020(int param_1)

{
  *(undefined4 *)(param_1 + 0x24) = *(undefined4 *)(param_1 + 0x1c);
  *(undefined4 *)(param_1 + 0x28) = *(undefined4 *)(param_1 + 0x20);
  *(uint *)(param_1 + 0x28) =
       *(int *)(param_1 + 0x28) - (*(uint *)(param_1 + 0x18) & *(uint *)(param_1 + 0x2c));
  *(undefined4 *)(param_1 + 0x34) = *(undefined4 *)(param_1 + 0x18);
  return;
}

