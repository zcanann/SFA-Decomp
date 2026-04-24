// Function: FUN_801a04a8
// Entry: 801a04a8
// Size: 68 bytes

void FUN_801a04a8(int param_1)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0xb8);
  *puVar1 = 0;
  puVar1[1] = 0;
  FUN_80035f20();
  *(undefined *)(param_1 + 0x36) = 0x80;
  return;
}

