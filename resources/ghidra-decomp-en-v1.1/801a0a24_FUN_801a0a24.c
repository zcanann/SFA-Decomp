// Function: FUN_801a0a24
// Entry: 801a0a24
// Size: 68 bytes

void FUN_801a0a24(int param_1)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0xb8);
  *puVar1 = 0;
  puVar1[1] = 0;
  FUN_80036018(param_1);
  *(undefined *)(param_1 + 0x36) = 0x80;
  return;
}

