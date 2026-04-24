// Function: FUN_801b48b4
// Entry: 801b48b4
// Size: 48 bytes

void FUN_801b48b4(int param_1)

{
  uint uVar1;
  
  uVar1 = *(uint *)(*(int *)(param_1 + 0xb8) + 0xa40);
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
  }
  return;
}

