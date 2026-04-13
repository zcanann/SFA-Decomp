// Function: FUN_80234e1c
// Entry: 80234e1c
// Size: 72 bytes

void FUN_80234e1c(int param_1)

{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
  }
  if (puVar2[1] != 0) {
    FUN_80054484();
  }
  return;
}

