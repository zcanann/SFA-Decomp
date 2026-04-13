// Function: FUN_80218a94
// Entry: 80218a94
// Size: 88 bytes

void FUN_80218a94(int param_1)

{
  uint uVar1;
  uint *puVar2;
  
  puVar2 = *(uint **)(param_1 + 0xb8);
  uVar1 = *puVar2;
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
    *puVar2 = 0;
  }
  FUN_8003709c(param_1,2);
  return;
}

