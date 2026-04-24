// Function: FUN_802171d0
// Entry: 802171d0
// Size: 48 bytes

void FUN_802171d0(int param_1)

{
  uint uVar1;
  
  uVar1 = *(uint *)(*(int *)(param_1 + 0xb8) + 4);
  if (uVar1 != 0) {
    FUN_8001f448(uVar1);
  }
  return;
}

