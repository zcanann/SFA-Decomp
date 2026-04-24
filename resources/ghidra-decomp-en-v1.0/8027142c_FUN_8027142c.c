// Function: FUN_8027142c
// Entry: 8027142c
// Size: 108 bytes

void FUN_8027142c(int param_1)

{
  byte bVar1;
  
  bVar1 = *(byte *)(param_1 + 0x2c);
  if (bVar1 == 2) {
    FUN_8026d0c4(*(undefined4 *)(param_1 + 0x28));
  }
  else if (bVar1 < 2) {
    if (bVar1 != 0) {
      FUN_8026d278(*(undefined4 *)(param_1 + 0x28));
    }
  }
  else if (bVar1 < 4) {
    FUN_8026d630(*(undefined4 *)(param_1 + 0x28),0,0);
  }
  return;
}

