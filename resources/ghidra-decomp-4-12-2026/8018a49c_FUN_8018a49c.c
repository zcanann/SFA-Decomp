// Function: FUN_8018a49c
// Entry: 8018a49c
// Size: 24 bytes

byte FUN_8018a49c(int param_1)

{
  byte bVar1;
  
  bVar1 = *(byte *)(*(int *)(param_1 + 0x4c) + 0x1d);
  if (bVar1 < 3) {
    return bVar1;
  }
  return 2;
}

