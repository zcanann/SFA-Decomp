// Function: FUN_80189f44
// Entry: 80189f44
// Size: 24 bytes

byte FUN_80189f44(int param_1)

{
  byte bVar1;
  
  bVar1 = *(byte *)(*(int *)(param_1 + 0x4c) + 0x1d);
  if (bVar1 < 3) {
    return bVar1;
  }
  return 2;
}

