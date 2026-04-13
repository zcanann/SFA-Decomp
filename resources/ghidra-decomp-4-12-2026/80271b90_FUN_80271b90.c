// Function: FUN_80271b90
// Entry: 80271b90
// Size: 108 bytes

void FUN_80271b90(int param_1)

{
  byte bVar1;
  
  bVar1 = *(byte *)(param_1 + 0x2c);
  if (bVar1 == 2) {
    FUN_8026d828(*(uint *)(param_1 + 0x28));
  }
  else if (bVar1 < 2) {
    if (bVar1 != 0) {
      FUN_8026d9dc(*(uint *)(param_1 + 0x28));
    }
  }
  else if (bVar1 < 4) {
    FUN_8026dd94(*(uint *)(param_1 + 0x28),0,0);
  }
  return;
}

