// Function: FUN_8006c820
// Entry: 8006c820
// Size: 76 bytes

void FUN_8006c820(int param_1)

{
  if (*(char *)(DAT_803ddc4c + 0x48) == '\0') {
    FUN_8025b054((uint *)(DAT_803ddc4c + 0x20),param_1);
  }
  else {
    FUN_8025aeac((uint *)(DAT_803ddc4c + 0x20),*(uint **)(DAT_803ddc4c + 0x40),param_1);
  }
  return;
}

