// Function: FUN_8006c8d8
// Entry: 8006c8d8
// Size: 76 bytes

void FUN_8006c8d8(int param_1)

{
  if (*(char *)(DAT_803ddc64 + 0x48) == '\0') {
    FUN_8025b054((uint *)(DAT_803ddc64 + 0x20),param_1);
  }
  else {
    FUN_8025aeac((uint *)(DAT_803ddc64 + 0x20),*(uint **)(DAT_803ddc64 + 0x40),param_1);
  }
  return;
}

