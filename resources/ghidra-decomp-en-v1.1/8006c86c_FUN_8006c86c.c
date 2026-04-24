// Function: FUN_8006c86c
// Entry: 8006c86c
// Size: 76 bytes

void FUN_8006c86c(int param_1)

{
  if (*(char *)(DAT_803ddbfc + 0x48) == '\0') {
    FUN_8025b054((uint *)(DAT_803ddbfc + 0x20),param_1);
  }
  else {
    FUN_8025aeac((uint *)(DAT_803ddbfc + 0x20),*(uint **)(DAT_803ddbfc + 0x40),param_1);
  }
  return;
}

