// Function: FUN_8004312c
// Entry: 8004312c
// Size: 64 bytes

void FUN_8004312c(void)

{
  FUN_80243e74();
  if ((DAT_803dd900 & 0x100000) != 0) {
    DAT_803dd900 = DAT_803dd900 ^ 0x100000;
  }
  FUN_80243e9c();
  return;
}

