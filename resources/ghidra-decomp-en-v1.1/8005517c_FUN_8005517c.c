// Function: FUN_8005517c
// Entry: 8005517c
// Size: 56 bytes

void FUN_8005517c(void)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_800e877c();
  DAT_803dda80 = 0xffffffff;
  *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) & 0xdf;
  return;
}

