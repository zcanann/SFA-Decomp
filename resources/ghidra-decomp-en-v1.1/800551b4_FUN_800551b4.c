// Function: FUN_800551b4
// Entry: 800551b4
// Size: 56 bytes

void FUN_800551b4(void)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_800e877c();
  DAT_803dda80 = 1;
  *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) | 0x20;
  return;
}

