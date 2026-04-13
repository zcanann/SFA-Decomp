// Function: FUN_8005d06c
// Entry: 8005d06c
// Size: 120 bytes

void FUN_8005d06c(int param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_800e877c();
  if (param_1 == 0) {
    DAT_803dda68 = DAT_803dda68 & 0xffffffaf;
    *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) & 0xf6;
  }
  else {
    DAT_803dda68 = DAT_803dda68 | 0x50;
    *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) | 9;
  }
  return;
}

