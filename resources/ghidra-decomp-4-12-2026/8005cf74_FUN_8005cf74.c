// Function: FUN_8005cf74
// Entry: 8005cf74
// Size: 116 bytes

void FUN_8005cf74(int param_1)

{
  undefined4 *puVar1;
  
  puVar1 = FUN_800e877c();
  if (param_1 == 0) {
    DAT_803dda68 = DAT_803dda68 & 0xffffffbf;
    *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) & 0xf7;
  }
  else {
    DAT_803dda68 = DAT_803dda68 | 0x40;
    *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) | 8;
  }
  return;
}

