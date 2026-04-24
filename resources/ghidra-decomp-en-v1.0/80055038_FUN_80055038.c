// Function: FUN_80055038
// Entry: 80055038
// Size: 56 bytes

void FUN_80055038(void)

{
  int iVar1;
  
  iVar1 = FUN_800e84f8();
  DAT_803dce00 = 1;
  *(byte *)(iVar1 + 0x40) = *(byte *)(iVar1 + 0x40) | 0x20;
  return;
}

