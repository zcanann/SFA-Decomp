// Function: FUN_80055000
// Entry: 80055000
// Size: 56 bytes

void FUN_80055000(void)

{
  int iVar1;
  
  iVar1 = FUN_800e84f8();
  DAT_803dce00 = 0xffffffff;
  *(byte *)(iVar1 + 0x40) = *(byte *)(iVar1 + 0x40) & 0xdf;
  return;
}

