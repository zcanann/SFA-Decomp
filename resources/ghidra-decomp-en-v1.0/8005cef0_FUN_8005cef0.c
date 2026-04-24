// Function: FUN_8005cef0
// Entry: 8005cef0
// Size: 120 bytes

void FUN_8005cef0(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_800e84f8();
  if (param_1 == 0) {
    DAT_803dcde8 = DAT_803dcde8 & 0xffffffaf;
    *(byte *)(iVar1 + 0x40) = *(byte *)(iVar1 + 0x40) & 0xf6;
  }
  else {
    DAT_803dcde8 = DAT_803dcde8 | 0x50;
    *(byte *)(iVar1 + 0x40) = *(byte *)(iVar1 + 0x40) | 9;
  }
  return;
}

