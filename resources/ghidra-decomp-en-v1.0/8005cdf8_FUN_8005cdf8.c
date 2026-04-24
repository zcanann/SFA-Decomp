// Function: FUN_8005cdf8
// Entry: 8005cdf8
// Size: 116 bytes

void FUN_8005cdf8(int param_1)

{
  int iVar1;
  
  iVar1 = FUN_800e84f8();
  if (param_1 == 0) {
    DAT_803dcde8 = DAT_803dcde8 & 0xffffffbf;
    *(byte *)(iVar1 + 0x40) = *(byte *)(iVar1 + 0x40) & 0xf7;
  }
  else {
    DAT_803dcde8 = DAT_803dcde8 | 0x40;
    *(byte *)(iVar1 + 0x40) = *(byte *)(iVar1 + 0x40) | 8;
  }
  return;
}

