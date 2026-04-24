// Function: FUN_802836e8
// Entry: 802836e8
// Size: 40 bytes

void FUN_802836e8(int param_1)

{
  int iVar1;
  
  iVar1 = DAT_803de344 + param_1 * 0xf4 + (uint)DAT_803de370 * 4;
  *(uint *)(iVar1 + 0x24) = *(uint *)(iVar1 + 0x24) | 0x40;
  return;
}

