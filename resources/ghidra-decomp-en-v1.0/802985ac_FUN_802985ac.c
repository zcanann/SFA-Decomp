// Function: FUN_802985ac
// Entry: 802985ac
// Size: 80 bytes

void FUN_802985ac(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(byte *)(iVar1 + 0x3f4) = *(byte *)(iVar1 + 0x3f4) & 0xdf;
  *(float *)(iVar1 + 0x414) = FLOAT_803e7ea4;
  *(byte *)(iVar1 + 0x3f3) = *(byte *)(iVar1 + 0x3f3) & 0xef;
  *(undefined2 *)(iVar1 + 0x80a) = 0xffff;
  FUN_80035ea4();
  return;
}

