// Function: FUN_80056bbc
// Entry: 80056bbc
// Size: 56 bytes

void FUN_80056bbc(int param_1,int param_2,int param_3,int param_4,int param_5)

{
  int iVar1;
  
  iVar1 = DAT_803dce68 + param_1 * 0x10;
  *(short *)(iVar1 + 8) = (short)((param_2 << 0x10) / (param_4 >> 6));
  *(short *)(iVar1 + 10) = (short)((param_3 << 0x10) / (param_5 >> 6));
  return;
}

