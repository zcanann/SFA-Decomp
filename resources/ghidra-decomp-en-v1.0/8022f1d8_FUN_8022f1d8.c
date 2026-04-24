// Function: FUN_8022f1d8
// Entry: 8022f1d8
// Size: 152 bytes

void FUN_8022f1d8(int param_1,char param_2,char param_3)

{
  float *pfVar1;
  
  pfVar1 = *(float **)(param_1 + 0xb8);
  if (param_2 == '\0') {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    *(undefined *)(param_1 + 0x36) = 0;
  }
  else {
    FUN_8002b884(param_1,param_3 != '\0');
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) & 0xbfff;
    *(undefined *)(param_1 + 0x36) = 0xff;
    *pfVar1 = FLOAT_803e7058;
  }
  return;
}

