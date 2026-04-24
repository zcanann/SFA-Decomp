// Function: FUN_80214d3c
// Entry: 80214d3c
// Size: 212 bytes

undefined4 FUN_80214d3c(int param_1)

{
  byte bVar1;
  
  bVar1 = *(byte *)(DAT_803ddd54 + 0x100);
  if (bVar1 == 0) {
    return 0;
  }
  if (bVar1 == 4) {
LAB_80214dc4:
    if (((*(float *)(param_1 + 0xc) - FLOAT_803e683c) - *(float *)(DAT_803ddd50 + 0x24) <=
         FLOAT_803e6844) &&
       (FLOAT_803e6844 <=
        (FLOAT_803e683c + *(float *)(param_1 + 0xc)) - *(float *)(DAT_803ddd50 + 0x24))) {
      return 1;
    }
    return 0;
  }
  if (bVar1 < 4) {
    if ((bVar1 < 3) && (bVar1 != 0)) {
      if (((*(float *)(param_1 + 0x14) - FLOAT_803e683c) - *(float *)(DAT_803ddd50 + 0x28) <=
           FLOAT_803e6840) &&
         (FLOAT_803e6840 <=
          (FLOAT_803e683c + *(float *)(param_1 + 0x14)) - *(float *)(DAT_803ddd50 + 0x28))) {
        return 1;
      }
      return 0;
    }
  }
  else if (bVar1 == 8) goto LAB_80214dc4;
  return 0;
}

