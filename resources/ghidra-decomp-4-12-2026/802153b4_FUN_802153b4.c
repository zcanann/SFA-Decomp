// Function: FUN_802153b4
// Entry: 802153b4
// Size: 212 bytes

undefined4 FUN_802153b4(int param_1)

{
  byte bVar1;
  
  bVar1 = *(byte *)(DAT_803de9d4 + 0x100);
  if (bVar1 == 0) {
    return 0;
  }
  if (bVar1 == 4) {
LAB_8021543c:
    if (((*(float *)(param_1 + 0xc) - FLOAT_803e74d4) - *(float *)(DAT_803de9d0 + 0x24) <=
         FLOAT_803e74dc) &&
       (FLOAT_803e74dc <=
        (FLOAT_803e74d4 + *(float *)(param_1 + 0xc)) - *(float *)(DAT_803de9d0 + 0x24))) {
      return 1;
    }
    return 0;
  }
  if (bVar1 < 4) {
    if ((bVar1 < 3) && (bVar1 != 0)) {
      if (((*(float *)(param_1 + 0x14) - FLOAT_803e74d4) - *(float *)(DAT_803de9d0 + 0x28) <=
           FLOAT_803e74d8) &&
         (FLOAT_803e74d8 <=
          (FLOAT_803e74d4 + *(float *)(param_1 + 0x14)) - *(float *)(DAT_803de9d0 + 0x28))) {
        return 1;
      }
      return 0;
    }
  }
  else if (bVar1 == 8) goto LAB_8021543c;
  return 0;
}

