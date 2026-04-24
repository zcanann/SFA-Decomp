// Function: FUN_8022fcd8
// Entry: 8022fcd8
// Size: 296 bytes

undefined4 FUN_8022fcd8(int param_1,char *param_2,int param_3)

{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  
  if (((byte)param_2[0x14] >> 4 & 1) == 0) {
    if ((*(float *)(param_1 + 0x14) - *(float *)(param_3 + 0x14) <= FLOAT_803e70a0) &&
       (FLOAT_803e70a0 <= *(float *)(param_1 + 0x14) - *(float *)(param_3 + 0x88))) {
      fVar1 = *(float *)(param_1 + 0xc) - *(float *)(param_3 + 0xc);
      fVar2 = *(float *)(param_1 + 0x10) - *(float *)(param_3 + 0x10);
      dVar4 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
      if (dVar4 < (double)FLOAT_803e70ac) {
        return 1;
      }
      if ((*param_2 == '\x02') && (((byte)param_2[0x14] >> 5 & 1) != 0)) {
        FUN_80125ba4(10);
      }
    }
  }
  else {
    fVar1 = *(float *)(param_1 + 0xc) - *(float *)(param_3 + 0xc);
    fVar2 = *(float *)(param_1 + 0x10) - *(float *)(param_3 + 0x10);
    if (fVar2 < FLOAT_803e70a0) {
      fVar2 = -fVar2;
    }
    fVar3 = *(float *)(param_1 + 0x14) - *(float *)(param_3 + 0x14);
    if ((fVar2 <= FLOAT_803e70a4) && (fVar1 * fVar1 + fVar3 * fVar3 < FLOAT_803e70a8)) {
      return 1;
    }
  }
  return 0;
}

