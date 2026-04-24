// Function: FUN_8001d620
// Entry: 8001d620
// Size: 144 bytes

void FUN_8001d620(int param_1,int param_2,short param_3)

{
  float fVar1;
  
  *(int *)(param_1 + 0x2d8) = param_2;
  if (param_2 != 0) {
    fVar1 = FLOAT_803de760;
    if ((int)param_3 != 0) {
      fVar1 = (float)((double)CONCAT44(0x43300000,(int)param_3 ^ 0x80000000) - DOUBLE_803de780);
    }
    *(float *)(param_1 + 0x2dc) = FLOAT_803de760 / fVar1;
    *(undefined *)(param_1 + 0xac) = *(undefined *)(param_1 + 0xa8);
    *(undefined *)(param_1 + 0xad) = *(undefined *)(param_1 + 0xa9);
    *(undefined *)(param_1 + 0xae) = *(undefined *)(param_1 + 0xaa);
    *(undefined *)(param_1 + 0x104) = *(undefined *)(param_1 + 0x100);
    *(undefined *)(param_1 + 0x105) = *(undefined *)(param_1 + 0x101);
    *(undefined *)(param_1 + 0x106) = *(undefined *)(param_1 + 0x102);
    fVar1 = FLOAT_803de75c;
    *(float *)(param_1 + 0x2e0) = FLOAT_803de75c;
    *(float *)(param_1 + 0x2e4) = fVar1;
  }
  return;
}

