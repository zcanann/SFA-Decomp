// Function: FUN_8001d6e4
// Entry: 8001d6e4
// Size: 144 bytes

void FUN_8001d6e4(int param_1,int param_2,short param_3)

{
  float fVar1;
  
  *(int *)(param_1 + 0x2d8) = param_2;
  if (param_2 != 0) {
    fVar1 = FLOAT_803df3e0;
    if ((int)param_3 != 0) {
      fVar1 = (float)((double)CONCAT44(0x43300000,(int)param_3 ^ 0x80000000) - DOUBLE_803df400);
    }
    *(float *)(param_1 + 0x2dc) = FLOAT_803df3e0 / fVar1;
    *(undefined *)(param_1 + 0xac) = *(undefined *)(param_1 + 0xa8);
    *(undefined *)(param_1 + 0xad) = *(undefined *)(param_1 + 0xa9);
    *(undefined *)(param_1 + 0xae) = *(undefined *)(param_1 + 0xaa);
    *(undefined *)(param_1 + 0x104) = *(undefined *)(param_1 + 0x100);
    *(undefined *)(param_1 + 0x105) = *(undefined *)(param_1 + 0x101);
    *(undefined *)(param_1 + 0x106) = *(undefined *)(param_1 + 0x102);
    fVar1 = FLOAT_803df3dc;
    *(float *)(param_1 + 0x2e0) = FLOAT_803df3dc;
    *(float *)(param_1 + 0x2e4) = fVar1;
  }
  return;
}

