// Function: FUN_8005eaa4
// Entry: 8005eaa4
// Size: 476 bytes

undefined4
FUN_8005eaa4(int param_1,int param_2,float *param_3,int param_4,float *param_5,float *param_6,
            float *param_7,float *param_8,float *param_9,float *param_10)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  double dVar8;
  
  dVar8 = DOUBLE_803debc0;
  *param_8 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xc) >> 3 ^ 0x80000000) -
                    DOUBLE_803debc0) + *(float *)(param_2 + 0x18);
  *param_5 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 6) >> 3 ^ 0x80000000) -
                    dVar8) + *(float *)(param_2 + 0x18);
  *param_9 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0xe) >> 3 ^ 0x80000000) -
                    dVar8) + *(float *)(param_2 + 0x28);
  *param_6 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 8) >> 3 ^ 0x80000000) -
                    dVar8) + *(float *)(param_2 + 0x28);
  *param_10 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 0x10) >> 3 ^ 0x80000000)
                     - dVar8) + *(float *)(param_2 + 0x38);
  *param_7 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 10) >> 3 ^ 0x80000000) -
                    dVar8) + *(float *)(param_2 + 0x38);
  if (0 < param_4) {
    do {
      bVar1 = *(byte *)(param_3 + 4);
      if ((bVar1 & 1) == 0) {
        fVar2 = *param_5;
        fVar3 = *param_8;
      }
      else {
        fVar2 = *param_8;
        fVar3 = *param_5;
      }
      if ((bVar1 & 2) == 0) {
        fVar4 = *param_6;
        fVar5 = *param_9;
      }
      else {
        fVar4 = *param_9;
        fVar5 = *param_6;
      }
      if ((bVar1 & 4) == 0) {
        fVar6 = *param_7;
        fVar7 = *param_10;
      }
      else {
        fVar6 = *param_10;
        fVar7 = *param_7;
      }
      if ((param_3[3] + fVar6 * param_3[2] + fVar2 * *param_3 + fVar4 * param_3[1] < FLOAT_803debcc)
         && (param_3[3] + fVar7 * param_3[2] + fVar3 * *param_3 + fVar5 * param_3[1] <
             FLOAT_803debcc)) {
        return 0;
      }
      param_3 = param_3 + 5;
      param_4 = param_4 + -1;
    } while (param_4 != 0);
  }
  return 1;
}

