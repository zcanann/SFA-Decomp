// Function: FUN_8006961c
// Entry: 8006961c
// Size: 808 bytes

void FUN_8006961c(uint *param_1,float *param_2,float *param_3,float *param_4,int param_5)

{
  double dVar1;
  double local_8;
  
  *param_1 = 1000000;
  param_1[3] = 0xfff0bdc0;
  param_1[1] = 1000000;
  param_1[4] = 0xfff0bdc0;
  param_1[2] = 1000000;
  param_1[5] = 0xfff0bdc0;
  dVar1 = DOUBLE_803decd8;
  if (param_5 != 0) {
    do {
      local_8 = (double)CONCAT44(0x43300000,*param_1 ^ 0x80000000);
      if (*param_2 - *param_4 < (float)(local_8 - dVar1)) {
        *param_1 = (int)(*param_2 - *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[3] ^ 0x80000000);
      if ((float)(local_8 - dVar1) < *param_2 + *param_4) {
        param_1[3] = (int)(*param_2 + *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[1] ^ 0x80000000);
      if (param_2[1] - *param_4 < (float)(local_8 - dVar1)) {
        param_1[1] = (int)(param_2[1] - *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[4] ^ 0x80000000);
      if ((float)(local_8 - dVar1) < param_2[1] + *param_4) {
        param_1[4] = (int)(param_2[1] + *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[2] ^ 0x80000000);
      if (param_2[2] - *param_4 < (float)(local_8 - dVar1)) {
        param_1[2] = (int)(param_2[2] - *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[5] ^ 0x80000000);
      if ((float)(local_8 - dVar1) < param_2[2] + *param_4) {
        param_1[5] = (int)(param_2[2] + *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,*param_1 ^ 0x80000000);
      if (*param_3 - *param_4 < (float)(local_8 - dVar1)) {
        *param_1 = (int)(*param_3 - *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[3] ^ 0x80000000);
      if ((float)(local_8 - dVar1) < *param_3 + *param_4) {
        param_1[3] = (int)(*param_3 + *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[1] ^ 0x80000000);
      if (param_3[1] - *param_4 < (float)(local_8 - dVar1)) {
        param_1[1] = (int)(param_3[1] - *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[4] ^ 0x80000000);
      if ((float)(local_8 - dVar1) < param_3[1] + *param_4) {
        param_1[4] = (int)(param_3[1] + *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[2] ^ 0x80000000);
      if (param_3[2] - *param_4 < (float)(local_8 - dVar1)) {
        param_1[2] = (int)(param_3[2] - *param_4);
      }
      local_8 = (double)CONCAT44(0x43300000,param_1[5] ^ 0x80000000);
      if ((float)(local_8 - dVar1) < param_3[2] + *param_4) {
        param_1[5] = (int)(param_3[2] + *param_4);
      }
      param_2 = param_2 + 3;
      param_3 = param_3 + 3;
      param_4 = param_4 + 1;
      param_5 = param_5 + -1;
    } while (param_5 != 0);
  }
  return;
}

