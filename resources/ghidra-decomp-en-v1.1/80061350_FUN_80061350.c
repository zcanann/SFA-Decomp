// Function: FUN_80061350
// Entry: 80061350
// Size: 392 bytes

void FUN_80061350(double param_1,float *param_2,float *param_3,uint *param_4)

{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  int iVar5;
  undefined8 local_8;
  
  *param_4 = 0x7fffffff;
  param_4[3] = 0x80000000;
  param_4[1] = 0x7fffffff;
  param_4[4] = 0x80000000;
  param_4[2] = 0x7fffffff;
  param_4[5] = 0x80000000;
  dVar4 = DOUBLE_803df8e0;
  iVar5 = 8;
  do {
    dVar1 = param_1 * (double)*param_2 + (double)*param_3;
    dVar2 = param_1 * (double)param_2[1] + (double)param_3[1];
    dVar3 = param_1 * (double)param_2[2] + (double)param_3[2];
    local_8 = (double)CONCAT44(0x43300000,*param_4 ^ 0x80000000);
    if ((float)dVar1 < (float)(local_8 - dVar4)) {
      *param_4 = (int)dVar1;
    }
    local_8 = (double)CONCAT44(0x43300000,param_4[3] ^ 0x80000000);
    if ((float)(local_8 - dVar4) < (float)dVar1) {
      param_4[3] = (int)dVar1;
    }
    local_8 = (double)CONCAT44(0x43300000,param_4[1] ^ 0x80000000);
    if ((float)dVar2 < (float)(local_8 - dVar4)) {
      param_4[1] = (int)dVar2;
    }
    local_8 = (double)CONCAT44(0x43300000,param_4[4] ^ 0x80000000);
    if ((float)(local_8 - dVar4) < (float)dVar2) {
      param_4[4] = (int)dVar2;
    }
    local_8 = (double)CONCAT44(0x43300000,param_4[2] ^ 0x80000000);
    if ((float)dVar3 < (float)(local_8 - dVar4)) {
      param_4[2] = (int)dVar3;
    }
    local_8 = (double)CONCAT44(0x43300000,param_4[5] ^ 0x80000000);
    if ((float)(local_8 - dVar4) < (float)dVar3) {
      param_4[5] = (int)dVar3;
    }
    param_2 = param_2 + 3;
    iVar5 = iVar5 + -1;
  } while (iVar5 != 0);
  return;
}

