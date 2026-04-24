// Function: FUN_802472e4
// Entry: 802472e4
// Size: 52 bytes

void FUN_802472e4(double param_1,double param_2,double param_3,float *param_4)

{
  float fVar1;
  float fVar2;
  undefined4 uVar3;
  double dVar4;
  undefined4 uVar5;
  
  fVar2 = FLOAT_803e761c;
  fVar1 = FLOAT_803e7618;
  dVar4 = (double)FLOAT_803e761c;
  param_4[3] = (float)param_1;
  param_4[7] = (float)param_2;
  uVar3 = (undefined4)((ulonglong)dVar4 >> 0x20);
  __psq_st0(param_4 + 1,uVar3,0);
  uVar5 = SUB84(dVar4,0);
  __psq_st1(param_4 + 1,uVar5,0);
  __psq_st0(param_4 + 8,uVar3,0);
  __psq_st1(param_4 + 8,uVar5,0);
  param_4[4] = fVar2;
  param_4[5] = fVar1;
  param_4[6] = fVar2;
  param_4[10] = fVar1;
  param_4[0xb] = (float)param_3;
  *param_4 = fVar1;
  return;
}

