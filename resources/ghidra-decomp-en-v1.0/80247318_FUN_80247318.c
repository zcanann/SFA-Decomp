// Function: FUN_80247318
// Entry: 80247318
// Size: 40 bytes

void FUN_80247318(double param_1,double param_2,double param_3,float *param_4)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  undefined4 uVar4;
  
  fVar1 = FLOAT_803e761c;
  dVar3 = (double)FLOAT_803e761c;
  *param_4 = (float)param_1;
  uVar2 = (undefined4)((ulonglong)dVar3 >> 0x20);
  __psq_st0(param_4 + 1,uVar2,0);
  uVar4 = SUB84(dVar3,0);
  __psq_st1(param_4 + 1,uVar4,0);
  __psq_st0(param_4 + 3,uVar2,0);
  __psq_st1(param_4 + 3,uVar4,0);
  param_4[5] = (float)param_2;
  __psq_st0(param_4 + 6,uVar2,0);
  __psq_st1(param_4 + 6,uVar4,0);
  __psq_st0(param_4 + 8,uVar2,0);
  __psq_st1(param_4 + 8,uVar4,0);
  param_4[10] = (float)param_3;
  param_4[0xb] = fVar1;
  return;
}

