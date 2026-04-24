// Function: FUN_80021370
// Entry: 80021370
// Size: 96 bytes

/* WARNING: Removing unreachable block (ram,0x800213b8) */

double FUN_80021370(double param_1,double param_2,undefined8 param_3)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  undefined8 in_f31;
  undefined auStack8 [8];
  
  uVar2 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  fVar1 = FLOAT_803de7c0;
  if (param_2 <= (double)FLOAT_803de7c4) {
    dVar3 = (double)FUN_80292b44((double)(float)((double)FLOAT_803de7c4 - param_2),param_3);
    fVar1 = (float)(param_1 * (double)(float)((double)FLOAT_803de7c4 - dVar3));
  }
  __psq_l0(auStack8,uVar2);
  __psq_l1(auStack8,uVar2);
  return (double)fVar1;
}

