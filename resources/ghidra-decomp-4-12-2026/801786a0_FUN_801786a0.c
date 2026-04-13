// Function: FUN_801786a0
// Entry: 801786a0
// Size: 212 bytes

void FUN_801786a0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  float *pfVar2;
  double dVar3;
  
  pfVar2 = *(float **)(param_9 + 0xb8);
  *pfVar2 = *pfVar2 + FLOAT_803dc074;
  dVar3 = (double)*pfVar2;
  if (dVar3 <= (double)FLOAT_803e42c8) {
    if (((double)FLOAT_803e42cc < dVar3) && (*(char *)((int)pfVar2 + 0x11) == '\0')) {
      FUN_80035eec(param_9,0x1a,1,0);
    }
  }
  else {
    *pfVar2 = (float)(dVar3 - (double)FLOAT_803e42c8);
    iVar1 = FUN_80178508(dVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         (int)pfVar2);
    if (iVar1 == 0) {
      return;
    }
  }
  *(float *)(param_9 + 0xc) = *(float *)(param_9 + 0x24) * *pfVar2 + pfVar2[1];
  *(float *)(param_9 + 0x10) = *(float *)(param_9 + 0x28) * *pfVar2 + pfVar2[2];
  *(float *)(param_9 + 0x14) = *(float *)(param_9 + 0x2c) * *pfVar2 + pfVar2[3];
  return;
}

