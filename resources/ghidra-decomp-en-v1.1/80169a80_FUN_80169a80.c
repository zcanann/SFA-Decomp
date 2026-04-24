// Function: FUN_80169a80
// Entry: 80169a80
// Size: 140 bytes

void FUN_80169a80(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  float *pfVar2;
  double dVar3;
  double dVar4;
  
  pfVar2 = *(float **)(param_9 + 0xb8);
  dVar4 = (double)*pfVar2;
  fVar1 = pfVar2[2];
  dVar3 = (double)fVar1;
  if (dVar4 != dVar3) {
    param_3 = (double)pfVar2[1];
    if (param_3 <= (double)FLOAT_803e3d6c) {
      if (dVar4 <= dVar3) {
        *pfVar2 = fVar1;
      }
      else {
        *pfVar2 = (float)(param_3 * (double)FLOAT_803dc074 + dVar4);
      }
    }
    else if (dVar3 <= dVar4) {
      *pfVar2 = fVar1;
    }
    else {
      *pfVar2 = (float)(param_3 * (double)FLOAT_803dc074 + dVar4);
    }
  }
  FUN_8003042c((double)*pfVar2,dVar4,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
               (uint)*(byte *)(pfVar2 + 3),0,param_12,param_13,param_14,param_15,param_16);
  return;
}

