// Function: FUN_8021e53c
// Entry: 8021e53c
// Size: 220 bytes

int FUN_8021e53c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9,int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13
                ,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  int iVar2;
  
  fVar1 = FLOAT_803e7740;
  iVar2 = *(int *)(param_9 + 0xb8);
  *(float *)(param_10 + 0x294) = FLOAT_803e7740;
  *(float *)(param_10 + 0x284) = fVar1;
  *(float *)(param_10 + 0x280) = fVar1;
  *(float *)(param_9 + 0x24) = fVar1;
  *(float *)(param_9 + 0x28) = fVar1;
  *(float *)(param_9 + 0x2c) = fVar1;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8002f66c(param_9,0x78);
    if (*(int *)(iVar2 + 0xc3c) == 4) {
      FUN_8003042c((double)FLOAT_803e7740,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x13,0,param_12,param_13,param_14,param_15,param_16);
      *(float *)(param_10 + 0x2a0) = FLOAT_803e7760;
    }
    else {
      FUN_8003042c((double)FLOAT_803e7740,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0x13,0,param_12,param_13,param_14,param_15,param_16);
      *(float *)(param_10 + 0x2a0) = FLOAT_803e7760;
    }
  }
  if (*(float *)(param_9 + 0x98) <= FLOAT_803e7798) {
    iVar2 = 0;
  }
  else {
    iVar2 = *(int *)(iVar2 + 0xc3c) + 1;
  }
  return iVar2;
}

