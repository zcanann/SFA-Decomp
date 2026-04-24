// Function: FUN_8016032c
// Entry: 8016032c
// Size: 188 bytes

undefined4 FUN_8016032c(int param_1,int param_2)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,0);
    fVar1 = FLOAT_803e2e7c;
    *(float *)(param_1 + 0x28) = FLOAT_803e2e7c;
    *(float *)(param_2 + 0x280) = fVar1;
    *(float *)(param_2 + 0x294) = fVar1;
  }
  fVar1 = FLOAT_803e2e68;
  if (DOUBLE_803e2e80 <= (double)*(float *)(param_1 + 0x28)) {
    dVar3 = (double)FLOAT_803e2e88;
    *(float *)(param_1 + 0x28) = (float)((double)*(float *)(param_1 + 0x28) / dVar3);
    *(float *)(param_2 + 0x280) = (float)((double)*(float *)(param_2 + 0x280) / dVar3);
    *(float *)(param_2 + 0x294) = (float)((double)*(float *)(param_2 + 0x294) / dVar3);
    uVar2 = 0;
  }
  else {
    *(float *)(param_1 + 0x28) = FLOAT_803e2e68;
    *(float *)(param_2 + 0x280) = fVar1;
    *(float *)(param_2 + 0x294) = fVar1;
    uVar2 = 6;
  }
  return uVar2;
}

