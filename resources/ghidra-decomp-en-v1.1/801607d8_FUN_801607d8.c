// Function: FUN_801607d8
// Entry: 801607d8
// Size: 188 bytes

undefined4 FUN_801607d8(int param_1,int param_2)

{
  float fVar1;
  undefined4 uVar2;
  double dVar3;
  
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
    fVar1 = FLOAT_803e3b14;
    *(float *)(param_1 + 0x28) = FLOAT_803e3b14;
    *(float *)(param_2 + 0x280) = fVar1;
    *(float *)(param_2 + 0x294) = fVar1;
  }
  fVar1 = FLOAT_803e3b00;
  if (DOUBLE_803e3b18 <= (double)*(float *)(param_1 + 0x28)) {
    dVar3 = (double)FLOAT_803e3b20;
    *(float *)(param_1 + 0x28) = (float)((double)*(float *)(param_1 + 0x28) / dVar3);
    *(float *)(param_2 + 0x280) = (float)((double)*(float *)(param_2 + 0x280) / dVar3);
    *(float *)(param_2 + 0x294) = (float)((double)*(float *)(param_2 + 0x294) / dVar3);
    uVar2 = 0;
  }
  else {
    *(float *)(param_1 + 0x28) = FLOAT_803e3b00;
    *(float *)(param_2 + 0x280) = fVar1;
    *(float *)(param_2 + 0x294) = fVar1;
    uVar2 = 6;
  }
  return uVar2;
}

