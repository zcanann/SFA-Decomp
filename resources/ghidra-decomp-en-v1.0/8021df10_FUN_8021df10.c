// Function: FUN_8021df10
// Entry: 8021df10
// Size: 220 bytes

int FUN_8021df10(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  
  fVar1 = FLOAT_803e6aa8;
  iVar2 = *(int *)(param_1 + 0xb8);
  *(float *)(param_2 + 0x294) = FLOAT_803e6aa8;
  *(float *)(param_2 + 0x284) = fVar1;
  *(float *)(param_2 + 0x280) = fVar1;
  *(float *)(param_1 + 0x24) = fVar1;
  *(float *)(param_1 + 0x28) = fVar1;
  *(float *)(param_1 + 0x2c) = fVar1;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_8002f574(param_1,0x78);
    if (*(int *)(iVar2 + 0xc3c) == 4) {
      FUN_80030334((double)FLOAT_803e6aa8,param_1,0x13,0);
      *(float *)(param_2 + 0x2a0) = FLOAT_803e6ac8;
    }
    else {
      FUN_80030334((double)FLOAT_803e6aa8,param_1,0x13,0);
      *(float *)(param_2 + 0x2a0) = FLOAT_803e6ac8;
    }
  }
  if (*(float *)(param_1 + 0x98) <= FLOAT_803e6b00) {
    iVar2 = 0;
  }
  else {
    iVar2 = *(int *)(iVar2 + 0xc3c) + 1;
  }
  return iVar2;
}

