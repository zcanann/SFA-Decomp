// Function: FUN_8016176c
// Entry: 8016176c
// Size: 276 bytes

bool FUN_8016176c(short *param_1,int param_2)

{
  short sVar1;
  float fVar2;
  int iVar3;
  
  iVar3 = *(int *)(*(int *)(param_1 + 0x5c) + 0x40c);
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_80030334((double)FLOAT_803e2eb8,param_1,7,0);
    *(undefined *)(param_2 + 0x346) = 0;
  }
  if (*(char *)(param_2 + 0x27a) != '\0') {
    FUN_8000bb18(param_1,0x27a);
  }
  *(float *)(param_2 + 0x2a0) = FLOAT_803e2eec;
  sVar1 = *(short *)(iVar3 + 0x58);
  iVar3 = (int)*param_1 - ((int)sVar1 & 0xffffU);
  if (0x8000 < iVar3) {
    iVar3 = iVar3 + -0xffff;
  }
  if (iVar3 < -0x8000) {
    iVar3 = iVar3 + 0xffff;
  }
  *param_1 = sVar1;
  if ((0x3ffc < iVar3) || (iVar3 < -0x3ffc)) {
    *param_1 = *param_1 + -0x8000;
  }
  fVar2 = FLOAT_803e2eb8;
  *(float *)(param_2 + 0x280) = FLOAT_803e2eb8;
  *(float *)(param_2 + 0x284) = fVar2;
  return *(char *)(param_2 + 0x346) != '\0';
}

