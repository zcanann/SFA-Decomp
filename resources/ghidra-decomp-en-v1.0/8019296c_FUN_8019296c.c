// Function: FUN_8019296c
// Entry: 8019296c
// Size: 244 bytes

void FUN_8019296c(int param_1,int param_2)

{
  double dVar1;
  float fVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 0xb8);
  piVar3[6] = (int)*(char *)(param_2 + 0x20);
  *piVar3 = (int)*(short *)(param_2 + 0x18);
  piVar3[1] = (int)*(short *)(param_2 + 0x1a);
  piVar3[2] = (int)*(char *)(param_2 + 0x1c);
  piVar3[3] = (int)*(char *)(param_2 + 0x1d);
  dVar1 = DOUBLE_803e3f68;
  piVar3[4] = (int)(float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x1e) ^ 0x80000000)
                          - DOUBLE_803e3f68);
  piVar3[5] = (int)(float)((double)CONCAT44(0x43300000,(int)*(char *)(param_2 + 0x1f) ^ 0x80000000)
                          - dVar1);
  piVar3[7] = (int)*(char *)(param_2 + 0x21);
  piVar3[8] = (int)*(char *)(param_2 + 0x22);
  fVar2 = FLOAT_803e3f70;
  piVar3[0xb] = (int)FLOAT_803e3f70;
  piVar3[0xc] = (int)fVar2;
  if (DAT_803ddae8 == '\0') {
    FUN_801923f8();
  }
  FUN_80037200(param_1,0x1b);
  DAT_803ddae8 = DAT_803ddae8 + '\x01';
  return;
}

