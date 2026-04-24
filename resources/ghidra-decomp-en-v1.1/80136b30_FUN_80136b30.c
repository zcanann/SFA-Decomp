// Function: FUN_80136b30
// Entry: 80136b30
// Size: 252 bytes

void FUN_80136b30(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  int iVar2;
  double dVar3;
  
  iVar2 = *(int *)(param_9 + 0x5c);
  *(undefined *)(iVar2 + 0x30) = 0;
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  sVar1 = param_9[0x23];
  if ((sVar1 < 0x77d) || (0x780 < sVar1)) {
    dVar3 = (double)FLOAT_803e2f88;
    *(float *)(iVar2 + 0x34) = FLOAT_803e2f88;
    *(undefined *)(iVar2 + 0x31) = 0xfe;
    if (param_9[0x23] == 0x78a) {
      FUN_8003042c(dVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,0,
                   param_12,param_13,param_14,param_15,param_16);
    }
    else if (param_9[0x23] == 0x781) {
      FUN_8003042c((double)FLOAT_803e2fa8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0,0,param_12,param_13,param_14,param_15,param_16);
      FUN_80028600(**(int **)(param_9 + 0x3e),FUN_8011853c);
    }
  }
  else {
    *(char *)(iVar2 + 0x31) = (char)sVar1 + -0x7d;
    *(undefined4 *)(iVar2 + 0x34) = *(undefined4 *)(&DAT_8030eac0 + (short)param_9[0x23] * 0x20);
    FUN_8003042c((double)FLOAT_803e2f88,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  }
  return;
}

