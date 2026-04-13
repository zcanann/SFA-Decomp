// Function: FUN_80012d20
// Entry: 80012d20
// Size: 268 bytes

void FUN_80012d20(float *param_1,short *param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  float local_38;
  float local_34;
  float local_30 [11];
  
  local_30[0] = *param_1;
  local_34 = param_1[1];
  local_38 = param_1[2];
  if (DAT_803dd54c != 0) {
    FUN_8000e054((double)local_30[0],(double)local_34,(double)local_38,local_30,&local_34,&local_38,
                 DAT_803dd54c);
  }
  iVar1 = (int)local_30[0];
  iVar2 = (int)local_34;
  iVar3 = (int)local_38;
  if (local_30[0] < FLOAT_803df330) {
    iVar1 = iVar1 + -10;
  }
  if (local_34 < FLOAT_803df330) {
    iVar2 = iVar2 + -10;
  }
  if (local_38 < FLOAT_803df330) {
    iVar3 = iVar3 + -10;
  }
  iVar1 = iVar1 / 10 + (iVar1 >> 0x1f);
  *param_2 = (short)iVar1 - (short)(iVar1 >> 0x1f);
  iVar1 = iVar2 / 10 + (iVar2 >> 0x1f);
  param_2[1] = (short)iVar1 - (short)(iVar1 >> 0x1f);
  iVar1 = iVar3 / 10 + (iVar3 >> 0x1f);
  param_2[2] = (short)iVar1 - (short)(iVar1 >> 0x1f);
  return;
}

