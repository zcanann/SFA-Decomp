// Function: FUN_801f8640
// Entry: 801f8640
// Size: 176 bytes

void FUN_801f8640(ushort *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  float local_38;
  undefined4 local_34;
  undefined4 local_30;
  ushort local_2c [4];
  float local_24;
  float local_20;
  float local_1c;
  float local_18;
  
  local_38 = *(float *)(param_2 + 4);
  local_34 = *(undefined4 *)(param_2 + 8);
  local_30 = *(undefined4 *)(param_2 + 0xc);
  local_20 = FLOAT_803e6c48;
  local_1c = FLOAT_803e6c48;
  local_18 = FLOAT_803e6c48;
  local_24 = FLOAT_803e6c4c;
  local_2c[2] = 0;
  local_2c[1] = 0;
  local_2c[0] = *param_1;
  FUN_80021b8c(local_2c,&local_38);
  iVar1 = FUN_80021884();
  iVar2 = FUN_80021884();
  param_1[1] = (ushort)iVar2;
  param_1[2] = (ushort)iVar1;
  return;
}

