// Function: FUN_801f4d54
// Entry: 801f4d54
// Size: 376 bytes

void FUN_801f4d54(undefined4 param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  short sVar3;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  double local_20;
  undefined4 local_18;
  uint uStack20;
  
  *(float *)(param_2 + 0x34) = FLOAT_803e5ec4;
  if (*(char *)(param_2 + 0x6b) == '\0') {
    uVar2 = FUN_800221a0(0,(int)*(short *)(param_2 + 100));
    local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    *(float *)(param_2 + 0x38) = (float)(local_20 - DOUBLE_803e5ed0);
  }
  else {
    local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 100) ^ 0x80000000);
    *(float *)(param_2 + 0x38) = (float)(local_20 - DOUBLE_803e5ed0);
    *(undefined *)(param_2 + 0x6b) = 0;
  }
  if (FLOAT_803e5ec8 <= *(float *)(param_2 + 0x50)) {
    iVar1 = (int)*(float *)(param_2 + 0x50);
    local_20 = (double)(longlong)iVar1;
    uStack20 = FUN_800221a0(0x14,(int)(short)iVar1);
    uStack20 = uStack20 ^ 0x80000000;
    local_18 = 0x43300000;
    *(float *)(param_2 + 0x3c) =
         *(float *)(param_2 + 0x50) -
         (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e5ed0);
  }
  else {
    *(float *)(param_2 + 0x3c) = FLOAT_803e5ec4;
  }
  sVar3 = FUN_800221a0(3000,5000);
  *(short *)(param_2 + 0x60) = *(short *)(param_2 + 0x60) + sVar3;
  local_2c = FLOAT_803e5ec4;
  local_28 = FLOAT_803e5ec4;
  local_24 = FLOAT_803e5ec4;
  local_30 = FLOAT_803e5eb4;
  local_34 = 0;
  local_36 = 0;
  local_38 = *(undefined2 *)(param_2 + 0x60);
  FUN_80021ac8(&local_38,param_2 + 0x34);
  *(float *)(param_2 + 0x34) = *(float *)(param_2 + 0x34) + *(float *)(param_2 + 0x54);
  *(float *)(param_2 + 0x38) = *(float *)(param_2 + 0x38) + *(float *)(param_2 + 0x58);
  *(float *)(param_2 + 0x3c) = *(float *)(param_2 + 0x3c) + *(float *)(param_2 + 0x5c);
  return;
}

