// Function: FUN_801868d0
// Entry: 801868d0
// Size: 268 bytes

void FUN_801868d0(int param_1)

{
  int iVar1;
  uint uVar2;
  short sVar3;
  int iVar4;
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
  
  iVar4 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar4 + 0x34) = FLOAT_803e3ab8;
  uVar2 = FUN_800221a0(-(int)*(short *)(iVar4 + 0x68));
  local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
  *(float *)(iVar4 + 0x38) = (float)(local_20 - DOUBLE_803e3ab0);
  if (FLOAT_803e3abc <= *(float *)(iVar4 + 0x50)) {
    iVar1 = (int)*(float *)(iVar4 + 0x50);
    local_20 = (double)(longlong)iVar1;
    uStack20 = FUN_800221a0(0x14,(int)(short)iVar1);
    uStack20 = uStack20 ^ 0x80000000;
    local_18 = 0x43300000;
    *(float *)(iVar4 + 0x3c) =
         *(float *)(iVar4 + 0x50) - (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e3ab0)
    ;
  }
  else {
    *(float *)(iVar4 + 0x3c) = FLOAT_803e3ab8;
  }
  sVar3 = FUN_800221a0(3000,5000);
  *(short *)(iVar4 + 100) = *(short *)(iVar4 + 100) + sVar3;
  local_2c = FLOAT_803e3ab8;
  local_28 = FLOAT_803e3ab8;
  local_24 = FLOAT_803e3ab8;
  local_30 = FLOAT_803e3aa0;
  local_34 = 0;
  local_36 = 0;
  local_38 = *(undefined2 *)(iVar4 + 100);
  FUN_80021ac8(&local_38,iVar4 + 0x34);
  return;
}

