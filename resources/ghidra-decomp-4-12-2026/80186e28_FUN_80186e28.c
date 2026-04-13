// Function: FUN_80186e28
// Entry: 80186e28
// Size: 268 bytes

void FUN_80186e28(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  ushort local_38 [4];
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined8 local_20;
  undefined4 local_18;
  uint uStack_14;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar3 + 0x34) = FLOAT_803e4750;
  uVar2 = FUN_80022264(-(int)*(short *)(iVar3 + 0x68),(int)*(short *)(iVar3 + 0x68));
  local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
  *(float *)(iVar3 + 0x38) = (float)(local_20 - DOUBLE_803e4748);
  if (FLOAT_803e4754 <= *(float *)(iVar3 + 0x50)) {
    iVar1 = (int)*(float *)(iVar3 + 0x50);
    local_20 = (double)(longlong)iVar1;
    uStack_14 = FUN_80022264(0x14,(int)(short)iVar1);
    uStack_14 = uStack_14 ^ 0x80000000;
    local_18 = 0x43300000;
    *(float *)(iVar3 + 0x3c) =
         *(float *)(iVar3 + 0x50) -
         (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e4748);
  }
  else {
    *(float *)(iVar3 + 0x3c) = FLOAT_803e4750;
  }
  uVar2 = FUN_80022264(3000,5000);
  *(short *)(iVar3 + 100) = *(short *)(iVar3 + 100) + (short)uVar2;
  local_2c = FLOAT_803e4750;
  local_28 = FLOAT_803e4750;
  local_24 = FLOAT_803e4750;
  local_30 = FLOAT_803e4738;
  local_38[2] = 0;
  local_38[1] = 0;
  local_38[0] = *(ushort *)(iVar3 + 100);
  FUN_80021b8c(local_38,(float *)(iVar3 + 0x34));
  return;
}

