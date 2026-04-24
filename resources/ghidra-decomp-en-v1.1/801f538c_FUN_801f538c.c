// Function: FUN_801f538c
// Entry: 801f538c
// Size: 376 bytes

void FUN_801f538c(undefined4 param_1,int param_2)

{
  int iVar1;
  uint uVar2;
  ushort local_38 [4];
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined8 local_20;
  undefined4 local_18;
  uint uStack_14;
  
  *(float *)(param_2 + 0x34) = FLOAT_803e6b5c;
  if (*(char *)(param_2 + 0x6b) == '\0') {
    uVar2 = FUN_80022264(0,(int)*(short *)(param_2 + 100));
    local_20 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    *(float *)(param_2 + 0x38) = (float)(local_20 - DOUBLE_803e6b68);
  }
  else {
    local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(param_2 + 100) ^ 0x80000000);
    *(float *)(param_2 + 0x38) = (float)(local_20 - DOUBLE_803e6b68);
    *(undefined *)(param_2 + 0x6b) = 0;
  }
  if (FLOAT_803e6b60 <= *(float *)(param_2 + 0x50)) {
    iVar1 = (int)*(float *)(param_2 + 0x50);
    local_20 = (double)(longlong)iVar1;
    uStack_14 = FUN_80022264(0x14,(int)(short)iVar1);
    uStack_14 = uStack_14 ^ 0x80000000;
    local_18 = 0x43300000;
    *(float *)(param_2 + 0x3c) =
         *(float *)(param_2 + 0x50) -
         (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e6b68);
  }
  else {
    *(float *)(param_2 + 0x3c) = FLOAT_803e6b5c;
  }
  uVar2 = FUN_80022264(3000,5000);
  *(short *)(param_2 + 0x60) = *(short *)(param_2 + 0x60) + (short)uVar2;
  local_2c = FLOAT_803e6b5c;
  local_28 = FLOAT_803e6b5c;
  local_24 = FLOAT_803e6b5c;
  local_30 = FLOAT_803e6b4c;
  local_38[2] = 0;
  local_38[1] = 0;
  local_38[0] = *(ushort *)(param_2 + 0x60);
  FUN_80021b8c(local_38,(float *)(param_2 + 0x34));
  *(float *)(param_2 + 0x34) = *(float *)(param_2 + 0x34) + *(float *)(param_2 + 0x54);
  *(float *)(param_2 + 0x38) = *(float *)(param_2 + 0x38) + *(float *)(param_2 + 0x58);
  *(float *)(param_2 + 0x3c) = *(float *)(param_2 + 0x3c) + *(float *)(param_2 + 0x5c);
  return;
}

