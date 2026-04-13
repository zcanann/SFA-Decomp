// Function: FUN_801e586c
// Entry: 801e586c
// Size: 560 bytes

void FUN_801e586c(short *param_1)

{
  int iVar1;
  double dVar2;
  undefined8 uVar3;
  double dVar4;
  double dVar5;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined2 local_38;
  undefined2 local_36;
  undefined2 local_34;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  longlong local_10;
  
  *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803dc074 + *(float *)(param_1 + 6);
  *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803dc074 + *(float *)(param_1 + 8);
  *(float *)(param_1 + 10) = *(float *)(param_1 + 0x16) * FLOAT_803dc074 + *(float *)(param_1 + 10);
  local_2c = FLOAT_803e65c4;
  local_28 = FLOAT_803e65c4;
  local_24 = FLOAT_803e65c4;
  local_30 = FLOAT_803e65c0;
  if ((int)*(uint *)(param_1 + 0x7a) < 0x3d) {
    uStack_1c = *(uint *)(param_1 + 0x7a) ^ 0x80000000;
    local_20 = 0x43300000;
    local_30 = (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e65d8) / FLOAT_803e65c8;
    local_18 = 0x43300000;
    iVar1 = (int)(FLOAT_803e65cc *
                 ((float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803e65d8) / FLOAT_803e65c8
                 ));
    local_10 = (longlong)iVar1;
    *(char *)(param_1 + 0x1b) = (char)iVar1;
    uStack_14 = uStack_1c;
  }
  local_34 = 0;
  local_36 = 0;
  local_38 = 0;
  (**(code **)(*DAT_803dd708 + 8))(param_1,0xa0,&local_38,1,0xffffffff,0);
  dVar4 = (double)(*(float *)(param_1 + 8) - *(float *)(param_1 + 0x42));
  dVar5 = (double)(*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44));
  dVar2 = (double)FLOAT_803e65d0;
  local_2c = (float)((double)(*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40)) / dVar2);
  local_28 = (float)(dVar4 / dVar2);
  local_24 = (float)(dVar5 / dVar2);
  (**(code **)(*DAT_803dd708 + 8))(param_1,0xa0,&local_38,1,0xffffffff,0);
  local_2c = local_2c * FLOAT_803e65d4;
  local_28 = local_28 * FLOAT_803e65d4;
  local_24 = local_24 * FLOAT_803e65d4;
  uVar3 = (**(code **)(*DAT_803dd708 + 8))(param_1,0xa0,&local_38,1,0xffffffff,0);
  *param_1 = *param_1 + (ushort)DAT_803dc070 * 0x374;
  param_1[1] = param_1[1] + (ushort)DAT_803dc070 * 300;
  *(uint *)(param_1 + 0x7a) = *(int *)(param_1 + 0x7a) - (uint)DAT_803dc070;
  if (*(int *)(param_1 + 0x7a) < 0) {
    FUN_8002cc9c(uVar3,dVar4,dVar5,in_f4,in_f5,in_f6,in_f7,in_f8,(int)param_1);
  }
  return;
}

