// Function: FUN_801a5544
// Entry: 801a5544
// Size: 680 bytes

void FUN_801a5544(undefined2 *param_1,int param_2,int param_3)

{
  float fVar1;
  double dVar2;
  int iVar3;
  uint uVar4;
  float local_48 [2];
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  local_48[0] = FLOAT_803e5088;
  *param_1 = *(undefined2 *)(param_3 + 0x1a);
  param_1[1] = *(undefined2 *)(param_3 + 0x1c);
  param_1[2] = *(undefined2 *)(param_3 + 0x1e);
  dVar2 = DOUBLE_803e50a8;
  fVar1 = FLOAT_803e5098;
  uStack_3c = (int)*(short *)(param_3 + 0x20) ^ 0x80000000;
  local_40 = 0x43300000;
  *(float *)(param_1 + 0x12) =
       (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e50a8) / FLOAT_803e5098;
  uStack_34 = (int)*(short *)(param_3 + 0x22) ^ 0x80000000;
  local_38 = 0x43300000;
  *(float *)(param_1 + 0x14) = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar2) / fVar1;
  uStack_2c = (int)*(short *)(param_3 + 0x24) ^ 0x80000000;
  local_30 = 0x43300000;
  *(float *)(param_1 + 0x16) = (float)((double)CONCAT44(0x43300000,uStack_2c) - dVar2) / fVar1;
  uStack_24 = (int)*(short *)(param_3 + 0x2c) ^ 0x80000000;
  local_28 = 0x43300000;
  *(float *)(param_2 + 0x18) = (float)((double)CONCAT44(0x43300000,uStack_24) - dVar2);
  uStack_1c = (int)*(short *)(param_3 + 0x2e) ^ 0x80000000;
  local_20 = 0x43300000;
  *(float *)(param_2 + 0x1c) = (float)((double)CONCAT44(0x43300000,uStack_1c) - dVar2);
  uStack_14 = (int)*(short *)(param_3 + 0x30) ^ 0x80000000;
  local_18 = 0x43300000;
  *(float *)(param_2 + 0x20) = (float)((double)CONCAT44(0x43300000,uStack_14) - dVar2);
  if (*(short *)(param_3 + 0x3a) == 0) {
    FUN_80065800((double)*(float *)(param_1 + 6),(double)(*(float *)(param_1 + 8) - FLOAT_803e509c),
                 (double)*(float *)(param_1 + 10),param_1,local_48,0);
    *(float *)(param_2 + 0x54) = *(float *)(param_1 + 8) - local_48[0];
  }
  else {
    *(float *)(param_2 + 0x54) =
         *(float *)(param_1 + 8) +
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x3a) ^ 0x80000000) - dVar2);
  }
  dVar2 = DOUBLE_803e50a8;
  fVar1 = FLOAT_803e509c;
  uStack_14 = (int)*(short *)(param_3 + 0x32) ^ 0x80000000;
  local_18 = 0x43300000;
  *(float *)(param_2 + 0x24) =
       (float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e50a8) / FLOAT_803e509c;
  uStack_1c = (int)*(short *)(param_3 + 0x34) ^ 0x80000000;
  local_20 = 0x43300000;
  *(float *)(param_2 + 0x28) = (float)((double)CONCAT44(0x43300000,uStack_1c) - dVar2) / fVar1;
  uStack_24 = (int)*(short *)(param_3 + 0x36) ^ 0x80000000;
  local_28 = 0x43300000;
  *(float *)(param_2 + 0x2c) = (float)((double)CONCAT44(0x43300000,uStack_24) - dVar2) / fVar1;
  fVar1 = FLOAT_803e50a0;
  uStack_2c = (int)*(short *)(param_3 + 0x26) ^ 0x80000000;
  local_30 = 0x43300000;
  *(float *)(param_2 + 0x30) =
       (float)((double)CONCAT44(0x43300000,uStack_2c) - dVar2) / FLOAT_803e50a0;
  uStack_34 = (int)*(short *)(param_3 + 0x28) ^ 0x80000000;
  local_38 = 0x43300000;
  *(float *)(param_2 + 0x34) = (float)((double)CONCAT44(0x43300000,uStack_34) - dVar2) / fVar1;
  uStack_3c = (int)*(short *)(param_3 + 0x2a) ^ 0x80000000;
  local_40 = 0x43300000;
  *(float *)(param_2 + 0x38) = (float)((double)CONCAT44(0x43300000,uStack_3c) - dVar2) / fVar1;
  *(undefined4 *)(param_2 + 0x58) = 0;
  if (*(short *)(param_3 + 0x38) == 0) {
    *(undefined4 *)(param_2 + 0x5c) = 0xffffffff;
  }
  else {
    uVar4 = FUN_80022264(0,100);
    iVar3 = (uint)*(ushort *)(param_3 + 0x38) * (uVar4 + 100);
    iVar3 = iVar3 / 200 + (iVar3 >> 0x1f);
    *(int *)(param_2 + 0x5c) = iVar3 - (iVar3 >> 0x1f);
  }
  return;
}

