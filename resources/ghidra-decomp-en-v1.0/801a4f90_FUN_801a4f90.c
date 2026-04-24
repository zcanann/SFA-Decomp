// Function: FUN_801a4f90
// Entry: 801a4f90
// Size: 680 bytes

void FUN_801a4f90(undefined2 *param_1,int param_2,int param_3)

{
  float fVar1;
  double dVar2;
  int iVar3;
  float local_48 [2];
  undefined4 local_40;
  uint uStack60;
  undefined4 local_38;
  uint uStack52;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  undefined4 local_18;
  uint uStack20;
  
  local_48[0] = FLOAT_803e43f0;
  *param_1 = *(undefined2 *)(param_3 + 0x1a);
  param_1[1] = *(undefined2 *)(param_3 + 0x1c);
  param_1[2] = *(undefined2 *)(param_3 + 0x1e);
  dVar2 = DOUBLE_803e4410;
  fVar1 = FLOAT_803e4400;
  uStack60 = (int)*(short *)(param_3 + 0x20) ^ 0x80000000;
  local_40 = 0x43300000;
  *(float *)(param_1 + 0x12) =
       (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e4410) / FLOAT_803e4400;
  uStack52 = (int)*(short *)(param_3 + 0x22) ^ 0x80000000;
  local_38 = 0x43300000;
  *(float *)(param_1 + 0x14) = (float)((double)CONCAT44(0x43300000,uStack52) - dVar2) / fVar1;
  uStack44 = (int)*(short *)(param_3 + 0x24) ^ 0x80000000;
  local_30 = 0x43300000;
  *(float *)(param_1 + 0x16) = (float)((double)CONCAT44(0x43300000,uStack44) - dVar2) / fVar1;
  uStack36 = (int)*(short *)(param_3 + 0x2c) ^ 0x80000000;
  local_28 = 0x43300000;
  *(float *)(param_2 + 0x18) = (float)((double)CONCAT44(0x43300000,uStack36) - dVar2);
  uStack28 = (int)*(short *)(param_3 + 0x2e) ^ 0x80000000;
  local_20 = 0x43300000;
  *(float *)(param_2 + 0x1c) = (float)((double)CONCAT44(0x43300000,uStack28) - dVar2);
  uStack20 = (int)*(short *)(param_3 + 0x30) ^ 0x80000000;
  local_18 = 0x43300000;
  *(float *)(param_2 + 0x20) = (float)((double)CONCAT44(0x43300000,uStack20) - dVar2);
  if (*(short *)(param_3 + 0x3a) == 0) {
    FUN_80065684((double)*(float *)(param_1 + 6),(double)(*(float *)(param_1 + 8) - FLOAT_803e4404),
                 (double)*(float *)(param_1 + 10),param_1,local_48,0);
    *(float *)(param_2 + 0x54) = *(float *)(param_1 + 8) - local_48[0];
  }
  else {
    *(float *)(param_2 + 0x54) =
         *(float *)(param_1 + 8) +
         (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x3a) ^ 0x80000000) - dVar2);
  }
  dVar2 = DOUBLE_803e4410;
  fVar1 = FLOAT_803e4404;
  uStack20 = (int)*(short *)(param_3 + 0x32) ^ 0x80000000;
  local_18 = 0x43300000;
  *(float *)(param_2 + 0x24) =
       (float)((double)CONCAT44(0x43300000,uStack20) - DOUBLE_803e4410) / FLOAT_803e4404;
  uStack28 = (int)*(short *)(param_3 + 0x34) ^ 0x80000000;
  local_20 = 0x43300000;
  *(float *)(param_2 + 0x28) = (float)((double)CONCAT44(0x43300000,uStack28) - dVar2) / fVar1;
  uStack36 = (int)*(short *)(param_3 + 0x36) ^ 0x80000000;
  local_28 = 0x43300000;
  *(float *)(param_2 + 0x2c) = (float)((double)CONCAT44(0x43300000,uStack36) - dVar2) / fVar1;
  fVar1 = FLOAT_803e4408;
  uStack44 = (int)*(short *)(param_3 + 0x26) ^ 0x80000000;
  local_30 = 0x43300000;
  *(float *)(param_2 + 0x30) =
       (float)((double)CONCAT44(0x43300000,uStack44) - dVar2) / FLOAT_803e4408;
  uStack52 = (int)*(short *)(param_3 + 0x28) ^ 0x80000000;
  local_38 = 0x43300000;
  *(float *)(param_2 + 0x34) = (float)((double)CONCAT44(0x43300000,uStack52) - dVar2) / fVar1;
  uStack60 = (int)*(short *)(param_3 + 0x2a) ^ 0x80000000;
  local_40 = 0x43300000;
  *(float *)(param_2 + 0x38) = (float)((double)CONCAT44(0x43300000,uStack60) - dVar2) / fVar1;
  *(undefined4 *)(param_2 + 0x58) = 0;
  if (*(short *)(param_3 + 0x38) == 0) {
    *(undefined4 *)(param_2 + 0x5c) = 0xffffffff;
  }
  else {
    iVar3 = FUN_800221a0(0,100);
    iVar3 = (uint)*(ushort *)(param_3 + 0x38) * (iVar3 + 100);
    iVar3 = iVar3 / 200 + (iVar3 >> 0x1f);
    *(int *)(param_2 + 0x5c) = iVar3 - (iVar3 >> 0x1f);
  }
  return;
}

