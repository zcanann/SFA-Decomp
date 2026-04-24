// Function: FUN_8022aecc
// Entry: 8022aecc
// Size: 2200 bytes

void FUN_8022aecc(undefined2 *param_1,int param_2)

{
  int iVar1;
  float fVar2;
  uint uVar3;
  double dVar4;
  float local_f8;
  float local_f4;
  float local_f0;
  undefined4 local_e8;
  uint uStack228;
  longlong local_e0;
  undefined4 local_d8;
  uint uStack212;
  longlong local_d0;
  undefined4 local_c8;
  uint uStack196;
  undefined4 local_c0;
  uint uStack188;
  longlong local_b8;
  undefined4 local_b0;
  uint uStack172;
  undefined4 local_a8;
  uint uStack164;
  longlong local_a0;
  undefined4 local_98;
  uint uStack148;
  longlong local_90;
  undefined4 local_88;
  uint uStack132;
  longlong local_80;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  longlong local_68;
  undefined4 local_60;
  uint uStack92;
  double local_58;
  double local_50;
  double local_48;
  double local_40;
  undefined4 local_38;
  uint uStack52;
  double local_30;
  double local_28;
  undefined4 local_20;
  uint uStack28;
  double local_18;
  
  if (*(char *)(param_1 + 0x56) == '&') {
    *(float *)(param_2 + 0x44) = FLOAT_803e6ecc;
  }
  FUN_80247754(param_2 + 0x3c,param_2 + 0x48,&local_f8);
  local_f8 = local_f8 * *(float *)(param_2 + 0x60);
  local_f4 = local_f4 * *(float *)(param_2 + 100);
  fVar2 = local_f0 * *(float *)(param_2 + 0x68);
  local_f0 = *(float *)(param_2 + 0x84);
  if ((local_f0 <= fVar2) && (local_f0 = fVar2, *(float *)(param_2 + 0x78) < fVar2)) {
    local_f0 = *(float *)(param_2 + 0x78);
  }
  FUN_80247778((double)FLOAT_803db414,&local_f8,&local_f8);
  FUN_80247730(param_2 + 0x48,&local_f8,param_2 + 0x48);
  FUN_8002b95c((double)(*(float *)(param_2 + 0x48) * FLOAT_803db414),
               (double)(*(float *)(param_2 + 0x4c) * FLOAT_803db414),
               (double)(*(float *)(param_2 + 0x50) * FLOAT_803db414),param_1);
  dVar4 = DOUBLE_803e6ee0;
  uStack228 = *(int *)(param_2 + 0x340) - (*(uint *)(param_2 + 0x344) & 0xffff);
  if (0x8000 < (int)uStack228) {
    uStack228 = uStack228 - 0xffff;
  }
  if ((int)uStack228 < -0x8000) {
    uStack228 = uStack228 + 0xffff;
  }
  uStack228 = uStack228 ^ 0x80000000;
  local_e8 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack228) - DOUBLE_803e6ee0) *
               *(float *)(param_2 + 0x34c));
  local_e0 = (longlong)iVar1;
  uStack212 = iVar1 - *(int *)(param_2 + 0x350) ^ 0x80000000;
  local_d8 = 0x43300000;
  uStack196 = (uint)((double)CONCAT44(0x43300000,uStack212) - DOUBLE_803e6ee0);
  local_d0 = (longlong)(int)uStack196;
  if ((int)uStack196 < -0x32) {
    uStack196 = 0xffffffce;
  }
  else if (0x32 < (int)uStack196) {
    uStack196 = 0x32;
  }
  uStack196 = uStack196 ^ 0x80000000;
  local_c8 = 0x43300000;
  uStack188 = *(uint *)(param_2 + 0x350) ^ 0x80000000;
  local_c0 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack196) - DOUBLE_803e6ee0) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack188) - DOUBLE_803e6ee0));
  local_b8 = (longlong)iVar1;
  *(int *)(param_2 + 0x350) = iVar1;
  uStack172 = *(uint *)(param_2 + 0x350) ^ 0x80000000;
  local_b0 = 0x43300000;
  uStack164 = *(uint *)(param_2 + 0x344) ^ 0x80000000;
  local_a8 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack172) - dVar4) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack164) - dVar4));
  local_a0 = (longlong)iVar1;
  *(int *)(param_2 + 0x344) = iVar1;
  dVar4 = DOUBLE_803e6ee0;
  uStack148 = *(int *)(param_2 + 0x354) - (*(uint *)(param_2 + 0x358) & 0xffff);
  if (0x8000 < (int)uStack148) {
    uStack148 = uStack148 - 0xffff;
  }
  if ((int)uStack148 < -0x8000) {
    uStack148 = uStack148 + 0xffff;
  }
  uStack148 = uStack148 ^ 0x80000000;
  local_98 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack148) - DOUBLE_803e6ee0) *
               *(float *)(param_2 + 0x360));
  local_90 = (longlong)iVar1;
  uStack132 = iVar1 - *(int *)(param_2 + 0x364) ^ 0x80000000;
  local_88 = 0x43300000;
  uStack116 = (uint)((double)CONCAT44(0x43300000,uStack132) - DOUBLE_803e6ee0);
  local_80 = (longlong)(int)uStack116;
  if ((int)uStack116 < -0x32) {
    uStack116 = 0xffffffce;
  }
  else if (0x32 < (int)uStack116) {
    uStack116 = 0x32;
  }
  uStack116 = uStack116 ^ 0x80000000;
  local_78 = 0x43300000;
  uStack108 = *(uint *)(param_2 + 0x364) ^ 0x80000000;
  local_70 = 0x43300000;
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e6ee0) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e6ee0));
  local_68 = (longlong)iVar1;
  *(int *)(param_2 + 0x364) = iVar1;
  uStack92 = *(uint *)(param_2 + 0x364) ^ 0x80000000;
  local_60 = 0x43300000;
  local_58 = (double)CONCAT44(0x43300000,*(uint *)(param_2 + 0x358) ^ 0x80000000);
  iVar1 = (int)((float)((double)CONCAT44(0x43300000,uStack92) - dVar4) * FLOAT_803db414 +
               (float)(local_58 - dVar4));
  local_50 = (double)(longlong)iVar1;
  *(int *)(param_2 + 0x358) = iVar1;
  dVar4 = DOUBLE_803e6ee0;
  uVar3 = *(int *)(param_2 + 0x368) - (*(uint *)(param_2 + 0x36c) & 0xffff);
  if (0x8000 < (int)uVar3) {
    uVar3 = uVar3 - 0xffff;
  }
  if ((int)uVar3 < -0x8000) {
    uVar3 = uVar3 + 0xffff;
  }
  local_48 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
  uStack52 = (uint)((float)(local_48 - DOUBLE_803e6ee0) * *(float *)(param_2 + 0x374));
  local_40 = (double)(longlong)(int)uStack52;
  uStack52 = uStack52 ^ 0x80000000;
  local_38 = 0x43300000;
  uVar3 = (uint)((float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e6ee0) -
                *(float *)(param_2 + 0x378));
  local_30 = (double)(longlong)(int)uVar3;
  if ((int)uVar3 < -100) {
    uVar3 = 0xffffff9c;
  }
  else if (100 < (int)uVar3) {
    uVar3 = 100;
  }
  local_28 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
  *(float *)(param_2 + 0x378) =
       (float)(local_28 - DOUBLE_803e6ee0) * FLOAT_803db414 + *(float *)(param_2 + 0x378);
  uStack28 = *(uint *)(param_2 + 0x36c) ^ 0x80000000;
  iVar1 = (int)(*(float *)(param_2 + 0x378) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack28) - dVar4));
  local_18 = (double)(longlong)iVar1;
  *(int *)(param_2 + 0x36c) = iVar1;
  dVar4 = DOUBLE_803e6ee0;
  if (*(char *)(param_2 + 0x478) == '\0') {
    uVar3 = *(int *)(param_2 + 0x37c) - (*(uint *)(param_2 + 0x380) & 0xffff);
    if (0x8000 < (int)uVar3) {
      uVar3 = uVar3 - 0xffff;
    }
    if ((int)uVar3 < -0x8000) {
      uVar3 = uVar3 + 0xffff;
    }
    local_18 = (double)CONCAT44(0x43300000,uVar3 ^ 0x80000000);
    uStack28 = *(uint *)(param_2 + 0x380) ^ 0x80000000;
    iVar1 = (int)(FLOAT_803db414 * (float)(local_18 - DOUBLE_803e6ee0) * *(float *)(param_2 + 0x388)
                 + (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e6ee0));
    local_28 = (double)(longlong)iVar1;
    *(int *)(param_2 + 0x380) = iVar1;
    uVar3 = *(uint *)(param_2 + 0x380) ^ 0x80000000;
    local_30 = (double)CONCAT44(0x43300000,uVar3);
    if ((*(float *)(param_2 + 0x394) < (float)(local_30 - dVar4)) ||
       (local_18 = (double)CONCAT44(0x43300000,uVar3),
       (float)(local_18 - dVar4) < -*(float *)(param_2 + 0x394))) {
      *(float *)(param_2 + 0x38c) =
           -(*(float *)(param_2 + 0x390) * FLOAT_803db414 - *(float *)(param_2 + 0x38c));
    }
    else {
      *(float *)(param_2 + 0x38c) =
           *(float *)(param_2 + 0x390) * FLOAT_803db414 + *(float *)(param_2 + 0x38c);
    }
  }
  else {
    *(float *)(param_2 + 0x38c) =
         -(*(float *)(param_2 + 0x390) * FLOAT_803db414 - *(float *)(param_2 + 0x38c));
  }
  local_20 = 0x43300000;
  if (FLOAT_803e6ecc <= *(float *)(param_2 + 0x38c)) {
    if (FLOAT_803e6ed0 < *(float *)(param_2 + 0x38c)) {
      *(float *)(param_2 + 0x38c) = FLOAT_803e6ed0;
    }
  }
  else {
    *(float *)(param_2 + 0x38c) = FLOAT_803e6ecc;
  }
  *param_1 = (short)*(undefined4 *)(param_2 + 0x344);
  param_1[1] = (short)*(undefined4 *)(param_2 + 0x358);
  if (*(char *)(param_2 + 0x478) == '\x01') {
    FUN_8022ab68(param_1,param_2);
  }
  else {
    local_18 = (double)CONCAT44(0x43300000,*(uint *)(param_2 + 0x36c) ^ 0x80000000);
    uStack28 = *(uint *)(param_2 + 0x380) ^ 0x80000000;
    local_20 = 0x43300000;
    iVar1 = (int)((float)(local_18 - DOUBLE_803e6ee0) * *(float *)(param_2 + 0x38c) +
                 (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e6ee0));
    local_28 = (double)(longlong)iVar1;
    param_1[2] = (short)iVar1;
    if ((short)param_1[2] < -0x4000) {
      param_1[2] = 0xc000;
    }
    else if (0x4000 < (short)param_1[2]) {
      param_1[2] = 0x4000;
    }
  }
  dVar4 = (double)FUN_802931a0((double)(*(float *)(param_2 + 0x48) * *(float *)(param_2 + 0x48) +
                                       *(float *)(param_2 + 0x4c) * *(float *)(param_2 + 0x4c)));
  if (((double)*(float *)(param_2 + 0x3b4) <= dVar4) || (*(char *)(param_2 + 0x478) != '\0')) {
    *(float *)(param_2 + 0x3dc) =
         -(*(float *)(param_2 + 0x3e0) * FLOAT_803db414 - *(float *)(param_2 + 0x3dc));
  }
  else {
    *(float *)(param_2 + 0x3dc) =
         *(float *)(param_2 + 0x3e0) * FLOAT_803db414 + *(float *)(param_2 + 0x3dc);
  }
  if (FLOAT_803e6ecc <= *(float *)(param_2 + 0x3dc)) {
    if (FLOAT_803e6ed0 < *(float *)(param_2 + 0x3dc)) {
      *(float *)(param_2 + 0x3dc) = FLOAT_803e6ed0;
    }
  }
  else {
    *(float *)(param_2 + 0x3dc) = FLOAT_803e6ecc;
  }
  local_18 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x3c0));
  dVar4 = (double)FUN_80293e80((double)((FLOAT_803e6efc * (float)(local_18 - DOUBLE_803e6ee8)) /
                                       FLOAT_803e6f00));
  uStack28 = (int)(short)param_1[2] ^ 0x80000000;
  local_20 = 0x43300000;
  iVar1 = (int)(*(float *)(param_2 + 0x3dc) * (float)((double)*(float *)(param_2 + 0x3bc) * dVar4) +
               (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803e6ee0));
  local_28 = (double)(longlong)iVar1;
  param_1[2] = (short)iVar1;
  local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x3cc));
  dVar4 = (double)FUN_80293e80((double)((FLOAT_803e6efc * (float)(local_30 - DOUBLE_803e6ee8)) /
                                       FLOAT_803e6f00));
  *(float *)(param_1 + 6) =
       *(float *)(param_2 + 0x3dc) * (float)((double)*(float *)(param_2 + 0x3c8) * dVar4) +
       *(float *)(param_1 + 6);
  uStack52 = (uint)*(ushort *)(param_2 + 0x3d8);
  local_38 = 0x43300000;
  dVar4 = (double)FUN_80293e80((double)((FLOAT_803e6efc *
                                        (float)((double)CONCAT44(0x43300000,uStack52) -
                                               DOUBLE_803e6ee8)) / FLOAT_803e6f00));
  *(float *)(param_1 + 8) =
       *(float *)(param_2 + 0x3dc) * (float)((double)*(float *)(param_2 + 0x3d4) * dVar4) +
       *(float *)(param_1 + 8);
  dVar4 = DOUBLE_803e6ee8;
  local_40 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x3c0));
  iVar1 = (int)(*(float *)(param_2 + 0x3b8) * FLOAT_803db414 + (float)(local_40 - DOUBLE_803e6ee8));
  local_48 = (double)(longlong)iVar1;
  *(short *)(param_2 + 0x3c0) = (short)iVar1;
  local_50 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(param_2 + 0x3cc));
  iVar1 = (int)(*(float *)(param_2 + 0x3c4) * FLOAT_803db414 + (float)(local_50 - dVar4));
  local_58 = (double)(longlong)iVar1;
  *(short *)(param_2 + 0x3cc) = (short)iVar1;
  uStack92 = (uint)*(ushort *)(param_2 + 0x3d8);
  local_60 = 0x43300000;
  iVar1 = (int)(*(float *)(param_2 + 0x3d0) * FLOAT_803db414 +
               (float)((double)CONCAT44(0x43300000,uStack92) - dVar4));
  local_68 = (longlong)iVar1;
  *(short *)(param_2 + 0x3d8) = (short)iVar1;
  FUN_8022ae1c(param_1,param_2);
  return;
}

