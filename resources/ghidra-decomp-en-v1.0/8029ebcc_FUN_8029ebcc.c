// Function: FUN_8029ebcc
// Entry: 8029ebcc
// Size: 1340 bytes

/* WARNING: Removing unreachable block (ram,0x8029f0d8) */
/* WARNING: Removing unreachable block (ram,0x8029f0e0) */

undefined4 FUN_8029ebcc(int param_1,int param_2)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  uint uVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  double dVar11;
  double local_68;
  double local_60;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar7 = *(int *)(param_1 + 0xb8);
  *(uint *)(iVar7 + 0x360) = *(uint *)(iVar7 + 0x360) & 0xfffffffd;
  FUN_80035f20();
  fVar1 = FLOAT_803e7ea4;
  iVar6 = *(int *)(iVar7 + 0x7f0);
  if (iVar6 == 0) {
    *(float *)(param_2 + 0x294) = FLOAT_803e7ea4;
    *(float *)(param_2 + 0x284) = fVar1;
    *(float *)(param_2 + 0x280) = fVar1;
    *(float *)(param_1 + 0x24) = fVar1;
    *(float *)(param_1 + 0x28) = fVar1;
    *(float *)(param_1 + 0x2c) = fVar1;
    FUN_80035f20(param_1);
  }
  else if (*(short *)(iVar6 + 0x46) != 0x714) {
    FUN_80035f00(param_1);
  }
  fVar1 = FLOAT_803e7ea4;
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(float *)(iVar7 + 0x7b8) = FLOAT_803e7ea4;
    *(float *)(iVar7 + 0x7bc) = fVar1;
    if (iVar6 == 0) {
      uVar5 = 0xfffffffe;
    }
    else {
      uVar5 = 0x12;
    }
    (**(code **)(*DAT_803dca50 + 0x1c))(0x53,1,uVar5,0,0,0,0xff);
    FUN_80030334((double)FLOAT_803e7ea4,param_1,0x43e,0);
    *(float *)(param_2 + 0x2a0) = FLOAT_803e7f34;
    *(float *)(iVar7 + 0x418) = FLOAT_803e7ea4;
    if ((DAT_803de44c != 0) && ((*(byte *)(iVar7 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar7 + 0x8b4) = 4;
      *(byte *)(iVar7 + 0x3f4) = *(byte *)(iVar7 + 0x3f4) & 0xf7 | 8;
    }
  }
  if (1 < *(byte *)(param_1 + 0x36)) {
    *(undefined *)(param_1 + 0x36) = 1;
  }
  *(float *)(iVar7 + 0x418) = *(float *)(iVar7 + 0x418) - FLOAT_803db414;
  if (*(float *)(iVar7 + 0x418) < FLOAT_803e7ea4) {
    *(float *)(iVar7 + 0x418) = FLOAT_803e7ea4;
  }
  if (((*(ushort *)(iVar7 + 0x6e2) & 0x100) != 0) && (*(float *)(iVar7 + 0x418) <= FLOAT_803e7ea4))
  {
    FUN_80014b3c(0,0x100);
    FUN_802aa014((double)*(float *)(iVar7 + 0x7bc),(double)FLOAT_803e7ea4,param_1,param_2);
    *(float *)(iVar7 + 0x418) = FLOAT_803e7f10;
  }
  fVar1 = *(float *)(param_2 + 0x28c) / FLOAT_803e7fa8;
  fVar2 = FLOAT_803e7ff0;
  if ((FLOAT_803e7ff0 <= fVar1) && (fVar2 = fVar1, FLOAT_803e7fc4 < fVar1)) {
    fVar2 = FLOAT_803e7fc4;
  }
  iVar6 = *(int *)(iVar7 + 0x7f0);
  if ((iVar6 != 0) && (*(short *)(iVar6 + 0x46) == 0x484)) {
    fVar2 = fVar2 + FLOAT_803dc6e0;
  }
  if (iVar6 == 0) {
    fVar2 = fVar2 + FLOAT_803dc6e4;
  }
  dVar9 = (double)FUN_80021370((double)(fVar2 - *(float *)(iVar7 + 0x7bc)),(double)FLOAT_803dc6d4,
                               (double)FLOAT_803db414);
  *(float *)(iVar7 + 0x7bc) = (float)((double)*(float *)(iVar7 + 0x7bc) + dVar9);
  fVar1 = *(float *)(param_2 + 0x290) / FLOAT_803e7fa8;
  fVar2 = FLOAT_803e7ecc;
  if ((FLOAT_803e7ecc <= fVar1) && (fVar2 = fVar1, FLOAT_803e7ee0 < fVar1)) {
    fVar2 = FLOAT_803e7ee0;
  }
  dVar9 = (double)FUN_80021370((double)(fVar2 - *(float *)(iVar7 + 0x7b8)),(double)FLOAT_803dc6d8,
                               (double)FLOAT_803db414);
  *(float *)(iVar7 + 0x7b8) = (float)((double)*(float *)(iVar7 + 0x7b8) + dVar9);
  fVar1 = *(float *)(iVar7 + 0x7b8);
  if (fVar1 <= FLOAT_803e7ea4) {
    fVar2 = FLOAT_803e7ea0 + fVar1;
    if (FLOAT_803e7ea4 < FLOAT_803e7ea0 + fVar1) {
      fVar2 = FLOAT_803e7ea4;
    }
  }
  else {
    fVar2 = fVar1 - FLOAT_803e7ea0;
    if (fVar1 - FLOAT_803e7ea0 < FLOAT_803e7ea4) {
      fVar2 = FLOAT_803e7ea4;
    }
  }
  local_68 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar7 + 0x478) ^ 0x80000000);
  *(short *)(iVar7 + 0x478) =
       (short)(int)(FLOAT_803e7fb4 * fVar2 * FLOAT_803dc6dc + (float)(local_68 - DOUBLE_803e7ec0));
  *(undefined2 *)(iVar7 + 0x484) = *(undefined2 *)(iVar7 + 0x478);
  fVar1 = *(float *)(iVar7 + 0x7bc);
  if (fVar1 <= FLOAT_803e7ea4) {
    FUN_8002ed6c(param_1,0x440,(int)(FLOAT_803e7fac * -fVar1));
  }
  else {
    FUN_8002ed6c(param_1,0x441,(int)(FLOAT_803e7fac * fVar1));
  }
  dVar9 = (double)FUN_80292b44((double)FLOAT_803e7ff4,(double)FLOAT_803db414);
  local_60 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar7 + 0x4d0) ^ 0x80000000);
  *(short *)(iVar7 + 0x4d0) = (short)(int)((double)(float)(local_60 - DOUBLE_803e7ec0) * dVar9);
  dVar9 = (double)FUN_80292b44((double)FLOAT_803e7f1c,(double)FLOAT_803db414);
  *(short *)(iVar7 + 0x4d6) =
       (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(iVar7 + 0x4d6) ^ 0x80000000) -
                                   DOUBLE_803e7ec0) * dVar9);
  *(short *)(iVar7 + 0x4d2) = (short)(int)(FLOAT_803e7fb0 * *(float *)(iVar7 + 0x7b8));
  *(short *)(iVar7 + 0x4d4) = *(short *)(iVar7 + 0x4d2) >> 1;
  *(uint *)(iVar7 + 0x360) = *(uint *)(iVar7 + 0x360) & 0xfffffbff;
  dVar10 = (double)*(float *)(iVar7 + 0x7bc);
  dVar11 = (double)*(float *)(iVar7 + 0x7b8);
  uVar4 = FUN_8006fed4();
  dVar9 = DOUBLE_803e7ec0;
  fVar1 = FLOAT_803e7e98;
  uVar3 = (int)(uVar4 & 0xffff) >> 1 ^ 0x80000000;
  *(float *)(iVar7 + 0x788) =
       FLOAT_803e7e98 *
       (float)(dVar11 * (double)(float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e7ec0)) +
       (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e7ec0);
  if ((double)FLOAT_803e7ea4 <= dVar10) {
    uVar3 = (int)uVar4 >> 0x11 ^ 0x80000000;
    *(float *)(iVar7 + 0x78c) =
         FLOAT_803e7f44 *
         (float)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uVar3) - dVar9)) +
         (float)((double)CONCAT44(0x43300000,uVar3) - dVar9);
  }
  else {
    uVar3 = (int)uVar4 >> 0x11 ^ 0x80000000;
    *(float *)(iVar7 + 0x78c) =
         fVar1 * (float)(dVar10 * (double)(float)((double)CONCAT44(0x43300000,uVar3) - dVar9)) +
         (float)((double)CONCAT44(0x43300000,uVar3) - dVar9);
  }
  *(uint *)(iVar7 + 0x360) = *(uint *)(iVar7 + 0x360) | 0x400;
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  return 0;
}

