// Function: FUN_8029f32c
// Entry: 8029f32c
// Size: 1340 bytes

/* WARNING: Removing unreachable block (ram,0x8029f840) */
/* WARNING: Removing unreachable block (ram,0x8029f838) */
/* WARNING: Removing unreachable block (ram,0x8029f344) */
/* WARNING: Removing unreachable block (ram,0x8029f33c) */

undefined4
FUN_8029f32c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  uint uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  int iVar10;
  int iVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  undefined8 local_68;
  undefined8 local_60;
  
  iVar11 = *(int *)(param_9 + 0xb8);
  *(uint *)(iVar11 + 0x360) = *(uint *)(iVar11 + 0x360) & 0xfffffffd;
  FUN_80036018(param_9);
  fVar1 = FLOAT_803e8b3c;
  iVar10 = *(int *)(iVar11 + 0x7f0);
  if (iVar10 == 0) {
    *(float *)(param_10 + 0x294) = FLOAT_803e8b3c;
    *(float *)(param_10 + 0x284) = fVar1;
    *(float *)(param_10 + 0x280) = fVar1;
    *(float *)(param_9 + 0x24) = fVar1;
    *(float *)(param_9 + 0x28) = fVar1;
    *(float *)(param_9 + 0x2c) = fVar1;
    FUN_80036018(param_9);
  }
  else if (*(short *)(iVar10 + 0x46) != 0x714) {
    FUN_80035ff8(param_9);
  }
  fVar1 = FLOAT_803e8b3c;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(float *)(iVar11 + 0x7b8) = FLOAT_803e8b3c;
    *(float *)(iVar11 + 0x7bc) = fVar1;
    if (iVar10 == 0) {
      uVar5 = 0xfffffffe;
    }
    else {
      uVar5 = 0x12;
    }
    uVar6 = 0;
    uVar7 = 0;
    uVar8 = 0;
    uVar9 = 0xff;
    iVar10 = *DAT_803dd6d0;
    (**(code **)(iVar10 + 0x1c))(0x53,1,uVar5);
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x43e,0,uVar6,uVar7,uVar8,uVar9,iVar10);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8bcc;
    *(float *)(iVar11 + 0x418) = FLOAT_803e8b3c;
    if ((DAT_803df0cc != 0) && ((*(byte *)(iVar11 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar11 + 0x8b4) = 4;
      *(byte *)(iVar11 + 0x3f4) = *(byte *)(iVar11 + 0x3f4) & 0xf7 | 8;
    }
  }
  if (1 < *(byte *)(param_9 + 0x36)) {
    *(undefined *)(param_9 + 0x36) = 1;
  }
  *(float *)(iVar11 + 0x418) = *(float *)(iVar11 + 0x418) - FLOAT_803dc074;
  if (*(float *)(iVar11 + 0x418) < FLOAT_803e8b3c) {
    *(float *)(iVar11 + 0x418) = FLOAT_803e8b3c;
  }
  if (((*(ushort *)(iVar11 + 0x6e2) & 0x100) != 0) && (*(float *)(iVar11 + 0x418) <= FLOAT_803e8b3c)
     ) {
    FUN_80014b68(0,0x100);
    FUN_802aa774((double)*(float *)(iVar11 + 0x7bc),(double)FLOAT_803e8b3c,param_3,param_4,param_5,
                 param_6,param_7,param_8);
    *(float *)(iVar11 + 0x418) = FLOAT_803e8ba8;
  }
  fVar1 = *(float *)(param_10 + 0x28c) / FLOAT_803e8c40;
  fVar2 = FLOAT_803e8c88;
  if ((FLOAT_803e8c88 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8c5c < fVar1)) {
    fVar2 = FLOAT_803e8c5c;
  }
  iVar10 = *(int *)(iVar11 + 0x7f0);
  if ((iVar10 != 0) && (*(short *)(iVar10 + 0x46) == 0x484)) {
    fVar2 = fVar2 + FLOAT_803dd348;
  }
  if (iVar10 == 0) {
    fVar2 = fVar2 + FLOAT_803dd34c;
  }
  dVar12 = FUN_80021434((double)(fVar2 - *(float *)(iVar11 + 0x7bc)),(double)FLOAT_803dd33c,
                        (double)FLOAT_803dc074);
  *(float *)(iVar11 + 0x7bc) = (float)((double)*(float *)(iVar11 + 0x7bc) + dVar12);
  fVar1 = *(float *)(param_10 + 0x290) / FLOAT_803e8c40;
  fVar2 = FLOAT_803e8b64;
  if ((FLOAT_803e8b64 <= fVar1) && (fVar2 = fVar1, FLOAT_803e8b78 < fVar1)) {
    fVar2 = FLOAT_803e8b78;
  }
  dVar12 = FUN_80021434((double)(fVar2 - *(float *)(iVar11 + 0x7b8)),(double)FLOAT_803dd340,
                        (double)FLOAT_803dc074);
  *(float *)(iVar11 + 0x7b8) = (float)((double)*(float *)(iVar11 + 0x7b8) + dVar12);
  dVar12 = DOUBLE_803e8b58;
  fVar1 = *(float *)(iVar11 + 0x7b8);
  if (fVar1 <= FLOAT_803e8b3c) {
    fVar2 = FLOAT_803e8b38 + fVar1;
    if (FLOAT_803e8b3c < FLOAT_803e8b38 + fVar1) {
      fVar2 = FLOAT_803e8b3c;
    }
  }
  else {
    fVar2 = fVar1 - FLOAT_803e8b38;
    if (fVar1 - FLOAT_803e8b38 < FLOAT_803e8b3c) {
      fVar2 = FLOAT_803e8b3c;
    }
  }
  dVar14 = (double)(FLOAT_803e8c4c * fVar2);
  local_68 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x478) ^ 0x80000000);
  *(short *)(iVar11 + 0x478) =
       (short)(int)(dVar14 * (double)FLOAT_803dd344 + (double)(float)(local_68 - DOUBLE_803e8b58));
  *(undefined2 *)(iVar11 + 0x484) = *(undefined2 *)(iVar11 + 0x478);
  dVar13 = (double)*(float *)(iVar11 + 0x7bc);
  if (dVar13 <= (double)FLOAT_803e8b3c) {
    FUN_8002ee64((double)FLOAT_803e8c44,dVar13,dVar14,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x440,(short)(int)((double)FLOAT_803e8c44 * -dVar13));
  }
  else {
    FUN_8002ee64(dVar12,dVar13,dVar14,param_4,param_5,param_6,param_7,param_8,param_9,0x441,
                 (short)(int)((double)FLOAT_803e8c44 * dVar13));
  }
  dVar12 = (double)FUN_802932a4((double)FLOAT_803e8c8c,(double)FLOAT_803dc074);
  local_60 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar11 + 0x4d0) ^ 0x80000000);
  *(short *)(iVar11 + 0x4d0) = (short)(int)((double)(float)(local_60 - DOUBLE_803e8b58) * dVar12);
  dVar12 = (double)FUN_802932a4((double)FLOAT_803e8bb4,(double)FLOAT_803dc074);
  *(short *)(iVar11 + 0x4d6) =
       (short)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(iVar11 + 0x4d6) ^ 0x80000000) -
                                   DOUBLE_803e8b58) * dVar12);
  *(short *)(iVar11 + 0x4d2) = (short)(int)(FLOAT_803e8c48 * *(float *)(iVar11 + 0x7b8));
  *(short *)(iVar11 + 0x4d4) = *(short *)(iVar11 + 0x4d2) >> 1;
  *(uint *)(iVar11 + 0x360) = *(uint *)(iVar11 + 0x360) & 0xfffffbff;
  dVar13 = (double)*(float *)(iVar11 + 0x7bc);
  dVar14 = (double)*(float *)(iVar11 + 0x7b8);
  uVar4 = FUN_80070050();
  dVar12 = DOUBLE_803e8b58;
  fVar1 = FLOAT_803e8b30;
  uVar3 = (int)(uVar4 & 0xffff) >> 1 ^ 0x80000000;
  *(float *)(iVar11 + 0x788) =
       FLOAT_803e8b30 *
       (float)(dVar14 * (double)(float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e8b58)) +
       (float)((double)CONCAT44(0x43300000,uVar3) - DOUBLE_803e8b58);
  if ((double)FLOAT_803e8b3c <= dVar13) {
    uVar3 = (int)uVar4 >> 0x11 ^ 0x80000000;
    *(float *)(iVar11 + 0x78c) =
         FLOAT_803e8bdc *
         (float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,uVar3) - dVar12)) +
         (float)((double)CONCAT44(0x43300000,uVar3) - dVar12);
  }
  else {
    uVar3 = (int)uVar4 >> 0x11 ^ 0x80000000;
    *(float *)(iVar11 + 0x78c) =
         fVar1 * (float)(dVar13 * (double)(float)((double)CONCAT44(0x43300000,uVar3) - dVar12)) +
         (float)((double)CONCAT44(0x43300000,uVar3) - dVar12);
  }
  *(uint *)(iVar11 + 0x360) = *(uint *)(iVar11 + 0x360) | 0x400;
  return 0;
}

