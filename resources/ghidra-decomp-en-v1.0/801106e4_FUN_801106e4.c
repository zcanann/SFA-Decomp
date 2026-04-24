// Function: FUN_801106e4
// Entry: 801106e4
// Size: 1168 bytes

/* WARNING: Removing unreachable block (ram,0x80110b50) */
/* WARNING: Removing unreachable block (ram,0x80110b40) */
/* WARNING: Removing unreachable block (ram,0x80110b30) */
/* WARNING: Removing unreachable block (ram,0x80110b20) */
/* WARNING: Removing unreachable block (ram,0x80110b28) */
/* WARNING: Removing unreachable block (ram,0x80110b38) */
/* WARNING: Removing unreachable block (ram,0x80110b48) */
/* WARNING: Removing unreachable block (ram,0x80110b58) */

void FUN_801106e4(short *param_1)

{
  float fVar1;
  float fVar2;
  int iVar3;
  short sVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  double dVar8;
  undefined8 uVar9;
  undefined8 in_f24;
  double dVar10;
  undefined8 in_f25;
  double dVar11;
  undefined8 in_f26;
  double dVar12;
  undefined8 in_f27;
  double dVar13;
  undefined8 in_f28;
  double dVar14;
  undefined8 in_f29;
  double dVar15;
  undefined8 in_f30;
  double dVar16;
  undefined8 in_f31;
  int local_c8;
  int local_c4;
  undefined4 local_c0;
  uint uStack188;
  undefined4 local_b8;
  uint uStack180;
  longlong local_b0;
  undefined4 local_a8;
  uint uStack164;
  undefined4 local_a0;
  uint uStack156;
  longlong local_98;
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  __psq_st0(auStack104,(int)((ulonglong)in_f25 >> 0x20),0);
  __psq_st1(auStack104,(int)in_f25,0);
  __psq_st0(auStack120,(int)((ulonglong)in_f24 >> 0x20),0);
  __psq_st1(auStack120,(int)in_f24,0);
  if (*(char *)((int)DAT_803dd5c0 + 0xd) == '\0') {
    if (DAT_803dd5c0[1] == 0) {
      iVar3 = FUN_8002e0fc(&local_c4,&local_c8);
      for (; local_c4 < local_c8; local_c4 = local_c4 + 1) {
        iVar5 = *(int *)(iVar3 + local_c4 * 4);
        if (*(short *)(iVar5 + 0x46) == 0x2ab) {
          DAT_803dd5c0[1] = iVar5;
        }
        else if (*(short *)(iVar5 + 0x46) == 0x4dc) {
          *DAT_803dd5c0 = iVar5;
        }
      }
    }
    if (DAT_803dd5c0[2] == 0) {
      iVar3 = FUN_8002b9ec();
      DAT_803dd5c0[2] = iVar3;
    }
    iVar5 = DAT_803dd5c0[1];
    iVar3 = *DAT_803dd5c0;
    dVar14 = (double)(*(float *)(iVar5 + 0x18) - *(float *)(iVar3 + 0x18));
    dVar13 = (double)(*(float *)(iVar5 + 0x1c) - *(float *)(iVar3 + 0x1c));
    dVar12 = (double)(*(float *)(iVar5 + 0x20) - *(float *)(iVar3 + 0x20));
    dVar16 = (double)(float)(dVar12 * dVar12);
    dVar15 = (double)(float)(dVar14 * dVar14);
    dVar7 = (double)FUN_802931a0((double)(float)(dVar16 + (double)(float)(dVar13 * dVar13 + dVar15))
                                );
    dVar11 = (double)(float)(dVar14 / dVar7);
    dVar10 = (double)(float)(dVar12 / dVar7);
    fVar1 = -(float)((double)FLOAT_803e1b40 * dVar11 - (double)*(float *)(*DAT_803dd5c0 + 0x18)) -
            *(float *)(DAT_803dd5c0[2] + 0x18);
    fVar2 = -(float)((double)FLOAT_803e1b40 * dVar10 - (double)*(float *)(*DAT_803dd5c0 + 0x20)) -
            *(float *)(DAT_803dd5c0[2] + 0x20);
    dVar8 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
    fVar1 = (float)((double)(float)((double)FLOAT_803e1b44 - dVar8) / (double)FLOAT_803e1b44);
    *(float *)(param_1 + 0x5a) = FLOAT_803e1b4c * fVar1 + FLOAT_803e1b48;
    dVar8 = (double)(FLOAT_803e1b54 * fVar1 + FLOAT_803e1b50);
    *(float *)(param_1 + 0xc) = -(float)(dVar11 * dVar8 - (double)*(float *)(*DAT_803dd5c0 + 0x18));
    *(float *)(param_1 + 0xe) =
         FLOAT_803e1b5c * fVar1 + FLOAT_803e1b58 + *(float *)(*DAT_803dd5c0 + 0x1c);
    *(float *)(param_1 + 0x10) = -(float)(dVar10 * dVar8 - (double)*(float *)(*DAT_803dd5c0 + 0x20))
    ;
    sVar4 = FUN_800217c0(dVar14,dVar12);
    *param_1 = -sVar4;
    uVar9 = FUN_802931a0((double)(float)(dVar15 + dVar16));
    sVar4 = FUN_800217c0(-(double)(float)((double)FLOAT_803e1b60 *
                                          (double)(float)(dVar7 / (double)FLOAT_803e1b64) - dVar13),
                         uVar9);
    param_1[1] = -sVar4;
    if (*(char *)(DAT_803dd5c0 + 3) == '\0') {
      fVar1 = (float)DAT_803dd5c0[4] / FLOAT_803e1b5c;
      *(float *)(param_1 + 0xc) =
           fVar1 * ((float)DAT_803dd5c0[5] - *(float *)(param_1 + 0xc)) + *(float *)(param_1 + 0xc);
      *(float *)(param_1 + 0xe) =
           fVar1 * ((float)DAT_803dd5c0[6] - *(float *)(param_1 + 0xe)) + *(float *)(param_1 + 0xe);
      *(float *)(param_1 + 0x10) =
           fVar1 * ((float)DAT_803dd5c0[7] - *(float *)(param_1 + 0x10)) +
           *(float *)(param_1 + 0x10);
      sVar4 = *(short *)(DAT_803dd5c0 + 8) - *param_1;
      if (0x8000 < sVar4) {
        sVar4 = sVar4 + 1;
      }
      if (sVar4 < -0x8000) {
        sVar4 = sVar4 + -1;
      }
      uStack188 = (int)sVar4 ^ 0x80000000;
      local_c0 = 0x43300000;
      uStack180 = (int)*param_1 ^ 0x80000000;
      local_b8 = 0x43300000;
      iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack188) - DOUBLE_803e1b70) * fVar1 +
                   (float)((double)CONCAT44(0x43300000,uStack180) - DOUBLE_803e1b70));
      local_b0 = (longlong)iVar3;
      *param_1 = (short)iVar3;
      sVar4 = *(short *)((int)DAT_803dd5c0 + 0x22) - param_1[1];
      if (0x8000 < sVar4) {
        sVar4 = sVar4 + 1;
      }
      if (sVar4 < -0x8000) {
        sVar4 = sVar4 + -1;
      }
      uStack164 = (int)sVar4 ^ 0x80000000;
      local_a8 = 0x43300000;
      uStack156 = (int)param_1[1] ^ 0x80000000;
      local_a0 = 0x43300000;
      iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack164) - DOUBLE_803e1b70) * fVar1 +
                   (float)((double)CONCAT44(0x43300000,uStack156) - DOUBLE_803e1b70));
      local_98 = (longlong)iVar3;
      param_1[1] = (short)iVar3;
      DAT_803dd5c0[4] = (int)((float)DAT_803dd5c0[4] - FLOAT_803db414);
      fVar1 = FLOAT_803e1b68;
      if ((float)DAT_803dd5c0[4] < FLOAT_803e1b68) {
        *(undefined *)(DAT_803dd5c0 + 3) = 1;
        DAT_803dd5c0[4] = (int)fVar1;
      }
    }
    FUN_8000e034((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0xe),
                 (double)*(float *)(param_1 + 0x10),param_1 + 6,param_1 + 8,param_1 + 10,
                 *(undefined4 *)(param_1 + 0x18));
  }
  else {
    (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0,0xff);
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  __psq_l0(auStack40,uVar6);
  __psq_l1(auStack40,uVar6);
  __psq_l0(auStack56,uVar6);
  __psq_l1(auStack56,uVar6);
  __psq_l0(auStack72,uVar6);
  __psq_l1(auStack72,uVar6);
  __psq_l0(auStack88,uVar6);
  __psq_l1(auStack88,uVar6);
  __psq_l0(auStack104,uVar6);
  __psq_l1(auStack104,uVar6);
  __psq_l0(auStack120,uVar6);
  __psq_l1(auStack120,uVar6);
  return;
}

