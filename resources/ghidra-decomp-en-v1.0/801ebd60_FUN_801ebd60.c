// Function: FUN_801ebd60
// Entry: 801ebd60
// Size: 1100 bytes

/* WARNING: Removing unreachable block (ram,0x801ec184) */
/* WARNING: Removing unreachable block (ram,0x801ec174) */
/* WARNING: Removing unreachable block (ram,0x801ec164) */
/* WARNING: Removing unreachable block (ram,0x801ec154) */
/* WARNING: Removing unreachable block (ram,0x801ec15c) */
/* WARNING: Removing unreachable block (ram,0x801ec16c) */
/* WARNING: Removing unreachable block (ram,0x801ec17c) */
/* WARNING: Removing unreachable block (ram,0x801ec18c) */

void FUN_801ebd60(int param_1,int param_2)

{
  byte bVar1;
  float fVar2;
  short sVar3;
  float fVar4;
  undefined4 uVar5;
  double dVar6;
  double dVar7;
  undefined8 in_f24;
  double dVar8;
  undefined8 in_f25;
  double dVar9;
  undefined8 in_f26;
  double dVar10;
  undefined8 in_f27;
  double dVar11;
  undefined8 in_f28;
  double dVar12;
  undefined8 in_f29;
  double dVar13;
  undefined8 in_f30;
  double dVar14;
  undefined8 in_f31;
  undefined2 local_a8;
  undefined2 local_a6;
  undefined2 local_a4;
  float local_a0;
  undefined4 local_9c;
  float local_98;
  undefined4 local_94;
  undefined4 local_90;
  uint uStack140;
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar5 = 0;
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
  dVar6 = (double)FUN_802931a0((double)(*(float *)(param_2 + 0x49c) * *(float *)(param_2 + 0x49c) +
                                       *(float *)(param_2 + 0x494) * *(float *)(param_2 + 0x494) +
                                       *(float *)(param_2 + 0x498) * *(float *)(param_2 + 0x498)));
  *(float *)(param_2 + 0x43c) = *(float *)(param_2 + 0x43c) - FLOAT_803db414;
  fVar2 = *(float *)(param_2 + 0x43c);
  fVar4 = FLOAT_803e5ae8;
  if ((FLOAT_803e5ae8 <= fVar2) && (fVar4 = fVar2, FLOAT_803e5b1c < fVar2)) {
    fVar4 = FLOAT_803e5b1c;
  }
  *(float *)(param_2 + 0x43c) = fVar4;
  if ((char)*(byte *)(param_2 + 0x428) < '\0') {
    dVar14 = (double)*(float *)(param_2 + 0x578);
    dVar12 = (double)*(float *)(param_2 + 0x574);
    dVar13 = (double)*(float *)(param_2 + 0x56c);
    dVar11 = (double)*(float *)(param_2 + 0x57c);
    dVar10 = (double)*(float *)(param_2 + 0x580);
    dVar9 = (double)FLOAT_803e5b20;
    dVar8 = (double)FLOAT_803e5af8;
  }
  else {
    bVar1 = *(byte *)(param_2 + 0x4b4);
    if (bVar1 == 9) {
      dVar14 = (double)FLOAT_803e5bec;
      dVar12 = (double)FLOAT_803e5bf4;
      dVar13 = (double)FLOAT_803e5c00;
      dVar11 = (double)FLOAT_803e5c04;
      dVar10 = (double)FLOAT_803e5c08;
      dVar9 = (double)FLOAT_803e5b20;
      dVar8 = (double)FLOAT_803e5c0c;
      if ((double)FLOAT_803e5b34 < dVar6) {
        local_a0 = FLOAT_803e5aec;
        local_a4 = 0;
        local_a6 = 0;
        local_a8 = 0;
        local_9c = *(undefined4 *)(param_1 + 0xc);
        local_98 = FLOAT_803e5c10 + *(float *)(param_1 + 0x10);
        local_94 = *(undefined4 *)(param_1 + 0x14);
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x80a,&local_a8,1,0xffffffff,0);
      }
    }
    else if ((bVar1 < 9) || (bVar1 != 0xd)) {
      dVar14 = (double)FLOAT_803e5bf0;
      dVar12 = (double)FLOAT_803e5bf4;
      dVar13 = (double)FLOAT_803e5bf8;
      dVar11 = (double)FLOAT_803e5bfc;
      dVar10 = (double)FLOAT_803e5be4;
      dVar9 = (double)FLOAT_803e5be8;
      dVar8 = (double)FLOAT_803e5af8;
    }
    else {
      dVar14 = (double)FLOAT_803e5bd8;
      dVar12 = (double)FLOAT_803e5bdc;
      dVar13 = (double)FLOAT_803e5b88;
      dVar11 = (double)FLOAT_803e5be0;
      dVar10 = (double)FLOAT_803e5be4;
      dVar9 = (double)FLOAT_803e5be8;
      dVar8 = (double)FLOAT_803e5af8;
      if (((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) &&
         (*(float *)(param_2 + 0x43c) <= FLOAT_803e5ae8)) {
        uStack140 = FUN_800221a0(5,10);
        uStack140 = uStack140 ^ 0x80000000;
        local_90 = 0x43300000;
        *(float *)(param_2 + 0x43c) =
             (float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803e5b00);
        dVar7 = (double)FUN_802477f0(param_1 + 0x24);
        if ((double)FLOAT_803e5bc4 < dVar7) {
          uStack140 = FUN_800221a0(1,3);
          uStack140 = uStack140 ^ 0x80000000;
          local_90 = 0x43300000;
          FUN_80014aa0((double)(float)((double)CONCAT44(0x43300000,uStack140) - DOUBLE_803e5b00));
        }
      }
      if ((double)FLOAT_803e5bec < dVar6) {
        (**(code **)(*DAT_803dca88 + 8))(param_1,0x80b,0,2,0xffffffff,0);
      }
    }
    sVar3 = *(short *)(param_2 + 0x44c);
    if (((0x1d < sVar3) && (sVar3 < 0x3d)) || ((299 < sVar3 && (sVar3 < 0x14b)))) {
      dVar14 = (double)(float)(dVar14 * (double)FLOAT_803e5b20);
      dVar12 = (double)(float)(dVar12 * (double)FLOAT_803e5b2c);
      dVar6 = (double)(float)(dVar13 + (double)FLOAT_803e5b20);
      dVar13 = (double)FLOAT_803e5ae8;
      if ((dVar13 <= dVar6) && (dVar13 = dVar6, (double)FLOAT_803e5b88 < dVar6)) {
        dVar13 = (double)FLOAT_803e5b88;
      }
    }
  }
  if ((*(byte *)(param_2 + 0x428) >> 1 & 1) != 0) {
    dVar14 = (double)FLOAT_803e5af8;
  }
  dVar6 = (double)FLOAT_803e5bd8;
  if ((dVar6 <= dVar14) && (dVar6 = dVar14, (double)FLOAT_803e5aec < dVar14)) {
    dVar6 = (double)FLOAT_803e5aec;
  }
  *(float *)(param_2 + 0x558) =
       (float)((double)FLOAT_803db414 *
               (double)(FLOAT_803e5c14 * (float)(dVar6 - (double)*(float *)(param_2 + 0x558))) +
              (double)*(float *)(param_2 + 0x558));
  *(float *)(param_2 + 0x534) =
       (float)((double)FLOAT_803db414 *
               (double)(FLOAT_803e5bbc * (float)(dVar12 - (double)*(float *)(param_2 + 0x534))) +
              (double)*(float *)(param_2 + 0x534));
  *(float *)(param_2 + 0x530) =
       (float)((double)FLOAT_803db414 *
               (double)(FLOAT_803e5c14 * (float)(dVar13 - (double)*(float *)(param_2 + 0x530))) +
              (double)*(float *)(param_2 + 0x530));
  fVar2 = FLOAT_803e5b20;
  *(float *)(param_2 + 0x548) =
       (float)((double)FLOAT_803db414 *
               (double)(FLOAT_803e5b20 * (float)(dVar11 - (double)*(float *)(param_2 + 0x548))) +
              (double)*(float *)(param_2 + 0x548));
  *(float *)(param_2 + 0x54c) =
       (float)((double)FLOAT_803db414 *
               (double)(fVar2 * (float)(dVar10 - (double)*(float *)(param_2 + 0x54c))) +
              (double)*(float *)(param_2 + 0x54c));
  *(float *)(param_2 + 0x540) =
       (float)((double)FLOAT_803db414 *
               (double)(fVar2 * (float)(dVar9 - (double)*(float *)(param_2 + 0x540))) +
              (double)*(float *)(param_2 + 0x540));
  *(float *)(param_2 + 0x544) =
       (float)((double)FLOAT_803db414 *
               (double)(fVar2 * (float)(dVar8 - (double)*(float *)(param_2 + 0x544))) +
              (double)*(float *)(param_2 + 0x544));
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  __psq_l0(auStack24,uVar5);
  __psq_l1(auStack24,uVar5);
  __psq_l0(auStack40,uVar5);
  __psq_l1(auStack40,uVar5);
  __psq_l0(auStack56,uVar5);
  __psq_l1(auStack56,uVar5);
  __psq_l0(auStack72,uVar5);
  __psq_l1(auStack72,uVar5);
  __psq_l0(auStack88,uVar5);
  __psq_l1(auStack88,uVar5);
  __psq_l0(auStack104,uVar5);
  __psq_l1(auStack104,uVar5);
  __psq_l0(auStack120,uVar5);
  __psq_l1(auStack120,uVar5);
  return;
}

