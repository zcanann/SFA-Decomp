// Function: FUN_800d55bc
// Entry: 800d55bc
// Size: 2500 bytes

/* WARNING: Removing unreachable block (ram,0x800d5f58) */
/* WARNING: Removing unreachable block (ram,0x800d5f48) */
/* WARNING: Removing unreachable block (ram,0x800d5f38) */
/* WARNING: Removing unreachable block (ram,0x800d5f28) */
/* WARNING: Removing unreachable block (ram,0x800d5f18) */
/* WARNING: Removing unreachable block (ram,0x800d5f08) */
/* WARNING: Removing unreachable block (ram,0x800d5f10) */
/* WARNING: Removing unreachable block (ram,0x800d5f20) */
/* WARNING: Removing unreachable block (ram,0x800d5f30) */
/* WARNING: Removing unreachable block (ram,0x800d5f40) */
/* WARNING: Removing unreachable block (ram,0x800d5f50) */
/* WARNING: Removing unreachable block (ram,0x800d5f60) */

void FUN_800d55bc(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 float *param_5,float *param_6,float *param_7,uint param_8)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined4 uVar9;
  double extraout_f1;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  double dVar16;
  undefined8 in_f20;
  double dVar17;
  undefined8 in_f21;
  double dVar18;
  undefined8 in_f22;
  undefined8 in_f23;
  undefined8 in_f24;
  undefined8 in_f25;
  double dVar19;
  undefined8 in_f26;
  undefined8 in_f27;
  undefined8 in_f28;
  undefined8 in_f29;
  double dVar20;
  undefined8 in_f30;
  double dVar21;
  undefined8 in_f31;
  double dVar22;
  undefined8 uVar23;
  undefined auStack360 [8];
  undefined4 local_160;
  uint uStack348;
  undefined4 local_158;
  uint uStack340;
  undefined4 local_150;
  uint uStack332;
  undefined4 local_148;
  uint uStack324;
  undefined4 local_140;
  uint uStack316;
  undefined4 local_138;
  uint uStack308;
  undefined4 local_130;
  uint uStack300;
  undefined4 local_128;
  uint uStack292;
  undefined4 local_120;
  uint uStack284;
  undefined4 local_118;
  uint uStack276;
  undefined4 local_110;
  uint uStack268;
  undefined4 local_108;
  uint uStack260;
  undefined4 local_100;
  uint uStack252;
  undefined4 local_f8;
  uint uStack244;
  undefined auStack184 [16];
  undefined auStack168 [16];
  undefined auStack152 [16];
  undefined auStack136 [16];
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
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
  __psq_st0(auStack136,(int)((ulonglong)in_f23 >> 0x20),0);
  __psq_st1(auStack136,(int)in_f23,0);
  __psq_st0(auStack152,(int)((ulonglong)in_f22 >> 0x20),0);
  __psq_st1(auStack152,(int)in_f22,0);
  __psq_st0(auStack168,(int)((ulonglong)in_f21 >> 0x20),0);
  __psq_st1(auStack168,(int)in_f21,0);
  __psq_st0(auStack184,(int)((ulonglong)in_f20 >> 0x20),0);
  __psq_st1(auStack184,(int)in_f20,0);
  uVar23 = FUN_802860c0();
  iVar2 = (int)((ulonglong)uVar23 >> 0x20);
  uVar5 = 1;
  if (iVar2 == 0) {
    uVar5 = 0;
  }
  else {
    dVar16 = extraout_f1;
    iVar3 = FUN_800d5530(*(undefined4 *)(iVar2 + (int)uVar23 * 4 + 0x20),auStack360);
    if (iVar3 == 0) {
      iVar3 = FUN_800d5530(*(undefined4 *)(iVar2 + (1 - (int)uVar23) * 4 + 0x20),auStack360);
      uVar5 = 2;
    }
    if (iVar3 == 0) {
      uVar5 = 0;
    }
    else {
      uStack348 = (uint)*(byte *)(iVar2 + 0x29) << 8 ^ 0x80000000;
      local_160 = 0x43300000;
      dVar10 = (double)FUN_80293e80((double)((FLOAT_803e04d8 *
                                             (float)((double)CONCAT44(0x43300000,uStack348) -
                                                    DOUBLE_803e04f0)) / FLOAT_803e04dc));
      dVar10 = -dVar10;
      uStack340 = (uint)*(byte *)(iVar2 + 0x29) << 8 ^ 0x80000000;
      local_158 = 0x43300000;
      dVar11 = (double)FUN_80294204((double)((FLOAT_803e04d8 *
                                             (float)((double)CONCAT44(0x43300000,uStack340) -
                                                    DOUBLE_803e04f0)) / FLOAT_803e04dc));
      dVar11 = -dVar11;
      uStack332 = (uint)*(byte *)(iVar3 + 0x29) << 8 ^ 0x80000000;
      local_150 = 0x43300000;
      dVar12 = (double)FUN_80293e80((double)((FLOAT_803e04d8 *
                                             (float)((double)CONCAT44(0x43300000,uStack332) -
                                                    DOUBLE_803e04f0)) / FLOAT_803e04dc));
      dVar12 = -dVar12;
      uStack324 = (uint)*(byte *)(iVar3 + 0x29) << 8 ^ 0x80000000;
      local_148 = 0x43300000;
      dVar13 = (double)FUN_80294204((double)((FLOAT_803e04d8 *
                                             (float)((double)CONCAT44(0x43300000,uStack324) -
                                                    DOUBLE_803e04f0)) / FLOAT_803e04dc));
      dVar15 = DOUBLE_803e04f0;
      dVar13 = -dVar13;
      uStack316 = (uint)*(byte *)(iVar2 + 0x2a);
      local_140 = 0x43300000;
      dVar18 = (double)(FLOAT_803e04e0 *
                       (float)((double)CONCAT44(0x43300000,uStack316) - DOUBLE_803e04f8));
      uStack308 = (uint)*(byte *)(iVar3 + 0x2a);
      local_138 = 0x43300000;
      dVar17 = (double)(FLOAT_803e04e0 *
                       (float)((double)CONCAT44(0x43300000,uStack308) - DOUBLE_803e04f8));
      param_8 = param_8 & 0xff;
      if (param_8 == 1) {
        iVar4 = 0;
        iVar8 = 0;
        dVar19 = (double)(float)(dVar18 * dVar11);
        dVar13 = (double)(float)(dVar17 * dVar13);
        dVar11 = (double)(float)(dVar18 * -dVar10);
        dVar10 = (double)(float)(dVar17 * -dVar12);
        dVar12 = (double)FLOAT_803e04d8;
        dVar20 = (double)FLOAT_803e04dc;
        dVar21 = (double)FLOAT_803e04e4;
        dVar22 = (double)FLOAT_803e04e8;
        dVar16 = DOUBLE_803e04f8;
        do {
          iVar7 = iVar2 + iVar8;
          uStack308 = (int)*(char *)(iVar7 + 0x2d) ^ 0x80000000;
          local_138 = 0x43300000;
          *param_5 = (float)((double)(float)((double)CONCAT44(0x43300000,uStack308) - dVar15) *
                             dVar19 + (double)*(float *)(iVar2 + 8));
          iVar6 = iVar3 + iVar8;
          uStack316 = (int)*(char *)(iVar6 + 0x2d) ^ 0x80000000;
          local_140 = 0x43300000;
          param_5[1] = (float)((double)(float)((double)CONCAT44(0x43300000,uStack316) - dVar15) *
                               dVar13 + (double)*(float *)(iVar3 + 8));
          uStack324 = (uint)*(byte *)(iVar2 + 0x3e) << 8 ^ 0x80000000;
          local_148 = 0x43300000;
          dVar14 = (double)FUN_80293e80((double)(float)((double)(float)(dVar12 * (double)(float)((
                                                  double)CONCAT44(0x43300000,uStack324) - dVar15)) /
                                                  dVar20));
          uStack332 = (uint)*(byte *)(iVar2 + 0x3d);
          local_150 = 0x43300000;
          param_5[2] = (float)(dVar21 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                         uStack332)
                                                                       - dVar16) * dVar14));
          uStack340 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
          local_158 = 0x43300000;
          dVar14 = (double)FUN_80293e80((double)(float)((double)(float)(dVar12 * (double)(float)((
                                                  double)CONCAT44(0x43300000,uStack340) - dVar15)) /
                                                  dVar20));
          uStack348 = (uint)*(byte *)(iVar3 + 0x3d);
          local_160 = 0x43300000;
          param_5[3] = (float)(dVar21 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                         uStack348)
                                                                       - dVar16) * dVar14));
          uStack300 = (int)*(char *)(iVar7 + 0x31) ^ 0x80000000;
          local_130 = 0x43300000;
          *param_6 = (float)(dVar18 * (double)(float)((double)CONCAT44(0x43300000,uStack300) -
                                                     dVar15) + (double)*(float *)(iVar2 + 0xc));
          uStack292 = (int)*(char *)(iVar6 + 0x31) ^ 0x80000000;
          local_128 = 0x43300000;
          param_6[1] = (float)(dVar17 * (double)(float)((double)CONCAT44(0x43300000,uStack292) -
                                                       dVar15) + (double)*(float *)(iVar3 + 0xc));
          param_6[2] = (float)dVar22;
          param_6[3] = (float)dVar22;
          uStack284 = (int)*(char *)(iVar7 + 0x2d) ^ 0x80000000;
          local_120 = 0x43300000;
          *param_7 = (float)((double)(float)((double)CONCAT44(0x43300000,uStack284) - dVar15) *
                             dVar11 + (double)*(float *)(iVar2 + 0x10));
          uStack276 = (int)*(char *)(iVar6 + 0x2d) ^ 0x80000000;
          local_118 = 0x43300000;
          param_7[1] = (float)((double)(float)((double)CONCAT44(0x43300000,uStack276) - dVar15) *
                               dVar10 + (double)*(float *)(iVar3 + 0x10));
          uStack268 = (uint)*(byte *)(iVar2 + 0x3e) << 8 ^ 0x80000000;
          local_110 = 0x43300000;
          dVar14 = (double)FUN_80294204((double)(float)((double)(float)(dVar12 * (double)(float)((
                                                  double)CONCAT44(0x43300000,uStack268) - dVar15)) /
                                                  dVar20));
          uStack260 = (uint)*(byte *)(iVar2 + 0x3d);
          local_108 = 0x43300000;
          param_7[2] = (float)(dVar21 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                         uStack260)
                                                                       - dVar16) * dVar14));
          uStack252 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
          local_100 = 0x43300000;
          dVar14 = (double)FUN_80294204((double)(float)((double)(float)(dVar12 * (double)(float)((
                                                  double)CONCAT44(0x43300000,uStack252) - dVar15)) /
                                                  dVar20));
          uStack244 = (uint)*(byte *)(iVar3 + 0x3d);
          local_f8 = 0x43300000;
          param_7[3] = (float)(dVar21 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                         uStack244)
                                                                       - dVar16) * dVar14));
          iVar8 = iVar8 + 1;
          param_5 = param_5 + 4;
          param_6 = param_6 + 4;
          param_7 = param_7 + 4;
          iVar4 = iVar4 + 4;
        } while (iVar4 < 0x10);
      }
      else if (param_8 == 0) {
        *param_5 = (float)(dVar16 * (double)(float)(dVar18 * dVar11) + (double)*(float *)(iVar2 + 8)
                          );
        param_5[1] = (float)(dVar16 * (double)(float)(dVar17 * dVar13) +
                            (double)*(float *)(iVar3 + 8));
        uStack244 = (uint)*(byte *)(iVar2 + 0x3e) << 8 ^ 0x80000000;
        local_f8 = 0x43300000;
        dVar15 = (double)FUN_80293e80((double)((FLOAT_803e04d8 *
                                               (float)((double)CONCAT44(0x43300000,uStack244) -
                                                      DOUBLE_803e04f0)) / FLOAT_803e04dc));
        uStack252 = (uint)*(byte *)(iVar2 + 0x3d);
        local_100 = 0x43300000;
        param_5[2] = FLOAT_803e04e4 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack252) -
                                            DOUBLE_803e04f8) * dVar15);
        uStack260 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
        local_108 = 0x43300000;
        dVar15 = (double)FUN_80293e80((double)((FLOAT_803e04d8 *
                                               (float)((double)CONCAT44(0x43300000,uStack260) -
                                                      DOUBLE_803e04f0)) / FLOAT_803e04dc));
        uStack268 = (uint)*(byte *)(iVar3 + 0x3d);
        local_110 = 0x43300000;
        param_5[3] = FLOAT_803e04e4 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack268) -
                                            DOUBLE_803e04f8) * dVar15);
        *param_6 = (float)(dVar18 * param_2 + (double)*(float *)(iVar2 + 0xc));
        param_6[1] = (float)(dVar17 * param_2 + (double)*(float *)(iVar3 + 0xc));
        fVar1 = FLOAT_803e04e8;
        param_6[2] = FLOAT_803e04e8;
        param_6[3] = fVar1;
        *param_7 = (float)(dVar16 * (double)(float)(dVar18 * -dVar10) +
                          (double)*(float *)(iVar2 + 0x10));
        param_7[1] = (float)(dVar16 * (double)(float)(dVar17 * -dVar12) +
                            (double)*(float *)(iVar3 + 0x10));
        uStack276 = (uint)*(byte *)(iVar2 + 0x3e) << 8 ^ 0x80000000;
        local_118 = 0x43300000;
        dVar16 = (double)FUN_80294204((double)((FLOAT_803e04d8 *
                                               (float)((double)CONCAT44(0x43300000,uStack276) -
                                                      DOUBLE_803e04f0)) / FLOAT_803e04dc));
        uStack284 = (uint)*(byte *)(iVar2 + 0x3d);
        local_120 = 0x43300000;
        param_7[2] = FLOAT_803e04e4 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack284) -
                                            DOUBLE_803e04f8) * dVar16);
        uStack292 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
        local_128 = 0x43300000;
        dVar16 = (double)FUN_80294204((double)((FLOAT_803e04d8 *
                                               (float)((double)CONCAT44(0x43300000,uStack292) -
                                                      DOUBLE_803e04f0)) / FLOAT_803e04dc));
        uStack300 = (uint)*(byte *)(iVar3 + 0x3d);
        local_130 = 0x43300000;
        param_7[3] = FLOAT_803e04e4 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack300) -
                                            DOUBLE_803e04f8) * dVar16);
      }
      else {
        iVar4 = iVar2 + (param_8 - 2);
        uStack244 = (int)*(char *)(iVar4 + 0x2d) ^ 0x80000000;
        local_f8 = 0x43300000;
        *param_5 = (float)((double)CONCAT44(0x43300000,uStack244) - DOUBLE_803e04f0) *
                   (float)(dVar18 * dVar11) + *(float *)(iVar2 + 8);
        iVar8 = iVar3 + (param_8 - 2);
        uStack252 = (int)*(char *)(iVar8 + 0x2d) ^ 0x80000000;
        local_100 = 0x43300000;
        param_5[1] = (float)((double)CONCAT44(0x43300000,uStack252) - dVar15) *
                     (float)(dVar17 * dVar13) + *(float *)(iVar3 + 8);
        uStack260 = (uint)*(byte *)(iVar2 + 0x3e) << 8 ^ 0x80000000;
        local_108 = 0x43300000;
        dVar16 = (double)FUN_80293e80((double)((FLOAT_803e04d8 *
                                               (float)((double)CONCAT44(0x43300000,uStack260) -
                                                      dVar15)) / FLOAT_803e04dc));
        uStack268 = (uint)*(byte *)(iVar2 + 0x3d);
        local_110 = 0x43300000;
        param_5[2] = FLOAT_803e04e4 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack268) -
                                            DOUBLE_803e04f8) * dVar16);
        uStack276 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
        local_118 = 0x43300000;
        dVar16 = (double)FUN_80293e80((double)((FLOAT_803e04d8 *
                                               (float)((double)CONCAT44(0x43300000,uStack276) -
                                                      DOUBLE_803e04f0)) / FLOAT_803e04dc));
        uStack284 = (uint)*(byte *)(iVar3 + 0x3d);
        local_120 = 0x43300000;
        param_5[3] = FLOAT_803e04e4 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack284) -
                                            DOUBLE_803e04f8) * dVar16);
        dVar16 = DOUBLE_803e04f0;
        uStack292 = (int)*(char *)(iVar4 + 0x31) ^ 0x80000000;
        local_128 = 0x43300000;
        *param_6 = (float)(dVar18 * (double)(float)((double)CONCAT44(0x43300000,uStack292) -
                                                   DOUBLE_803e04f0) +
                          (double)*(float *)(iVar2 + 0xc));
        uStack300 = (int)*(char *)(iVar8 + 0x31) ^ 0x80000000;
        local_130 = 0x43300000;
        param_6[1] = (float)(dVar17 * (double)(float)((double)CONCAT44(0x43300000,uStack300) -
                                                     dVar16) + (double)*(float *)(iVar3 + 0xc));
        fVar1 = FLOAT_803e04e8;
        param_6[2] = FLOAT_803e04e8;
        param_6[3] = fVar1;
        uStack308 = (int)*(char *)(iVar4 + 0x2d) ^ 0x80000000;
        local_138 = 0x43300000;
        *param_7 = (float)((double)CONCAT44(0x43300000,uStack308) - dVar16) *
                   (float)(dVar18 * -dVar10) + *(float *)(iVar2 + 0x10);
        uStack316 = (int)*(char *)(iVar8 + 0x2d) ^ 0x80000000;
        local_140 = 0x43300000;
        param_7[1] = (float)((double)CONCAT44(0x43300000,uStack316) - dVar16) *
                     (float)(dVar17 * -dVar12) + *(float *)(iVar3 + 0x10);
        uStack324 = (uint)*(byte *)(iVar2 + 0x3e) << 8 ^ 0x80000000;
        local_148 = 0x43300000;
        dVar16 = (double)FUN_80294204((double)((FLOAT_803e04d8 *
                                               (float)((double)CONCAT44(0x43300000,uStack324) -
                                                      dVar16)) / FLOAT_803e04dc));
        uStack332 = (uint)*(byte *)(iVar2 + 0x3d);
        local_150 = 0x43300000;
        param_7[2] = FLOAT_803e04e4 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack332) -
                                            DOUBLE_803e04f8) * dVar16);
        uStack340 = (uint)*(byte *)(iVar3 + 0x3e) << 8 ^ 0x80000000;
        local_158 = 0x43300000;
        dVar16 = (double)FUN_80294204((double)((FLOAT_803e04d8 *
                                               (float)((double)CONCAT44(0x43300000,uStack340) -
                                                      DOUBLE_803e04f0)) / FLOAT_803e04dc));
        uStack348 = (uint)*(byte *)(iVar3 + 0x3d);
        local_160 = 0x43300000;
        param_7[3] = FLOAT_803e04e4 *
                     (float)((double)(float)((double)CONCAT44(0x43300000,uStack348) -
                                            DOUBLE_803e04f8) * dVar16);
      }
    }
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  __psq_l0(auStack40,uVar9);
  __psq_l1(auStack40,uVar9);
  __psq_l0(auStack56,uVar9);
  __psq_l1(auStack56,uVar9);
  __psq_l0(auStack72,uVar9);
  __psq_l1(auStack72,uVar9);
  __psq_l0(auStack88,uVar9);
  __psq_l1(auStack88,uVar9);
  __psq_l0(auStack104,uVar9);
  __psq_l1(auStack104,uVar9);
  __psq_l0(auStack120,uVar9);
  __psq_l1(auStack120,uVar9);
  __psq_l0(auStack136,uVar9);
  __psq_l1(auStack136,uVar9);
  __psq_l0(auStack152,uVar9);
  __psq_l1(auStack152,uVar9);
  __psq_l0(auStack168,uVar9);
  __psq_l1(auStack168,uVar9);
  __psq_l0(auStack184,uVar9);
  __psq_l1(auStack184,uVar9);
  FUN_8028610c(uVar5);
  return;
}

