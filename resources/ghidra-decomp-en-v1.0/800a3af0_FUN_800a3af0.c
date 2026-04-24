// Function: FUN_800a3af0
// Entry: 800a3af0
// Size: 1552 bytes

/* WARNING: Removing unreachable block (ram,0x800a40d8) */
/* WARNING: Removing unreachable block (ram,0x800a40c8) */
/* WARNING: Removing unreachable block (ram,0x800a40b8) */
/* WARNING: Removing unreachable block (ram,0x800a40a8) */
/* WARNING: Removing unreachable block (ram,0x800a4098) */
/* WARNING: Removing unreachable block (ram,0x800a4088) */
/* WARNING: Removing unreachable block (ram,0x800a4090) */
/* WARNING: Removing unreachable block (ram,0x800a40a0) */
/* WARNING: Removing unreachable block (ram,0x800a40b0) */
/* WARNING: Removing unreachable block (ram,0x800a40c0) */
/* WARNING: Removing unreachable block (ram,0x800a40d0) */
/* WARNING: Removing unreachable block (ram,0x800a40e0) */

void FUN_800a3af0(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int param_5)

{
  char cVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  undefined2 *puVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  double extraout_f1;
  undefined8 in_f20;
  double dVar11;
  undefined8 in_f21;
  undefined8 in_f22;
  double dVar12;
  double dVar13;
  undefined8 in_f23;
  double dVar14;
  double dVar15;
  undefined8 in_f24;
  double dVar16;
  double dVar17;
  undefined8 in_f25;
  double dVar18;
  undefined8 in_f26;
  double dVar19;
  undefined8 in_f27;
  double dVar20;
  undefined8 in_f28;
  double dVar21;
  undefined8 in_f29;
  double dVar22;
  undefined8 in_f30;
  double dVar23;
  undefined8 in_f31;
  double dVar24;
  undefined8 uVar25;
  undefined2 local_148;
  undefined2 local_146;
  undefined2 local_144;
  float local_140;
  float local_13c;
  float local_138;
  float local_134;
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
  undefined4 local_f0;
  uint uStack236;
  undefined4 local_e8;
  uint uStack228;
  undefined4 local_e0;
  uint uStack220;
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
  
  uVar10 = 0;
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
  uVar25 = FUN_802860dc();
  iVar9 = (int)((ulonglong)uVar25 >> 0x20);
  iVar7 = (int)uVar25;
  bVar4 = false;
  dVar11 = extraout_f1;
  puVar5 = (undefined2 *)FUN_8000faac();
  DAT_803dd29c = puVar5[1];
  DAT_803dd29a = *puVar5;
  dVar12 = (double)(*(float *)(puVar5 + 6) - *(float *)(param_5 + 0xc));
  dVar14 = (double)(*(float *)(puVar5 + 8) - *(float *)(param_5 + 0x10));
  dVar16 = (double)(*(float *)(puVar5 + 10) - *(float *)(param_5 + 0x14));
  for (iVar8 = 0; iVar8 < iVar7; iVar8 = iVar8 + 1) {
    cVar1 = *(char *)(iVar9 + iVar8 * 0x4c + 0x48);
    if ((((cVar1 == '\x12') || ((byte)(cVar1 - 0x10U) < 2)) || ((byte)(cVar1 - 0x14U) < 2)) ||
       (cVar1 == '\x17')) {
      DAT_8030fde8 = (float)dVar12;
      DAT_8030fdec = (float)dVar14;
      DAT_8030fdf0 = (float)dVar16;
      dVar13 = (double)FUN_802931a0((double)(float)(dVar16 * dVar16 +
                                                   (double)(float)(dVar12 * dVar12 +
                                                                  (double)(float)(dVar14 * dVar14)))
                                   );
      dVar15 = (double)(float)((double)FLOAT_803df468 * dVar13);
      if ((double)FLOAT_803df46c != dVar13) {
        dVar12 = (double)(float)(dVar12 / dVar13);
        dVar14 = (double)(float)(dVar14 / dVar13);
        dVar16 = (double)(float)(dVar16 / dVar13);
      }
      dVar12 = (double)(float)(dVar12 * dVar15);
      dVar14 = (double)(float)(dVar14 * dVar15);
      dVar16 = (double)(float)(dVar16 * dVar15);
      local_13c = FLOAT_803df46c;
      local_138 = FLOAT_803df46c;
      local_134 = FLOAT_803df46c;
      local_140 = FLOAT_803df470;
      local_144 = 0;
      local_146 = 0;
      local_148 = 0;
      bVar4 = true;
      iVar8 = iVar7;
    }
  }
  if (bVar4) {
    for (iVar8 = 0; iVar8 < iVar7; iVar8 = iVar8 + 1) {
      cVar1 = *(char *)(iVar9 + 0x48);
      if (((cVar1 == '\x12') || ((byte)(cVar1 - 0x10U) < 2)) ||
         (((byte)(cVar1 - 0x14U) < 2 || (cVar1 == '\x17')))) {
        fVar2 = *(float *)(param_5 + 0xc);
        uStack300 = (int)*(short *)(iVar9 + 0x10) ^ 0x80000000;
        local_130 = 0x43300000;
        dVar24 = (double)(fVar2 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack300) -
                                                         DOUBLE_803df480) - dVar11));
        uStack292 = (int)*(short *)(iVar9 + 0x16) ^ 0x80000000;
        local_128 = 0x43300000;
        dVar23 = (double)(float)((double)CONCAT44(0x43300000,uStack292) - DOUBLE_803df480);
        fVar3 = *(float *)(param_5 + 0x14);
        uStack284 = (int)*(short *)(iVar9 + 0x1c) ^ 0x80000000;
        local_120 = 0x43300000;
        dVar22 = (double)(fVar3 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack284) -
                                                         DOUBLE_803df480) - param_2));
        uStack276 = (int)*(short *)(iVar9 + 0x12) ^ 0x80000000;
        local_118 = 0x43300000;
        dVar21 = (double)(fVar2 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack276) -
                                                         DOUBLE_803df480) - dVar11));
        uStack268 = (int)*(short *)(iVar9 + 0x18) ^ 0x80000000;
        local_110 = 0x43300000;
        dVar20 = (double)(float)((double)CONCAT44(0x43300000,uStack268) - DOUBLE_803df480);
        uStack260 = (int)*(short *)(iVar9 + 0x1e) ^ 0x80000000;
        local_108 = 0x43300000;
        dVar19 = (double)(fVar3 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack260) -
                                                         DOUBLE_803df480) - param_2));
        uStack252 = (int)*(short *)(iVar9 + 0x14) ^ 0x80000000;
        local_100 = 0x43300000;
        dVar18 = (double)(fVar2 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack252) -
                                                         DOUBLE_803df480) - dVar11));
        uStack244 = (int)*(short *)(iVar9 + 0x1a) ^ 0x80000000;
        local_f8 = 0x43300000;
        dVar17 = (double)(float)((double)CONCAT44(0x43300000,uStack244) - DOUBLE_803df480);
        uStack236 = (int)*(short *)(iVar9 + 0x20) ^ 0x80000000;
        local_f0 = 0x43300000;
        dVar15 = (double)(fVar3 + (float)((double)(float)((double)CONCAT44(0x43300000,uStack236) -
                                                         DOUBLE_803df480) - param_2));
        uStack228 = FUN_800221a0(1,1000);
        uStack228 = uStack228 ^ 0x80000000;
        local_e8 = 0x43300000;
        dVar13 = (double)((float)((double)CONCAT44(0x43300000,uStack228) - DOUBLE_803df480) /
                         FLOAT_803df474);
        uStack220 = FUN_800221a0(1,1000);
        uStack220 = uStack220 ^ 0x80000000;
        local_e0 = 0x43300000;
        dVar12 = (double)FUN_802931a0((double)((float)((double)CONCAT44(0x43300000,uStack220) -
                                                      DOUBLE_803df480) / FLOAT_803df474));
        dVar14 = (double)(float)((double)FLOAT_803df470 - dVar12);
        dVar16 = (double)(float)((double)(float)((double)FLOAT_803df470 - dVar13) * dVar12);
        dVar12 = (double)(float)(dVar13 * dVar12);
        local_13c = (float)(dVar12 * dVar18 +
                           (double)(float)(dVar14 * dVar24 + (double)(float)(dVar16 * dVar21)));
        local_134 = (float)(dVar12 * dVar15 +
                           (double)(float)(dVar14 * dVar22 + (double)(float)(dVar16 * dVar19)));
        local_138 = (float)(dVar12 * dVar17 +
                           (double)(float)(dVar14 * dVar23 + (double)(float)(dVar16 * dVar20))) +
                    FLOAT_803df478;
        cVar1 = *(char *)(iVar9 + 0x48);
        if ((cVar1 == '\x12') || (cVar1 == '\x10')) {
          iVar6 = FUN_800221a0(0,0x1e);
          if (iVar6 == 1) {
            (**(code **)(*DAT_803dca88 + 8))(param_5,0x72,&local_148,0x200001,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x11') {
          iVar6 = FUN_800221a0(0,8);
          if (iVar6 == 2) {
            (**(code **)(*DAT_803dca88 + 8))(param_5,0x73,&local_148,0x111,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x14') {
          iVar6 = FUN_800221a0(0,8);
          if (iVar6 == 2) {
            (**(code **)(*DAT_803dca88 + 8))(param_5,0x73,&local_148,0x111,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x15') {
          iVar6 = FUN_800221a0(0,8);
          if (iVar6 == 2) {
            (**(code **)(*DAT_803dca88 + 8))(param_5,0x73,&local_148,0x111,0xffffffff,0);
          }
        }
        else if (cVar1 == '\x17') {
          (**(code **)(*DAT_803dca88 + 8))(param_5,400,&local_148,0x111,0xffffffff,0);
          (**(code **)(*DAT_803dca88 + 8))(param_5,400,&local_148,0x111,0xffffffff,0);
          (**(code **)(*DAT_803dca88 + 8))(param_5,400,&local_148,0x111,0xffffffff,0);
        }
      }
      iVar9 = iVar9 + 0x4c;
    }
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  __psq_l0(auStack40,uVar10);
  __psq_l1(auStack40,uVar10);
  __psq_l0(auStack56,uVar10);
  __psq_l1(auStack56,uVar10);
  __psq_l0(auStack72,uVar10);
  __psq_l1(auStack72,uVar10);
  __psq_l0(auStack88,uVar10);
  __psq_l1(auStack88,uVar10);
  __psq_l0(auStack104,uVar10);
  __psq_l1(auStack104,uVar10);
  __psq_l0(auStack120,uVar10);
  __psq_l1(auStack120,uVar10);
  __psq_l0(auStack136,uVar10);
  __psq_l1(auStack136,uVar10);
  __psq_l0(auStack152,uVar10);
  __psq_l1(auStack152,uVar10);
  __psq_l0(auStack168,uVar10);
  __psq_l1(auStack168,uVar10);
  __psq_l0(auStack184,uVar10);
  __psq_l1(auStack184,uVar10);
  FUN_80286128();
  return;
}

