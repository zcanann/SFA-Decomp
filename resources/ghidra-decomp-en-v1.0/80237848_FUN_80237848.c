// Function: FUN_80237848
// Entry: 80237848
// Size: 1960 bytes

/* WARNING: Removing unreachable block (ram,0x80237fc8) */
/* WARNING: Removing unreachable block (ram,0x80237fb8) */
/* WARNING: Removing unreachable block (ram,0x80237fa8) */
/* WARNING: Removing unreachable block (ram,0x80237fb0) */
/* WARNING: Removing unreachable block (ram,0x80237fc0) */
/* WARNING: Removing unreachable block (ram,0x80237fd0) */

void FUN_80237848(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  bool bVar1;
  byte bVar2;
  float fVar3;
  short sVar4;
  uint uVar5;
  short *psVar6;
  char cVar9;
  int iVar7;
  int iVar8;
  undefined4 uVar10;
  int iVar11;
  byte bVar12;
  int iVar13;
  float *pfVar14;
  undefined4 uVar15;
  undefined8 in_f26;
  double dVar16;
  undefined8 in_f27;
  double dVar17;
  undefined8 in_f28;
  double dVar18;
  undefined8 in_f29;
  double dVar19;
  undefined8 in_f30;
  double dVar20;
  undefined8 in_f31;
  double dVar21;
  undefined8 uVar22;
  undefined auStack216 [8];
  float local_d0;
  float local_c8;
  double local_c0;
  double local_b8;
  double local_b0;
  double local_a8;
  undefined4 local_a0;
  uint uStack156;
  double local_98;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar15 = 0;
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
  uVar22 = FUN_802860c0();
  psVar6 = (short *)((ulonglong)uVar22 >> 0x20);
  uVar10 = (undefined4)uVar22;
  pfVar14 = *(float **)(psVar6 + 0x5c);
  iVar13 = *(int *)(psVar6 + 0x26);
  if (param_6 != '\0') {
    cVar9 = FUN_8002073c();
    fVar3 = FLOAT_803db414;
    if (cVar9 != '\0') {
      fVar3 = FLOAT_803e73d0;
    }
    dVar17 = (double)fVar3;
    if ((*(char *)((int)pfVar14 + 0x26) < '\0') || (*pfVar14 != FLOAT_803e73d0)) {
      sVar4 = psVar6[0x23];
      if ((sVar4 == 0x835) || (sVar4 == 0x838)) {
        iVar7 = FUN_800394ac(psVar6,0,0);
        if (iVar7 != 0) {
          bVar1 = *(short *)(iVar13 + 0x1c) != 0;
          uVar5 = (uint)bVar1;
          if ((*(short *)(iVar13 + 0x1e) != -1) && (iVar8 = FUN_8001ffb4(), iVar8 != 0)) {
            uVar5 = countLeadingZeros((uint)bVar1);
            uVar5 = uVar5 >> 5 & 0xff;
          }
          if (uVar5 == 0) {
            local_b8 = (double)(longlong)(int)((double)FLOAT_803e73d4 * dVar17);
            *(short *)(iVar7 + 8) =
                 *(short *)(iVar7 + 8) + (short)(int)((double)FLOAT_803e73d4 * dVar17);
            if (9999 < *(short *)(iVar7 + 8)) {
              *(short *)(iVar7 + 8) = *(short *)(iVar7 + 8) + -10000;
            }
          }
          else {
            local_c0 = (double)(longlong)(int)((double)FLOAT_803e73d4 * dVar17);
            *(short *)(iVar7 + 8) =
                 *(short *)(iVar7 + 8) - (short)(int)((double)FLOAT_803e73d4 * dVar17);
            local_b8 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar7 + 8) ^ 0x80000000);
            if ((float)(local_b8 - DOUBLE_803e73f0) <= FLOAT_803e73d0) {
              *(short *)(iVar7 + 8) = *(short *)(iVar7 + 8) + 10000;
            }
          }
        }
        pfVar14[1] = (float)((double)pfVar14[1] - dVar17);
        fVar3 = FLOAT_803e73d0;
        if ((pfVar14[1] <= FLOAT_803e73d0) && (cVar9 == '\0')) {
          pfVar14[1] = FLOAT_803e73d8;
          local_b8 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar13 + 0x1a) ^ 0x80000000);
          local_d0 = ((float)(local_b8 - DOUBLE_803e73f0) / FLOAT_803e73dc) *
                     *(float *)(psVar6 + 4) * *pfVar14;
          local_c8 = fVar3;
          (**(code **)(*DAT_803dca88 + 8))(psVar6,0x7f7,auStack216,2,0xffffffff,0);
        }
        iVar7 = FUN_8002b588(psVar6);
        dVar19 = (double)*(float *)(psVar6 + 4);
        bVar2 = *(byte *)(psVar6 + 0x1b);
        sVar4 = *psVar6;
        dVar18 = (double)*(float *)(psVar6 + 8);
        dVar21 = (double)FLOAT_803e73dc;
        dVar16 = DOUBLE_803e73f8;
        dVar20 = DOUBLE_803e73f0;
        for (bVar12 = 0; bVar12 < 2; bVar12 = bVar12 + 1) {
          uVar5 = (uint)bVar12;
          iVar8 = uVar5 * 2;
          psVar6[2] = *(short *)(&DAT_803dc414 + iVar8);
          iVar11 = iVar8 + 0x20;
          *psVar6 = *(short *)((int)pfVar14 + iVar11);
          local_b8 = (double)CONCAT44(0x43300000,(int)*(short *)(&DAT_803dc410 + iVar8) ^ 0x80000000
                                     );
          local_c0 = (double)CONCAT44(0x43300000,(int)*(short *)((int)pfVar14 + iVar11) ^ 0x80000000
                                     );
          iVar8 = (int)(dVar17 * (double)(float)(local_b8 - dVar20) +
                       (double)(float)(local_c0 - dVar20));
          local_b0 = (double)(longlong)iVar8;
          *(short *)((int)pfVar14 + iVar11) = (short)iVar8;
          local_a8 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar13 + 0x1a) ^ 0x80000000);
          *(float *)(psVar6 + 4) =
               (float)((double)(float)(local_a8 - dVar20) / dVar21) *
               *pfVar14 * (float)((double)pfVar14[uVar5 + 5] * dVar19);
          local_a0 = 0x43300000;
          iVar8 = (int)(*pfVar14 *
                       pfVar14[uVar5 + 2] *
                       (float)((double)CONCAT44(0x43300000,(uint)bVar2) - dVar16));
          local_98 = (double)(longlong)iVar8;
          *(char *)((int)psVar6 + 0x37) = (char)iVar8;
          *(ushort *)(iVar7 + 0x18) = *(ushort *)(iVar7 + 0x18) & 0xfff7;
          uStack156 = (uint)bVar2;
          FUN_8003b8f4((double)FLOAT_803e73e0,psVar6,uVar10,param_3,param_4,param_5);
        }
        *(float *)(psVar6 + 4) = (float)dVar19;
        *(byte *)(psVar6 + 0x1b) = bVar2;
        *psVar6 = sVar4;
        *(float *)(psVar6 + 8) = (float)dVar18;
      }
      else if (sVar4 == 0x83d) {
        iVar13 = FUN_800394ac(psVar6,0,0);
        if (iVar13 != 0) {
          *(short *)(iVar13 + 8) =
               *(short *)(iVar13 + 8) + (short)(int)((double)FLOAT_803e73e4 * dVar17);
        }
        local_98 = (double)(longlong)(int)((double)FLOAT_803e73d4 * dVar17);
        *psVar6 = *psVar6 + (short)(int)((double)FLOAT_803e73d4 * dVar17);
        if (9999 < *(short *)(iVar13 + 8)) {
          *(short *)(iVar13 + 8) = *(short *)(iVar13 + 8) + -10000;
        }
        iVar13 = FUN_8002b588(psVar6);
        dVar21 = (double)*(float *)(psVar6 + 4);
        bVar2 = *(byte *)(psVar6 + 0x1b);
        sVar4 = *psVar6;
        dVar19 = (double)*(float *)(psVar6 + 8);
        dVar18 = (double)FLOAT_803e73e8;
        dVar16 = DOUBLE_803e73f8;
        dVar20 = DOUBLE_803e73f0;
        for (bVar12 = 0; bVar12 < 3; bVar12 = bVar12 + 1) {
          uVar5 = (uint)bVar12;
          iVar8 = uVar5 * 2 + 0x20;
          *psVar6 = *(short *)((int)pfVar14 + iVar8);
          local_98 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(&DAT_803dc3e8 + uVar5 * 2) ^ 0x80000000);
          uStack156 = (int)*(short *)((int)pfVar14 + iVar8) ^ 0x80000000;
          local_a0 = 0x43300000;
          iVar7 = (int)(dVar17 * (double)(float)(local_98 - dVar20) +
                       (double)(float)((double)CONCAT44(0x43300000,uStack156) - dVar20));
          local_a8 = (double)(longlong)iVar7;
          *(short *)((int)pfVar14 + iVar8) = (short)iVar7;
          *(float *)(psVar6 + 4) = *pfVar14 * (float)((double)pfVar14[uVar5 + 5] * dVar21);
          local_b0 = (double)CONCAT44(0x43300000,(uint)bVar2);
          iVar7 = (int)(*pfVar14 * pfVar14[uVar5 + 2] * (float)(local_b0 - dVar16));
          local_b8 = (double)(longlong)iVar7;
          *(char *)((int)psVar6 + 0x37) = (char)iVar7;
          *(float *)(psVar6 + 8) =
               -(float)((double)(float)(dVar18 * (double)pfVar14[uVar5 + 5]) * (double)*pfVar14 -
                       dVar19);
          *(ushort *)(iVar13 + 0x18) = *(ushort *)(iVar13 + 0x18) & 0xfff7;
          FUN_8003b8f4((double)FLOAT_803e73e0,psVar6,uVar10,param_3,param_4,param_5);
        }
        *(float *)(psVar6 + 4) = (float)dVar21;
        *(byte *)(psVar6 + 0x1b) = bVar2;
        *psVar6 = sVar4;
        *(float *)(psVar6 + 8) = (float)dVar19;
      }
      else {
        iVar13 = FUN_800394ac(psVar6,0,0);
        if (iVar13 != 0) {
          *(short *)(iVar13 + 8) =
               *(short *)(iVar13 + 8) + (short)(int)((double)FLOAT_803e73e4 * dVar17);
        }
        local_98 = (double)(longlong)(int)((double)FLOAT_803e73d4 * dVar17);
        *psVar6 = *psVar6 + (short)(int)((double)FLOAT_803e73d4 * dVar17);
        if (9999 < *(short *)(iVar13 + 8)) {
          *(short *)(iVar13 + 8) = *(short *)(iVar13 + 8) + -10000;
        }
        local_d0 = *(float *)(psVar6 + 4) * *pfVar14;
        if (cVar9 == '\0') {
          (**(code **)(*DAT_803dca88 + 8))(psVar6,0x7c2,auStack216,2,0xffffffff,0);
        }
        iVar13 = FUN_8002b588(psVar6);
        dVar21 = (double)*(float *)(psVar6 + 4);
        bVar2 = *(byte *)(psVar6 + 0x1b);
        sVar4 = *psVar6;
        dVar19 = (double)*(float *)(psVar6 + 8);
        dVar18 = (double)FLOAT_803e73ec;
        dVar16 = DOUBLE_803e73f8;
        dVar20 = DOUBLE_803e73f0;
        for (bVar12 = 0; bVar12 < 3; bVar12 = bVar12 + 1) {
          uVar5 = (uint)bVar12;
          iVar8 = uVar5 * 2 + 0x20;
          *psVar6 = *(short *)((int)pfVar14 + iVar8);
          local_98 = (double)CONCAT44(0x43300000,
                                      (int)*(short *)(&DAT_803dc3f0 + uVar5 * 2) ^ 0x80000000);
          uStack156 = (int)*(short *)((int)pfVar14 + iVar8) ^ 0x80000000;
          local_a0 = 0x43300000;
          iVar7 = (int)(dVar17 * (double)(float)(local_98 - dVar20) +
                       (double)(float)((double)CONCAT44(0x43300000,uStack156) - dVar20));
          local_a8 = (double)(longlong)iVar7;
          *(short *)((int)pfVar14 + iVar8) = (short)iVar7;
          *(float *)(psVar6 + 4) = *pfVar14 * (float)((double)pfVar14[uVar5 + 5] * dVar21);
          local_b0 = (double)CONCAT44(0x43300000,(uint)bVar2);
          iVar7 = (int)(*pfVar14 * pfVar14[uVar5 + 2] * (float)(local_b0 - dVar16));
          local_b8 = (double)(longlong)iVar7;
          *(char *)((int)psVar6 + 0x37) = (char)iVar7;
          *(float *)(psVar6 + 8) =
               (float)((double)(float)(dVar18 * (double)pfVar14[uVar5 + 5]) * (double)*pfVar14 +
                      dVar19);
          *(ushort *)(iVar13 + 0x18) = *(ushort *)(iVar13 + 0x18) & 0xfff7;
          FUN_8003b8f4((double)FLOAT_803e73e0,psVar6,uVar10,param_3,param_4,param_5);
        }
        *(float *)(psVar6 + 4) = (float)dVar21;
        *(byte *)(psVar6 + 0x1b) = bVar2;
        *psVar6 = sVar4;
        *(float *)(psVar6 + 8) = (float)dVar19;
      }
    }
  }
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  __psq_l0(auStack24,uVar15);
  __psq_l1(auStack24,uVar15);
  __psq_l0(auStack40,uVar15);
  __psq_l1(auStack40,uVar15);
  __psq_l0(auStack56,uVar15);
  __psq_l1(auStack56,uVar15);
  __psq_l0(auStack72,uVar15);
  __psq_l1(auStack72,uVar15);
  __psq_l0(auStack88,uVar15);
  __psq_l1(auStack88,uVar15);
  FUN_8028610c();
  return;
}

