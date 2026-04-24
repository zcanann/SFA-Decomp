// Function: FUN_8012c000
// Entry: 8012c000
// Size: 1368 bytes

/* WARNING: Removing unreachable block (ram,0x8012c530) */
/* WARNING: Removing unreachable block (ram,0x8012c520) */
/* WARNING: Removing unreachable block (ram,0x8012c510) */
/* WARNING: Removing unreachable block (ram,0x8012c500) */
/* WARNING: Removing unreachable block (ram,0x8012c508) */
/* WARNING: Removing unreachable block (ram,0x8012c518) */
/* WARNING: Removing unreachable block (ram,0x8012c528) */
/* WARNING: Removing unreachable block (ram,0x8012c538) */

void FUN_8012c000(void)

{
  float fVar1;
  bool bVar2;
  short sVar3;
  short sVar4;
  int iVar5;
  char cVar8;
  int iVar6;
  ushort uVar7;
  byte bVar9;
  byte bVar10;
  uint uVar11;
  undefined4 uVar12;
  double dVar13;
  double dVar14;
  undefined8 in_f24;
  double dVar15;
  undefined8 in_f25;
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
  undefined auStack264 [32];
  undefined4 local_e8;
  uint uStack228;
  double local_e0;
  undefined4 local_d8;
  uint uStack212;
  undefined4 local_d0;
  uint uStack204;
  undefined4 local_c8;
  uint uStack196;
  undefined4 local_c0;
  uint uStack188;
  undefined4 local_b8;
  uint uStack180;
  undefined4 local_b0;
  uint uStack172;
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar12 = 0;
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
  FUN_802860cc();
  iVar5 = FUN_8002b9ec();
  uVar11 = 5;
  FUN_80295bc8();
  bVar10 = 5;
  bVar9 = 1;
  cVar8 = FUN_8012b6bc();
  if (cVar8 == '\0') {
    bVar9 = 4;
    uVar11 = 2;
  }
  if (iVar5 == 0) {
    bVar2 = true;
  }
  else {
    bVar2 = false;
    iVar6 = FUN_8005afac((double)*(float *)(iVar5 + 0xc),(double)*(float *)(iVar5 + 0x14));
    if ((iVar6 != 0) || (iVar5 = FUN_802972a8(iVar5), iVar5 == 0)) {
      bVar2 = true;
    }
  }
  if (((DAT_803db424 == '\0') || (uVar7 = FUN_800ea2bc(), uVar7 < 3)) || (!bVar2)) {
    uVar11 = uVar11 - 1;
    bVar10 = 4;
  }
  sVar3 = (short)(0x10000 / (uVar11 & 0xff));
  sVar4 = -(short)DAT_803dba64 * sVar3 - DAT_803dd782;
  if (0x8000 < sVar4) {
    sVar4 = sVar4 + 1;
  }
  if (sVar4 < -0x8000) {
    sVar4 = sVar4 + -1;
  }
  iVar5 = (int)sVar4 / 7 + ((int)sVar4 >> 0x1f);
  DAT_803dd782 = DAT_803dd782 + ((short)iVar5 - (short)(iVar5 >> 0x1f));
  DAT_803dd78a = DAT_803dd78a + (ushort)DAT_803db410;
  *DAT_803dd868 = (short)((int)DAT_803dd78a << 9);
  uStack228 = DAT_803dd78a * 1000 ^ 0x80000000;
  local_e8 = 0x43300000;
  dVar13 = (double)FUN_80293e80((double)((FLOAT_803e1ec8 *
                                         (float)((double)CONCAT44(0x43300000,uStack228) -
                                                DOUBLE_803e1e78)) / FLOAT_803e1e94));
  local_e0 = (double)(longlong)(int)((double)FLOAT_803e2178 * dVar13);
  DAT_803dd868[2] = (short)(int)((double)FLOAT_803e2178 * dVar13);
  uStack212 = DAT_803dd78a * 400 ^ 0x80000000;
  local_d8 = 0x43300000;
  dVar13 = (double)FUN_80293e80((double)((FLOAT_803e1ec8 *
                                         (float)((double)CONCAT44(0x43300000,uStack212) -
                                                DOUBLE_803e1e78)) / FLOAT_803e1e94));
  *(float *)(DAT_803dd868 + 8) = (float)(DOUBLE_803e2180 * dVar13 + (double)FLOAT_803e217c);
  dVar13 = DOUBLE_803e1e78;
  uStack204 = (0x400 - DAT_803dd78c) * (0x400 - DAT_803dd78c) ^ 0x80000000;
  local_d0 = 0x43300000;
  *(float *)(DAT_803dd868 + 8) =
       *(float *)(DAT_803dd868 + 8) -
       (float)((double)CONCAT44(0x43300000,uStack204) - DOUBLE_803e1e78) / FLOAT_803e2188;
  *(undefined4 *)(iRam803dd86c + 0x10) = *(undefined4 *)(DAT_803dd868 + 8);
  uStack196 = (int)DAT_803dd78c ^ 0x80000000;
  local_c8 = 0x43300000;
  *(float *)(iRam803dd86c + 8) =
       FLOAT_803e218c * (float)((double)CONCAT44(0x43300000,uStack196) - dVar13) * FLOAT_803e2190;
  FUN_8002fa48((double)FLOAT_803e1e58,(double)FLOAT_803db414,iRam803dd86c,auStack264);
  dVar16 = (double)FLOAT_803e2190;
  dVar17 = (double)FLOAT_803e1ec8;
  dVar18 = (double)FLOAT_803e1e94;
  dVar19 = (double)FLOAT_803e1e64;
  dVar20 = (double)FLOAT_803e2050;
  dVar21 = (double)FLOAT_803e2010;
  dVar13 = DOUBLE_803e1e78;
  for (; bVar9 <= bVar10; bVar9 = bVar9 + 1) {
    uVar11 = (uint)bVar9;
    if (0x90000000 < *(uint *)((&DAT_803a9410)[uVar11] + 0x4c)) {
      *(undefined4 *)((&DAT_803a9410)[uVar11] + 0x4c) = 0;
    }
    fVar1 = FLOAT_803e2194;
    if ((uint)bVar9 == (int)DAT_803dba64) {
      fVar1 = FLOAT_803e1fc0;
    }
    uStack196 = (int)DAT_803dd784 ^ 0x80000000;
    local_c8 = 0x43300000;
    *(float *)((&DAT_803a9410)[uVar11] + 8) =
         (float)((double)((float)((double)CONCAT44(0x43300000,uStack196) - dVar13) * fVar1) * dVar16
                );
    *(undefined *)((&DAT_803a9410)[uVar11] + 0x37) = 0xff;
    FUN_8002fa48((double)*(float *)(&DAT_8031bfa8 + uVar11 * 4),(double)FLOAT_803db414,
                 (&DAT_803a9410)[uVar11],auStack264);
    iVar5 = (uint)bVar9 * (int)sVar3;
    uStack204 = DAT_803dd782 + iVar5 ^ 0x80000000;
    local_d0 = 0x43300000;
    dVar14 = (double)FUN_80293e80((double)(float)((double)(float)(dVar17 * (double)(float)((double)
                                                  CONCAT44(0x43300000,uStack204) - dVar13)) / dVar18
                                                 ));
    uStack212 = (int)DAT_803dd784 ^ 0x80000000;
    local_d8 = 0x43300000;
    *(float *)((&DAT_803a9410)[uVar11] + 0xc) =
         (float)((double)((float)((double)CONCAT44(0x43300000,uStack212) - dVar13) *
                         (float)(dVar19 * dVar14)) * dVar16 + (double)*(float *)(DAT_803dd868 + 6));
    local_e0 = (double)CONCAT44(0x43300000,DAT_803dd782 + iVar5 ^ 0x80000000);
    dVar14 = (double)FUN_80293e80((double)(float)((double)(float)(dVar17 * (double)(float)(local_e0 
                                                  - dVar13)) / dVar18));
    dVar15 = (double)(float)(dVar20 * dVar14 +
                            (double)(float)((double)*(float *)(DAT_803dd868 + 8) + dVar21));
    uStack228 = DAT_803dd782 + iVar5 ^ 0x80000000;
    local_e8 = 0x43300000;
    dVar14 = (double)FUN_80294204((double)(float)((double)(float)(dVar17 * (double)(float)((double)
                                                  CONCAT44(0x43300000,uStack228) - dVar13)) / dVar18
                                                 ));
    uStack188 = (int)DAT_803dd784 ^ 0x80000000;
    local_c0 = 0x43300000;
    *(float *)((&DAT_803a9410)[uVar11] + 0x10) =
         (float)((double)((float)((double)CONCAT44(0x43300000,uStack188) - dVar13) *
                         (float)(dVar19 - dVar14)) * dVar16 + dVar15);
    uStack180 = DAT_803dd782 + iVar5 ^ 0x80000000;
    local_b8 = 0x43300000;
    dVar14 = (double)FUN_80294204((double)(float)((double)(float)(dVar17 * (double)(float)((double)
                                                  CONCAT44(0x43300000,uStack180) - dVar13)) / dVar18
                                                 ));
    uStack172 = (int)DAT_803dd784 ^ 0x80000000;
    local_b0 = 0x43300000;
    *(float *)((&DAT_803a9410)[uVar11] + 0x14) =
         (float)((double)((float)((double)CONCAT44(0x43300000,uStack172) - dVar13) *
                         (float)(dVar19 * dVar14)) * dVar16 + (double)*(float *)(DAT_803dd868 + 10))
    ;
  }
  __psq_l0(auStack8,uVar12);
  __psq_l1(auStack8,uVar12);
  __psq_l0(auStack24,uVar12);
  __psq_l1(auStack24,uVar12);
  __psq_l0(auStack40,uVar12);
  __psq_l1(auStack40,uVar12);
  __psq_l0(auStack56,uVar12);
  __psq_l1(auStack56,uVar12);
  __psq_l0(auStack72,uVar12);
  __psq_l1(auStack72,uVar12);
  __psq_l0(auStack88,uVar12);
  __psq_l1(auStack88,uVar12);
  __psq_l0(auStack104,uVar12);
  __psq_l1(auStack104,uVar12);
  __psq_l0(auStack120,uVar12);
  __psq_l1(auStack120,uVar12);
  FUN_80286118();
  return;
}

