// Function: FUN_8013351c
// Entry: 8013351c
// Size: 508 bytes

/* WARNING: Removing unreachable block (ram,0x801336f8) */
/* WARNING: Removing unreachable block (ram,0x801336e8) */
/* WARNING: Removing unreachable block (ram,0x801336e0) */
/* WARNING: Removing unreachable block (ram,0x801336f0) */
/* WARNING: Removing unreachable block (ram,0x80133700) */

void FUN_8013351c(void)

{
  undefined4 uVar1;
  double dVar2;
  double dVar3;
  undefined8 in_f27;
  double dVar4;
  undefined8 in_f28;
  double dVar5;
  undefined8 in_f29;
  double dVar6;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  uint local_78;
  uint local_74;
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar1 = 0;
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
  local_74 = DAT_803e2200 & 0xffffff00 | (uint)(byte)DAT_803dd930;
  FLOAT_803dd94c = -(FLOAT_803e2260 * FLOAT_803db414 - FLOAT_803dd94c);
  if (FLOAT_803e2224 < FLOAT_803dd94c) {
    FLOAT_803dd94c = FLOAT_803dd94c - FLOAT_803e2264;
  }
  dVar2 = (double)FUN_80293e80((double)((FLOAT_803e2220 * FLOAT_803dd94c) / FLOAT_803e2224));
  dVar8 = (double)(float)((double)FLOAT_803e2268 * dVar2);
  dVar2 = (double)FUN_80294204((double)((FLOAT_803e2220 * FLOAT_803dd94c) / FLOAT_803e2224));
  dVar7 = (double)(float)((double)FLOAT_803e2268 * dVar2);
  dVar2 = (double)FUN_80293e80((double)((FLOAT_803e2220 * (FLOAT_803dd94c + FLOAT_803e2270)) /
                                       FLOAT_803e2224));
  dVar6 = (double)(float)((double)FLOAT_803e226c * dVar2);
  dVar2 = (double)FUN_80294204((double)((FLOAT_803e2220 * (FLOAT_803dd94c + FLOAT_803e2270)) /
                                       FLOAT_803e2224));
  dVar5 = (double)(float)((double)FLOAT_803e226c * dVar2);
  dVar2 = (double)FUN_80293e80((double)((FLOAT_803e2220 * (FLOAT_803dd94c + FLOAT_803e2274)) /
                                       FLOAT_803e2224));
  dVar4 = (double)(float)((double)FLOAT_803e226c * dVar2);
  dVar2 = (double)FUN_80294204((double)((FLOAT_803e2220 * (FLOAT_803dd94c + FLOAT_803e2274)) /
                                       FLOAT_803e2224));
  local_78 = local_74;
  dVar3 = (double)FLOAT_803e2278;
  uStack108 = DAT_803dd938 + 0x32U ^ 0x80000000;
  local_70 = 0x43300000;
  local_68 = 0x43300000;
  local_60 = 0x43300000;
  uStack100 = uStack108;
  uStack92 = uStack108;
  FUN_80075a1c((double)(float)(dVar3 - dVar8),
               (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack108) -
                                              DOUBLE_803e2250) - dVar7),
               (double)(float)(dVar3 - dVar6),
               (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack108) -
                                              DOUBLE_803e2250) - dVar5),
               (double)(float)(dVar3 - dVar4),
               (double)((float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e2250) -
                       (float)((double)FLOAT_803e226c * dVar2)),&local_78);
  __psq_l0(auStack8,uVar1);
  __psq_l1(auStack8,uVar1);
  __psq_l0(auStack24,uVar1);
  __psq_l1(auStack24,uVar1);
  __psq_l0(auStack40,uVar1);
  __psq_l1(auStack40,uVar1);
  __psq_l0(auStack56,uVar1);
  __psq_l1(auStack56,uVar1);
  __psq_l0(auStack72,uVar1);
  __psq_l1(auStack72,uVar1);
  return;
}

