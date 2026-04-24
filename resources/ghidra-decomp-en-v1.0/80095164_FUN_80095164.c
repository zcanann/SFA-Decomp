// Function: FUN_80095164
// Entry: 80095164
// Size: 664 bytes

/* WARNING: Removing unreachable block (ram,0x800953d4) */
/* WARNING: Removing unreachable block (ram,0x800953c4) */
/* WARNING: Removing unreachable block (ram,0x800953b4) */
/* WARNING: Removing unreachable block (ram,0x800953a4) */
/* WARNING: Removing unreachable block (ram,0x80095394) */
/* WARNING: Removing unreachable block (ram,0x80095384) */
/* WARNING: Removing unreachable block (ram,0x8009538c) */
/* WARNING: Removing unreachable block (ram,0x8009539c) */
/* WARNING: Removing unreachable block (ram,0x800953ac) */
/* WARNING: Removing unreachable block (ram,0x800953bc) */
/* WARNING: Removing unreachable block (ram,0x800953cc) */
/* WARNING: Removing unreachable block (ram,0x800953dc) */

void FUN_80095164(void)

{
  float fVar1;
  float *pfVar2;
  undefined4 uVar3;
  uint uVar4;
  float *pfVar5;
  int iVar6;
  undefined4 uVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  undefined8 in_f20;
  double dVar13;
  undefined8 in_f21;
  undefined8 in_f22;
  double dVar14;
  undefined8 in_f23;
  double dVar15;
  undefined8 in_f24;
  double dVar16;
  undefined8 in_f25;
  undefined8 in_f26;
  double dVar17;
  undefined8 in_f27;
  double dVar18;
  undefined8 in_f28;
  double dVar19;
  undefined8 in_f29;
  double dVar20;
  undefined8 in_f30;
  double dVar21;
  undefined8 in_f31;
  double dVar22;
  undefined auStack424 [48];
  undefined auStack376 [48];
  undefined auStack328 [48];
  undefined auStack280 [48];
  undefined4 local_e8;
  uint uStack228;
  longlong local_e0;
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
  
  uVar7 = 0;
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
  pfVar2 = (float *)FUN_802860dc();
  dVar9 = (double)pfVar2[3];
  FUN_80247318(dVar9,dVar9,dVar9,auStack328);
  uVar4 = 0;
  iVar6 = 0;
  dVar15 = (double)FLOAT_803df2e0;
  dVar16 = (double)FLOAT_803df2e4;
  dVar17 = (double)FLOAT_803df2f8;
  dVar18 = (double)FLOAT_803df2e8;
  dVar19 = (double)FLOAT_803df2f0;
  dVar20 = (double)FLOAT_803df2ec;
  dVar21 = (double)FLOAT_803df2f4;
  dVar22 = (double)FLOAT_803df2fc;
  dVar13 = (double)FLOAT_803df304;
  pfVar5 = pfVar2;
  dVar9 = DOUBLE_803df308;
  do {
    dVar10 = (double)pfVar2[4];
    uStack228 = uVar4 ^ 0x80000000;
    local_e8 = 0x43300000;
    dVar12 = (double)(float)(dVar16 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                       uStack228) -
                                                                     dVar9) / dVar17));
    dVar11 = (double)(float)((double)(float)(dVar15 + dVar12) * dVar10);
    fVar1 = (float)(dVar11 - dVar18);
    dVar14 = -(double)(float)(dVar19 * (double)(fVar1 * fVar1) - dVar20);
    dVar8 = (double)(float)(dVar21 + dVar12);
    dVar12 = dVar20;
    if (dVar8 <= dVar10) {
      dVar12 = (double)((float)(dVar20 - dVar10) / (float)(dVar20 - dVar8));
    }
    dVar8 = (double)(float)(dVar22 * dVar11 + dVar20);
    FUN_80247318(dVar8,dVar20,dVar8,auStack376);
    FUN_802472e4((double)FLOAT_803df300,(double)(float)(dVar22 * dVar14),(double)FLOAT_803df300,
                 auStack424);
    FUN_80246eb4(auStack424,auStack376,auStack280);
    FUN_80246eb4(auStack328,auStack280,auStack280);
    FUN_802472e4((double)(*pfVar2 - FLOAT_803dcdd8),(double)pfVar2[1],
                 (double)(pfVar2[2] - FLOAT_803dcddc),auStack424);
    FUN_80246eb4(auStack424,auStack280,auStack280);
    uVar3 = FUN_8000f54c();
    FUN_80246eb4(uVar3,auStack280,auStack280);
    FUN_8025d0a8(auStack280,iVar6);
    local_e0 = (longlong)(int)(dVar13 * dVar12);
    pfVar5[6] = (float)((int)(dVar13 * dVar12) & 0xff);
    iVar6 = iVar6 + 3;
    pfVar5 = pfVar5 + 1;
    uVar4 = uVar4 + 1;
  } while ((int)uVar4 < 8);
  FUN_80241a1c(pfVar2 + 6,0x20);
  FUN_80257e74(0xb,pfVar2 + 6,4);
  FUN_80258b24(1);
  FUN_8025ced8(DAT_803dd208,DAT_803dd204);
  FUN_80258b24(2);
  FUN_8025ced8(DAT_803dd208,DAT_803dd204);
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  __psq_l0(auStack56,uVar7);
  __psq_l1(auStack56,uVar7);
  __psq_l0(auStack72,uVar7);
  __psq_l1(auStack72,uVar7);
  __psq_l0(auStack88,uVar7);
  __psq_l1(auStack88,uVar7);
  __psq_l0(auStack104,uVar7);
  __psq_l1(auStack104,uVar7);
  __psq_l0(auStack120,uVar7);
  __psq_l1(auStack120,uVar7);
  __psq_l0(auStack136,uVar7);
  __psq_l1(auStack136,uVar7);
  __psq_l0(auStack152,uVar7);
  __psq_l1(auStack152,uVar7);
  __psq_l0(auStack168,uVar7);
  __psq_l1(auStack168,uVar7);
  __psq_l0(auStack184,uVar7);
  __psq_l1(auStack184,uVar7);
  FUN_80286128();
  return;
}

