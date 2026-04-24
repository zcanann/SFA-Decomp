// Function: FUN_8003befc
// Entry: 8003befc
// Size: 636 bytes

/* WARNING: Removing unreachable block (ram,0x8003c150) */
/* WARNING: Removing unreachable block (ram,0x8003c140) */
/* WARNING: Removing unreachable block (ram,0x8003c138) */
/* WARNING: Removing unreachable block (ram,0x8003c148) */
/* WARNING: Removing unreachable block (ram,0x8003c158) */

void FUN_8003befc(void)

{
  int iVar1;
  float *pfVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  int iVar6;
  byte *pbVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  undefined8 in_f27;
  double dVar11;
  undefined8 in_f28;
  double dVar12;
  undefined8 in_f29;
  double dVar13;
  undefined8 in_f30;
  double dVar14;
  undefined8 in_f31;
  double dVar15;
  undefined8 uVar16;
  undefined auStack280 [48];
  float local_e8;
  float local_e4;
  float local_e0;
  float local_dc;
  float local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  undefined4 local_88;
  uint uStack132;
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
  uVar16 = FUN_802860cc();
  iVar1 = (int)((ulonglong)uVar16 >> 0x20);
  uVar5 = (undefined4)uVar16;
  iVar9 = 0;
  dVar14 = (double)FLOAT_803dea18;
  dVar15 = (double)FLOAT_803dea1c;
  dVar13 = DOUBLE_803dea20;
  for (iVar8 = 0; iVar8 < (int)(uint)*(byte *)(iVar1 + 0xf4); iVar8 = iVar8 + 1) {
    pbVar7 = (byte *)(*(int *)(iVar1 + 0x54) + iVar9);
    pfVar2 = (float *)FUN_8002856c(uVar5,iVar8 + (uint)*(byte *)(iVar1 + 0xf3));
    uVar3 = FUN_8002856c(uVar5,*pbVar7);
    uVar4 = FUN_8002856c(uVar5,pbVar7[1]);
    uStack132 = (uint)pbVar7[2];
    local_88 = 0x43300000;
    dVar12 = (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack132) - dVar13) *
                            dVar14);
    dVar11 = (double)(float)(dVar15 - dVar12);
    iVar6 = *(int *)(iVar1 + 0x3c) + (uint)*pbVar7 * 0x1c;
    FUN_802472e4(-(double)*(float *)(iVar6 + 0x10),-(double)*(float *)(iVar6 + 0x14),
                 -(double)*(float *)(iVar6 + 0x18),auStack280);
    FUN_80246eb4(uVar3,auStack280,&local_b8);
    iVar6 = *(int *)(iVar1 + 0x3c) + (uint)pbVar7[1] * 0x1c;
    FUN_802472e4(-(double)*(float *)(iVar6 + 0x10),-(double)*(float *)(iVar6 + 0x14),
                 -(double)*(float *)(iVar6 + 0x18),auStack280);
    FUN_80246eb4(uVar4,auStack280,&local_e8);
    *pfVar2 = (float)((double)local_b8 * dVar12 + (double)(float)((double)local_e8 * dVar11));
    pfVar2[1] = (float)((double)local_b4 * dVar12 + (double)(float)((double)local_e4 * dVar11));
    pfVar2[2] = (float)((double)local_b0 * dVar12 + (double)(float)((double)local_e0 * dVar11));
    pfVar2[3] = (float)((double)local_ac * dVar12 + (double)(float)((double)local_dc * dVar11));
    pfVar2[4] = (float)((double)local_a8 * dVar12 + (double)(float)((double)local_d8 * dVar11));
    pfVar2[5] = (float)((double)local_a4 * dVar12 + (double)(float)((double)local_d4 * dVar11));
    pfVar2[6] = (float)((double)local_a0 * dVar12 + (double)(float)((double)local_d0 * dVar11));
    pfVar2[7] = (float)((double)local_9c * dVar12 + (double)(float)((double)local_cc * dVar11));
    pfVar2[8] = (float)((double)local_98 * dVar12 + (double)(float)((double)local_c8 * dVar11));
    pfVar2[9] = (float)((double)local_94 * dVar12 + (double)(float)((double)local_c4 * dVar11));
    pfVar2[10] = (float)((double)local_90 * dVar12 + (double)(float)((double)local_c0 * dVar11));
    pfVar2[0xb] = (float)((double)local_8c * dVar12 + (double)(float)((double)local_bc * dVar11));
    iVar9 = iVar9 + 4;
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
  FUN_80286118();
  return;
}

