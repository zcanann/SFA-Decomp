// Function: FUN_800e5434
// Entry: 800e5434
// Size: 624 bytes

/* WARNING: Removing unreachable block (ram,0x800e567c) */
/* WARNING: Removing unreachable block (ram,0x800e566c) */
/* WARNING: Removing unreachable block (ram,0x800e5674) */
/* WARNING: Removing unreachable block (ram,0x800e5684) */

void FUN_800e5434(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  float *pfVar4;
  short sVar5;
  undefined2 uVar6;
  uint *puVar7;
  float **ppfVar8;
  uint uVar9;
  int iVar10;
  float *pfVar11;
  uint *puVar12;
  undefined4 uVar13;
  double dVar14;
  undefined8 in_f28;
  double dVar15;
  undefined8 in_f29;
  double dVar16;
  undefined8 in_f30;
  double dVar17;
  undefined8 in_f31;
  double dVar18;
  undefined8 uVar19;
  float **local_98;
  float local_94 [5];
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  undefined4 local_70;
  uint uStack108;
  undefined4 local_68;
  uint uStack100;
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  uVar19 = FUN_802860d8();
  iVar2 = (int)((ulonglong)uVar19 >> 0x20);
  puVar7 = (uint *)uVar19;
  if ((int)(uint)*(byte *)(puVar7 + 0x97) >> 4 == 4) {
    dVar15 = (double)FLOAT_803e0668;
    uVar9 = 0;
    pfVar11 = local_94;
    puVar12 = puVar7;
    dVar16 = dVar15;
    dVar17 = dVar15;
    dVar18 = dVar15;
    for (iVar10 = 0; dVar14 = DOUBLE_803e0670, iVar10 < (int)(uint)*(byte *)(puVar7 + 0x97) >> 4;
        iVar10 = iVar10 + 1) {
      *pfVar11 = (float)puVar12[3];
      iVar3 = FUN_80065e50((double)(float)puVar12[2],(double)*(float *)(iVar2 + 0x1c),
                           (double)(float)puVar12[4],iVar2,&local_98,0xffffffff,0);
      bVar1 = false;
      if ((iVar3 != 0) && (ppfVar8 = local_98, 0 < iVar3)) {
        do {
          if (!bVar1) {
            pfVar4 = *ppfVar8;
            dVar14 = (double)*pfVar4;
            if ((dVar14 < (double)(FLOAT_803e066c + *(float *)(iVar2 + 0x1c))) &&
               (*(char *)(pfVar4 + 5) != '\x0e')) {
              *pfVar11 = *pfVar4;
              dVar18 = (double)(float)(dVar18 + (double)pfVar4[1]);
              dVar17 = (double)(float)(dVar17 + (double)pfVar4[2]);
              dVar16 = (double)(float)(dVar16 + (double)pfVar4[3]);
              dVar15 = (double)(float)(dVar15 + dVar14);
              uVar9 = uVar9 + 1;
              bVar1 = true;
            }
          }
          iVar3 = iVar3 + -1;
          ppfVar8 = ppfVar8 + 1;
        } while (iVar3 != 0);
      }
      puVar12[3] = (uint)*pfVar11;
      puVar12 = puVar12 + 3;
      pfVar11 = pfVar11 + 1;
    }
    if (uVar9 == 0) {
      *(undefined *)((int)puVar7 + 0x261) = 0;
    }
    else {
      uStack124 = uVar9 ^ 0x80000000;
      local_80 = 0x43300000;
      *(float *)(iVar2 + 0x1c) =
           (float)(dVar15 / (double)(float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e0670
                                           ));
      local_78 = 0x43300000;
      puVar7[0x68] = (uint)(float)(dVar18 / (double)(float)((double)CONCAT44(0x43300000,uStack124) -
                                                           dVar14));
      local_70 = 0x43300000;
      puVar7[0x69] = (uint)(float)(dVar17 / (double)(float)((double)CONCAT44(0x43300000,uStack124) -
                                                           dVar14));
      local_68 = 0x43300000;
      puVar7[0x6a] = (uint)(float)(dVar16 / (double)(float)((double)CONCAT44(0x43300000,uStack124) -
                                                           dVar14));
      *(undefined *)((int)puVar7 + 0x261) = 1;
      uStack116 = uStack124;
      uStack108 = uStack124;
      uStack100 = uStack124;
    }
    dVar17 = (double)(*(float *)(puVar7[1] + 0x2c) - *(float *)(puVar7[1] + 8));
    dVar16 = (double)(local_94[3] - local_94[0]);
    FUN_800217c0(dVar16,dVar17);
    sVar5 = FUN_800217c0(dVar16,dVar17);
    *(short *)(iVar2 + 2) = -sVar5;
    if ((*puVar7 & 0x400) != 0) {
      uVar6 = FUN_800217c0((double)(local_94[1] - local_94[0]),
                           (double)(((float *)puVar7[1])[3] - *(float *)puVar7[1]));
      *(undefined2 *)(iVar2 + 4) = uVar6;
    }
  }
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  __psq_l0(auStack24,uVar13);
  __psq_l1(auStack24,uVar13);
  __psq_l0(auStack40,uVar13);
  __psq_l1(auStack40,uVar13);
  __psq_l0(auStack56,uVar13);
  __psq_l1(auStack56,uVar13);
  FUN_80286124();
  return;
}

