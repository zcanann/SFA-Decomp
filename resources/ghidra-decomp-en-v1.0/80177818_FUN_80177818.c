// Function: FUN_80177818
// Entry: 80177818
// Size: 1024 bytes

/* WARNING: Removing unreachable block (ram,0x80177bf0) */
/* WARNING: Removing unreachable block (ram,0x80177be8) */
/* WARNING: Removing unreachable block (ram,0x80177bf8) */

void FUN_80177818(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  char cVar5;
  int iVar6;
  float *pfVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  double dVar12;
  undefined8 in_f29;
  double dVar13;
  undefined8 in_f30;
  double dVar14;
  undefined8 in_f31;
  double dVar15;
  int local_58 [2];
  undefined4 local_50;
  uint uStack76;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar4 = FUN_802860dc();
  pfVar7 = *(float **)(iVar4 + 0xb8);
  *(undefined4 *)(iVar4 + 0x80) = *(undefined4 *)(iVar4 + 0xc);
  *(undefined4 *)(iVar4 + 0x84) = *(undefined4 *)(iVar4 + 0x10);
  *(undefined4 *)(iVar4 + 0x88) = *(undefined4 *)(iVar4 + 0x14);
  switch(*(undefined *)(pfVar7 + 2)) {
  case 0:
    iVar10 = FUN_8002b9ec();
    dVar12 = DOUBLE_803e35f8;
    while (iVar10 != 0) {
      fVar2 = *(float *)(iVar4 + 0xc) - *(float *)(iVar10 + 0xc);
      fVar1 = *(float *)(iVar4 + 0x10) - *(float *)(iVar10 + 0x10);
      fVar3 = *(float *)(iVar4 + 0x14) - *(float *)(iVar10 + 0x14);
      dVar13 = (double)FUN_802931a0((double)(fVar3 * fVar3 + fVar2 * fVar2 + fVar1 * fVar1));
      uStack76 = *(uint *)(iVar4 + 0xf8) ^ 0x80000000;
      local_50 = 0x43300000;
      if (dVar13 < (double)(float)((double)CONCAT44(0x43300000,uStack76) - dVar12)) {
        iVar6 = *(int *)(iVar10 + 0x54);
        *(char *)(iVar6 + 0x71) = *(char *)(iVar6 + 0x71) + '\x01';
        *(ushort *)(iVar6 + 0x60) = *(ushort *)(iVar6 + 0x60) & 0xfffe;
        *(char *)(*(int *)(iVar4 + 0x54) + 0x71) = *(char *)(*(int *)(iVar4 + 0x54) + 0x71) + '\x01'
        ;
      }
      if (*(short *)(iVar10 + 0x44) == 1) {
        iVar10 = FUN_8002b9ac();
      }
      else {
        iVar10 = 0;
      }
    }
    break;
  case 1:
    FUN_80038208(*(undefined4 *)(iVar4 + 0xf4));
    break;
  case 3:
    iVar10 = FUN_8002b9ec();
    if (iVar10 != 0) {
      DAT_803ac780 = *(undefined4 *)(iVar4 + 0x18);
      DAT_803ac784 = *(undefined4 *)(iVar4 + 0x1c);
      DAT_803ac788 = *(undefined4 *)(iVar4 + 0x20);
    }
    break;
  case 4:
    *(uint *)(iVar4 + 0xf8) = *(int *)(iVar4 + 0xf8) - (uint)DAT_803db410;
    if (*(int *)(*(int *)(iVar4 + 0x54) + 0x50) != 0) {
      *(undefined2 *)(*(int *)(iVar4 + 0x54) + 0x60) = 0;
    }
    iVar10 = *(int *)(iVar4 + 0xf4);
    if (iVar10 != 0) {
      iVar6 = FUN_80038208(iVar10);
      fVar2 = FLOAT_803e35ec;
      if (iVar6 == 0) break;
      fVar1 = *(float *)(iVar10 + 0x14);
      *(float *)(iVar4 + 0xc) =
           ((*(float *)(iVar10 + 0xc) - *(float *)(iVar4 + 0xc)) / FLOAT_803e35ec) * FLOAT_803db414
           + *(float *)(iVar4 + 0xc);
      *(float *)(iVar4 + 0x14) =
           ((fVar1 - *(float *)(iVar4 + 0x14)) / fVar2) * FLOAT_803db414 + *(float *)(iVar4 + 0x14);
      fVar2 = *(float *)(iVar10 + 0xc) - *pfVar7;
      fVar1 = *(float *)(iVar10 + 0x14) - pfVar7[1];
      dVar12 = (double)FUN_802931a0((double)(fVar2 * fVar2 + fVar1 * fVar1));
      dVar13 = (double)(float)((double)FLOAT_803e35f0 + dVar12);
      dVar15 = (double)(*(float *)(iVar4 + 0xc) - *pfVar7);
      dVar14 = (double)(*(float *)(iVar4 + 0x14) - pfVar7[1]);
      dVar12 = (double)FUN_802931a0((double)(float)(dVar15 * dVar15 +
                                                   (double)(float)(dVar14 * dVar14)));
      if (dVar13 < dVar12) {
        *(float *)(iVar4 + 0xc) = *pfVar7 + (float)(dVar15 * (double)(float)(dVar13 / dVar12));
        *(float *)(iVar4 + 0x14) = pfVar7[1] + (float)(dVar14 * (double)(float)(dVar13 / dVar12));
      }
      (**(code **)(*DAT_803dca88 + 8))(iVar4,0x25,0,0,0xffffffff,0);
      (**(code **)(*DAT_803dca88 + 8))(iVar4,0x56,0,0,0xffffffff,0);
    }
    cVar5 = FUN_80065e50((double)*(float *)(iVar4 + 0xc),(double)*(float *)(iVar4 + 0x10),
                         (double)*(float *)(iVar4 + 0x14),iVar4,local_58,0,0);
    fVar2 = FLOAT_803e35f4;
    for (iVar10 = 0; iVar10 < cVar5; iVar10 = iVar10 + 1) {
      fVar1 = **(float **)(local_58[0] + iVar10 * 4);
      if ((fVar1 < fVar2 + *(float *)(iVar4 + 0x10)) && (*(float *)(iVar4 + 0x10) - fVar2 < fVar1))
      {
        *(float *)(iVar4 + 0x10) = fVar1;
        iVar10 = (int)cVar5;
      }
    }
    break;
  case 5:
    iVar10 = FUN_8002b9ec();
    iVar6 = FUN_80296118();
    if ((iVar10 != 0) && (iVar6 != 0)) {
      DAT_803ac780 = *(undefined4 *)(iVar4 + 0x18);
      DAT_803ac784 = *(undefined4 *)(iVar4 + 0x1c);
      DAT_803ac788 = *(undefined4 *)(iVar4 + 0x20);
    }
    break;
  case 7:
    iVar9 = *(int *)(iVar4 + 0x54);
    iVar8 = *(int *)(*(int *)(iVar4 + 0xf4) + 0x54);
    iVar10 = iVar8;
    for (iVar6 = 0; iVar6 < *(char *)(iVar8 + 0x71); iVar6 = iVar6 + 1) {
      if (*(int *)(iVar10 + 0x7c) == iVar4) {
        *(ushort *)(iVar9 + 0x60) = *(ushort *)(iVar9 + 0x60) & 0xfffe;
        FUN_8002cbc4(iVar4);
      }
      iVar10 = iVar10 + 4;
    }
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  __psq_l0(auStack40,uVar11);
  __psq_l1(auStack40,uVar11);
  FUN_80286128();
  return;
}

