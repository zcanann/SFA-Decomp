// Function: FUN_8000fe8c
// Entry: 8000fe8c
// Size: 396 bytes

/* WARNING: Removing unreachable block (ram,0x8000fff8) */

void FUN_8000fe8c(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  float *pfVar7;
  float *pfVar8;
  float *pfVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined4 uVar13;
  double dVar14;
  undefined8 in_f31;
  double dVar15;
  undefined8 uVar16;
  float local_138 [21];
  float local_e4 [21];
  float local_90 [34];
  undefined auStack8 [8];
  
  uVar13 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar16 = FUN_802860c8();
  iVar4 = (int)((ulonglong)uVar16 >> 0x20);
  iVar12 = 0;
  iVar11 = 0;
  iVar10 = 0;
  if (*(int *)(iVar4 + 0x84) != 0) {
    iVar12 = *(int *)(iVar4 + 0x84) + *(int *)(iVar4 + 0x10) * 4;
  }
  if (*(int *)(iVar4 + 0x88) != 0) {
    iVar11 = *(int *)(iVar4 + 0x88) + *(int *)(iVar4 + 0x10) * 4;
  }
  if (*(int *)(iVar4 + 0x8c) != 0) {
    iVar10 = *(int *)(iVar4 + 0x8c) + *(int *)(iVar4 + 0x10) * 4;
  }
  if (*(int *)(iVar4 + 0x98) != 0) {
    FUN_80010018(iVar12,iVar11,iVar10,local_90,local_e4,local_138,(int)uVar16);
  }
  dVar15 = (double)FLOAT_803de658;
  *(float *)(iVar4 + 0x14) = FLOAT_803de658;
  pfVar9 = local_90;
  pfVar8 = local_e4;
  pfVar7 = local_138;
  iVar6 = iVar4;
  for (iVar5 = 0; iVar5 < (int)uVar16; iVar5 = iVar5 + 1) {
    fVar1 = FLOAT_803de658;
    if (iVar12 != 0) {
      fVar1 = pfVar9[1] - *pfVar9;
    }
    fVar2 = FLOAT_803de658;
    if (iVar11 != 0) {
      fVar2 = pfVar8[1] - *pfVar8;
    }
    fVar3 = FLOAT_803de658;
    if (iVar10 != 0) {
      fVar3 = pfVar7[1] - *pfVar7;
    }
    if ((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2) <= dVar15) {
      *(float *)(iVar6 + 0x18) = FLOAT_803de67c;
    }
    else {
      dVar14 = (double)FUN_802931a0();
      *(float *)(iVar6 + 0x18) = (float)dVar14;
    }
    *(float *)(iVar4 + 0x14) = *(float *)(iVar4 + 0x14) + *(float *)(iVar6 + 0x18);
    pfVar9 = pfVar9 + 1;
    pfVar8 = pfVar8 + 1;
    pfVar7 = pfVar7 + 1;
    iVar6 = iVar6 + 4;
  }
  __psq_l0(auStack8,uVar13);
  __psq_l1(auStack8,uVar13);
  FUN_80286114();
  return;
}

