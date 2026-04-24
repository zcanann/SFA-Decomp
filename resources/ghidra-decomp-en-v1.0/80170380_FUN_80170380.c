// Function: FUN_80170380
// Entry: 80170380
// Size: 1788 bytes

/* WARNING: Removing unreachable block (ram,0x80170a54) */
/* WARNING: Removing unreachable block (ram,0x80170a44) */
/* WARNING: Removing unreachable block (ram,0x80170a4c) */
/* WARNING: Removing unreachable block (ram,0x80170a5c) */

void FUN_80170380(void)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int *piVar6;
  int *piVar7;
  float *pfVar8;
  undefined4 uVar9;
  double dVar10;
  double dVar11;
  undefined8 in_f28;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar12;
  double dVar13;
  undefined8 in_f31;
  double dVar14;
  undefined8 uVar15;
  double local_78;
  double local_70;
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
  uVar15 = FUN_802860d4();
  iVar4 = (int)((ulonglong)uVar15 >> 0x20);
  pfVar8 = (float *)&DAT_80320a28;
  piVar6 = *(int **)(iVar4 + 0xb8);
  iVar2 = FUN_8002b9ec();
  iVar3 = 0;
  if (iVar2 != 0) {
    iVar3 = FUN_802966cc();
  }
  fVar1 = FLOAT_803e33cc;
  switch((uint)uVar15 & 0xff) {
  case 0:
    if (*piVar6 != 0) {
      FUN_8001db6c((double)FLOAT_803e33a8,*piVar6,0);
    }
    fVar1 = FLOAT_803e33b0;
    if (FLOAT_803e33ac != (float)piVar6[2]) {
      piVar6[4] = (int)FLOAT_803e33b0;
      piVar6[1] = (int)fVar1;
      if (iVar3 != 0) {
        FUN_8016d9ec(iVar3,7,0);
      }
    }
    piVar6[2] = (int)FLOAT_803e33ac;
    piVar6[3] = (int)FLOAT_803e33b4;
    FUN_8000b824(iVar4,0x42c);
    FUN_8000b824(iVar4,0x42d);
    break;
  case 1:
    if (FLOAT_803e33ac == (float)piVar6[2]) {
      if (iVar3 != 0) {
        FUN_8016d9ec(iVar3,7,8);
      }
      if (*piVar6 == 0) {
        iVar2 = FUN_8001f4c8(0,1);
        *piVar6 = iVar2;
      }
      if (*piVar6 != 0) {
        FUN_8001db2c(*piVar6,2);
        FUN_8001dd88((double)*(float *)(iVar4 + 0xc),
                     (double)(*(float *)(iVar4 + 0x10) - FLOAT_803e33b8),
                     (double)*(float *)(iVar4 + 0x14),*piVar6);
        FUN_8001daf0(*piVar6,0,0xff,0xff,0xff);
        FUN_8001da18(*piVar6,0,0xff,0xff,0xff);
        FUN_8001dc38((double)FLOAT_803e33bc,(double)FLOAT_803e33c0,*piVar6);
        FUN_8001db54(*piVar6,1);
        FUN_8001db6c((double)FLOAT_803e33ac,*piVar6,1);
        FUN_8001d620(*piVar6,0,0);
        FUN_8001dd40(*piVar6,1);
      }
      fVar1 = FLOAT_803e33ac;
      if (FLOAT_803e33ac == (float)piVar6[2]) {
        piVar6[4] = (int)FLOAT_803e33b0;
        piVar6[1] = (int)fVar1;
      }
      piVar6[2] = (int)FLOAT_803e33b0;
      dVar12 = (double)FLOAT_803e33c4;
      piVar6[3] = (int)FLOAT_803e33c4;
      iVar2 = 0;
      piVar7 = &DAT_80320a38;
      dVar11 = (double)FLOAT_803e33a8;
      dVar14 = (double)FLOAT_803e33c8;
      piVar5 = piVar6;
      dVar13 = DOUBLE_803e33d0;
      do {
        *(undefined2 *)(piVar5 + 0xd) = 0xc000;
        dVar10 = (double)FUN_8029333c(*(undefined2 *)(piVar5 + 0xd));
        piVar6[9] = (int)(*pfVar8 * (float)((double)(float)(dVar12 + dVar10) * dVar11));
        piVar6[5] = *piVar7;
        iVar3 = FUN_800221a0(0x78,0x7f);
        local_78 = (double)CONCAT44(0x43300000,iVar2 * iVar3 ^ 0x80000000);
        *(short *)(piVar5 + 0xf) = (short)(int)(dVar14 + (double)(float)(local_78 - dVar13));
        piVar5 = (int *)((int)piVar5 + 2);
        pfVar8 = pfVar8 + 1;
        piVar6 = piVar6 + 1;
        piVar7 = piVar7 + 1;
        iVar2 = iVar2 + 1;
      } while (iVar2 < 4);
      FUN_8000bb18(iVar4,0x42c);
      FUN_8000bb18(iVar4,0x42d);
    }
    break;
  case 2:
    if (iVar3 != 0) {
      FUN_8016d9ec(iVar3,7,0);
    }
    if (FLOAT_803e33ac != (float)piVar6[2]) {
      piVar6[4] = (int)FLOAT_803e33cc;
    }
    piVar6[2] = (int)FLOAT_803e33ac;
    piVar6[3] = (int)FLOAT_803e33b4;
    if (*piVar6 != 0) {
      FUN_8001db6c((double)FLOAT_803e33a8,*piVar6,0);
    }
    FUN_8000b824(iVar4,0x42c);
    FUN_8000b824(iVar4,0x42d);
    break;
  case 3:
    if (iVar3 != 0) {
      FUN_8016d9ec(iVar3,7,8);
    }
    if (*piVar6 == 0) {
      iVar2 = FUN_8001f4c8(0,1);
      *piVar6 = iVar2;
    }
    if (*piVar6 != 0) {
      FUN_8001db2c(*piVar6,2);
      FUN_8001dd88((double)*(float *)(iVar4 + 0xc),
                   (double)(*(float *)(iVar4 + 0x10) - FLOAT_803e33b8),
                   (double)*(float *)(iVar4 + 0x14),*piVar6);
      FUN_8001daf0(*piVar6,0,0xff,0xff,0xff);
      FUN_8001da18(*piVar6,0,0xff,0xff,0xff);
      FUN_8001dc38((double)FLOAT_803e33bc,(double)FLOAT_803e33c0,*piVar6);
      FUN_8001db54(*piVar6,1);
      FUN_8001db6c((double)FLOAT_803e33ac,*piVar6,1);
      FUN_8001d620(*piVar6,0,0);
      FUN_8001dd40(*piVar6,1);
    }
    if (FLOAT_803e33ac == (float)piVar6[2]) {
      piVar6[4] = (int)FLOAT_803e33cc;
    }
    piVar6[2] = (int)FLOAT_803e33cc;
    dVar14 = (double)FLOAT_803e33c4;
    piVar6[3] = (int)FLOAT_803e33c4;
    iVar2 = 0;
    piVar7 = &DAT_80320a38;
    dVar13 = (double)FLOAT_803e33a8;
    piVar5 = piVar6;
    do {
      *(undefined2 *)(piVar6 + 0xd) = 0;
      dVar11 = (double)FUN_8029333c(*(undefined2 *)(piVar6 + 0xd));
      piVar5[9] = (int)(*pfVar8 * (float)((double)(float)(dVar14 + dVar11) * dVar13));
      piVar5[5] = *piVar7;
      piVar6 = (int *)((int)piVar6 + 2);
      pfVar8 = pfVar8 + 1;
      piVar5 = piVar5 + 1;
      piVar7 = piVar7 + 1;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 4);
    FUN_8000bb18(iVar4,0x42d);
    FUN_8000bb18(iVar4,0x42c);
    break;
  case 4:
    piVar6[2] = (int)FLOAT_803e33cc;
    dVar14 = (double)FLOAT_803e33c4;
    piVar6[3] = (int)FLOAT_803e33c4;
    piVar6[4] = (int)fVar1;
    iVar2 = 0;
    pfVar8 = (float *)&DAT_80320a48;
    piVar7 = &DAT_80320a58;
    dVar11 = (double)FLOAT_803e33a8;
    dVar12 = (double)FLOAT_803e33c8;
    piVar5 = piVar6;
    dVar13 = DOUBLE_803e33d0;
    do {
      *(undefined2 *)(piVar6 + 0xd) = 0xc000;
      dVar10 = (double)FUN_8029333c(*(undefined2 *)(piVar6 + 0xd));
      piVar5[9] = (int)(*pfVar8 * (float)((double)(float)(dVar14 + dVar10) * dVar11));
      piVar5[5] = *piVar7;
      iVar3 = FUN_800221a0(0x78,0x7f);
      local_70 = (double)CONCAT44(0x43300000,iVar2 * iVar3 ^ 0x80000000);
      *(short *)(piVar6 + 0xf) = (short)(int)(dVar12 + (double)(float)(local_70 - dVar13));
      piVar6 = (int *)((int)piVar6 + 2);
      pfVar8 = pfVar8 + 1;
      piVar5 = piVar5 + 1;
      piVar7 = piVar7 + 1;
      iVar2 = iVar2 + 1;
    } while (iVar2 < 4);
    FUN_8000bb18(iVar4,0x42d);
    FUN_8000bb18(iVar4,0x42c);
    break;
  case 5:
    piVar6[2] = (int)FLOAT_803e33ac;
    piVar6[3] = (int)FLOAT_803e33b4;
    piVar6[4] = (int)FLOAT_803e33cc;
    FUN_8000b824(iVar4,0x42c);
    FUN_8000b824(iVar4,0x42d);
    break;
  case 6:
    iVar4 = 0;
    pfVar8 = (float *)&DAT_80320a48;
    piVar7 = &DAT_80320a58;
    dVar13 = (double)FLOAT_803e33c4;
    dVar14 = (double)FLOAT_803e33a8;
    piVar5 = piVar6;
    do {
      *(undefined2 *)(piVar6 + 0xd) = 0x4000;
      dVar11 = (double)FUN_8029333c(*(undefined2 *)(piVar6 + 0xd));
      piVar5[9] = (int)(*pfVar8 * (float)((double)(float)(dVar13 + dVar11) * dVar14));
      piVar5[5] = *piVar7;
      piVar6 = (int *)((int)piVar6 + 2);
      pfVar8 = pfVar8 + 1;
      piVar5 = piVar5 + 1;
      piVar7 = piVar7 + 1;
      iVar4 = iVar4 + 1;
    } while (iVar4 < 4);
    break;
  case 7:
    if (iVar3 != 0) {
      FUN_8016d9ec(iVar3,7,0);
    }
    if (*piVar6 != 0) {
      FUN_8001db6c((double)FLOAT_803e33a8,*piVar6,0);
    }
    fVar1 = FLOAT_803e33ac;
    piVar6[2] = (int)FLOAT_803e33ac;
    piVar6[3] = (int)fVar1;
    piVar6[4] = (int)fVar1;
    piVar6[1] = (int)fVar1;
    *(byte *)(piVar6 + 0x17) = *(byte *)(piVar6 + 0x17) | 1;
    *(byte *)((int)piVar6 + 0x5d) = *(byte *)((int)piVar6 + 0x5d) | 1;
    *(byte *)((int)piVar6 + 0x5e) = *(byte *)((int)piVar6 + 0x5e) | 1;
    *(byte *)((int)piVar6 + 0x5f) = *(byte *)((int)piVar6 + 0x5f) | 1;
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  __psq_l0(auStack40,uVar9);
  __psq_l1(auStack40,uVar9);
  __psq_l0(auStack56,uVar9);
  __psq_l1(auStack56,uVar9);
  FUN_80286120();
  return;
}

