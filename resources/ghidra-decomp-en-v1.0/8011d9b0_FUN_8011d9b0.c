// Function: FUN_8011d9b0
// Entry: 8011d9b0
// Size: 896 bytes

/* WARNING: Removing unreachable block (ram,0x8011dd08) */
/* WARNING: Removing unreachable block (ram,0x8011dd00) */
/* WARNING: Removing unreachable block (ram,0x8011dd10) */

void FUN_8011d9b0(void)

{
  undefined4 uVar1;
  short *psVar2;
  int iVar3;
  undefined4 *puVar4;
  int *piVar5;
  short sVar6;
  int iVar7;
  short **ppsVar8;
  short **ppsVar9;
  undefined4 uVar10;
  undefined8 in_f29;
  double dVar11;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
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
  FUN_802860d4();
  if (DAT_803dd7c5 == '\0') {
    sVar6 = 0;
    iVar7 = 0;
    ppsVar9 = (short **)&DAT_803a93ec;
    ppsVar8 = (short **)&DAT_803a93e0;
    dVar11 = (double)FLOAT_803e1e3c;
    dVar13 = (double)FLOAT_803e1e40;
    dVar12 = (double)FLOAT_803e1e44;
    do {
      uVar1 = FUN_8002bdf4(0x20,0x65e);
      psVar2 = (short *)FUN_8002df90(uVar1,4,0xffffffff,0xffffffff,0);
      *ppsVar9 = psVar2;
      *(float *)(*ppsVar9 + 6) = (float)dVar11;
      *(float *)(*ppsVar9 + 8) = (float)dVar13;
      *(float *)(*ppsVar9 + 10) = (float)dVar12;
      **ppsVar9 = sVar6;
      *(char *)((int)*ppsVar9 + 0xad) = (char)iVar7;
      uVar1 = FUN_8002b588(*ppsVar9);
      FUN_8002853c(uVar1,FUN_80124794);
      uVar1 = FUN_8002bdf4(0x20,0x65f);
      psVar2 = (short *)FUN_8002df90(uVar1,4,0xffffffff,0xffffffff,0);
      *ppsVar8 = psVar2;
      *(float *)(*ppsVar8 + 6) = (float)dVar11;
      *(float *)(*ppsVar8 + 8) = (float)dVar13;
      *(float *)(*ppsVar8 + 10) = (float)dVar12;
      **ppsVar8 = sVar6;
      uVar1 = FUN_8002b588(*ppsVar8);
      FUN_8002853c(uVar1,FUN_80124854);
      sVar6 = sVar6 + 0x5555;
      ppsVar9 = ppsVar9 + 1;
      ppsVar8 = ppsVar8 + 1;
      iVar7 = iVar7 + 1;
    } while (iVar7 < 3);
    uVar1 = FUN_8002bdf4(0x20,0x6e9);
    DAT_803dd868 = (undefined2 *)FUN_8002df90(uVar1,4,0xffffffff,0xffffffff,0);
    *(float *)(DAT_803dd868 + 6) = FLOAT_803e1e3c;
    *(float *)(DAT_803dd868 + 8) = FLOAT_803e1e48;
    *(float *)(DAT_803dd868 + 10) = FLOAT_803e1e4c;
    *DAT_803dd868 = 0x7447;
    *(float *)(DAT_803dd868 + 4) = FLOAT_803e1e50;
    uVar1 = FUN_8002bdf4(0x20,0x602);
    puRam803dd86c = (undefined2 *)FUN_8002df90(uVar1,4,0xffffffff,0xffffffff,0);
    *(float *)(puRam803dd86c + 6) = FLOAT_803e1e3c;
    *(float *)(puRam803dd86c + 8) = FLOAT_803e1e54;
    *(float *)(puRam803dd86c + 10) = FLOAT_803e1e4c;
    *puRam803dd86c = 0x7447;
    *(float *)(puRam803dd86c + 4) = FLOAT_803e1e58;
    uVar1 = FUN_8002bdf4(0x20,0x755);
    DAT_803dd860 = FUN_8002df90(uVar1,4,0xffffffff,0xffffffff,0);
    FUN_8002853c(**(undefined4 **)(DAT_803dd860 + 0x7c),FUN_8011e0d8);
    uVar1 = FUN_8002bdf4(0x20,0x756);
    iRam803dd864 = FUN_8002df90(uVar1,4,0xffffffff,0xffffffff,0);
    FUN_8002853c(**(undefined4 **)(iRam803dd864 + 0x7c),FUN_8011e0d8);
    iVar7 = 4;
    puVar4 = &DAT_8031bfa0;
    piVar5 = &DAT_803a9420;
    dVar11 = (double)FLOAT_803e1e3c;
    dVar12 = (double)FLOAT_803e1e5c;
    do {
      uVar1 = FUN_8002bdf4(0x20,*puVar4);
      iVar3 = FUN_8002df90(uVar1,4,0xffffffff,0xffffffff,0);
      *piVar5 = iVar3;
      *(float *)(*piVar5 + 0xc) = (float)dVar11;
      *(float *)(*piVar5 + 0x10) = (float)dVar12;
      *(float *)(*piVar5 + 0x14) = (float)dVar12;
      *(undefined2 *)*piVar5 = 0x7447;
      *(float *)(*piVar5 + 8) = (float)dVar11;
      if (0x90000000 < *(uint *)(*piVar5 + 0x4c)) {
        *(undefined4 *)(*piVar5 + 0x4c) = 0;
      }
      puVar4 = puVar4 + 1;
      piVar5 = piVar5 + 1;
      iVar7 = iVar7 + 1;
    } while (iVar7 < 6);
    iVar7 = FUN_8002bdf4(0x24,0x14b);
    *(undefined2 *)(iVar7 + 0x1c) = 1;
    DAT_803dd85c = FUN_8002df90(iVar7,4,0xffffffff,0xffffffff,0);
    DAT_803dd7c5 = '\x01';
  }
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  __psq_l0(auStack40,uVar10);
  __psq_l1(auStack40,uVar10);
  FUN_80286120();
  return;
}

