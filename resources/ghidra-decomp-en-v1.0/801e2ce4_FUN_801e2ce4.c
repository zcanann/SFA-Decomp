// Function: FUN_801e2ce4
// Entry: 801e2ce4
// Size: 1384 bytes

/* WARNING: Removing unreachable block (ram,0x801e3224) */
/* WARNING: Removing unreachable block (ram,0x801e321c) */
/* WARNING: Removing unreachable block (ram,0x801e322c) */

void FUN_801e2ce4(void)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  char cVar5;
  int iVar6;
  int *piVar7;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  double dVar11;
  undefined8 in_f29;
  double dVar12;
  undefined8 in_f30;
  double dVar13;
  undefined8 in_f31;
  double dVar14;
  int local_88;
  int local_84;
  int local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined auStack112 [4];
  int local_6c;
  undefined auStack104 [8];
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
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
  iVar1 = FUN_802860d8();
  iVar9 = 0;
  iVar2 = FUN_8002b9ec();
  iVar8 = *(int *)(iVar1 + 0x30);
  iVar3 = DAT_803ddc48;
  if (iVar8 != 0) {
    FUN_801e1da8();
    iVar3 = FUN_801e12dc();
    if (iVar3 == 2) {
      dVar11 = (double)FUN_80021704(iVar2 + 0x18,iVar1 + 0x18);
      if ((double)FLOAT_803e5840 <= dVar11) {
        FUN_8000b7bc(iVar1,0x40);
      }
      else {
        FUN_8000bb18(iVar1,0x312);
      }
    }
    iVar3 = *(int *)(iVar8 + 0xf4);
    piVar7 = *(int **)(iVar1 + 0xb8);
    if (*piVar7 == 0) {
      iVar4 = FUN_8002e0fc(&local_80,&local_84);
      for (; local_80 < local_84; local_80 = local_80 + 1) {
        iVar6 = *(int *)(iVar4 + local_80 * 4);
        if (*(short *)(iVar6 + 0x46) == 0x8c) {
          *piVar7 = iVar6;
          local_80 = local_84;
        }
      }
    }
    iVar4 = FUN_800374ec(iVar1,&local_88,auStack104,auStack112);
    if (iVar4 != 0) {
      if (local_88 == 0x130002) {
        iVar9 = 1;
      }
      else if ((0x130001 < local_88) && (local_88 < 0x130004)) {
        iVar9 = 2;
      }
    }
    iVar4 = (**(code **)(**(int **)(iVar8 + 0x68) + 0x28))(iVar8);
    if ((((1 < iVar4) && (*(int *)(iVar1 + 0xf8) < 1)) && ((iVar3 - 3U < 2 || (iVar3 == 5)))) &&
       ((iVar4 = FUN_8003687c(iVar1,&local_6c,0,0), iVar4 != 0 &&
        (*(short *)(local_6c + 0x46) != 0x114)))) {
      FUN_8002ac30(iVar1,0xf,200,0,0,1);
      FUN_8000bb18(iVar1,0x37);
      *(char *)(piVar7 + 1) = *(char *)(piVar7 + 1) + -1;
      if (*(char *)(piVar7 + 1) < '\x01') {
        (**(code **)(**(int **)(iVar8 + 0x68) + 0x20))(iVar8);
        *(undefined4 *)(iVar1 + 0xf8) = 300;
        FUN_80035f00(iVar1);
      }
    }
    if (0 < *(int *)(iVar1 + 0xf8)) {
      *(uint *)(iVar1 + 0xf8) = *(int *)(iVar1 + 0xf8) - (uint)DAT_803db410;
    }
    if ((iVar3 == 8) &&
       (*(int *)(iVar1 + 0xf4) = *(int *)(iVar1 + 0xf4) + 1, 10 < *(int *)(iVar1 + 0xf4))) {
      *(undefined4 *)(iVar1 + 0xf4) = 0;
    }
    if ((iVar3 == 5) && (DAT_803ddc48 != 5)) {
      FUN_80030334((double)FLOAT_803e5834,iVar1,1,0);
      DAT_803dc090 = '\0';
    }
    if ((((*(short *)(iVar1 + 0xa0) == 1) && (FLOAT_803e5844 <= *(float *)(iVar1 + 0x98))) &&
        (DAT_803dc090 == '\0')) && (cVar5 = FUN_8002e04c(), cVar5 != '\0')) {
      DAT_803dc090 = '\x01';
      *(uint *)(iVar1 + 0xf4) = *(int *)(iVar1 + 0xf4) + (uint)DAT_803db410;
      FUN_8000bb18(iVar1,0x38);
      *(float *)(iVar1 + 0x10) = *(float *)(iVar1 + 0x10) + FLOAT_803e5848;
      *(float *)(iVar1 + 0x14) = *(float *)(iVar1 + 0x14) - FLOAT_803e584c;
      FUN_8000e10c(iVar1,&local_74,&local_78,&local_7c);
      *(float *)(iVar1 + 0x10) = *(float *)(iVar1 + 0x10) - FLOAT_803e5848;
      *(float *)(iVar1 + 0x14) = *(float *)(iVar1 + 0x14) + FLOAT_803e584c;
      iVar8 = FUN_8002bdf4(0x18,0x114);
      *(undefined *)(iVar8 + 6) = 0xff;
      *(undefined *)(iVar8 + 7) = 0xff;
      *(undefined *)(iVar8 + 4) = 2;
      *(undefined *)(iVar8 + 5) = 1;
      *(undefined4 *)(iVar8 + 8) = local_74;
      *(undefined4 *)(iVar8 + 0xc) = local_78;
      *(undefined4 *)(iVar8 + 0x10) = local_7c;
      iVar8 = FUN_8002df90(iVar8,5,0xffffffff,0xffffffff,0);
      dVar14 = (double)(*(float *)(iVar2 + 0x18) - *(float *)(iVar8 + 0xc));
      dVar13 = (double)((*(float *)(iVar2 + 0x1c) - FLOAT_803e5850) - *(float *)(iVar8 + 0x10));
      dVar12 = (double)(*(float *)(iVar2 + 0x20) - *(float *)(iVar8 + 0x14));
      dVar11 = (double)FUN_802931a0((double)(float)(dVar12 * dVar12 +
                                                   (double)(float)(dVar14 * dVar14 +
                                                                  (double)(float)(dVar13 * dVar13)))
                                   );
      dVar11 = (double)(float)((double)FLOAT_803e5850 / dVar11);
      *(float *)(iVar8 + 0x24) = (float)(dVar14 * dVar11);
      *(float *)(iVar8 + 0x28) = (float)(dVar13 * dVar11);
      *(float *)(iVar8 + 0x2c) = (float)(dVar12 * dVar11);
      *(undefined4 *)(iVar8 + 0xf4) = 0x78;
      *(int *)(iVar8 + 0xf8) = *piVar7;
    }
    if ((iVar9 == 1) && (cVar5 = FUN_8002e04c(), cVar5 != '\0')) {
      FUN_8000bb18(iVar1,0x38);
      iVar2 = FUN_8002b9ec();
      iVar8 = FUN_8002bdf4(0x18,0x138);
      *(float *)(iVar8 + 8) = FLOAT_803e5854 + *(float *)(iVar2 + 0x18);
      uStack92 = FUN_800221a0(0xfffffffa,6);
      uStack92 = uStack92 ^ 0x80000000;
      local_60 = 0x43300000;
      *(float *)(iVar8 + 0xc) =
           FLOAT_803e5848 +
           *(float *)(iVar2 + 0x1c) +
           (float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e5860);
      uStack84 = FUN_800221a0(0xfffffffa,6);
      uStack84 = uStack84 ^ 0x80000000;
      local_58 = 0x43300000;
      *(float *)(iVar8 + 0x10) =
           FLOAT_803e5858 +
           *(float *)(iVar2 + 0x20) +
           (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e5860);
      *(undefined *)(iVar8 + 4) = 2;
      *(undefined *)(iVar8 + 5) = 1;
      *(undefined *)(iVar8 + 6) = 0xff;
      *(undefined *)(iVar8 + 7) = 0xff;
      FUN_8002df90(iVar8,5,0xffffffff,0xffffffff,0);
    }
    iVar2 = FUN_8002fa48((double)FLOAT_803e585c,(double)FLOAT_803db414,iVar1,0);
    if ((*(short *)(iVar1 + 0xa0) == 1) && (iVar2 != 0)) {
      FUN_80030334((double)FLOAT_803e5834,iVar1,0,0);
    }
  }
  DAT_803ddc48 = iVar3;
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  __psq_l0(auStack40,uVar10);
  __psq_l1(auStack40,uVar10);
  FUN_80286124();
  return;
}

