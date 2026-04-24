// Function: FUN_801b1ff4
// Entry: 801b1ff4
// Size: 592 bytes

/* WARNING: Removing unreachable block (ram,0x801b221c) */
/* WARNING: Removing unreachable block (ram,0x801b2224) */

void FUN_801b1ff4(void)

{
  short *psVar1;
  char cVar6;
  int iVar2;
  int iVar3;
  short *psVar4;
  short **ppsVar5;
  int iVar7;
  int iVar8;
  undefined4 uVar9;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  ulonglong uVar13;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar13 = FUN_802860d8();
  psVar1 = (short *)(uVar13 >> 0x20);
  iVar8 = *(int *)(psVar1 + 0x26);
  cVar6 = FUN_8002e04c();
  if (((cVar6 != '\0') && (iVar7 = *(int *)(psVar1 + 0x5c), *(char *)(iVar7 + 0xad) != '\0')) &&
     (*(short *)(iVar7 + 0xa4) < 1)) {
    iVar2 = FUN_800395d8(psVar1,0);
    iVar3 = FUN_8002bdf4(0x24,0x1d6);
    *(undefined *)(iVar3 + 4) = *(undefined *)(iVar8 + 4);
    *(undefined *)(iVar3 + 6) = *(undefined *)(iVar8 + 6);
    *(undefined *)(iVar3 + 5) = *(undefined *)(iVar8 + 5);
    *(undefined *)(iVar3 + 7) = *(undefined *)(iVar8 + 7);
    *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(iVar7 + 0x8c);
    *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(iVar7 + 0x90);
    *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar7 + 0x94);
    psVar4 = (short *)FUN_8002df90(iVar3,5,(int)*(char *)(psVar1 + 0x56),0xffffffff,0);
    ppsVar5 = *(short ***)(psVar4 + 0x5c);
    *ppsVar5 = psVar1;
    *(char *)(ppsVar5 + 1) = (char)uVar13;
    if ((uVar13 & 0xff) == 0) {
      *(undefined *)((int)ppsVar5 + 5) = 0x14;
      *(undefined *)((int)ppsVar5 + 6) = 1;
    }
    else {
      if (*(char *)(psVar1 + 0x56) == '\x1b') {
        *(undefined *)((int)ppsVar5 + 5) = 100;
      }
      else {
        *(undefined *)((int)ppsVar5 + 5) = 0x3c;
      }
      *(undefined *)((int)ppsVar5 + 6) = 100;
    }
    dVar12 = (double)*(float *)(iVar7 + 0x98);
    dVar11 = (double)(float)((double)FLOAT_803e48ac * dVar12);
    *psVar4 = *psVar1 + *(short *)(iVar2 + 2);
    dVar10 = (double)FUN_80293e80((double)((FLOAT_803e48b0 *
                                           (float)((double)CONCAT44(0x43300000,
                                                                    (int)*psVar4 ^ 0x80000000) -
                                                  DOUBLE_803e48c0)) / FLOAT_803e48b4));
    *(float *)(psVar4 + 0x12) = (float)(dVar11 * -dVar10);
    *(float *)(psVar4 + 0x14) = (float)dVar12;
    dVar10 = (double)FUN_80294204((double)((FLOAT_803e48b0 *
                                           (float)((double)CONCAT44(0x43300000,
                                                                    (int)*psVar4 ^ 0x80000000) -
                                                  DOUBLE_803e48c0)) / FLOAT_803e48b4));
    *(float *)(psVar4 + 0x16) = (float)(dVar11 * -dVar10);
    *(undefined *)(iVar7 + 0xad) = 0;
    *(undefined2 *)(iVar7 + 0xa6) = 0x32;
    if (*(char *)(iVar7 + 0xac) == '\x03') {
      *(undefined2 *)(iVar7 + 0xa4) = 0x32;
    }
    else {
      iVar8 = FUN_800221a0(*(undefined *)(iVar8 + 0x29),*(undefined *)(iVar8 + 0x2a));
      *(short *)(iVar7 + 0xa4) = (short)(iVar8 << 2);
    }
    FUN_80030334((double)FLOAT_803e48b8,psVar1,0,0);
    FUN_8000bb18(psVar1,0x1fd);
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  FUN_80286124();
  return;
}

