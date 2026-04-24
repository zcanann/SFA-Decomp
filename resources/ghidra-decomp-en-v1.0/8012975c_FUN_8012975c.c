// Function: FUN_8012975c
// Entry: 8012975c
// Size: 632 bytes

/* WARNING: Removing unreachable block (ram,0x801299ac) */
/* WARNING: Removing unreachable block (ram,0x8012999c) */
/* WARNING: Removing unreachable block (ram,0x80129994) */
/* WARNING: Removing unreachable block (ram,0x801299a4) */
/* WARNING: Removing unreachable block (ram,0x801299b4) */

void FUN_8012975c(void)

{
  byte bVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  char cVar5;
  char cVar6;
  undefined4 uVar7;
  undefined8 in_f27;
  double dVar8;
  undefined8 in_f28;
  double dVar9;
  undefined8 in_f29;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
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
  FUN_802860d0();
  if (DAT_803dd770 != 0) {
    bVar1 = (byte)DAT_803dd770;
    FUN_8007719c((double)FLOAT_803e213c,(double)FLOAT_803e2140,DAT_803a8ac0,0xff,0x100);
    cVar5 = -0x56;
    dVar9 = DOUBLE_803e2158;
    dVar10 = DOUBLE_803e1e78;
    dVar11 = DOUBLE_803e2150;
    dVar12 = DOUBLE_803e2148;
    for (cVar6 = '\x02'; -1 < cVar6; cVar6 = cVar6 + -1) {
      uVar4 = (uint)(char)(bVar1 & 0x1f);
      dVar8 = dVar11 * ((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - dVar10);
      uVar2 = 0x5f - ((int)uVar4 >> 2);
      iVar3 = uVar4 * 2 + 0xbb;
      FUN_8007719c((double)(float)(dVar12 + dVar8),
                   (double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - dVar10),
                   DAT_803a8ac4,-1 - cVar5,iVar3);
      FUN_8007681c((double)(float)(dVar9 - dVar8),
                   (double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - dVar10),
                   DAT_803a8ac4,-1 - cVar5,iVar3,0x18,0x34,1);
      bVar1 = (bVar1 & 0x1f) + 3;
      cVar5 = cVar5 + -0x55;
    }
    bVar1 = (byte)DAT_803dd770 & 0x1f ^ 0x10;
    cVar5 = -0x56;
    dVar9 = DOUBLE_803e2148;
    dVar10 = DOUBLE_803e2150;
    dVar11 = DOUBLE_803e1e78;
    dVar12 = DOUBLE_803e2158;
    for (cVar6 = '\x02'; -1 < cVar6; cVar6 = cVar6 + -1) {
      uVar2 = (uint)(char)bVar1;
      dVar8 = dVar10 * ((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - dVar11);
      uVar4 = 0x5f - ((int)uVar2 >> 2);
      iVar3 = uVar2 * 2 + 0xbb;
      FUN_8007719c((double)(float)(dVar9 + dVar8),
                   (double)(float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - dVar11),
                   DAT_803a8ac4,-1 - cVar5,iVar3);
      FUN_8007681c((double)(float)(dVar12 - dVar8),
                   (double)(float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - dVar11),
                   DAT_803a8ac4,-1 - cVar5,iVar3,0x18,0x34,1);
      bVar1 = bVar1 + 3 & 0x1f;
      cVar5 = cVar5 + -0x55;
    }
  }
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
  FUN_8028611c();
  return;
}

