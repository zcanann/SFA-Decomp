// Function: FUN_80052974
// Entry: 80052974
// Size: 576 bytes

/* WARNING: Removing unreachable block (ram,0x80052b84) */
/* WARNING: Removing unreachable block (ram,0x80052b74) */
/* WARNING: Removing unreachable block (ram,0x80052b64) */
/* WARNING: Removing unreachable block (ram,0x80052b54) */
/* WARNING: Removing unreachable block (ram,0x80052b4c) */
/* WARNING: Removing unreachable block (ram,0x80052b5c) */
/* WARNING: Removing unreachable block (ram,0x80052b6c) */
/* WARNING: Removing unreachable block (ram,0x80052b7c) */
/* WARNING: Removing unreachable block (ram,0x80052b8c) */

void FUN_80052974(void)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  double dVar4;
  undefined8 in_f23;
  double dVar5;
  undefined8 in_f24;
  double dVar6;
  undefined8 in_f25;
  double dVar7;
  undefined8 in_f26;
  double dVar8;
  undefined8 in_f27;
  double dVar9;
  undefined8 in_f28;
  double dVar10;
  undefined8 in_f29;
  double dVar11;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  undefined auStack136 [16];
  undefined auStack120 [16];
  undefined auStack104 [16];
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar3 = 0;
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
  if (DAT_803dcd98 == '\0') {
    FUN_80258228(1,0);
    FUN_802419b8(&DAT_803779c0,0x6640);
    FUN_8025cd3c(&DAT_803779c0,0x6640);
    uVar2 = 0;
    dVar9 = (double)FLOAT_803deb58;
    dVar10 = (double)FLOAT_803deb5c;
    dVar11 = (double)FLOAT_803deb54;
    dVar13 = (double)FLOAT_803deb64;
    dVar12 = DOUBLE_803deb68;
    do {
      FUN_8025889c(0x98,4,0x22);
      uVar1 = 0;
      dVar8 = (double)(float)((double)(float)((double)(float)(dVar11 * (double)(float)((double)
                                                  CONCAT44(0x43300000,uVar2) - dVar12)) / dVar9) -
                             dVar10);
      dVar5 = (double)(float)((double)(float)((double)(float)(dVar11 * (double)(float)((double)
                                                  CONCAT44(0x43300000,uVar2 + 1) - dVar12)) / dVar9)
                             - dVar10);
      do {
        dVar7 = (double)(float)((double)(float)((double)(float)(dVar11 * (double)(float)((double)
                                                  CONCAT44(0x43300000,uVar1) - dVar12)) / dVar9) -
                               dVar10);
        dVar6 = (double)(float)(dVar7 * dVar7);
        dVar4 = (double)(float)(dVar8 * dVar8 + dVar6);
        if (dVar10 <= dVar4) {
          dVar4 = (double)FLOAT_803deb60;
        }
        else {
          dVar4 = (double)FUN_802931a0((double)(float)(dVar10 - dVar4));
        }
        write_volatile_4(0xcc008000,(float)dVar8);
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,(float)dVar13);
        write_volatile_4(0xcc008000,(float)dVar8);
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,(float)dVar4);
        dVar4 = (double)(float)(dVar5 * dVar5 + dVar6);
        if (dVar10 <= dVar4) {
          dVar4 = (double)FLOAT_803deb60;
        }
        else {
          dVar4 = (double)FUN_802931a0((double)(float)(dVar10 - dVar4));
        }
        write_volatile_4(0xcc008000,(float)dVar5);
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,(float)dVar13);
        write_volatile_4(0xcc008000,(float)dVar5);
        write_volatile_4(0xcc008000,(float)dVar7);
        write_volatile_4(0xcc008000,(float)dVar4);
        uVar1 = uVar1 + 1;
      } while (uVar1 < 0x11);
      uVar2 = uVar2 + 1;
    } while (uVar2 < 0x10);
    DAT_803dcd9c = FUN_8025ce04();
    DAT_803dcd98 = '\x01';
    FUN_80258228(1,8);
  }
  FUN_8025ced8(&DAT_803779c0,DAT_803dcd9c);
  __psq_l0(auStack8,uVar3);
  __psq_l1(auStack8,uVar3);
  __psq_l0(auStack24,uVar3);
  __psq_l1(auStack24,uVar3);
  __psq_l0(auStack40,uVar3);
  __psq_l1(auStack40,uVar3);
  __psq_l0(auStack56,uVar3);
  __psq_l1(auStack56,uVar3);
  __psq_l0(auStack72,uVar3);
  __psq_l1(auStack72,uVar3);
  __psq_l0(auStack88,uVar3);
  __psq_l1(auStack88,uVar3);
  __psq_l0(auStack104,uVar3);
  __psq_l1(auStack104,uVar3);
  __psq_l0(auStack120,uVar3);
  __psq_l1(auStack120,uVar3);
  __psq_l0(auStack136,uVar3);
  __psq_l1(auStack136,uVar3);
  return;
}

