// Function: FUN_8020718c
// Entry: 8020718c
// Size: 992 bytes

/* WARNING: Removing unreachable block (ram,0x80207544) */
/* WARNING: Removing unreachable block (ram,0x8020753c) */
/* WARNING: Removing unreachable block (ram,0x8020754c) */

void FUN_8020718c(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  char cVar5;
  char cVar6;
  char cVar7;
  int iVar8;
  short *psVar9;
  undefined4 uVar10;
  undefined8 in_f29;
  double dVar11;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  undefined2 local_78;
  undefined2 local_76;
  undefined2 local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  undefined4 local_60;
  uint uStack92;
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
  iVar2 = FUN_802860d4();
  psVar9 = *(short **)(iVar2 + 0xb8);
  iVar3 = FUN_8002b9ec();
  iVar8 = 0;
  cVar7 = '\0';
  cVar6 = '\0';
  cVar5 = '\0';
  dVar13 = (double)(*(float *)(iVar3 + 0xc) - *(float *)(iVar2 + 0xc));
  dVar11 = (double)(*(float *)(iVar3 + 0x10) - *(float *)(iVar2 + 0x10));
  dVar12 = (double)(*(float *)(iVar3 + 0x14) - *(float *)(iVar2 + 0x14));
  if ((psVar9[4] == -1) || (iVar4 = FUN_8001ffb4(), iVar4 == 0)) {
    iVar4 = FUN_8001ffb4((int)psVar9[5]);
    if (iVar4 != 0) {
      FUN_800200e8((int)psVar9[5],0);
    }
    if (dVar13 <= (double)FLOAT_803e6438) {
      uStack92 = (int)*psVar9 ^ 0x80000000;
      local_60 = 0x43300000;
      if (-(double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e6440) < dVar13) {
        iVar8 = 1;
        cVar7 = '\x01';
      }
    }
    if ((double)FLOAT_803e6438 < dVar13) {
      uStack92 = (int)*psVar9 ^ 0x80000000;
      local_60 = 0x43300000;
      if (dVar13 < (double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e6440)) {
        iVar8 = iVar8 + 1;
        cVar7 = cVar7 + -1;
      }
    }
    if (dVar12 <= (double)FLOAT_803e6438) {
      uStack92 = (int)psVar9[1] ^ 0x80000000;
      local_60 = 0x43300000;
      if (-(double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e6440) < dVar12) {
        iVar8 = iVar8 + 1;
        cVar5 = '\x01';
      }
    }
    if ((double)FLOAT_803e6438 < dVar12) {
      uStack92 = (int)psVar9[1] ^ 0x80000000;
      local_60 = 0x43300000;
      if (dVar12 < (double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e6440)) {
        iVar8 = iVar8 + 1;
        cVar5 = cVar5 + -1;
      }
    }
    if (dVar11 <= (double)FLOAT_803e6438) {
      uStack92 = (int)psVar9[2] ^ 0x80000000;
      local_60 = 0x43300000;
      if (-(double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e6440) < dVar11) {
        iVar8 = iVar8 + 1;
        cVar6 = '\x01';
      }
    }
    if ((double)FLOAT_803e6438 < dVar11) {
      uStack92 = (int)psVar9[2] ^ 0x80000000;
      local_60 = 0x43300000;
      if (dVar11 < (double)(float)((double)CONCAT44(0x43300000,uStack92) - DOUBLE_803e6440)) {
        iVar8 = iVar8 + 1;
        cVar6 = cVar6 + -1;
      }
    }
    if (iVar8 == 3) {
      local_6c = (float)dVar13;
      local_68 = (float)dVar11;
      local_64 = (float)dVar12;
      local_70 = FLOAT_803e6448;
      local_74 = 0;
      local_76 = 0;
      local_78 = 0;
      if (cVar7 != *(char *)(psVar9 + 8)) {
        local_78 = 0x3fff;
      }
      iVar8 = FUN_8001ffb4(0x1d9);
      if (iVar8 == 0) {
        FUN_800378c4(iVar3,0x60004,iVar2,1);
        (**(code **)(*DAT_803dca88 + 8))(iVar2,0x5ed,&local_78,2,0xffffffff,0);
        iVar3 = 9;
        do {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,0x5fd,&local_78,2,0xffffffff,0);
          bVar1 = iVar3 != 0;
          iVar3 = iVar3 + -1;
        } while (bVar1);
      }
      else {
        FUN_800200e8(0x468,1);
        FUN_800378c4(iVar3,0x60004,iVar2,0);
        (**(code **)(*DAT_803dca88 + 8))(iVar2,0x5ed,&local_78,2,0xffffffff,0);
        iVar3 = 9;
        do {
          (**(code **)(*DAT_803dca88 + 8))(iVar2,0x5fd,&local_78,2,0xffffffff,0);
          bVar1 = iVar3 != 0;
          iVar3 = iVar3 + -1;
        } while (bVar1);
      }
      FUN_800200e8((int)psVar9[5],1);
      FUN_8000bb18(iVar2,0x1c9);
    }
    *(char *)(psVar9 + 8) = cVar7;
    *(char *)((int)psVar9 + 0x11) = cVar6;
    *(char *)(psVar9 + 9) = cVar5;
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

