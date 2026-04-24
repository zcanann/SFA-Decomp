// Function: FUN_8001b7b8
// Entry: 8001b7b8
// Size: 960 bytes

/* WARNING: Removing unreachable block (ram,0x8001bb50) */
/* WARNING: Removing unreachable block (ram,0x8001bb58) */

void FUN_8001b7b8(void)

{
  undefined4 *puVar1;
  bool bVar2;
  int iVar3;
  int *piVar4;
  uint uVar5;
  undefined4 uVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined4 unaff_r29;
  uint uVar10;
  undefined4 uVar11;
  undefined8 in_f30;
  double dVar12;
  double in_f31;
  int local_58;
  int local_54;
  int local_50;
  int local_4c;
  undefined4 local_48;
  uint uStack68;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,SUB84(in_f31,0),0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  FUN_802860d0();
  uVar10 = 0;
  dVar12 = (double)FLOAT_803de730;
  if (DAT_803dc9f0 != 0) {
    unaff_r29 = FUN_80019b14();
    FUN_80019b1c(1,1);
  }
  iVar3 = FUN_80019570(DAT_803dc9fc);
  DAT_803dca18 = 0;
  DAT_803dca14 = 0;
  for (iVar8 = 0; iVar8 < 0x100; iVar8 = iVar8 + 1) {
    (&DAT_8033ba40)[iVar8] = FLOAT_803de734;
  }
  for (iVar8 = 0; iVar8 < (int)(uint)*(ushort *)(iVar3 + 2); iVar8 = iVar8 + 1) {
    uVar6 = *(undefined4 *)(*(int *)(iVar3 + 8) + iVar8 * 4);
    iVar9 = FUN_80018ed4(uVar6,0xe018,&local_54);
    if (iVar9 != 0) {
      iVar9 = local_4c / 0x3c + (local_4c >> 0x1f);
      (&DAT_8033ba40)[DAT_803dca18] =
           (float)((double)CONCAT44(0x43300000,
                                    local_50 + local_54 * 0x3c + (iVar9 - (iVar9 >> 0x1f)) ^
                                    0x80000000) - DOUBLE_803de728);
    }
    uStack68 = (uint)DAT_802c7542;
    local_48 = 0x43300000;
    iVar9 = FUN_80016c9c((double)(float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803de738),
                         (double)DAT_802c754c,uVar6,&local_58,0);
    if (iVar9 != 0) {
      for (iVar7 = 0; iVar7 < local_58; iVar7 = iVar7 + 1) {
        puVar1 = &DAT_8033b640 + DAT_803dca18;
        DAT_803dca18 = DAT_803dca18 + 1;
        *puVar1 = *(undefined4 *)(iVar9 + iVar7 * 4);
      }
      if ((&DAT_8033b240)[DAT_803dca14] != 0) {
        uVar6 = FUN_80023834(0);
        FUN_80023800((&DAT_8033b240)[DAT_803dca14]);
        FUN_80023834(uVar6);
      }
      piVar4 = &DAT_8033b240 + DAT_803dca14;
      DAT_803dca14 = DAT_803dca14 + 1;
      *piVar4 = iVar9;
    }
  }
  iVar3 = 0;
LAB_8001bb14:
  if (DAT_803dca18 <= iVar3) {
    DAT_803dca08 = 0;
    DAT_803dca10 = 0;
    DAT_803dca04 = 2;
    if (DAT_803dc9f0 != 0) {
      FUN_80019b1c(unaff_r29,1);
    }
    __psq_l0(auStack8,uVar11);
    __psq_l1(auStack8,uVar11);
    __psq_l0(auStack24,uVar11);
    __psq_l1(auStack24,uVar11);
    FUN_8028611c();
    return;
  }
  if (FLOAT_803de734 == (float)(&DAT_8033ba40)[iVar3]) {
    bVar2 = false;
    iVar8 = iVar3;
    for (iVar9 = 0; iVar9 < 0x100; iVar9 = iVar9 + 1) {
      uStack68 = uVar10 ^ 0x80000000;
      local_48 = 0x43300000;
      if (iVar8 < 0xff) {
        if (FLOAT_803de734 != (float)(&DAT_8033ba44)[iVar8]) {
          in_f31 = (double)(float)((double)(float)(&DAT_8033ba44)[iVar8] - dVar12);
          bVar2 = true;
        }
        uVar5 = FUN_8001860c((&DAT_8033b640)[iVar8]);
        uStack68 = uVar5 ^ 0x80000000;
        (&DAT_8033ba40)[iVar8] = (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803de728);
        uVar10 = uVar10 + uVar5;
        if (bVar2) goto LAB_8001baf4;
        iVar8 = iVar8 + 1;
      }
      local_48 = 0x43300000;
    }
  }
  else {
    dVar12 = (double)(float)(&DAT_8033ba40)[iVar3];
    uVar10 = FUN_8001860c((&DAT_8033b640)[iVar3]);
  }
  goto LAB_8001bb10;
LAB_8001baf4:
  for (; local_48 = 0x43300000, iVar3 <= iVar8; iVar8 = iVar8 + -1) {
    uStack68 = uVar10 ^ 0x80000000;
    (&DAT_8033ba40)[iVar8] =
         -(float)(in_f31 * (double)((float)(&DAT_8033ba40)[iVar8] /
                                   (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803de728))
                 - (double)(float)(&DAT_8033ba44)[iVar8]);
  }
LAB_8001bb10:
  iVar3 = iVar3 + 1;
  goto LAB_8001bb14;
}

