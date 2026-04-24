// Function: FUN_80138fa8
// Entry: 80138fa8
// Size: 444 bytes

/* WARNING: Removing unreachable block (ram,0x8013913c) */
/* WARNING: Removing unreachable block (ram,0x80139144) */

void FUN_80138fa8(void)

{
  short sVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined4 uVar9;
  double extraout_f1;
  double dVar10;
  undefined8 in_f30;
  double dVar11;
  undefined8 in_f31;
  undefined8 uVar12;
  int local_48 [12];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar12 = FUN_802860d0();
  iVar8 = 0;
  dVar11 = extraout_f1;
  piVar2 = (int *)FUN_80036f50(3,local_48);
  dVar11 = (double)(float)(dVar11 * dVar11);
  for (iVar7 = 0; iVar7 < local_48[0]; iVar7 = iVar7 + 1) {
    iVar3 = FUN_80111d14(*piVar2);
    if (iVar3 == 0) {
      dVar10 = (double)FUN_8014c5d0(*piVar2);
    }
    else {
      dVar10 = (double)(**(code **)(*DAT_803dcab8 + 0x60))(*piVar2);
    }
    iVar3 = *(int *)(*piVar2 + 0x4c);
    if (*(short *)(iVar3 + 0x18) == -1) {
      iVar5 = 0;
    }
    else {
      iVar5 = FUN_8001ffb4();
    }
    if (*(short *)(iVar3 + 0x1a) == -1) {
      iVar6 = 1;
    }
    else {
      iVar6 = FUN_8001ffb4();
    }
    iVar4 = FUN_80036c0c(*piVar2,0x31);
    if ((((((iVar4 == 0) && ((double)FLOAT_803e23dc < dVar10)) && (iVar5 == 0)) &&
         ((iVar6 != 0 && (*(short *)(*piVar2 + 0x46) != 0x851)))) &&
        (iVar3 = (**(code **)(*DAT_803dcaac + 0x68))(*(undefined4 *)(iVar3 + 0x14)), iVar3 != 0)) &&
       ((((int)uVar12 != 0 ||
         (((sVar1 = *(short *)(*piVar2 + 0x46), sVar1 != 0x3fe && (sVar1 != 0x4d7)) &&
          ((sVar1 != 0x27c && (sVar1 != 0x251)))))) &&
        (dVar10 = (double)FUN_800216d0((int)((ulonglong)uVar12 >> 0x20) + 0x18,*piVar2 + 0x18),
        dVar10 < dVar11)))) {
      iVar8 = *piVar2;
      dVar11 = dVar10;
    }
    piVar2 = piVar2 + 1;
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  FUN_8028611c(iVar8);
  return;
}

