// Function: FUN_80239fcc
// Entry: 80239fcc
// Size: 412 bytes

/* WARNING: Removing unreachable block (ram,0x8023a148) */

void FUN_80239fcc(void)

{
  short *psVar1;
  char cVar5;
  short sVar4;
  uint uVar2;
  int iVar3;
  int *piVar6;
  int iVar7;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined8 uVar11;
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar11 = FUN_802860d8();
  psVar1 = (short *)((ulonglong)uVar11 >> 0x20);
  piVar6 = (int *)uVar11;
  cVar5 = FUN_8002e04c();
  if (cVar5 != '\0') {
    iVar7 = (int)DAT_803dddc4;
    DAT_803dddc0 = (int)DAT_803dddc6;
    sVar4 = FUN_800221a0(0xffff8000,0x7fff);
    uVar2 = FUN_800221a0(100,300);
    iVar3 = FUN_8002bdf4(0x20,0x859);
    dVar10 = (double)((FLOAT_803e74a0 *
                      (float)((double)CONCAT44(0x43300000,(int)sVar4 ^ 0x80000000) - DOUBLE_803e7498
                             )) / FLOAT_803e74a4);
    dVar9 = (double)FUN_80293e80(dVar10);
    *(float *)(iVar3 + 8) =
         (float)((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e7498)
                 * dVar9 + (double)*(float *)(*piVar6 + 0xc));
    dVar9 = (double)FUN_80294204(dVar10);
    *(float *)(iVar3 + 0xc) =
         (float)((double)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e7498)
                 * dVar9 + (double)*(float *)(*piVar6 + 0x10));
    *(float *)(iVar3 + 0x10) = (float)piVar6[0x32] - FLOAT_803e74a8;
    *(char *)(iVar3 + 0x1a) = (char)((uint)(*psVar1 + iVar7) >> 8);
    *(char *)(iVar3 + 0x19) = (char)DAT_803dddc0;
    *(undefined *)(iVar3 + 0x18) = 0;
    *(undefined *)(iVar3 + 4) = 1;
    *(undefined *)(iVar3 + 5) = 1;
    iVar3 = FUN_8002b5a0(psVar1,iVar3);
    if (iVar3 != 0) {
      *(float *)(iVar3 + 8) = FLOAT_803dc4e4;
      FUN_8022e600(iVar3,DAT_803dc4e0);
      FUN_8022e54c((double)FLOAT_803e74ac,iVar3);
    }
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  FUN_80286124();
  return;
}

