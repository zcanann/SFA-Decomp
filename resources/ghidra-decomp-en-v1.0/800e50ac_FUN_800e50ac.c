// Function: FUN_800e50ac
// Entry: 800e50ac
// Size: 300 bytes

/* WARNING: Removing unreachable block (ram,0x800e51b0) */
/* WARNING: Removing unreachable block (ram,0x800e51b8) */

void FUN_800e50ac(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  undefined4 uVar9;
  double extraout_f1;
  double dVar10;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar11;
  double dVar12;
  undefined8 uVar13;
  float local_58;
  float local_54;
  float local_50;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar9 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar13 = FUN_802860d0();
  iVar2 = (int)uVar13;
  dVar11 = (double)FLOAT_803e0664;
  iVar8 = 0;
  iVar7 = 0;
  local_58 = (float)extraout_f1;
  local_54 = (float)param_2;
  local_50 = (float)param_3;
  piVar6 = &DAT_803a17e8;
  dVar12 = dVar11;
  for (iVar5 = 0; iVar5 < DAT_803dd478; iVar5 = iVar5 + 1) {
    iVar4 = *piVar6;
    iVar3 = 0;
    do {
      if ((iVar2 < 1) ||
         ((int)*(char *)(iVar4 + 0x19) == *(int *)((int)((ulonglong)uVar13 >> 0x20) + iVar3 * 4))) {
        dVar10 = (double)FUN_800216d0(&local_58,iVar4 + 8);
        if (dVar10 < dVar12) {
          iVar8 = iVar4;
          dVar12 = dVar10;
        }
        iVar3 = iVar2;
        if ((*(char *)(iVar4 + 0x18) == param_6) && (dVar10 < dVar11)) {
          iVar7 = iVar4;
          dVar11 = dVar10;
        }
      }
      iVar3 = iVar3 + 1;
    } while (iVar3 < iVar2);
    piVar6 = piVar6 + 1;
  }
  if (iVar7 != 0) {
    iVar8 = iVar7;
  }
  if (iVar8 == 0) {
    uVar1 = 0xffffffff;
  }
  else {
    uVar1 = *(undefined4 *)(iVar8 + 0x14);
  }
  __psq_l0(auStack8,uVar9);
  __psq_l1(auStack8,uVar9);
  __psq_l0(auStack24,uVar9);
  __psq_l1(auStack24,uVar9);
  FUN_8028611c(uVar1);
  return;
}

