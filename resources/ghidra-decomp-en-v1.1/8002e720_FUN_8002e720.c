// Function: FUN_8002e720
// Entry: 8002e720
// Size: 876 bytes

void FUN_8002e720(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,int param_12,
                 undefined4 param_13,int param_14,undefined4 param_15,undefined4 param_16)

{
  short sVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int *piVar5;
  undefined4 extraout_r4;
  undefined4 uVar6;
  undefined4 extraout_r4_00;
  undefined4 extraout_r4_01;
  undefined4 extraout_r4_02;
  int iVar7;
  code *pcVar8;
  short *psVar9;
  int iVar10;
  undefined8 extraout_f1;
  undefined8 extraout_f1_00;
  undefined8 uVar11;
  undefined8 uVar12;
  int local_28;
  int local_24 [9];
  
  uVar3 = FUN_80286840();
  DAT_803dd7f8 = uVar3 & 0xff;
  iVar10 = (int)sRam803dd7fe;
  uVar2 = uVar3 & 1;
  if (uVar2 == 0) {
    FUN_80065780();
  }
  FUN_8002e574();
  uVar12 = FUN_80035728(DAT_803dd804);
  uVar11 = extraout_f1;
  for (psVar9 = psRam803dd800; (psVar9 != (short *)0x0 && (*(char *)(psVar9 + 0x57) == 'd'));
      psVar9 = *(short **)((int)psVar9 + iVar10)) {
    uVar12 = FUN_8002c85c(psVar9,(int)uVar12,param_11,param_12,param_13,param_14,param_15,param_16);
    uVar11 = extraout_f1_00;
  }
  while( true ) {
    iVar4 = (int)((ulonglong)uVar12 >> 0x20);
    uVar6 = (undefined4)uVar12;
    if ((psVar9 == (short *)0x0) ||
       (iVar4 = *(int *)(psVar9 + 0x28), (*(uint *)(iVar4 + 0x44) & 0x40) == 0)) break;
    uVar11 = FUN_8002c85c(psVar9,uVar6,param_11,param_12,param_13,param_14,param_15,param_16);
    uVar6 = extraout_r4;
    iVar4 = FUN_8000e360();
    uVar12 = CONCAT44(iVar4,uVar6);
    *(char *)((int)psVar9 + 0x35) = (char)iVar4;
    psVar9 = *(short **)((int)psVar9 + iVar10);
  }
  if (uVar2 == 0) {
    uVar11 = FUN_80036a3c(iVar4,uVar6,param_11,param_12,param_13,param_14,param_15,param_16);
    uVar6 = extraout_r4_00;
  }
  for (; psVar9 != (short *)0x0; psVar9 = *(short **)((int)psVar9 + iVar10)) {
    iVar4 = *(int *)(psVar9 + 0x2a);
    if (iVar4 == 0) {
      uVar11 = FUN_8002c85c(psVar9,uVar6,param_11,param_12,param_13,param_14,param_15,param_16);
      uVar6 = extraout_r4_02;
    }
    else if (((*(byte *)(iVar4 + 0x62) & 8) == 0) || ((*(ushort *)(iVar4 + 0x60) & 1) == 0)) {
      uVar11 = FUN_8002c85c(psVar9,uVar6,param_11,param_12,param_13,param_14,param_15,param_16);
      uVar6 = extraout_r4_01;
    }
  }
  piVar5 = FUN_80037048(0,local_24);
  if (local_24[0] == 0) {
    iVar4 = 0;
  }
  else {
    iVar4 = *piVar5;
  }
  if ((iVar4 != 0) && (iVar7 = *(int *)(iVar4 + 200), iVar7 != 0)) {
    *(undefined4 *)(iVar7 + 0x30) = *(undefined4 *)(iVar4 + 0x30);
    uVar11 = FUN_8002c85c(*(short **)(iVar4 + 200),iVar7,param_11,param_12,param_13,param_14,
                          param_15,param_16);
  }
  if (uVar2 != 0) goto LAB_8002e9d8;
  FUN_80034dd4(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  for (psVar9 = psRam803dd800; psVar9 != (short *)0x0; psVar9 = *(short **)((int)psVar9 + iVar10)) {
    if ((psVar9[0x58] & 0x2000U) == 0) {
      sVar1 = psVar9[0x23];
      if ((sVar1 == 0x1f) || ((sVar1 < 0x1f && (sVar1 == 0)))) {
        FUN_802b5fa0(psVar9);
      }
      else {
        if ((*(int **)(psVar9 + 0x34) == (int *)0x0) ||
           (pcVar8 = *(code **)(**(int **)(psVar9 + 0x34) + 0xc), pcVar8 == (code *)0x0))
        goto LAB_8002e8fc;
        (*pcVar8)(psVar9);
      }
      FUN_8000e12c((int)psVar9,(float *)(psVar9 + 0xc),(float *)(psVar9 + 0xe),
                   (float *)(psVar9 + 0x10));
    }
LAB_8002e8fc:
  }
  piVar5 = FUN_80037048(0,&local_28);
  if (local_28 == 0) {
    iVar10 = 0;
  }
  else {
    iVar10 = *piVar5;
  }
  if ((iVar10 != 0) && (*(int *)(iVar10 + 200) != 0)) {
    *(undefined4 *)(*(int *)(iVar10 + 200) + 0x30) = *(undefined4 *)(iVar10 + 0x30);
    psVar9 = *(short **)(iVar10 + 200);
    if ((psVar9[0x58] & 0x2000U) == 0) {
      sVar1 = psVar9[0x23];
      if ((sVar1 == 0x1f) || ((sVar1 < 0x1f && (sVar1 == 0)))) {
        FUN_802b5fa0(psVar9);
      }
      else {
        if ((*(int **)(psVar9 + 0x34) == (int *)0x0) ||
           (pcVar8 = *(code **)(**(int **)(psVar9 + 0x34) + 0xc), pcVar8 == (code *)0x0))
        goto LAB_8002e9c0;
        (*pcVar8)(psVar9);
      }
      FUN_8000e12c((int)psVar9,(float *)(psVar9 + 0xc),(float *)(psVar9 + 0xe),
                   (float *)(psVar9 + 0x10));
    }
  }
LAB_8002e9c0:
  (**(code **)(*DAT_803dd718 + 4))(DAT_803dc070);
LAB_8002e9d8:
  if ((uVar3 & 2) == 0) {
    (**(code **)(*DAT_803dd6fc + 0xc))(0,0,0);
    (**(code **)(*DAT_803dd6f8 + 0xc))(0,DAT_803dc070,0,0);
  }
  if (uVar2 == 0) {
    FUN_800324c8();
    (**(code **)(*DAT_803dd6d4 + 0x28))();
    (**(code **)(*DAT_803dd6d4 + 0x18))();
    (**(code **)(*DAT_803dd6d0 + 8))(DAT_803dc070);
  }
  FUN_8028688c();
  return;
}

