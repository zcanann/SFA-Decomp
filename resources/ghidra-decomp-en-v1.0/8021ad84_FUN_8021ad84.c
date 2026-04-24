// Function: FUN_8021ad84
// Entry: 8021ad84
// Size: 592 bytes

/* WARNING: Removing unreachable block (ram,0x8021afac) */
/* WARNING: Removing unreachable block (ram,0x8021afb4) */

void FUN_8021ad84(undefined4 param_1,undefined4 param_2,int param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7)

{
  int iVar1;
  undefined4 uVar2;
  short sVar3;
  undefined2 uVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int *piVar9;
  int iVar10;
  undefined4 uVar11;
  undefined8 in_f30;
  undefined8 in_f31;
  double dVar12;
  undefined8 uVar13;
  undefined auStack104 [12];
  float local_5c;
  float local_58;
  float local_54;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar11 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar13 = FUN_802860c0();
  iVar1 = (int)((ulonglong)uVar13 >> 0x20);
  iVar6 = (int)uVar13;
  piVar9 = *(int **)(iVar1 + 0xb8);
  iVar8 = *(int *)(iVar1 + 0x4c);
  if (*(char *)((int)piVar9 + 0x1a) < '\0') {
    piVar9[2] = *(int *)(iVar1 + 0xc);
    piVar9[3] = *(int *)(iVar1 + 0x10);
    piVar9[4] = *(int *)(iVar1 + 0x14);
    iVar10 = (int)*(char *)(*(int *)(*(int *)(iVar6 + 0x50) + 0x2c) + param_3 * 0x18 +
                            (int)*(char *)(iVar1 + 0xad) + 0x12);
    piVar5 = *(int **)(*(int *)(iVar6 + 0x7c) + *(char *)(iVar6 + 0xad) * 4);
    iVar7 = *piVar5;
    *(undefined2 *)(iVar1 + 4) = 0;
    *(undefined2 *)(iVar1 + 2) = 0;
    FUN_80028384(piVar5,iVar10,&local_5c);
    FUN_80028384(piVar5,(int)*(char *)(*(int *)(iVar7 + 0x3c) + iVar10 * 0x1c),auStack104);
    FUN_80247754(auStack104,&local_5c,&local_5c);
    if (*(short *)(iVar8 + 0x1c) == 0) {
      dVar12 = (double)local_58;
      local_58 = FLOAT_803e6a28;
      uVar13 = FUN_802477f0(&local_5c);
      sVar3 = FUN_800217c0((double)local_5c,(double)local_54);
      *(short *)(iVar1 + 4) = (short)DAT_803dc2f0 + sVar3;
      sVar3 = FUN_800217c0(uVar13,dVar12);
      *(short *)(iVar1 + 2) = (short)DAT_803ddd70 + sVar3;
      FUN_800383a0(iVar6,param_3);
      FUN_800412d4();
    }
    else {
      sVar3 = FUN_800217c0((double)local_54,(double)local_5c);
      *(short *)(iVar1 + 4) = (short)((int)*(short *)(iVar8 + 0x1c) << 0xe) + sVar3;
      uVar4 = FUN_800217c0((double)local_54,(double)local_58);
      *(undefined2 *)(iVar1 + 2) = uVar4;
    }
    FUN_8003842c(iVar6,param_3,iVar1 + 0xc,iVar1 + 0x10,iVar1 + 0x14,0);
    FUN_8003b8f4((double)FLOAT_803e6a2c,iVar1,param_4,param_5,param_6,param_7);
    piVar5 = piVar9;
    for (iVar6 = 0; iVar6 < piVar9[5]; iVar6 = iVar6 + 1) {
      iVar8 = *piVar5;
      if (iVar8 != 0) {
        FUN_8003842c(iVar1,*(undefined *)((int)piVar9 + iVar6 + 0x1b),iVar8 + 0xc,iVar8 + 0x10,
                     iVar8 + 0x14,0);
      }
      piVar5 = piVar5 + 1;
    }
    uVar2 = 0;
  }
  else {
    uVar2 = 1;
  }
  __psq_l0(auStack8,uVar11);
  __psq_l1(auStack8,uVar11);
  __psq_l0(auStack24,uVar11);
  __psq_l1(auStack24,uVar11);
  FUN_8028610c(uVar2);
  return;
}

