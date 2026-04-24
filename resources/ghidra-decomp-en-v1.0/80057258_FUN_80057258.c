// Function: FUN_80057258
// Entry: 80057258
// Size: 408 bytes

/* WARNING: Removing unreachable block (ram,0x800573d0) */

void FUN_80057258(undefined8 param_1,undefined8 param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int *param_6)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int unaff_r28;
  undefined4 uVar5;
  double extraout_f1;
  double dVar6;
  double dVar7;
  undefined8 in_f31;
  undefined8 uVar8;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar8 = FUN_802860dc();
  iVar3 = (int)((ulonglong)uVar8 >> 0x20);
  uVar4 = 0;
  if ((((DAT_803db624 != iVar3) && (uVar4 = 1, cRam803db625 != iVar3)) &&
      (uVar4 = 2, cRam803db626 != iVar3)) &&
     ((uVar4 = 3, cRam803db627 != iVar3 && (uVar4 = 4, cRam803db628 != iVar3)))) {
    uVar4 = 5;
  }
  DAT_803dcde1 = 0;
  dVar7 = extraout_f1;
  dVar6 = (double)FUN_80291e40((double)(float)(param_3 / (double)FLOAT_803debb4));
  dVar7 = (double)FUN_80291e40((double)(float)(dVar7 / (double)FLOAT_803debb4));
  iVar1 = FUN_80059ac0((int)dVar7,(int)dVar6,uVar4);
  uVar2 = FUN_80048f10(0x1f);
  iVar3 = DAT_803dce78;
  if ((iVar1 < 0) || ((int)(uVar2 >> 5) <= iVar1)) {
    DAT_803dcea4 = '\0';
    iVar3 = unaff_r28;
  }
  else {
    FUN_8001f71c(DAT_803dce78,0x1f,iVar1 << 5,0x20);
    DAT_803dcea4 = *(char *)(iVar3 + 0x1c);
  }
  DAT_803dceb4 = 0;
  if (DAT_803dcea4 == '\x01') {
    DAT_803dceb6 = (undefined2)iVar1;
    DAT_803dceb4 = *(undefined2 *)(iVar3 + 0x1e);
  }
  *(int *)uVar8 = iVar1;
  if (iVar1 != -1) {
    iVar3 = (**(code **)(*DAT_803dcaac + 0x90))();
    *param_6 = (int)*(char *)(iVar3 + 0xe);
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  FUN_80286128();
  return;
}

