// Function: FUN_8011d038
// Entry: 8011d038
// Size: 548 bytes

void FUN_8011d038(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9)

{
  uint uVar1;
  char cVar4;
  ushort *puVar2;
  undefined *puVar3;
  int iVar5;
  int *piVar6;
  int iVar7;
  double dVar8;
  undefined8 extraout_f1;
  double dVar9;
  undefined8 uVar10;
  double dVar11;
  undefined8 local_18;
  
  iVar7 = DAT_803dc690 * 0x10;
  cVar4 = FUN_80134f44();
  if (cVar4 == '\0') {
    dVar9 = (double)(**(code **)(*DAT_803dd6cc + 0x18))();
    dVar8 = (double)FLOAT_803e2a54;
    FUN_8001b4f8(FUN_80135e18);
    uVar1 = (int)(dVar8 - dVar9) & 0xff;
    if (uVar1 < 0x80) {
      local_18 = (double)CONCAT44(0x43300000,uVar1 * 0x86 ^ 0x80000000);
      param_3 = (double)(float)(local_18 - DOUBLE_803e2a68);
      dVar11 = -(double)(float)(param_3 * (double)FLOAT_803e2a60 - (double)FLOAT_803e2a5c);
      FUN_80135ba8((double)FLOAT_803e2a58,dVar11);
      iVar5 = 0;
    }
    else {
      dVar11 = (double)FLOAT_803e2a64;
      FUN_80135ba8((double)FLOAT_803e2a58,dVar11);
      iVar5 = ((int)(dVar8 - dVar9) & 0x7fU) << 1;
    }
    FUN_801350c8(iVar5,0,0);
    if (*(short *)(&DAT_8031b912 + iVar7) != -1) {
      uVar10 = FUN_80019940(0xff,0xff,0xff,0xff);
      puVar2 = FUN_800195a8(uVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,
                            (uint)*(ushort *)(&DAT_8031b912 + iVar7));
      puVar3 = FUN_80017400((uint)*(byte *)(puVar2 + 2));
      puVar3[0x1e] = (byte)iVar5;
      FUN_800168a8(uVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,
                   (uint)*(ushort *)(&DAT_8031b912 + iVar7));
    }
    if (*(short *)(&DAT_8031b914 + iVar7) != -1) {
      uVar10 = FUN_80019940(0xff,0xff,0xff,(byte)iVar5);
      FUN_800168a8(uVar10,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,
                   (uint)*(ushort *)(&DAT_8031b914 + iVar7));
    }
    iVar7 = 0;
    piVar6 = &DAT_803a9430;
    do {
      if (*piVar6 != 0) {
        (**(code **)(*DAT_803dd724 + 0x18))(*piVar6,param_9,iVar5);
      }
      piVar6 = piVar6 + 1;
      iVar7 = iVar7 + 1;
    } while (iVar7 < 8);
    (**(code **)(*DAT_803dd720 + 0x30))(iVar5);
    (**(code **)(*DAT_803dd720 + 0x10))(param_9);
    dVar8 = (double)FUN_8001b4f8(0);
    FUN_80134fb0(dVar8,dVar11,param_3,param_4,param_5,param_6,param_7,param_8,'\0');
    DAT_803de386 = DAT_803de386 + -1;
    if (DAT_803de386 < '\0') {
      DAT_803de386 = '\0';
    }
  }
  else {
    FUN_80134d50(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  return;
}

