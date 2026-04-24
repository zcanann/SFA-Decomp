// Function: FUN_8011b698
// Entry: 8011b698
// Size: 544 bytes

void FUN_8011b698(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 extraout_r4;
  undefined4 uVar4;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar5;
  undefined4 *puVar6;
  int *piVar7;
  short *psVar8;
  undefined8 uVar9;
  
  DAT_803de328 = FUN_80023d8c(0x6c,5);
  uVar3 = 5;
  uVar4 = 0;
  DAT_803de32c = FUN_80023d8c(0x6c,5);
  DAT_803de348 = FUN_80054ed0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x2dd,
                              uVar3,uVar4,in_r6,in_r7,in_r8,in_r9,in_r10);
  uVar9 = FUN_800199a8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x15);
  uVar3 = extraout_r4;
  if (DAT_803de320 == (ushort *)0x0) {
    DAT_803de320 = FUN_800195a8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xec);
  }
  iVar5 = 0;
  psVar8 = (short *)&DAT_803dc664;
  puVar6 = &DAT_803a92e0;
  do {
    uVar1 = FUN_80054ed0(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)*psVar8,
                         uVar3,uVar4,in_r6,in_r7,in_r8,in_r9,in_r10);
    *puVar6 = uVar1;
    psVar8 = psVar8 + 1;
    puVar6 = puVar6 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 4);
  iVar5 = FUN_8001495c();
  if (iVar5 == 6) {
    FUN_8011a9b4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    DAT_803de330 = DAT_803de328;
    if (DAT_803dc65b != -1) {
      (**(code **)(*DAT_803dd720 + 8))();
    }
    DAT_803dc65b = '\x01';
    *(ushort *)(PTR_DAT_8031b418 + 0x16) = *(ushort *)(PTR_DAT_8031b418 + 0x16) & 0xbfff;
    PTR_DAT_8031b418[0x56] = 0;
    *(undefined2 *)(PTR_DAT_8031b418 + 0x3c) = 0x3d6;
    DAT_803de345 = 0;
    (**(code **)(*DAT_803dd720 + 4))
              (PTR_DAT_8031b418,DAT_8031b41c,0,0,5,4,0x14,200,0xff,0xff,0xff,0xff);
    (**(code **)(*DAT_803dd720 + 0x18))(0);
    DAT_803de33c = 0;
    DAT_803de33d = 0;
    DAT_803de33e = 0;
  }
  else {
    iVar5 = FUN_8001495c();
    if (iVar5 != 5) {
      uVar9 = (**(code **)(*DAT_803dd6cc + 0xc))(0x14,5);
    }
    FUN_8011aa8c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  iVar5 = 0;
  DAT_803de34c = 0;
  DAT_803de34d = 0;
  DAT_803de34f = 0;
  DAT_803de34e = 4;
  DAT_803de334 = 0;
  piVar7 = &DAT_803a92b8;
  do {
    iVar2 = FUN_80023d8c(5,5);
    *piVar7 = iVar2;
    piVar7 = piVar7 + 1;
    iVar5 = iVar5 + 1;
  } while (iVar5 < 10);
  return;
}

