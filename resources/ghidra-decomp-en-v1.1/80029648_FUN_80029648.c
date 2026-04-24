// Function: FUN_80029648
// Entry: 80029648
// Size: 300 bytes

void FUN_80029648(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 *param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  char *pcVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  undefined8 extraout_f1;
  undefined8 uVar6;
  undefined8 extraout_f1_00;
  longlong lVar7;
  char *local_38;
  int aiStack_34 [13];
  
  lVar7 = FUN_8028683c();
  iVar2 = (int)((ulonglong)lVar7 >> 0x20);
  if (lVar7 < 0) {
    uVar5 = -iVar2;
    uVar6 = extraout_f1;
  }
  else {
    param_12 = 8;
    uVar6 = FUN_800490c4(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x2c,
                         DAT_803dd7e4,iVar2 << 1,8,param_13,param_14,param_15,param_16);
    uVar5 = (uint)*DAT_803dd7e4;
  }
  iVar2 = FUN_80013c30(DAT_803dd7d4,uVar5,(uint)&local_38);
  if (iVar2 == 0) {
    local_38 = FUN_80029260(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar5);
    uVar6 = FUN_80029058((int)local_38);
    pcVar1 = local_38;
    iVar2 = 0;
    for (iVar4 = 0; iVar4 < (int)(uint)(byte)pcVar1[0xf2]; iVar4 = iVar4 + 1) {
      uVar3 = FUN_80054620(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      *(undefined4 *)(*(int *)(pcVar1 + 0x20) + iVar2) = uVar3;
      iVar2 = iVar2 + 4;
      uVar6 = extraout_f1_00;
    }
    uVar6 = FUN_80028e34((int)local_38);
    FUN_800254e4(uVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_38,uVar5,
                 (int)(local_38 + *(int *)(local_38 + 0xc)),param_12,param_13,param_14,param_15,
                 param_16);
    FUN_80013d08(DAT_803dd7d4,(short)uVar5,(uint)&local_38);
  }
  else {
    *local_38 = *local_38 + '\x01';
  }
  uVar3 = FUN_80025944((int)local_38,(uint)lVar7,aiStack_34,0);
  *param_11 = uVar3;
  FUN_80286888();
  return;
}

