// Function: FUN_8012f04c
// Entry: 8012f04c
// Size: 572 bytes

void FUN_8012f04c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  undefined8 extraout_f1;
  undefined8 uVar7;
  float local_38;
  float local_34 [2];
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  uVar7 = FUN_80286840();
  uVar1 = (undefined4)((ulonglong)uVar7 >> 0x20);
  uVar5 = (undefined4)uVar7;
  uVar7 = extraout_f1;
  iVar2 = FUN_8002bac4();
  iVar3 = FUN_8022de2c();
  iVar4 = FUN_8001ffa0();
  if (iVar4 == 0) {
    if (iVar3 == 0) {
      uVar7 = FUN_801265b0(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      uVar7 = FUN_8012dab8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar5
                           ,param_11,param_12,param_13,param_14,param_15,param_16);
      if (DAT_803de3fe != '\0') {
        FUN_8012cd38(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      FUN_80296328(iVar2);
      uVar7 = FUN_8025da88(0,0,0x280,0x1e0);
      if ((iVar2 != 0) && (DAT_803de400 == '\0')) {
        iVar3 = FUN_802967bc(iVar2,local_34,&local_38);
        if (iVar3 != 0) {
          FUN_800540a8(DAT_803de544,&DAT_803de4ac,&DAT_803de4a8);
          param_3 = (double)FLOAT_803e2af0;
          uStack_2c = (uint)*(ushort *)(DAT_803de544 + 10);
          local_34[1] = 176.0;
          uStack_24 = (uint)*(ushort *)(DAT_803de544 + 0xc);
          local_28 = 0x43300000;
          param_2 = -(double)(float)(param_3 * (double)(float)((double)CONCAT44(0x43300000,uStack_24
                                                                               ) - DOUBLE_803e2b08)
                                    - (double)local_38);
          uVar7 = FUN_80077318(-(double)(float)(param_3 * (double)(float)((double)CONCAT44(
                                                  0x43300000,uStack_2c) - DOUBLE_803e2b08) -
                                               (double)local_34[0]),param_2,DAT_803de544,0x96,0x100)
          ;
        }
        FUN_80121724(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      uVar6 = 0x1e0;
      uVar7 = FUN_8025da88(0,0,0x280,0x1e0);
      if (iVar2 != 0) {
        uVar7 = FUN_801234e8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,
                             uVar5,param_11,uVar6,param_13,param_14,param_15,param_16);
        uVar7 = FUN_8012ebbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        uVar7 = FUN_80125528(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1);
      }
      if (DAT_803de3db != '\0') {
        FUN_801291ac(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      FUN_8000f0d8();
    }
    else {
      uVar7 = FUN_80126188();
      uVar7 = FUN_801265b0(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      uVar7 = FUN_8012ebbc(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_8012dab8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar1,uVar5,
                   param_11,param_12,param_13,param_14,param_15,param_16);
    }
    FUN_8011faa8();
    uVar7 = FUN_8011f6e8();
    if (-1 < DAT_803dc6f8) {
      FUN_801294d8(uVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
    DAT_803de42a = 0;
    DAT_803de42c = 0;
  }
  FUN_8028688c();
  return;
}

