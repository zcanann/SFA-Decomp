// Function: FUN_801164c0
// Entry: 801164c0
// Size: 920 bytes

void FUN_801164c0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  undefined4 uVar2;
  bool bVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar8;
  int local_28;
  int local_24;
  int local_20;
  int local_1c;
  int local_18;
  uint local_14 [3];
  
  DAT_803de291 = 1;
  iVar1 = FUN_801195e0(2);
  if (iVar1 != 0) {
    iVar1 = FUN_801192a8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    if (iVar1 == 0) {
      FUN_80119594();
    }
    else {
      FUN_801184a0(0x803de2b8);
      DAT_803de2c4 = (uint)*(ushort *)(DAT_803dd970 + 4) - DAT_803de2b8 >> 1;
      DAT_803de2c0 = (uint)*(ushort *)(DAT_803dd970 + 6) - iRam803de2bc >> 1;
      FUN_80119154(local_14,&local_18,&local_1c,&local_20,&local_24,&local_28);
      DAT_803de2b4 = FUN_80023d8c(local_14[0],0x18);
      DAT_803de2b0 = FUN_80023d8c(local_18,0x18);
      DAT_803de2ac = FUN_80023d8c(local_1c,0x18);
      DAT_803de2a8 = FUN_80023d8c(local_20,0x18);
      if (local_24 == 0) {
        DAT_803de2a4 = 0;
      }
      else {
        DAT_803de2a4 = FUN_80023d8c(local_24,0x18);
      }
      DAT_803de2a0 = FUN_80023d8c(local_28,0x18);
      DAT_803de29c = FUN_80023d8c(0x4000,0x18);
      if (((((DAT_803de2b4 == 0) || (DAT_803de2b0 == 0)) || (DAT_803de2ac == 0)) ||
          ((DAT_803de2a8 == 0 || ((DAT_803de2a4 == 0 && (local_24 != 0)))))) ||
         ((DAT_803de2a0 == 0 || (DAT_803de29c == 0)))) {
        FUN_80119594();
        uVar2 = FUN_800238f8(0);
        if (DAT_803de2b4 != 0) {
          FUN_800238c4(DAT_803de2b4);
          DAT_803de2b4 = 0;
        }
        if (DAT_803de2b0 != 0) {
          FUN_800238c4(DAT_803de2b0);
          DAT_803de2b0 = 0;
        }
        if (DAT_803de2ac != 0) {
          FUN_800238c4(DAT_803de2ac);
          DAT_803de2ac = 0;
        }
        if (DAT_803de2a8 != 0) {
          FUN_800238c4(DAT_803de2a8);
          DAT_803de2a8 = 0;
        }
        if (DAT_803de2a4 != 0) {
          FUN_800238c4(DAT_803de2a4);
          DAT_803de2a4 = 0;
        }
        if (DAT_803de2a0 != 0) {
          FUN_800238c4(DAT_803de2a0);
          DAT_803de2a0 = 0;
        }
        if (DAT_803de29c != 0) {
          FUN_800238c4(DAT_803de29c);
          DAT_803de29c = 0;
        }
        FUN_800238f8(uVar2);
        FUN_8007d858();
        FUN_80022e1c();
        FUN_80041f34();
        FUN_8007d858();
        FUN_80022e1c();
      }
      else {
        DAT_803de291 = 0;
        FUN_802420b0(DAT_803de2b4,local_14[0]);
        FUN_802420b0(DAT_803de2b0,local_18);
        FUN_802420b0(DAT_803de2ac,local_1c);
        FUN_802420b0(DAT_803de2a8,local_20);
        if (DAT_803de2a4 != 0) {
          FUN_802420b0(DAT_803de2a4,local_24);
        }
        FUN_802420b0(DAT_803de2a0,local_28);
        FUN_802420b0(DAT_803de29c,0x4000);
        uVar4 = DAT_803de2ac;
        uVar5 = DAT_803de2a8;
        uVar6 = DAT_803de2a4;
        uVar7 = DAT_803de2a0;
        uVar8 = FUN_80118f30(DAT_803de2b4,DAT_803de2b0,DAT_803de2ac,DAT_803de2a8,DAT_803de2a4,
                             DAT_803de2a0);
        bVar3 = FUN_80118c08(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0,1,uVar4
                             ,uVar5,uVar6,uVar7,in_r9,in_r10);
        if (!bVar3) {
          FUN_80242fc0(uVar8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       s_n_attractmode_c_8031afdc,0x33e,s_Fail_to_prepare_8031afec,uVar5,uVar6,uVar7
                       ,in_r9,in_r10);
        }
        FUN_80118ba8();
        DAT_803de288 = 2;
        FUN_8024d054();
        DAT_803de2cd = 10;
        DAT_803de318 = 0;
        if (DAT_803de28c == '\x04') {
          FUN_80117e10(100,1);
        }
        else {
          FUN_80117e10(0,1);
        }
      }
    }
  }
  return;
}

