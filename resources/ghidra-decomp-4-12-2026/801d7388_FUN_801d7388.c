// Function: FUN_801d7388
// Entry: 801d7388
// Size: 796 bytes

undefined4
FUN_801d7388(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            undefined4 param_9,undefined4 param_10,int param_11)

{
  undefined4 uVar1;
  uint uVar2;
  undefined8 uVar3;
  char local_18;
  char local_17 [19];
  
  FUN_8002bac4();
  uVar3 = FUN_80014ba4(0,local_17,&local_18);
  if (param_11 == 0x17) {
    uVar2 = FUN_800e8024('\x01',0);
    if (('\0' < local_17[0]) && (uVar2 == 0)) {
      FUN_8000bb38(0,0x418);
      return 1;
    }
  }
  else if (param_11 < 0x17) {
    if (param_11 == 0x15) {
      if (('\0' < local_18) && (DAT_803dccb8 == 0)) {
        FUN_8000bb38(0,0x418);
        return 1;
      }
    }
    else if (param_11 < 0x15) {
      if ((0x13 < param_11) && (local_17[0] < '\0')) {
        FUN_80043070(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x42);
        FUN_80043604(0,0,1);
        uVar1 = FUN_8004832c(0x42);
        FUN_80043658(uVar1,0);
        uVar1 = FUN_8004832c(7);
        FUN_80043658(uVar1,1);
        (**(code **)(*DAT_803dd72c + 0x44))(0x42,1);
        FUN_8000bb38(0,0x418);
        return 1;
      }
    }
    else if (('\0' < local_17[0]) && (uVar2 = FUN_800e8024('\x01',0), uVar2 != 0)) {
      FUN_80043070(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x42);
      uVar1 = FUN_8004832c(0x42);
      FUN_80043658(uVar1,0);
      uVar1 = FUN_8004832c(7);
      FUN_80043658(uVar1,1);
      uVar2 = FUN_80020078(0xbfd);
      if (uVar2 == 0) {
        uVar2 = FUN_80020078(0xff);
        if (uVar2 == 0) {
          uVar2 = FUN_80020078(0xc6e);
          if (uVar2 == 0) {
            uVar2 = FUN_80020078(0xc85);
            if (uVar2 != 0) {
              (**(code **)(*DAT_803dd72c + 0x44))(0x42,2);
            }
          }
          else {
            (**(code **)(*DAT_803dd72c + 0x44))(0x42,2);
          }
        }
        else {
          (**(code **)(*DAT_803dd72c + 0x44))(0x42,2);
        }
      }
      else {
        (**(code **)(*DAT_803dd72c + 0x44))(0x42,2);
      }
      FUN_8000bb38(0,0x418);
      return 1;
    }
  }
  else if (param_11 == 0x19) {
    uVar2 = FUN_80014e9c(0);
    if ((uVar2 & 0x200) != 0) {
      FUN_80043604(0,0,1);
      FUN_8004832c(0x42);
      uVar3 = FUN_80043938(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_8004832c(0x17);
      FUN_80043938(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      FUN_8000bb38(0,0x419);
      return 1;
    }
  }
  else if ((param_11 < 0x19) && (DAT_803de874 = 1, '\0' < local_18)) {
    FUN_80043070(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,9);
    uVar1 = FUN_8004832c(9);
    FUN_80043658(uVar1,0);
    uVar1 = FUN_8004832c(7);
    FUN_80043658(uVar1,1);
    FUN_8000bb38(0,0x418);
    return 1;
  }
  return 0;
}

