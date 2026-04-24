// Function: FUN_801d6d98
// Entry: 801d6d98
// Size: 796 bytes

undefined4 FUN_801d6d98(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  char local_18;
  char local_17 [19];
  
  FUN_8002b9ec();
  FUN_80014b78(0,local_17,&local_18);
  if (param_3 == 0x17) {
    iVar2 = FUN_800e7da0(1,0);
    if (('\0' < local_17[0]) && (iVar2 == 0)) {
      FUN_8000bb18(0,0x418);
      return 1;
    }
  }
  else if (param_3 < 0x17) {
    if (param_3 == 0x15) {
      if (('\0' < local_18) && (DAT_803dc050 == 0)) {
        FUN_8000bb18(0,0x418);
        return 1;
      }
    }
    else if (param_3 < 0x15) {
      if ((0x13 < param_3) && (local_17[0] < '\0')) {
        FUN_80042f78(0x42);
        FUN_8004350c(0,0,1);
        uVar1 = FUN_800481b0(0x42);
        FUN_80043560(uVar1,0);
        uVar1 = FUN_800481b0(7);
        FUN_80043560(uVar1,1);
        (**(code **)(*DAT_803dcaac + 0x44))(0x42,1);
        FUN_8000bb18(0,0x418);
        return 1;
      }
    }
    else if (('\0' < local_17[0]) && (iVar2 = FUN_800e7da0(1,0), iVar2 != 0)) {
      FUN_80042f78(0x42);
      uVar1 = FUN_800481b0(0x42);
      FUN_80043560(uVar1,0);
      uVar1 = FUN_800481b0(7);
      FUN_80043560(uVar1,1);
      iVar2 = FUN_8001ffb4(0xbfd);
      if (iVar2 == 0) {
        iVar2 = FUN_8001ffb4(0xff);
        if (iVar2 == 0) {
          iVar2 = FUN_8001ffb4(0xc6e);
          if (iVar2 == 0) {
            iVar2 = FUN_8001ffb4(0xc85);
            if (iVar2 != 0) {
              (**(code **)(*DAT_803dcaac + 0x44))(0x42,2);
            }
          }
          else {
            (**(code **)(*DAT_803dcaac + 0x44))(0x42,2);
          }
        }
        else {
          (**(code **)(*DAT_803dcaac + 0x44))(0x42,2);
        }
      }
      else {
        (**(code **)(*DAT_803dcaac + 0x44))(0x42,2);
      }
      FUN_8000bb18(0,0x418);
      return 1;
    }
  }
  else if (param_3 == 0x19) {
    uVar3 = FUN_80014e70(0);
    if ((uVar3 & 0x200) != 0) {
      FUN_8004350c(0,0,1);
      uVar1 = FUN_800481b0(0x42);
      FUN_800437bc(uVar1,0x20000000);
      uVar1 = FUN_800481b0(0x17);
      FUN_800437bc(uVar1,0x20000000);
      FUN_8000bb18(0,0x419);
      return 1;
    }
  }
  else if ((param_3 < 0x19) && (DAT_803ddbf4 = 1, '\0' < local_18)) {
    FUN_80042f78(9);
    uVar1 = FUN_800481b0(9);
    FUN_80043560(uVar1,0);
    uVar1 = FUN_800481b0(7);
    FUN_80043560(uVar1,1);
    FUN_8000bb18(0,0x418);
    return 1;
  }
  return 0;
}

