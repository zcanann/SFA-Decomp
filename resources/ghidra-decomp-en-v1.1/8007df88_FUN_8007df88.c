// Function: FUN_8007df88
// Entry: 8007df88
// Size: 228 bytes

undefined4
FUN_8007df88(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,char param_9
            )

{
  int iVar1;
  int local_18;
  uint auStack_14 [4];
  
  if (param_9 != '\0') {
    DAT_803ddcd8 = '\0';
  }
  do {
    iVar1 = -1;
    while (iVar1 == -1) {
      iVar1 = FUN_802622ac(0,auStack_14,&local_18);
    }
    if (iVar1 == 0) {
      if (local_18 == 0x2000) {
        DAT_803dc360 = 0xd;
        return 1;
      }
      DAT_803dc360 = 7;
    }
    else if (iVar1 == -3) {
      DAT_803dc360 = 2;
    }
    else if (iVar1 == -2) {
      DAT_803dc360 = 1;
    }
    else {
      DAT_803dc360 = 0;
    }
    if (param_9 != '\0') {
      param_1 = FUN_8007e328(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    }
  } while ((DAT_803ddcd8 != '\0') && (param_9 != '\0'));
  return 0;
}

