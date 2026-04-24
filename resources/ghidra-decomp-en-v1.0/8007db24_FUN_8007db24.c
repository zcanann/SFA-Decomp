// Function: FUN_8007db24
// Entry: 8007db24
// Size: 156 bytes

void FUN_8007db24(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 uVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_802860dc();
  DAT_803dd058 = '\0';
  FUN_8007e54c(1);
  do {
    uVar1 = FUN_8007eb44(0,(int)((ulonglong)uVar2 >> 0x20),0,(int)uVar2,param_3,FUN_8007e6d4);
    FUN_8007e1ac(0);
    if (DAT_803dd058 != '\0') {
      FUN_8007e54c(1);
    }
  } while (DAT_803dd058 != '\0');
  FUN_80286128(uVar1);
  return;
}

