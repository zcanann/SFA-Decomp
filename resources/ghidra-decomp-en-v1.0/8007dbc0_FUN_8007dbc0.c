// Function: FUN_8007dbc0
// Entry: 8007dbc0
// Size: 156 bytes

undefined4 FUN_8007dbc0(undefined4 param_1)

{
  undefined4 uVar1;
  
  DAT_803dd058 = '\0';
  FUN_8007e54c(0);
  do {
    uVar1 = FUN_8007eb44(1,0,0,param_1,0,FUN_8007e748);
    FUN_8007e1ac(1);
    if (DAT_803dd058 != '\0') {
      FUN_8007e54c(0);
    }
  } while (DAT_803dd058 != '\0');
  return uVar1;
}

