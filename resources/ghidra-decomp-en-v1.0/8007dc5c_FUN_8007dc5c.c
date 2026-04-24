// Function: FUN_8007dc5c
// Entry: 8007dc5c
// Size: 168 bytes

undefined4 FUN_8007dc5c(undefined4 param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  DAT_803dd058 = '\0';
  FUN_8007e54c(0);
  do {
    uVar1 = FUN_8007eb44(1,param_1,0,param_2,0,FUN_8007e77c);
    FUN_8007e1ac(0);
    if (DAT_803dd058 != '\0') {
      FUN_8007e54c(0);
    }
  } while (DAT_803dd058 != '\0');
  return uVar1;
}

