// Function: FUN_8007de0c
// Entry: 8007de0c
// Size: 228 bytes

undefined4 FUN_8007de0c(char param_1)

{
  int iVar1;
  int local_18;
  undefined auStack20 [16];
  
  if (param_1 != '\0') {
    DAT_803dd058 = '\0';
  }
  do {
    iVar1 = -1;
    while (iVar1 == -1) {
      iVar1 = FUN_80261b48(0,auStack20,&local_18);
    }
    if (iVar1 == 0) {
      if (local_18 == 0x2000) {
        DAT_803db700 = 0xd;
        return 1;
      }
      DAT_803db700 = 7;
    }
    else if (iVar1 == -3) {
      DAT_803db700 = 2;
    }
    else if (iVar1 == -2) {
      DAT_803db700 = 1;
    }
    else {
      DAT_803db700 = 0;
    }
    if (param_1 != '\0') {
      FUN_8007e1ac(0);
    }
  } while ((DAT_803dd058 != '\0') && (param_1 != '\0'));
  return 0;
}

