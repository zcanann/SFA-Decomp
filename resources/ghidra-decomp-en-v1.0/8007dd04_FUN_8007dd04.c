// Function: FUN_8007dd04
// Entry: 8007dd04
// Size: 264 bytes

int FUN_8007dd04(char param_1)

{
  int iVar1;
  
  if (param_1 != '\0') {
    DAT_803dd058 = '\0';
    FUN_8007e54c(2);
  }
  do {
    iVar1 = FUN_8007f83c(0);
    if (iVar1 != 0) {
      if (DAT_803dd05a != '\0') {
        DAT_803dd05a = '\0';
        FUN_80263124(&DAT_80396900);
      }
      FUN_80262490(0);
      FUN_80023800(DAT_803dd040);
      DAT_803dd040 = 0;
      DAT_803db700 = 0xd;
      if (iVar1 == 2) {
        iVar1 = FUN_8007eb44(0,0,0,0,0,0);
      }
    }
    if (param_1 != '\0') {
      FUN_8007e1ac(0);
    }
    if (DAT_803dd058 != '\0') {
      FUN_8007e54c(2);
    }
  } while ((DAT_803dd058 != '\0') && (param_1 != '\0'));
  return iVar1;
}

