// Function: FUN_8024bfb8
// Entry: 8024bfb8
// Size: 284 bytes

void FUN_8024bfb8(undefined *param_1)

{
  undefined *puVar1;
  int *piVar2;
  
  FUN_80243e74();
  FUN_8024c0d4();
  puVar1 = param_1;
  if (DAT_803deba8 == 0) {
    if (DAT_803deb88 != (int *)0x0) {
      DAT_803deb88[10] = 0;
    }
    FUN_80243e74();
    FUN_80243e74();
    DAT_803deb94 = 1;
    if (DAT_803deb88 == (int *)0x0) {
      DAT_803deb98 = 1;
    }
    FUN_80243e9c();
    while (piVar2 = FUN_8024c174(), piVar2 != (int *)0x0) {
      FUN_8024bb8c(piVar2,(undefined *)0x0);
    }
    if (DAT_803deb88 == (int *)0x0) {
      if (param_1 != (undefined *)0x0) {
        (*(code *)param_1)(0,0);
      }
    }
    else {
      FUN_8024bb8c(DAT_803deb88,param_1);
    }
    FUN_80243e74();
    DAT_803deb94 = 0;
    if (DAT_803deb98 != 0) {
      DAT_803deb98 = 0;
      FUN_8024a91c();
    }
    FUN_80243e9c();
    FUN_80243e9c();
    puVar1 = DAT_803debac;
  }
  DAT_803debac = puVar1;
  FUN_80243e9c();
  return;
}

