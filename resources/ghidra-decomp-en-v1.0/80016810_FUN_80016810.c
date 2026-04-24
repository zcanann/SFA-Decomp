// Function: FUN_80016810
// Entry: 80016810
// Size: 96 bytes

void FUN_80016810(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803dc9c8;
  if (DAT_803dc96c == 0) {
    iVar1 = DAT_803dc9c8 * 5;
    DAT_803dc9c8 = DAT_803dc9c8 + 1;
    (&DAT_8033a540)[iVar1] = 2;
    (&DAT_8033a544)[iVar2 * 5] = param_1;
    (&DAT_8033a548)[iVar2 * 5] = param_2;
    (&DAT_8033a54c)[iVar2 * 5] = param_3;
  }
  else {
    FUN_8001658c();
  }
  return;
}

