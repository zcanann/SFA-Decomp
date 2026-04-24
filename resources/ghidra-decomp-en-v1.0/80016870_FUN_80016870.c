// Function: FUN_80016870
// Entry: 80016870
// Size: 108 bytes

void FUN_80016870(undefined4 param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803dc9c8;
  if (DAT_803dc96c == 0) {
    iVar1 = DAT_803dc9c8 * 5;
    DAT_803dc9c8 = DAT_803dc9c8 + 1;
    (&DAT_8033a540)[iVar1] = 2;
    (&DAT_8033a544)[iVar2 * 5] = param_1;
    (&DAT_8033a548)[iVar2 * 5] = 0;
    (&DAT_8033a54c)[iVar2 * 5] = 0;
  }
  else {
    FUN_8001658c(param_1,0,0);
  }
  return;
}

