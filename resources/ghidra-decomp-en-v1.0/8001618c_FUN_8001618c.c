// Function: FUN_8001618c
// Entry: 8001618c
// Size: 148 bytes

void FUN_8001618c(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = DAT_803dc9c8;
  if (DAT_803dc96c == 0) {
    iVar1 = DAT_803dc9c8 * 5;
    DAT_803dc9c8 = DAT_803dc9c8 + 1;
    (&DAT_8033a540)[iVar1] = 6;
    iVar1 = DAT_803dc9c4;
    iVar3 = FUN_80015bf0(DAT_803dc9c4,param_1);
    DAT_803dc9c4 = iVar3 + 1;
    (&DAT_8033a544)[iVar2 * 5] = iVar1;
    (&DAT_8033a548)[iVar2 * 5] = param_2;
  }
  else {
    FUN_80015e84();
  }
  return;
}

