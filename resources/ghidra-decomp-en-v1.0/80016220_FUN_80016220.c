// Function: FUN_80016220
// Entry: 80016220
// Size: 108 bytes

void FUN_80016220(undefined4 param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = DAT_803dc9c8;
  iVar3 = DAT_803dc9c8 * 5;
  DAT_803dc9c8 = DAT_803dc9c8 + 1;
  (&DAT_8033a540)[iVar3] = 5;
  uVar1 = DAT_803dc9c4;
  iVar3 = FUN_80015bf0(DAT_803dc9c4,param_1);
  DAT_803dc9c4 = iVar3 + 1;
  (&DAT_8033a544)[iVar2 * 5] = uVar1;
  return;
}

