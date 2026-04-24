// Function: FUN_80015dc8
// Entry: 80015dc8
// Size: 188 bytes

void FUN_80015dc8(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860dc();
  iVar1 = DAT_803dc9c8;
  if (DAT_803dc96c == 0) {
    iVar2 = DAT_803dc9c8 * 5;
    DAT_803dc9c8 = DAT_803dc9c8 + 1;
    (&DAT_8033a540)[iVar2] = 7;
    iVar2 = DAT_803dc9c4;
    iVar3 = FUN_80015bf0(DAT_803dc9c4,(int)((ulonglong)uVar4 >> 0x20));
    DAT_803dc9c4 = iVar3 + 1;
    (&DAT_8033a544)[iVar1 * 5] = iVar2;
    (&DAT_8033a548)[iVar1 * 5] = (int)uVar4;
    (&DAT_8033a54c)[iVar1 * 5] = param_3;
    (&DAT_8033a550)[iVar1 * 5] = param_4;
  }
  else {
    iVar1 = (int)uVar4 * 0x20;
    *(short *)(&DAT_802c7418 + iVar1) = (short)param_3;
    *(short *)(&DAT_802c741a + iVar1) = (short)param_4;
    FUN_80015e84();
  }
  FUN_80286128();
  return;
}

