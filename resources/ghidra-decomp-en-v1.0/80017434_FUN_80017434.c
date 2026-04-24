// Function: FUN_80017434
// Entry: 80017434
// Size: 156 bytes

void FUN_80017434(int param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar2 = DAT_803dc9c8;
  if (param_1 == 0) {
    iVar1 = DAT_803dc9c8 * 5;
    DAT_803dc9cc = (undefined *)0x0;
    DAT_803dc9c8 = DAT_803dc9c8 + 1;
    (&DAT_8033a540)[iVar1] = 8;
    (&DAT_8033a544)[iVar2 * 5] = 0xff;
    return;
  }
  iVar1 = DAT_803dc9c8 * 5;
  uVar3 = param_1 + 0x7fd38c00;
  iVar4 = ((int)uVar3 >> 5) + (uint)((int)uVar3 < 0 && (uVar3 & 0x1f) != 0);
  if (iVar4 == 0xff) {
    DAT_803dc9cc = (undefined *)0x0;
  }
  else {
    DAT_803dc9cc = &DAT_802c7400 + iVar4 * 0x20;
  }
  DAT_803dc9c8 = DAT_803dc9c8 + 1;
  (&DAT_8033a540)[iVar1] = 8;
  (&DAT_8033a544)[iVar2 * 5] = iVar4;
  return;
}

