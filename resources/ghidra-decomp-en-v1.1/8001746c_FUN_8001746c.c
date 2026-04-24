// Function: FUN_8001746c
// Entry: 8001746c
// Size: 156 bytes

void FUN_8001746c(int param_1)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar2 = DAT_803dd648;
  if (param_1 == 0) {
    iVar1 = DAT_803dd648 * 5;
    DAT_803dd64c = (undefined *)0x0;
    DAT_803dd648 = DAT_803dd648 + 1;
    (&DAT_8033b1a0)[iVar1] = 8;
    (&DAT_8033b1a4)[iVar2 * 5] = 0xff;
    return;
  }
  iVar1 = DAT_803dd648 * 5;
  uVar3 = param_1 + 0x7fd38480;
  iVar4 = ((int)uVar3 >> 5) + (uint)((int)uVar3 < 0 && (uVar3 & 0x1f) != 0);
  if (iVar4 == 0xff) {
    DAT_803dd64c = (undefined *)0x0;
  }
  else {
    DAT_803dd64c = &DAT_802c7b80 + iVar4 * 0x20;
  }
  DAT_803dd648 = DAT_803dd648 + 1;
  (&DAT_8033b1a0)[iVar1] = 8;
  (&DAT_8033b1a4)[iVar2 * 5] = iVar4;
  return;
}

