// Function: FUN_800592e4
// Entry: 800592e4
// Size: 80 bytes

int FUN_800592e4(void)

{
  int iVar1;
  int iVar2;
  
  iVar2 = (int)*(short *)(DAT_803822a0 + 0x594);
  if (*(short *)(DAT_803822a0 + 0x594) < 0) {
    iVar2 = DAT_803db648;
  }
  if (iVar2 < 0) {
    return 0;
  }
  iVar1 = (&DAT_80386468)[iVar2];
  if (iVar1 == 0) {
    return 0;
  }
  DAT_803db648 = iVar2;
  DAT_803dcea0 = iVar1;
  return iVar1;
}

