// Function: FUN_80059460
// Entry: 80059460
// Size: 80 bytes

int FUN_80059460(void)

{
  int iVar1;
  int iVar2;
  
  iVar2 = (int)*(short *)(DAT_80382f00 + 0x594);
  if (*(short *)(DAT_80382f00 + 0x594) < 0) {
    iVar2 = DAT_803dc2a8;
  }
  if (iVar2 < 0) {
    return 0;
  }
  iVar1 = (&DAT_803870c8)[iVar2];
  if (iVar1 == 0) {
    return 0;
  }
  DAT_803dc2a8 = iVar2;
  DAT_803ddb20 = iVar1;
  return iVar1;
}

