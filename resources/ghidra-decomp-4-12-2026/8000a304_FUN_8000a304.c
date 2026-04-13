// Function: FUN_8000a304
// Entry: 8000a304
// Size: 148 bytes

void FUN_8000a304(int param_1)

{
  short *psVar1;
  int iVar2;
  
  psVar1 = DAT_803dd480;
  iVar2 = DAT_803dd484;
  if (DAT_803dd484 != 0) {
    do {
      if (*psVar1 == 0xec) goto LAB_8000a34c;
      psVar1 = psVar1 + 8;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  psVar1 = (short *)0x0;
LAB_8000a34c:
  FUN_8000a3a0(3,1,0);
  psVar1[1] = (&DAT_802c5e80)[param_1 * 8];
  FUN_8000a538((int *)0xec,1);
  return;
}

