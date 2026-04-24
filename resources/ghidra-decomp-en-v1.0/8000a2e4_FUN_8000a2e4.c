// Function: FUN_8000a2e4
// Entry: 8000a2e4
// Size: 148 bytes

void FUN_8000a2e4(int param_1)

{
  short *psVar1;
  int iVar2;
  
  psVar1 = DAT_803dc800;
  iVar2 = DAT_803dc804;
  if (DAT_803dc804 != 0) {
    do {
      if (*psVar1 == 0xec) goto LAB_8000a32c;
      psVar1 = psVar1 + 8;
      iVar2 = iVar2 + -1;
    } while (iVar2 != 0);
  }
  psVar1 = (short *)0x0;
LAB_8000a32c:
  FUN_8000a380(3,1,0);
  psVar1[1] = (&DAT_802c5700)[param_1 * 8];
  FUN_8000a518(0xec,1);
  return;
}

