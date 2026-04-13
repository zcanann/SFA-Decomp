// Function: FUN_802c16e8
// Entry: 802c16e8
// Size: 200 bytes

void FUN_802c16e8(void)

{
  short *psVar1;
  char in_r8;
  int iVar2;
  
  psVar1 = (short *)FUN_80286838();
  iVar2 = *(int *)(psVar1 + 0x5c);
  if (*(int *)(psVar1 + 0x7a) == 0) {
    if (in_r8 == -1) {
      FUN_8003b9ec((int)psVar1);
      FUN_80038524(psVar1,3,(float *)(iVar2 + 0xae8),(undefined4 *)(iVar2 + 0xaec),
                   (float *)(iVar2 + 0xaf0),0);
    }
    if ((*(char *)(iVar2 + 0xbb2) != '\x02') && (in_r8 != '\0')) {
      FUN_8003b9ec((int)psVar1);
      FUN_80115088(psVar1,iVar2 + 0x4c4,0);
    }
  }
  FUN_80286884();
  return;
}

