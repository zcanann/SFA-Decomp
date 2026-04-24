// Function: FUN_80131f0c
// Entry: 80131f0c
// Size: 116 bytes

void FUN_80131f0c(void)

{
  int iVar1;
  int iVar2;
  short *psVar3;
  int *piVar4;
  
  iVar2 = 0;
  piVar4 = &DAT_803a9db8;
  psVar3 = &DAT_8031c2a8;
  do {
    if (*piVar4 == 0) {
      iVar1 = FUN_80054d54((int)*psVar3);
      *piVar4 = iVar1;
    }
    piVar4 = piVar4 + 1;
    psVar3 = psVar3 + 1;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 6);
  return;
}

