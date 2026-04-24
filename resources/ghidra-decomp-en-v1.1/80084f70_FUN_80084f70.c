// Function: FUN_80084f70
// Entry: 80084f70
// Size: 220 bytes

void FUN_80084f70(void)

{
  int iVar1;
  int iVar2;
  char *pcVar3;
  int iVar4;
  
  iVar1 = FUN_80286840();
  for (iVar4 = 0; iVar4 < *(short *)(iVar1 + 0x62); iVar4 = iVar4 + 1) {
    pcVar3 = (char *)(*(int *)(iVar1 + 0x94) + iVar4 * 4);
    if (((*pcVar3 != '\0') && (*pcVar3 == '\v')) && (0 < *(short *)(pcVar3 + 2))) {
      if (((*(uint *)(pcVar3 + 4) & 0x3f) == 4) &&
         (iVar2 = FUN_80083e7c(*(uint *)(pcVar3 + 4) >> 6 & 0x3ff,iVar1), iVar2 != 0)) break;
      iVar4 = iVar4 + *(short *)(pcVar3 + 2);
    }
  }
  FUN_8028688c();
  return;
}

