// Function: FUN_80065780
// Entry: 80065780
// Size: 60 bytes

void FUN_80065780(void)

{
  char cVar1;
  int iVar2;
  short sVar3;
  
  sVar3 = 0;
  iVar2 = 0;
  do {
    cVar1 = *(char *)(DAT_803ddbc8 + iVar2 + 0x14);
    if (cVar1 != '\0') {
      *(char *)(DAT_803ddbc8 + iVar2 + 0x14) = cVar1 + -1;
    }
    iVar2 = iVar2 + 0x18;
    sVar3 = sVar3 + 1;
  } while (sVar3 < 0x40);
  return;
}

