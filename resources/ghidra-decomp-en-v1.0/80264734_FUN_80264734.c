// Function: FUN_80264734
// Entry: 80264734
// Size: 316 bytes

undefined4 FUN_80264734(void)

{
  char cVar1;
  int iVar2;
  char *pcVar3;
  undefined *puVar4;
  int iVar5;
  byte bVar6;
  
  *(int *)(DAT_803de210 + 0x69c) = *(int *)(DAT_803de210 + 0x69c) + 2;
  pcVar3 = *(char **)(DAT_803de210 + 0x69c);
  *(char **)(DAT_803de210 + 0x69c) = pcVar3 + 1;
  if (*pcVar3 != '\b') {
    return 10;
  }
  *(undefined2 *)(DAT_803de210 + 0x694) = **(undefined2 **)(DAT_803de210 + 0x69c);
  *(int *)(DAT_803de210 + 0x69c) = *(int *)(DAT_803de210 + 0x69c) + 2;
  *(undefined2 *)(DAT_803de210 + 0x692) = **(undefined2 **)(DAT_803de210 + 0x69c);
  *(int *)(DAT_803de210 + 0x69c) = *(int *)(DAT_803de210 + 0x69c) + 2;
  pcVar3 = *(char **)(DAT_803de210 + 0x69c);
  *(char **)(DAT_803de210 + 0x69c) = pcVar3 + 1;
  if (*pcVar3 != '\x03') {
    return 0xc;
  }
  bVar6 = 0;
  iVar5 = 0;
  while( true ) {
    if (2 < bVar6) {
      return 0;
    }
    *(int *)(DAT_803de210 + 0x69c) = *(int *)(DAT_803de210 + 0x69c) + 1;
    pcVar3 = *(char **)(DAT_803de210 + 0x69c);
    *(char **)(DAT_803de210 + 0x69c) = pcVar3 + 1;
    cVar1 = *pcVar3;
    if (((bVar6 == 0) && (cVar1 != '\"')) || ((bVar6 != 0 && (cVar1 != '\x11')))) break;
    iVar2 = iVar5 + 0x680;
    iVar5 = iVar5 + 6;
    puVar4 = *(undefined **)(DAT_803de210 + 0x69c);
    bVar6 = bVar6 + 1;
    *(undefined **)(DAT_803de210 + 0x69c) = puVar4 + 1;
    *(undefined *)(DAT_803de210 + iVar2) = *puVar4;
  }
  return 0x13;
}

