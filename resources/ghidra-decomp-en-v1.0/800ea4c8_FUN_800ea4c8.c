// Function: FUN_800ea4c8
// Entry: 800ea4c8
// Size: 260 bytes

void FUN_800ea4c8(void)

{
  bool bVar1;
  undefined *puVar2;
  int iVar3;
  int iVar4;
  char **ppcVar5;
  char *pcVar6;
  
  iVar3 = 0xd;
  puVar2 = (undefined *)0x803a4225;
  while( true ) {
    puVar2 = puVar2 + -1;
    bVar1 = iVar3 == 0;
    iVar3 = iVar3 + -1;
    if (bVar1) break;
    *puVar2 = 0xff;
  }
  iVar3 = 0x49;
  ppcVar5 = (char **)0x802c73c0;
  while( true ) {
    ppcVar5 = ppcVar5 + -1;
    bVar1 = iVar3 == 0;
    iVar3 = iVar3 + -1;
    if (bVar1) break;
    pcVar6 = *ppcVar5;
    if ((((((*pcVar6 == 'T') && (pcVar6[1] == 'a')) && (pcVar6[2] == 's')) &&
         ((pcVar6[3] == 'k' && (pcVar6[4] == 'T')))) &&
        ((pcVar6[5] == 'e' && ((pcVar6[6] == 'x' && (pcVar6[7] == 't')))))) &&
       ((pcVar6[8] == 's' &&
        (iVar4 = ((byte)pcVar6[9] - 0x30) * 100 + ((byte)pcVar6[10] - 0x30) * 10 +
                 (uint)(byte)pcVar6[0xb], iVar4 + -0x30 < 0xd)))) {
      (&DAT_803a41e8)[iVar4] = (char)iVar3;
    }
  }
  return;
}

