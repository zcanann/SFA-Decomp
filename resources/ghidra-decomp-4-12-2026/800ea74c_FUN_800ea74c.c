// Function: FUN_800ea74c
// Entry: 800ea74c
// Size: 260 bytes

void FUN_800ea74c(void)

{
  bool bVar1;
  undefined *puVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar5;
  char *pcVar6;
  
  iVar3 = 0xd;
  puVar2 = (undefined *)0x803a4e85;
  while( true ) {
    puVar2 = puVar2 + -1;
    bVar1 = iVar3 == 0;
    iVar3 = iVar3 + -1;
    if (bVar1) break;
    *puVar2 = 0xff;
  }
  iVar3 = 0x49;
  puVar5 = (undefined4 *)0x802c7b40;
  while( true ) {
    puVar5 = puVar5 + -1;
    bVar1 = iVar3 == 0;
    iVar3 = iVar3 + -1;
    if (bVar1) break;
    pcVar6 = (char *)*puVar5;
    if ((((((*pcVar6 == 'T') && (pcVar6[1] == 'a')) && (pcVar6[2] == 's')) &&
         ((pcVar6[3] == 'k' && (pcVar6[4] == 'T')))) &&
        ((pcVar6[5] == 'e' && ((pcVar6[6] == 'x' && (pcVar6[7] == 't')))))) &&
       ((pcVar6[8] == 's' &&
        (iVar4 = ((byte)pcVar6[9] - 0x30) * 100 + ((byte)pcVar6[10] - 0x30) * 10 +
                 (uint)(byte)pcVar6[0xb], iVar4 + -0x30 < 0xd)))) {
      (&DAT_803a4e48)[iVar4] = (char)iVar3;
    }
  }
  return;
}

