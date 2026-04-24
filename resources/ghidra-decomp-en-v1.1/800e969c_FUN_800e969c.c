// Function: FUN_800e969c
// Entry: 800e969c
// Size: 296 bytes

void FUN_800e969c(void)

{
  char *pcVar1;
  int iVar2;
  
  pcVar1 = &DAT_803a3be0;
  iVar2 = 4;
  do {
    if ((*pcVar1 != -1) && (pcVar1[2] = pcVar1[2] + -1, pcVar1[2] < '\x01')) {
      *pcVar1 = -1;
    }
    if ((pcVar1[3] != -1) && (pcVar1[5] = pcVar1[5] + -1, pcVar1[5] < '\x01')) {
      pcVar1[3] = -1;
    }
    if ((pcVar1[6] != -1) && (pcVar1[8] = pcVar1[8] + -1, pcVar1[8] < '\x01')) {
      pcVar1[6] = -1;
    }
    if ((pcVar1[9] != -1) && (pcVar1[0xb] = pcVar1[0xb] + -1, pcVar1[0xb] < '\x01')) {
      pcVar1[9] = -1;
    }
    if ((pcVar1[0xc] != -1) && (pcVar1[0xe] = pcVar1[0xe] + -1, pcVar1[0xe] < '\x01')) {
      pcVar1[0xc] = -1;
    }
    pcVar1 = pcVar1 + 0xf;
    iVar2 = iVar2 + -1;
  } while (iVar2 != 0);
  return;
}

