// Function: FUN_800e97c4
// Entry: 800e97c4
// Size: 252 bytes

int FUN_800e97c4(int param_1,uint param_2)

{
  char *pcVar1;
  char cVar2;
  int iVar3;
  
  cVar2 = '\0';
  pcVar1 = &DAT_803a3be0;
  iVar3 = 4;
  while( true ) {
    if ((param_1 == *pcVar1) && (param_2 == (byte)pcVar1[1])) {
      return (int)cVar2;
    }
    if ((param_1 == pcVar1[3]) && (param_2 == (byte)pcVar1[4])) {
      return (int)(char)(cVar2 + '\x01');
    }
    if ((param_1 == pcVar1[6]) && (param_2 == (byte)pcVar1[7])) {
      return (int)(char)(cVar2 + '\x02');
    }
    if ((param_1 == pcVar1[9]) && (param_2 == (byte)pcVar1[10])) break;
    if ((param_1 == pcVar1[0xc]) && (param_2 == (byte)pcVar1[0xd])) {
      return (int)(char)(cVar2 + '\x04');
    }
    pcVar1 = pcVar1 + 0xf;
    cVar2 = cVar2 + '\x05';
    iVar3 = iVar3 + -1;
    if (iVar3 == 0) {
      return -1;
    }
  }
  return (int)(char)(cVar2 + '\x03');
}

