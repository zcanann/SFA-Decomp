// Function: FUN_8024bb68
// Entry: 8024bb68
// Size: 284 bytes

char FUN_8024bb68(uint param_1)

{
  uint *puVar1;
  char cVar2;
  int iVar3;
  
  iVar3 = 2;
  puVar1 = &DAT_8032dd38;
  cVar2 = '\0';
  while( true ) {
    if (param_1 == *puVar1) {
      return cVar2;
    }
    if (param_1 == puVar1[1]) {
      return cVar2 + '\x01';
    }
    if (param_1 == puVar1[2]) {
      return cVar2 + '\x02';
    }
    if (param_1 == puVar1[3]) {
      return cVar2 + '\x03';
    }
    if (param_1 == puVar1[4]) {
      return cVar2 + '\x04';
    }
    if (param_1 == puVar1[5]) {
      return cVar2 + '\x05';
    }
    if (param_1 == puVar1[6]) {
      return cVar2 + '\x06';
    }
    if (param_1 == puVar1[7]) break;
    if (param_1 == puVar1[8]) {
      return cVar2 + '\b';
    }
    puVar1 = puVar1 + 9;
    cVar2 = cVar2 + '\t';
    iVar3 = iVar3 + -1;
    if (iVar3 == 0) {
      if ((0xfffff < param_1) && (param_1 < 0x100009)) {
        return '\x11';
      }
      return '\x1d';
    }
  }
  return cVar2 + '\a';
}

