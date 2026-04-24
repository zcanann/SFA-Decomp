// Function: FUN_8028e304
// Entry: 8028e304
// Size: 232 bytes

void FUN_8028e304(undefined *param_1,char *param_2,undefined2 param_3)

{
  int iVar1;
  byte *pbVar2;
  int iVar3;
  
  *(undefined2 *)(param_1 + 2) = param_3;
  iVar3 = 0;
  *param_1 = 0;
  for (; (iVar3 < 0x24 && (*param_2 != '\0')); param_2 = param_2 + 1) {
    iVar1 = iVar3 + 5;
    iVar3 = iVar3 + 1;
    param_1[iVar1] = *param_2 + -0x30;
  }
  param_1[4] = (char)iVar3;
  if (*param_2 == '\0') {
    return;
  }
  if (*param_2 < '\x05') {
    return;
  }
  do {
    param_2 = param_2 + 1;
    if (*param_2 == '\0') {
      if ((param_1[iVar3 + 4] & 1) == 0) {
        return;
      }
      break;
    }
  } while (*param_2 == '0');
  pbVar2 = param_1 + 5 + ((byte)param_1[4] - 1);
  while( true ) {
    if (*pbVar2 < 9) {
      *pbVar2 = *pbVar2 + 1;
      return;
    }
    if (pbVar2 == param_1 + 5) break;
    *pbVar2 = 0;
    pbVar2 = pbVar2 + -1;
  }
  *pbVar2 = 1;
  *(short *)(param_1 + 2) = *(short *)(param_1 + 2) + 1;
  return;
}

