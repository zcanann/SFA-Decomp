// Function: FUN_8017d278
// Entry: 8017d278
// Size: 252 bytes

void FUN_8017d278(short *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  
  pcVar4 = *(char **)(param_1 + 0x5c);
  *param_1 = (ushort)*(byte *)(param_2 + 0x38) << 8;
  *(code **)(param_1 + 0x5e) = FUN_8017cf90;
  param_1[0x58] = param_1[0x58] | 0x6000;
  FUN_80037200(param_1,0xf);
  iVar2 = 0;
  iVar3 = param_2;
  do {
    if ((*(short *)(iVar3 + 0x18) == -1) || (iVar1 = FUN_8001ffb4(), iVar1 == 0)) break;
    iVar3 = iVar3 + 2;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 8);
  if ((iVar2 < 8) && (*(short *)(param_2 + iVar2 * 2 + 0x18) == -1)) {
    *pcVar4 = '\b';
  }
  else {
    *pcVar4 = (char)iVar2;
  }
  if ((*pcVar4 == '\b') && ((*(byte *)(param_2 + 0x39) & 0x10) != 0)) {
    *pcVar4 = '\t';
  }
  return;
}

