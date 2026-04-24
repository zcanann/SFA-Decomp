// Function: FUN_80296afc
// Entry: 80296afc
// Size: 116 bytes

void FUN_80296afc(int param_1,int param_2)

{
  char *pcVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  pcVar1 = *(char **)(iVar2 + 0x35c);
  param_2 = *pcVar1 + param_2;
  if (param_2 < 0) {
    param_2 = 0;
  }
  else if (pcVar1[1] < param_2) {
    param_2 = (int)pcVar1[1];
  }
  *pcVar1 = (char)param_2;
  if (**(char **)(iVar2 + 0x35c) < '\x01') {
    FUN_802aaa80();
  }
  return;
}

