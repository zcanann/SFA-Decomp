// Function: FUN_80282194
// Entry: 80282194
// Size: 244 bytes

void FUN_80282194(uint param_1,uint param_2,int param_3)

{
  char *pcVar1;
  char *pcVar2;
  int iVar3;
  
  if (param_3 == 0) {
    pcVar2 = (char *)0x802c2f18;
  }
  else {
    pcVar2 = &DAT_802c2e90;
  }
  if ((param_2 & 0xff) == 0xff) {
    pcVar1 = (char *)((param_1 & 0xff) * 0x86 + -0x7fc2d880);
  }
  else {
    pcVar1 = (char *)((param_2 & 0xff) * 0x860 + -0x7fc31b80 + (param_1 & 0xff) * 0x86);
  }
  if (param_3 == 0) {
    iVar3 = 0x43;
    do {
      if (*pcVar2 != -1) {
        *pcVar1 = *pcVar2;
      }
      if (pcVar2[1] != -1) {
        pcVar1[1] = pcVar2[1];
      }
      pcVar1 = pcVar1 + 2;
      pcVar2 = pcVar2 + 2;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  else {
    FUN_80003494((uint)pcVar1,(uint)pcVar2,0x86);
  }
  FUN_8028274c(param_1,param_2,0xff);
  return;
}

