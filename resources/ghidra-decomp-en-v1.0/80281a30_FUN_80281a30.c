// Function: FUN_80281a30
// Entry: 80281a30
// Size: 244 bytes

void FUN_80281a30(uint param_1,uint param_2,int param_3)

{
  char *pcVar1;
  char *pcVar2;
  int iVar3;
  
  if (param_3 == 0) {
    pcVar2 = (char *)0x802c2798;
  }
  else {
    pcVar2 = &DAT_802c2710;
  }
  if ((param_2 & 0xff) == 0xff) {
    pcVar1 = (char *)((param_1 & 0xff) * 0x86 + -0x7fc2e4e0);
  }
  else {
    pcVar1 = (char *)((param_2 & 0xff) * 0x860 + -0x7fc327e0 + (param_1 & 0xff) * 0x86);
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
    FUN_80003494(pcVar1,pcVar2,0x86);
  }
  FUN_80281fe8(param_1,param_2,0xff);
  return;
}

