// Function: FUN_802493ec
// Entry: 802493ec
// Size: 352 bytes

int FUN_802493ec(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  char *pcVar3;
  char *pcVar4;
  char *pcVar5;
  
  if (param_1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar1 = *(int *)(DAT_803deb6c + 4 + param_1 * 0xc);
    pcVar5 = (char *)(DAT_803deb70 + (*(uint *)(DAT_803deb6c + param_1 * 0xc) & 0xffffff));
    if (iVar1 == 0) {
      iVar1 = 0;
    }
    else {
      iVar1 = iVar1 * 0xc;
      pcVar4 = (char *)(DAT_803deb70 + (*(uint *)(DAT_803deb6c + iVar1) & 0xffffff));
      iVar1 = FUN_802493ec(*(int *)(DAT_803deb6c + 4 + iVar1),param_2,param_3);
      if (iVar1 != param_3) {
        iVar2 = iVar1 + 1;
        *(undefined *)(param_2 + iVar1) = 0x2f;
        pcVar3 = (char *)(param_2 + iVar2);
        iVar1 = param_3 - iVar2;
        for (; (iVar1 != 0 && (*pcVar4 != '\0')); pcVar4 = pcVar4 + 1) {
          iVar1 = iVar1 + -1;
          *pcVar3 = *pcVar4;
          pcVar3 = pcVar3 + 1;
        }
        iVar1 = iVar2 + ((param_3 - iVar2) - iVar1);
      }
    }
    if (iVar1 != param_3) {
      iVar2 = iVar1 + 1;
      *(undefined *)(param_2 + iVar1) = 0x2f;
      pcVar4 = (char *)(param_2 + iVar2);
      iVar1 = param_3 - iVar2;
      for (; (iVar1 != 0 && (*pcVar5 != '\0')); pcVar5 = pcVar5 + 1) {
        iVar1 = iVar1 + -1;
        *pcVar4 = *pcVar5;
        pcVar4 = pcVar4 + 1;
      }
      iVar1 = iVar2 + ((param_3 - iVar2) - iVar1);
    }
  }
  return iVar1;
}

