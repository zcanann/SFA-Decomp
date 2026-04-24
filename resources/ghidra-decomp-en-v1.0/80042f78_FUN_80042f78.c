// Function: FUN_80042f78
// Entry: 80042f78
// Size: 188 bytes

int FUN_80042f78(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (param_1 < 0x4b) {
    iVar3 = (&DAT_802cbcd0)[param_1];
  }
  else {
    iVar3 = 5;
  }
  iVar2 = (int)*(short *)(&DAT_802cbdfc + iVar3 * 2);
  if (iVar2 != -1) {
    if (DAT_8035f592 == iVar2) {
      iVar1 = 0;
    }
    else if (DAT_8035f5d6 == iVar2) {
      iVar1 = 1;
    }
    else {
      iVar1 = -1;
    }
    if (iVar1 == -1) {
      FUN_80042e74(iVar2);
      return iVar2;
    }
  }
  FUN_80042e74(iVar3);
  return iVar3;
}

