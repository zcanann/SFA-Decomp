// Function: FUN_80043070
// Entry: 80043070
// Size: 188 bytes

int FUN_80043070(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  if (param_9 < 0x4b) {
    iVar3 = (&DAT_802cc8a8)[param_9];
  }
  else {
    iVar3 = 5;
  }
  iVar2 = (int)*(short *)(&DAT_802cc9d4 + iVar3 * 2);
  if (iVar2 != -1) {
    if (DAT_803601f2 == iVar2) {
      iVar1 = 0;
    }
    else if (DAT_80360236 == iVar2) {
      iVar1 = 1;
    }
    else {
      iVar1 = -1;
    }
    if (iVar1 == -1) {
      FUN_80042f6c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2);
      return iVar2;
    }
  }
  FUN_80042f6c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar3);
  return iVar3;
}

