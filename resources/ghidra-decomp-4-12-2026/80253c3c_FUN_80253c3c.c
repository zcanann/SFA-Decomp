// Function: FUN_80253c3c
// Entry: 80253c3c
// Size: 160 bytes

undefined4 FUN_80253c3c(int param_1,byte *param_2,int param_3,int param_4)

{
  int iVar1;
  int iVar2;
  
  while( true ) {
    if (param_3 == 0) {
      return 1;
    }
    iVar2 = param_3;
    if (3 < param_3) {
      iVar2 = 4;
    }
    iVar1 = FUN_802539e0(param_1,param_2,iVar2,param_4,0);
    if (iVar1 == 0) break;
    iVar1 = FUN_80253dc8(param_1);
    if (iVar1 == 0) {
      return 0;
    }
    param_2 = param_2 + iVar2;
    param_3 = param_3 - iVar2;
  }
  return 0;
}

