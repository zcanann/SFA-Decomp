// Function: FUN_80242f78
// Entry: 80242f78
// Size: 140 bytes

void FUN_80242f78(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  while (0 < param_2) {
    iVar2 = param_2;
    if (0x100 < param_2) {
      iVar2 = 0x100;
    }
    param_2 = param_2 - iVar2;
    do {
      iVar1 = FUN_802455a0(param_1,iVar2,param_3);
    } while (iVar1 == 0);
    param_3 = param_3 + iVar2;
    param_1 = param_1 + iVar2;
  }
  return;
}

