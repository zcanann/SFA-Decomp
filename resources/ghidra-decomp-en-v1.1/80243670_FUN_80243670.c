// Function: FUN_80243670
// Entry: 80243670
// Size: 140 bytes

void FUN_80243670(uint param_1,int param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  
  while (0 < param_2) {
    iVar2 = param_2;
    if (0x100 < param_2) {
      iVar2 = 0x100;
    }
    param_2 = param_2 - iVar2;
    do {
      uVar1 = FUN_80245c98(param_1,iVar2,param_3);
    } while (uVar1 == 0);
    param_3 = param_3 + iVar2;
    param_1 = param_1 + iVar2;
  }
  return;
}

