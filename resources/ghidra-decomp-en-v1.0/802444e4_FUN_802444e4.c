// Function: FUN_802444e4
// Entry: 802444e4
// Size: 112 bytes

void FUN_802444e4(int param_1)

{
  int iVar1;
  int iVar2;
  
  while (iVar1 = *(int *)(param_1 + 0x2f4), iVar1 != 0) {
    iVar2 = *(int *)(iVar1 + 0x10);
    if (iVar2 == 0) {
      *(undefined4 *)(param_1 + 0x2f8) = 0;
    }
    else {
      *(undefined4 *)(iVar2 + 0x14) = 0;
    }
    *(int *)(param_1 + 0x2f4) = iVar2;
    *(undefined4 *)(iVar1 + 0xc) = 0;
    *(undefined4 *)(iVar1 + 8) = 0;
    FUN_80246b4c(iVar1);
  }
  return;
}

