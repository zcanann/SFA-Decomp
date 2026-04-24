// Function: FUN_801ece40
// Entry: 801ece40
// Size: 132 bytes

void FUN_801ece40(int param_1)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  FUN_80036fa4(param_1,10);
  iVar2 = 0;
  iVar3 = iVar1;
  do {
    FUN_80023800(*(undefined4 *)(iVar3 + 0x4c8));
    iVar3 = iVar3 + 8;
    iVar2 = iVar2 + 1;
  } while (iVar2 < 9);
  if ((*(byte *)(iVar1 + 0x428) >> 5 & 1) != 0) {
    (**(code **)(*DAT_803dca68 + 0x60))();
  }
  return;
}

