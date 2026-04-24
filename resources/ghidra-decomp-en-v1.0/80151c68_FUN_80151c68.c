// Function: FUN_80151c68
// Entry: 80151c68
// Size: 336 bytes

void FUN_80151c68(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = FUN_8002b9ec();
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar2 = (**(code **)(*DAT_803dca68 + 0x20))(0x1be);
  if (iVar2 == 0) {
    FUN_8011f38c(2);
    *(undefined2 *)(param_2 + 0x338) = DAT_803dbca0;
    (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
  }
  else if ((iVar1 == 0) || (iVar2 = FUN_8029689c(iVar1), iVar2 < 0x19)) {
    FUN_8011f38c(2);
    *(undefined2 *)(param_2 + 0x338) = uRam803dbca2;
    (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
  }
  else {
    FUN_802968ac(iVar1,0xffffffe7);
    FUN_800200e8((int)*(short *)(iVar3 + 0x1c),1);
    *(undefined2 *)(param_2 + 0x338) = uRam803dbca4;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_8011f38c(2);
    (**(code **)(*DAT_803dca54 + 0x48))(2,param_1,0xffffffff);
  }
  return;
}

