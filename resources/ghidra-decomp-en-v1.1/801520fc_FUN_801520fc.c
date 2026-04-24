// Function: FUN_801520fc
// Entry: 801520fc
// Size: 336 bytes

void FUN_801520fc(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  int iVar3;
  
  iVar1 = FUN_8002bac4();
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar2 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x1be);
  if (iVar2 == 0) {
    FUN_8011f670(2);
    *(undefined2 *)(param_2 + 0x338) = DAT_803dc908;
    (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
  }
  else if ((iVar1 == 0) || (iVar2 = FUN_80296ffc(iVar1), iVar2 < 0x19)) {
    FUN_8011f670(2);
    *(undefined2 *)(param_2 + 0x338) = uRam803dc90a;
    (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_1,0xffffffff);
  }
  else {
    FUN_8029700c(iVar1,-0x19);
    FUN_800201ac((int)*(short *)(iVar3 + 0x1c),1);
    *(undefined2 *)(param_2 + 0x338) = uRam803dc90c;
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_8011f670(2);
    (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_1,0xffffffff);
  }
  return;
}

