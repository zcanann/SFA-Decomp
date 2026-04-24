// Function: FUN_80114420
// Entry: 80114420
// Size: 160 bytes

undefined4 FUN_80114420(int param_1,undefined2 *param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  if (param_1 < 0x1c) {
    iVar2 = (**(code **)(*DAT_803dd71c + 0x40))();
    if (iVar2 < 0) {
      uVar1 = 0;
    }
    else {
      iVar2 = (**(code **)(*DAT_803dd71c + 0x1c))();
      *(undefined4 *)(param_2 + 6) = *(undefined4 *)(iVar2 + 8);
      *(undefined4 *)(param_2 + 8) = *(undefined4 *)(iVar2 + 0xc);
      *(undefined4 *)(param_2 + 10) = *(undefined4 *)(iVar2 + 0x10);
      *param_2 = (short)((int)*(char *)(iVar2 + 0x2c) << 8);
      uVar1 = 1;
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

