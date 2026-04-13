// Function: FUN_802634f8
// Entry: 802634f8
// Size: 152 bytes

undefined4 FUN_802634f8(int param_1,char *param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  if (*param_2 == -1) {
    uVar1 = 0xfffffffc;
  }
  else if ((*(undefined **)(param_1 + 0x10c) == &DAT_803b0060) ||
          ((iVar2 = FUN_8028f988((int)param_2,(int)*(undefined **)(param_1 + 0x10c),4), iVar2 == 0
           && (iVar2 = FUN_8028f988((int)(param_2 + 4),*(int *)(param_1 + 0x10c) + 4,2), iVar2 == 0)
           ))) {
    uVar1 = 0;
  }
  else {
    uVar1 = 0xfffffff6;
  }
  return uVar1;
}

