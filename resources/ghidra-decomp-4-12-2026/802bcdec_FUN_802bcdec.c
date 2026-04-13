// Function: FUN_802bcdec
// Entry: 802bcdec
// Size: 192 bytes

void FUN_802bcdec(undefined2 *param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *(code **)(param_1 + 0x5e) = FUN_802bcb60;
  iVar2 = *(int *)(param_1 + 0x5c);
  iVar1 = *(int *)(param_1 + 0x32);
  if (iVar1 != 0) {
    *(uint *)(iVar1 + 0x30) = *(uint *)(iVar1 + 0x30) | 0xa10;
    *(uint *)(*(int *)(param_1 + 0x32) + 0x30) = *(uint *)(*(int *)(param_1 + 0x32) + 0x30) | 0x8020
    ;
  }
  (**(code **)(*DAT_803dd70c + 4))(param_1,iVar2,4,1);
  *(undefined *)(iVar2 + 0x25f) = 0;
  param_1[0x58] = param_1[0x58] | 0x2000;
  return;
}

