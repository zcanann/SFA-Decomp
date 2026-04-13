// Function: FUN_802967bc
// Entry: 802967bc
// Size: 136 bytes

undefined4 FUN_802967bc(int param_1,undefined4 *param_2,undefined4 *param_3)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((iVar3 == 0) || (iVar1 = FUN_80080490(), iVar1 != 0)) {
    uVar2 = 0;
  }
  else if ((*(uint *)(iVar3 + 0x360) & 0x400) == 0) {
    uVar2 = 0;
  }
  else {
    *param_2 = *(undefined4 *)(iVar3 + 0x788);
    *param_3 = *(undefined4 *)(iVar3 + 0x78c);
    uVar2 = 1;
  }
  return uVar2;
}

