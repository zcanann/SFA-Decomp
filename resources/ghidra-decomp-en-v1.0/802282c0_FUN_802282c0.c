// Function: FUN_802282c0
// Entry: 802282c0
// Size: 180 bytes

void FUN_802282c0(int param_1)

{
  int iVar1;
  
  if ((*(int *)(param_1 + 0xf4) != 0) && (iVar1 = FUN_800221a0(0,5), iVar1 == 0)) {
    if (*(char *)(param_1 + 0xad) == '\0') {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x73f,0,2,0xffffffff,param_1);
    }
    else {
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x740,0,2,0xffffffff,param_1);
    }
  }
  return;
}

