// Function: FUN_802114ac
// Entry: 802114ac
// Size: 80 bytes

void FUN_802114ac(int param_1)

{
  undefined *puVar1;
  
  puVar1 = *(undefined **)(param_1 + 0xb8);
  FUN_800372f8(param_1,0x1e);
  *puVar1 = 1;
  *(undefined **)(param_1 + 0xbc) = &LAB_80211260;
  return;
}

