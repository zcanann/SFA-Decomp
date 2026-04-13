// Function: FUN_802870dc
// Entry: 802870dc
// Size: 24 bytes

void FUN_802870dc(undefined *param_1,undefined param_2)

{
  *param_1 = param_2;
  *(undefined4 *)(param_1 + 4) = 0;
  *(undefined4 *)(param_1 + 8) = 0xffffffff;
  return;
}

