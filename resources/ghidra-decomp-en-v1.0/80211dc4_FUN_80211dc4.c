// Function: FUN_80211dc4
// Entry: 80211dc4
// Size: 168 bytes

void FUN_80211dc4(int param_1)

{
  if (*(int *)(param_1 + 0xf4) == 0) {
    FUN_80088c94(7,1);
    FUN_80008cbc(param_1,param_1,399,0);
    FUN_80008cbc(param_1,param_1,0x18e,0);
    FUN_80008cbc(param_1,param_1,400,0);
    FUN_80088e54((double)FLOAT_803e67a4,1);
    FUN_800200e8(0x55e,1);
    *(undefined4 *)(param_1 + 0xf4) = 1;
  }
  DAT_803ddd40 = FUN_8001ffb4(0x572);
  return;
}

