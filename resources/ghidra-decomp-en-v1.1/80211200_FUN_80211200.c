// Function: FUN_80211200
// Entry: 80211200
// Size: 88 bytes

void FUN_80211200(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_80210ff8;
  *(undefined *)(iVar1 + 8) = 2;
  FUN_800803f8((undefined4 *)(iVar1 + 4));
  FUN_800201ac(0xe24,1);
  FUN_8000a3a0(3,2,1000);
  return;
}

