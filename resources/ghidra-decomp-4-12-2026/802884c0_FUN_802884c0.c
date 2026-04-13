// Function: FUN_802884c0
// Entry: 802884c0
// Size: 132 bytes

undefined4 FUN_802884c0(int param_1)

{
  undefined4 uVar1;
  byte local_18 [16];
  
  uVar1 = 0x500;
  FUN_80287e2c(param_1,0);
  FUN_80287a2c(param_1,(int)local_18);
  if (local_18[0] < DAT_803d8f48) {
    uVar1 = (*(code *)(&PTR_FUN_80332e90)[local_18[0]])(param_1);
  }
  return uVar1;
}

