// Function: FUN_80287d5c
// Entry: 80287d5c
// Size: 132 bytes

undefined4 FUN_80287d5c(undefined4 param_1)

{
  undefined4 uVar1;
  byte local_18 [16];
  
  uVar1 = 0x500;
  FUN_802876c8(param_1,0);
  FUN_802872c8(param_1,local_18);
  if (local_18[0] < DAT_803d82e8) {
    uVar1 = (*(code *)(&PTR_FUN_80332230)[local_18[0]])(param_1);
  }
  return uVar1;
}

