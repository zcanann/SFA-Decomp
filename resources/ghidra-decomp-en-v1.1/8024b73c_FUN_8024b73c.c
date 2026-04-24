// Function: FUN_8024b73c
// Entry: 8024b73c
// Size: 188 bytes

undefined4 FUN_8024b73c(undefined4 *param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uVar2;
  
  param_1[2] = 7;
  param_1[10] = param_2;
  if ((DAT_803dd1d0 != 0) &&
     (((iVar1 = param_1[2], iVar1 == 1 || (iVar1 - 4U < 2)) || (iVar1 == 0xe)))) {
    FUN_802420b0(param_1[6],param_1[5]);
  }
  FUN_80243e74();
  param_1[3] = 2;
  uVar2 = FUN_8024c10c(1,param_1);
  if ((DAT_803deb88 == 0) && (DAT_803deb94 == 0)) {
    FUN_8024a91c();
  }
  FUN_80243e9c();
  return uVar2;
}

