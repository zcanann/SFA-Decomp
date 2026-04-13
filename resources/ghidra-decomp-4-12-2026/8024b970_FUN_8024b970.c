// Function: FUN_8024b970
// Entry: 8024b970
// Size: 208 bytes

undefined4 FUN_8024b970(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 uVar2;
  
  param_1[2] = 0xe;
  param_1[6] = param_2;
  param_1[5] = 0x20;
  param_1[8] = 0;
  param_1[10] = param_3;
  if ((DAT_803dd1d0 != 0) &&
     (((iVar1 = param_1[2], iVar1 == 1 || (iVar1 - 4U < 2)) || (iVar1 == 0xe)))) {
    FUN_802420b0(param_1[6],param_1[5]);
  }
  FUN_80243e74();
  param_1[3] = 2;
  uVar2 = FUN_8024c10c(2,param_1);
  if ((DAT_803deb88 == 0) && (DAT_803deb94 == 0)) {
    FUN_8024a91c();
  }
  FUN_80243e9c();
  return uVar2;
}

