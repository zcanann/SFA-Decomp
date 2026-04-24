// Function: FUN_8011730c
// Entry: 8011730c
// Size: 68 bytes

undefined4 FUN_8011730c(undefined4 param_1)

{
  int iVar1;
  undefined4 local_8 [2];
  
  iVar1 = FUN_80244128(&DAT_803a4460,local_8,param_1);
  if (iVar1 != 1) {
    local_8[0] = 0;
  }
  return local_8[0];
}

