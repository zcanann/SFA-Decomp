// Function: FUN_80119724
// Entry: 80119724
// Size: 68 bytes

undefined4 FUN_80119724(undefined4 param_1)

{
  int iVar1;
  undefined4 local_8 [2];
  
  iVar1 = FUN_80244128(&DAT_803a7308,local_8,param_1);
  if (iVar1 != 1) {
    local_8[0] = 0;
  }
  return local_8[0];
}

