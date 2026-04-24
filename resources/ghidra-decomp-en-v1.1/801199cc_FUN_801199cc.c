// Function: FUN_801199cc
// Entry: 801199cc
// Size: 68 bytes

undefined4 FUN_801199cc(uint param_1)

{
  int iVar1;
  undefined4 local_8 [2];
  
  iVar1 = FUN_80244820((int *)&DAT_803a7f68,local_8,param_1);
  if (iVar1 != 1) {
    local_8[0] = 0;
  }
  return local_8[0];
}

