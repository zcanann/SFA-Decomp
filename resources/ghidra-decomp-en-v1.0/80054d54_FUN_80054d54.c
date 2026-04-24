// Function: FUN_80054d54
// Entry: 80054d54
// Size: 92 bytes

undefined4 FUN_80054d54(undefined4 param_1)

{
  uint uVar1;
  undefined4 local_18 [5];
  
  local_18[0] = 0;
  uVar1 = FUN_800430ac(0);
  if ((uVar1 & 0x100000) == 0) {
    FUN_8001f6d8(local_18,param_1);
  }
  else {
    local_18[0] = 0;
  }
  return local_18[0];
}

