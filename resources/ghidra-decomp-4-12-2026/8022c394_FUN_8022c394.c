// Function: FUN_8022c394
// Entry: 8022c394
// Size: 324 bytes

void FUN_8022c394(undefined4 param_1,int param_2)

{
  byte bVar1;
  undefined local_28 [4];
  undefined auStack_24 [6];
  undefined2 local_1e;
  float local_1c;
  float local_18;
  float local_14;
  float local_10;
  
  local_28[0] = 0;
  if (*(char *)(param_2 + 0x468) < '\x05') {
    bVar1 = *(byte *)(param_2 + 0x476);
    *(byte *)(param_2 + 0x476) = bVar1 + 1;
    if ((bVar1 & 1) != 0) {
      local_1c = FLOAT_803e7ba0;
      local_18 = FLOAT_803e7ba4;
      local_14 = FLOAT_803e7ba8;
      local_10 = FLOAT_803e7bac;
      if (*(char *)(param_2 + 0x468) < '\x03') {
        local_1e = 25000;
      }
      else {
        local_1e = 40000;
      }
      (**(code **)(*DAT_803dd708 + 8))(param_1,2000,auStack_24,4,0xffffffff,local_28);
    }
  }
  if (*(char *)(param_2 + 0x468) < '\x03') {
    local_1c = FLOAT_803e7bb0;
    local_1e = 0xc0a;
    local_18 = FLOAT_803e7b64;
    local_14 = FLOAT_803e7bb4;
    local_10 = FLOAT_803e7bb8;
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x7d1,auStack_24,4,0xffffffff,local_28);
  }
  return;
}

