// Function: FUN_8022bcd0
// Entry: 8022bcd0
// Size: 324 bytes

void FUN_8022bcd0(undefined4 param_1,int param_2)

{
  byte bVar1;
  undefined local_28 [4];
  undefined auStack36 [6];
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
      local_1c = FLOAT_803e6f08;
      local_18 = FLOAT_803e6f0c;
      local_14 = FLOAT_803e6f10;
      local_10 = FLOAT_803e6f14;
      if (*(char *)(param_2 + 0x468) < '\x03') {
        local_1e = 25000;
      }
      else {
        local_1e = 40000;
      }
      (**(code **)(*DAT_803dca88 + 8))(param_1,2000,auStack36,4,0xffffffff,local_28);
    }
  }
  if (*(char *)(param_2 + 0x468) < '\x03') {
    local_1c = FLOAT_803e6f18;
    local_1e = 0xc0a;
    local_18 = FLOAT_803e6ecc;
    local_14 = FLOAT_803e6f1c;
    local_10 = FLOAT_803e6f20;
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x7d1,auStack36,4,0xffffffff,local_28);
  }
  return;
}

