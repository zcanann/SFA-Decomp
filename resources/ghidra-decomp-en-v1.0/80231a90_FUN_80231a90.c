// Function: FUN_80231a90
// Entry: 80231a90
// Size: 512 bytes

void FUN_80231a90(undefined4 param_1,int param_2)

{
  byte bVar1;
  undefined local_28 [4];
  undefined2 local_24;
  undefined2 local_22;
  undefined2 local_20;
  undefined2 local_1e;
  float local_1c;
  undefined auStack24 [4];
  undefined auStack20 [4];
  undefined auStack16 [8];
  
  local_28[0] = 1;
  if (*(char *)(param_2 + 0x15e) < '\x03') {
    bVar1 = *(byte *)(param_2 + 0x15f);
    *(byte *)(param_2 + 0x15f) = bVar1 + 1;
    if ((bVar1 & 1) != 0) {
      FUN_800382f0(param_1,4,auStack24,auStack20,auStack16);
      local_1c = *(float *)(param_2 + 0x11c);
      if (*(char *)(param_2 + 0x15e) < '\x02') {
        local_1e = 25000;
      }
      else {
        local_1e = 40000;
      }
      (**(code **)(*DAT_803dca88 + 8))(param_1,2000,&local_24,4,0xffffffff,local_28);
    }
  }
  if (*(char *)(param_2 + 0x15e) < '\x02') {
    local_1e = 0xc0a;
    FUN_800382f0(param_1,5,auStack24,auStack20,auStack16);
    local_1c = *(float *)(param_2 + 0x120);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x7d1,&local_24,4,0xffffffff,local_28);
  }
  if ((*(char *)(param_2 + 0x15a) != '\0') && ('\x01' < *(char *)(param_2 + 0x15e))) {
    local_24 = 0;
    local_22 = 0;
    local_20 = 0;
    local_1c = FLOAT_803e7168;
    FUN_800382f0(param_1,2,auStack24,auStack20,auStack16);
    FUN_8009837c((double)*(float *)(param_2 + 0x114),(double)*(float *)(param_2 + 0x118),param_1,2,0
                 ,0,&local_24);
  }
  if ((1 < *(byte *)(param_2 + 0x15a)) && ('\x01' < *(char *)(param_2 + 0x15e))) {
    FUN_800382f0(param_1,3,auStack24,auStack20,auStack16);
    FUN_8009837c((double)*(float *)(param_2 + 0x114),(double)*(float *)(param_2 + 0x118),param_1,2,0
                 ,0,&local_24);
  }
  return;
}

