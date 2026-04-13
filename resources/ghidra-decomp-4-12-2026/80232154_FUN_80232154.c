// Function: FUN_80232154
// Entry: 80232154
// Size: 512 bytes

void FUN_80232154(int param_1,int param_2)

{
  byte bVar1;
  undefined local_28 [4];
  undefined2 local_24;
  undefined2 local_22;
  undefined2 local_20;
  undefined2 local_1e;
  float local_1c;
  undefined4 uStack_18;
  undefined4 uStack_14;
  undefined4 auStack_10 [2];
  
  local_28[0] = 1;
  if (*(char *)(param_2 + 0x15e) < '\x03') {
    bVar1 = *(byte *)(param_2 + 0x15f);
    *(byte *)(param_2 + 0x15f) = bVar1 + 1;
    if ((bVar1 & 1) != 0) {
      FUN_800383e8(param_1,4,&uStack_18,&uStack_14,auStack_10);
      local_1c = *(float *)(param_2 + 0x11c);
      if (*(char *)(param_2 + 0x15e) < '\x02') {
        local_1e = 25000;
      }
      else {
        local_1e = 40000;
      }
      (**(code **)(*DAT_803dd708 + 8))(param_1,2000,&local_24,4,0xffffffff,local_28);
    }
  }
  if (*(char *)(param_2 + 0x15e) < '\x02') {
    local_1e = 0xc0a;
    FUN_800383e8(param_1,5,&uStack_18,&uStack_14,auStack_10);
    local_1c = *(float *)(param_2 + 0x120);
    (**(code **)(*DAT_803dd708 + 8))(param_1,0x7d1,&local_24,4,0xffffffff,local_28);
  }
  if ((*(char *)(param_2 + 0x15a) != '\0') && ('\x01' < *(char *)(param_2 + 0x15e))) {
    local_24 = 0;
    local_22 = 0;
    local_20 = 0;
    local_1c = FLOAT_803e7e00;
    FUN_800383e8(param_1,2,&uStack_18,&uStack_14,auStack_10);
    FUN_80098608((double)*(float *)(param_2 + 0x114),(double)*(float *)(param_2 + 0x118));
  }
  if ((1 < *(byte *)(param_2 + 0x15a)) && ('\x01' < *(char *)(param_2 + 0x15e))) {
    FUN_800383e8(param_1,3,&uStack_18,&uStack_14,auStack_10);
    FUN_80098608((double)*(float *)(param_2 + 0x114),(double)*(float *)(param_2 + 0x118));
  }
  return;
}

