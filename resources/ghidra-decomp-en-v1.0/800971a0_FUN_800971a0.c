// Function: FUN_800971a0
// Entry: 800971a0
// Size: 316 bytes

void FUN_800971a0(double param_1,undefined4 param_2,byte param_3,uint param_4,uint param_5,
                 int param_6)

{
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined2 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  undefined2 local_24;
  undefined auStack32 [6];
  undefined2 local_1a;
  float local_18;
  float local_14;
  float local_10;
  float local_c;
  longlong local_8;
  
  local_38 = DAT_802c20ec;
  local_34 = DAT_802c20f0;
  local_30 = DAT_802c20f4;
  local_2c = DAT_802c20f8;
  local_28 = DAT_802c20fc;
  local_24 = DAT_802c2100;
  local_48 = DAT_802c2104;
  local_44 = DAT_802c2108;
  local_40 = DAT_802c210c;
  local_3c = DAT_802c2110;
  if (((param_3 != 0) && ((param_4 & 0xff) != 0)) &&
     (local_8 = (longlong)(int)FLOAT_803dd25c, ((int)FLOAT_803dd25c & 0xffffU & param_5 & 0xff) != 0
     )) {
    local_18 = (float)param_1;
    local_1a = *(undefined2 *)((int)&local_38 + (param_4 & 0xff) * 2);
    if (param_6 == 0) {
      local_14 = FLOAT_803df35c;
      local_10 = FLOAT_803df35c;
      local_c = FLOAT_803df35c;
    }
    else {
      local_14 = *(float *)(param_6 + 0xc);
      local_10 = *(float *)(param_6 + 0x10);
      local_c = *(float *)(param_6 + 0x14);
    }
    (**(code **)(*DAT_803dca88 + 8))
              (param_2,*(undefined2 *)((int)&local_48 + (uint)param_3 * 2),auStack32,2,0xffffffff,0)
    ;
  }
  return;
}

