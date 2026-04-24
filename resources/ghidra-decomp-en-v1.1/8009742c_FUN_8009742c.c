// Function: FUN_8009742c
// Entry: 8009742c
// Size: 316 bytes

void FUN_8009742c(double param_1,undefined4 param_2,byte param_3,uint param_4,uint param_5,
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
  undefined auStack_20 [6];
  undefined2 local_1a;
  float local_18;
  float local_14;
  float local_10;
  float local_c;
  longlong local_8;
  
  local_38 = DAT_802c286c;
  local_34 = DAT_802c2870;
  local_30 = DAT_802c2874;
  local_2c = DAT_802c2878;
  local_28 = DAT_802c287c;
  local_24 = DAT_802c2880;
  local_48 = DAT_802c2884;
  local_44 = DAT_802c2888;
  local_40 = DAT_802c288c;
  local_3c = DAT_802c2890;
  if (((param_3 != 0) && ((param_4 & 0xff) != 0)) &&
     (local_8 = (longlong)(int)FLOAT_803ddedc, ((int)FLOAT_803ddedc & 0xffffU & param_5 & 0xff) != 0
     )) {
    local_18 = (float)param_1;
    local_1a = *(undefined2 *)((int)&local_38 + (param_4 & 0xff) * 2);
    if (param_6 == 0) {
      local_14 = FLOAT_803dffdc;
      local_10 = FLOAT_803dffdc;
      local_c = FLOAT_803dffdc;
    }
    else {
      local_14 = *(float *)(param_6 + 0xc);
      local_10 = *(float *)(param_6 + 0x10);
      local_c = *(float *)(param_6 + 0x14);
    }
    (**(code **)(*DAT_803dd708 + 8))
              (param_2,*(undefined2 *)((int)&local_48 + (uint)param_3 * 2),auStack_20,2,0xffffffff,0
              );
  }
  return;
}

