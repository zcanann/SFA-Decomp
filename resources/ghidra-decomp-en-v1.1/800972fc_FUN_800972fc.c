// Function: FUN_800972fc
// Entry: 800972fc
// Size: 304 bytes

void FUN_800972fc(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,int param_5)

{
  int iVar1;
  double extraout_f1;
  ulonglong uVar2;
  undefined4 local_58;
  undefined2 local_54;
  undefined4 local_50;
  undefined4 local_4c;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined2 local_3c;
  undefined auStack_38 [6];
  undefined2 local_32;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  uVar2 = FUN_80286840();
  local_50 = DAT_802c2894;
  local_4c = DAT_802c2898;
  local_48 = DAT_802c289c;
  local_44 = DAT_802c28a0;
  local_40 = DAT_802c28a4;
  local_3c = DAT_802c28a8;
  local_58 = DAT_803dffc0;
  local_54 = DAT_803dffc4;
  if (((uVar2 & 0xff) != 0) && ((param_3 & 0xff) != 0)) {
    local_30 = (float)extraout_f1;
    local_32 = *(undefined2 *)((int)&local_50 + (param_3 & 0xff) * 2);
    if (param_5 == 0) {
      local_2c = FLOAT_803dffdc;
      local_28 = FLOAT_803dffdc;
      local_24 = FLOAT_803dffdc;
    }
    else {
      local_2c = *(float *)(param_5 + 0xc);
      local_28 = *(float *)(param_5 + 0x10);
      local_24 = *(float *)(param_5 + 0x14);
    }
    for (iVar1 = 0; iVar1 < (int)(param_4 & 0xff); iVar1 = iVar1 + 1) {
      (**(code **)(*DAT_803dd708 + 8))
                ((int)(uVar2 >> 0x20),*(undefined2 *)((int)&local_58 + ((uint)uVar2 & 0xff) * 2),
                 auStack_38,2,0xffffffff,0);
    }
  }
  FUN_8028688c();
  return;
}

