// Function: FUN_80097070
// Entry: 80097070
// Size: 304 bytes

void FUN_80097070(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,int param_5)

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
  undefined auStack56 [6];
  undefined2 local_32;
  float local_30;
  float local_2c;
  float local_28;
  float local_24;
  
  uVar2 = FUN_802860dc();
  local_50 = DAT_802c2114;
  local_4c = DAT_802c2118;
  local_48 = DAT_802c211c;
  local_44 = DAT_802c2120;
  local_40 = DAT_802c2124;
  local_3c = DAT_802c2128;
  local_58 = DAT_803df340;
  local_54 = DAT_803df344;
  if (((uVar2 & 0xff) != 0) && ((param_3 & 0xff) != 0)) {
    local_30 = (float)extraout_f1;
    local_32 = *(undefined2 *)((int)&local_50 + (param_3 & 0xff) * 2);
    if (param_5 == 0) {
      local_2c = FLOAT_803df35c;
      local_28 = FLOAT_803df35c;
      local_24 = FLOAT_803df35c;
    }
    else {
      local_2c = *(float *)(param_5 + 0xc);
      local_28 = *(float *)(param_5 + 0x10);
      local_24 = *(float *)(param_5 + 0x14);
    }
    for (iVar1 = 0; iVar1 < (int)(param_4 & 0xff); iVar1 = iVar1 + 1) {
      (**(code **)(*DAT_803dca88 + 8))
                ((int)(uVar2 >> 0x20),*(undefined2 *)((int)&local_58 + ((uint)uVar2 & 0xff) * 2),
                 auStack56,2,0xffffffff,0);
    }
  }
  FUN_80286128();
  return;
}

