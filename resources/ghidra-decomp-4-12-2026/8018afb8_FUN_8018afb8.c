// Function: FUN_8018afb8
// Entry: 8018afb8
// Size: 632 bytes

void FUN_8018afb8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  int iVar2;
  byte *pbVar3;
  undefined4 uStack_48;
  int local_44;
  uint uStack_40;
  float local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined2 local_28;
  undefined2 local_26;
  undefined2 local_24;
  float local_20;
  float local_1c;
  undefined4 uStack_18;
  float local_14 [2];
  
  pbVar3 = *(byte **)(param_9 + 0xb8);
  iVar2 = *(int *)(param_9 + 0x4c);
  local_3c = FLOAT_803e48c0;
  if (((*pbVar3 >> 6 & 1) != 0) && ((char)*pbVar3 < '\0')) {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
    FUN_8003042c((double)FLOAT_803e48c4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  }
  if (-1 < (char)*pbVar3) {
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
      iVar1 = FUN_8002bac4();
      FUN_80296f40(iVar1,1);
      iVar1 = FUN_80036f50(4,param_9,&local_3c);
      if (iVar1 == 0) {
        (**(code **)(*DAT_803dd6d4 + 0x7c))((int)*(short *)(iVar2 + 0x1a),0,0);
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dd6d4 + 0x7c))((int)*(short *)(iVar1 + 0x46),0,0);
        (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
      }
      FUN_800201ac((int)*(short *)(iVar2 + 0x1e),1);
      *pbVar3 = *pbVar3 & 0x7f | 0x80;
      FUN_80035ff8(param_9);
    }
    *pbVar3 = *pbVar3 & 0xbf;
    local_38 = DAT_802c2a30;
    local_34 = DAT_802c2a34;
    local_30 = DAT_802c2a38;
    local_2c = DAT_802c2a3c;
    local_44 = -1;
    iVar2 = FUN_80036868(param_9,&uStack_48,&local_44,&uStack_40,&local_1c,&uStack_18,local_14);
    if ((iVar2 != 0) && (iVar2 != 0xe)) {
      local_1c = local_1c + FLOAT_803dda58;
      local_14[0] = local_14[0] + FLOAT_803dda5c;
      local_20 = FLOAT_803e48b8;
      local_24 = 0;
      local_26 = 0;
      local_28 = 0;
      if (DAT_803de764 == 0) {
        (**(code **)(*DAT_803de760 + 4))(0,1,&local_28,0x401,0xffffffff,&local_38);
        DAT_803de764 = 0x3c;
      }
    }
    if (DAT_803de764 != 0) {
      DAT_803de764 = DAT_803de764 + -1;
    }
  }
  return;
}

