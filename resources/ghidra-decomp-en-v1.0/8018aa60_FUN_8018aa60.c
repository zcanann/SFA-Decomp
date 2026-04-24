// Function: FUN_8018aa60
// Entry: 8018aa60
// Size: 632 bytes

void FUN_8018aa60(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  undefined auStack72 [4];
  undefined4 local_44;
  undefined auStack64 [4];
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
  undefined auStack24 [4];
  float local_14 [2];
  
  pbVar4 = *(byte **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  local_3c = FLOAT_803e3c28;
  if (((*pbVar4 >> 6 & 1) != 0) && ((char)*pbVar4 < '\0')) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_80030334((double)FLOAT_803e3c2c,param_1,0,0);
  }
  if (-1 < (char)*pbVar4) {
    if ((*(byte *)(param_1 + 0xaf) & 1) != 0) {
      *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
      uVar1 = FUN_8002b9ec();
      FUN_802967e0(uVar1,1);
      iVar2 = FUN_80036e58(4,param_1,&local_3c);
      if (iVar2 == 0) {
        (**(code **)(*DAT_803dca54 + 0x7c))((int)*(short *)(iVar3 + 0x1a),0,0);
        (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      }
      else {
        (**(code **)(*DAT_803dca54 + 0x7c))((int)*(short *)(iVar2 + 0x46),0,0);
        (**(code **)(*DAT_803dca54 + 0x48))(1,param_1,0xffffffff);
      }
      FUN_800200e8((int)*(short *)(iVar3 + 0x1e),1);
      *pbVar4 = *pbVar4 & 0x7f | 0x80;
      FUN_80035f00(param_1);
    }
    *pbVar4 = *pbVar4 & 0xbf;
    local_38 = DAT_802c22b0;
    local_34 = DAT_802c22b4;
    local_30 = DAT_802c22b8;
    local_2c = DAT_802c22bc;
    local_44 = 0xffffffff;
    iVar3 = FUN_80036770(param_1,auStack72,&local_44,auStack64,&local_1c,auStack24,local_14);
    if ((iVar3 != 0) && (iVar3 != 0xe)) {
      local_1c = local_1c + FLOAT_803dcdd8;
      local_14[0] = local_14[0] + FLOAT_803dcddc;
      local_20 = FLOAT_803e3c20;
      local_24 = 0;
      local_26 = 0;
      local_28 = 0;
      if (DAT_803ddae4 == 0) {
        (**(code **)(*DAT_803ddae0 + 4))(0,1,&local_28,0x401,0xffffffff,&local_38);
        DAT_803ddae4 = 0x3c;
      }
    }
    if (DAT_803ddae4 != 0) {
      DAT_803ddae4 = DAT_803ddae4 + -1;
    }
  }
  return;
}

