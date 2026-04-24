// Function: FUN_801f270c
// Entry: 801f270c
// Size: 444 bytes

void FUN_801f270c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  undefined4 local_18;
  uint uStack_14;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  FUN_8002bac4();
  local_28 = DAT_802c2bfc;
  local_24 = DAT_802c2c00;
  local_20 = DAT_802c2c04;
  if ((*(byte *)(param_9 + 0xaf) & 8) != 0) {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) ^ 8;
  }
  uVar1 = FUN_80020078(0x2fb);
  if (uVar1 == 0) {
    if (*(short *)(param_9 + 0xa0) != 7) {
      FUN_8003042c((double)FLOAT_803e6a30,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,7,0,param_12,param_13,param_14,param_15,param_16);
    }
    uStack_14 = (uint)DAT_803dc070;
    local_18 = 0x43300000;
    FUN_8002fb40((double)FLOAT_803e6a34,
                 (double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e6a38));
  }
  else {
    if (*(short *)(param_9 + 0xa0) != 2) {
      FUN_8003042c((double)FLOAT_803e6a30,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,2,0,param_12,param_13,param_14,param_15,param_16);
    }
    uStack_14 = (uint)DAT_803dc070;
    local_18 = 0x43300000;
    FUN_8002fb40((double)FLOAT_803e6a34,
                 (double)(float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e6a38));
  }
  if (((*(byte *)(param_9 + 0xaf) & 1) == 0) || (uVar1 = FUN_80020078(0x2fb), uVar1 != 0)) {
    if (((*(byte *)(param_9 + 0xaf) & 1) != 0) &&
       (iVar2 = (**(code **)(*DAT_803dd6e8 + 0x24))(&local_28,3), -1 < iVar2)) {
      FUN_800201ac(0x310,1);
      *(char *)(iVar3 + 0x27) = *(char *)(iVar3 + 0x27) + '\x01';
      FUN_80014b68(0,0x100);
    }
  }
  else {
    FUN_800201ac(0x2fb,1);
    *(undefined *)(iVar3 + 0x27) = 0;
    FUN_80014b68(0,0x100);
  }
  return;
}

