// Function: FUN_801f2e1c
// Entry: 801f2e1c
// Size: 400 bytes

void FUN_801f2e1c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  if (*(short *)(param_9 + 0xa0) != 2) {
    FUN_8003042c((double)FLOAT_803e6a30,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,2,0,param_12,param_13,param_14,param_15,param_16);
  }
  FUN_8002fb40((double)FLOAT_803e6a34,
               (double)(float)((double)CONCAT44(0x43300000,(uint)DAT_803dc070) - DOUBLE_803e6a38));
  *(undefined *)(iVar3 + 0x24) = 1;
  if (*(char *)(iVar3 + 0x24) == '\0') {
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      FUN_800201ac(0xd0,1);
      *(undefined *)(iVar3 + 0x24) = 1;
      FUN_80014b68(0,0x100);
    }
  }
  else {
    *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
    if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
      iVar1 = FUN_8002bac4();
      iVar1 = FUN_80297174(iVar1);
      if (iVar1 < 1) {
        uVar2 = FUN_80020078(0xb1);
        if (((uVar2 == 0) || (uVar2 = FUN_80020078(0xb2), uVar2 == 0)) ||
           (uVar2 = FUN_80020078(0xb3), uVar2 == 0)) {
          *(undefined *)(iVar3 + 0x25) = 1;
          (**(code **)(*DAT_803dd6d4 + 0x48))(1,param_9,0xffffffff);
          FUN_80014b68(0,0x100);
        }
      }
      else {
        *(undefined *)(iVar3 + 0x25) = 2;
        (**(code **)(*DAT_803dd6d4 + 0x48))(2,param_9,0xffffffff);
        FUN_80014b68(0,0x100);
      }
    }
  }
  return;
}

