// Function: FUN_802ba934
// Entry: 802ba934
// Size: 536 bytes

undefined4
FUN_802ba934(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  
  fVar1 = FLOAT_803e8ecc;
  param_10[0xa5] = (uint)FLOAT_803e8ecc;
  param_10[0xa1] = (uint)fVar1;
  param_10[0xa0] = (uint)fVar1;
  *(float *)(param_9 + 0x24) = fVar1;
  *(float *)(param_9 + 0x28) = fVar1;
  *(float *)(param_9 + 0x2c) = fVar1;
  *param_10 = *param_10 | 0x200000;
  iVar5 = *(int *)(param_9 + 0xb8);
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) & 0xf7;
  uVar2 = FUN_80020078(0x170);
  *(byte *)(param_9 + 0xe4) = (byte)((byte)(-uVar2 >> 0x18) | (byte)(uVar2 >> 0x18)) >> 7;
  if ((*(char *)((int)param_10 + 0x27a) != '\0') &&
     (param_10[0xa8] = (uint)FLOAT_803e8f14, *(short *)(param_9 + 0xa0) != 0x13)) {
    FUN_8003042c((double)FLOAT_803e8ecc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x13,0,param_12,param_13,param_14,param_15,param_16);
  }
  if ((*(byte *)(param_9 + 0xaf) & 4) != 0) {
    iVar3 = (**(code **)(*DAT_803dd6e8 + 0x20))(0x170);
    if (iVar3 == 0) {
      if ((*(byte *)(param_9 + 0xaf) & 1) != 0) {
        uVar2 = FUN_80020078(0x28);
        if (uVar2 == 0) {
          *(undefined *)(iVar5 + 0xa8d) = 1;
        }
        else {
          *(undefined *)(iVar5 + 0xa8d) = 3;
        }
        (**(code **)(*DAT_803dd6d4 + 0x48))(*(undefined *)(iVar5 + 0xa8d),param_9,0xffffffff);
        FUN_80014b68(0,0x100);
      }
    }
    else {
      uVar2 = FUN_80020078(0x170);
      uVar2 = uVar2 & 0xff;
      uVar4 = FUN_80020078(0x28);
      if (uVar4 == 0) {
        if (uVar2 == 2) {
          *(undefined *)(iVar5 + 0xa8d) = 4;
          FUN_800201ac(0x16f,1);
        }
        else if ((uVar2 < 2) && (uVar2 != 0)) {
          FUN_800201ac(0x28,1);
          *(undefined *)(iVar5 + 0xa8d) = 2;
        }
      }
      else {
        *(undefined *)(iVar5 + 0xa8d) = 4;
        FUN_800201ac(0x16f,1);
      }
      (**(code **)(*DAT_803dd6d4 + 0x48))(*(undefined *)(iVar5 + 0xa8d),param_9,0xffffffff);
      uVar4 = FUN_80020078(0x170);
      FUN_800201ac(0x170,uVar4 - uVar2);
      FUN_80014b68(0,0x100);
    }
  }
  return 0;
}

