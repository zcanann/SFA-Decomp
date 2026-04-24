// Function: FUN_801eb484
// Entry: 801eb484
// Size: 648 bytes

void FUN_801eb484(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 short *param_9,int param_10)

{
  float fVar1;
  float fVar2;
  uint uVar3;
  short sVar4;
  undefined uVar5;
  
  if ((*(byte *)(param_10 + 0x428) >> 3 & 1) == 0) {
    *(undefined4 *)(param_10 + 0x38) = 0xffffffff;
    *(undefined4 *)(param_10 + 0x3c) = 0xffffffff;
    *(undefined4 *)(param_10 + 0x40) = 0xffffffff;
    *(undefined4 *)(param_10 + 0x44) = 0;
    DAT_803dcd24 = -1;
    uVar3 = FUN_80020078((int)**(short **)(param_10 + 0x60));
    if (uVar3 != 0) {
      *(byte *)(param_10 + 0x428) = *(byte *)(param_10 + 0x428) & 0xf7 | 8;
    }
    if ((*(byte *)(param_10 + 0x428) >> 3 & 1) != 0) {
      if ((*(byte *)(param_10 + 0x428) >> 1 & 1) == 0) {
        (**(code **)(*DAT_803dd6ec + 0x10))(param_9,param_10 + 0x28,*(undefined *)(param_10 + 0x5c))
        ;
      }
      else {
        FUN_801ed09c(param_9);
      }
      (**(code **)(*DAT_803dd6ec + 0x28))(param_10 + 0x28);
    }
  }
  else {
    if ((*(byte *)(param_10 + 0x428) >> 1 & 1) == 0) {
      sVar4 = (**(code **)(*DAT_803dd6ec + 0x14))(param_9,param_10 + 0x28);
      sVar4 = *param_9 - sVar4;
      if (0x8000 < sVar4) {
        sVar4 = sVar4 + 1;
      }
      if (sVar4 < -0x8000) {
        sVar4 = sVar4 + -1;
      }
      uVar3 = (uint)sVar4;
      if ((int)uVar3 < 0) {
        uVar3 = -uVar3;
      }
      fVar1 = FLOAT_803dc074;
      if ((int)(((int)(uVar3 ^ (int)DAT_803dcd44) >> 1) - ((uVar3 ^ (int)DAT_803dcd44) & uVar3)) < 0
         ) {
        fVar1 = -FLOAT_803dc074;
      }
      *(float *)(param_10 + 0x68) = *(float *)(param_10 + 0x68) + fVar1;
      fVar1 = *(float *)(param_10 + 0x68);
      fVar2 = FLOAT_803e6780;
      if ((FLOAT_803e6780 <= fVar1) && (fVar2 = fVar1, FLOAT_803e6800 < fVar1)) {
        fVar2 = FLOAT_803e6800;
      }
      *(float *)(param_10 + 0x68) = fVar2;
      if ((double)FLOAT_803e6814 < (double)*(float *)(param_10 + 0x68)) {
        FUN_800168a8((double)*(float *)(param_10 + 0x68),param_2,param_3,param_4,param_5,param_6,
                     param_7,param_8,0x475);
      }
      (**(code **)(*DAT_803dd6ec + 0x2c))(param_10 + 0x28);
      uVar5 = (**(code **)(*DAT_803dd6ec + 0x34))(param_10 + 0x28);
      *(undefined *)(param_10 + 0x422) = uVar5;
      if ((*(char *)(param_10 + 0x422) == '\x01') && (DAT_803dcd24 == -1)) {
        DAT_803dcd24 = -1;
      }
      else {
        DAT_803dcd24 = (int)*(char *)(param_10 + 0x422);
        DAT_803add04 = *(undefined4 *)(param_10 + 0x44);
        DAT_803adcf4 = *(undefined4 *)(param_10 + 0x34);
      }
    }
    uVar3 = FUN_80020078((int)*(short *)(*(int *)(param_10 + 0x60) + 2));
    if (uVar3 != 0) {
      *(byte *)(param_10 + 0x428) = *(byte *)(param_10 + 0x428) & 0xf7;
    }
  }
  return;
}

