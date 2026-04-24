// Function: FUN_801eae4c
// Entry: 801eae4c
// Size: 648 bytes

void FUN_801eae4c(short *param_1,int param_2)

{
  float fVar1;
  float fVar2;
  int iVar3;
  short sVar4;
  undefined uVar5;
  uint uVar6;
  
  if ((*(byte *)(param_2 + 0x428) >> 3 & 1) == 0) {
    *(undefined4 *)(param_2 + 0x38) = 0xffffffff;
    *(undefined4 *)(param_2 + 0x3c) = 0xffffffff;
    *(undefined4 *)(param_2 + 0x40) = 0xffffffff;
    *(undefined4 *)(param_2 + 0x44) = 0;
    DAT_803dc0bc = -1;
    iVar3 = FUN_8001ffb4((int)**(short **)(param_2 + 0x60));
    if (iVar3 != 0) {
      *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xf7 | 8;
    }
    if ((*(byte *)(param_2 + 0x428) >> 3 & 1) != 0) {
      if ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) {
        (**(code **)(*DAT_803dca6c + 0x10))(param_1,param_2 + 0x28,*(undefined *)(param_2 + 0x5c));
      }
      else {
        FUN_801eca64(param_1);
      }
      (**(code **)(*DAT_803dca6c + 0x28))(param_2 + 0x28);
    }
  }
  else {
    if ((*(byte *)(param_2 + 0x428) >> 1 & 1) == 0) {
      sVar4 = (**(code **)(*DAT_803dca6c + 0x14))(param_1,param_2 + 0x28);
      sVar4 = *param_1 - sVar4;
      if (0x8000 < sVar4) {
        sVar4 = sVar4 + 1;
      }
      if (sVar4 < -0x8000) {
        sVar4 = sVar4 + -1;
      }
      uVar6 = (uint)sVar4;
      if ((int)uVar6 < 0) {
        uVar6 = -uVar6;
      }
      fVar1 = FLOAT_803db414;
      if ((int)(((int)(uVar6 ^ (int)DAT_803dc0dc) >> 1) - ((uVar6 ^ (int)DAT_803dc0dc) & uVar6)) < 0
         ) {
        fVar1 = -FLOAT_803db414;
      }
      *(float *)(param_2 + 0x68) = *(float *)(param_2 + 0x68) + fVar1;
      fVar1 = *(float *)(param_2 + 0x68);
      fVar2 = FLOAT_803e5ae8;
      if ((FLOAT_803e5ae8 <= fVar1) && (fVar2 = fVar1, FLOAT_803e5b68 < fVar1)) {
        fVar2 = FLOAT_803e5b68;
      }
      *(float *)(param_2 + 0x68) = fVar2;
      if (FLOAT_803e5b7c < *(float *)(param_2 + 0x68)) {
        FUN_80016870(0x475);
      }
      (**(code **)(*DAT_803dca6c + 0x2c))(param_2 + 0x28);
      uVar5 = (**(code **)(*DAT_803dca6c + 0x34))(param_2 + 0x28);
      *(undefined *)(param_2 + 0x422) = uVar5;
      if ((*(char *)(param_2 + 0x422) == '\x01') && (DAT_803dc0bc == -1)) {
        DAT_803dc0bc = -1;
      }
      else {
        DAT_803dc0bc = (int)*(char *)(param_2 + 0x422);
        DAT_803ad0a4 = *(undefined4 *)(param_2 + 0x44);
        DAT_803ad094 = *(undefined4 *)(param_2 + 0x34);
      }
    }
    iVar3 = FUN_8001ffb4((int)*(short *)(*(int *)(param_2 + 0x60) + 2));
    if (iVar3 != 0) {
      *(byte *)(param_2 + 0x428) = *(byte *)(param_2 + 0x428) & 0xf7;
    }
  }
  return;
}

