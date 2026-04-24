// Function: FUN_801e8680
// Entry: 801e8680
// Size: 324 bytes

void FUN_801e8680(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 ushort *param_9)

{
  int iVar1;
  undefined4 uVar2;
  undefined2 uVar3;
  int iVar4;
  float local_18 [3];
  
  iVar1 = FUN_8002bac4();
  iVar4 = *(int *)(param_9 + 0x5c);
  local_18[0] = FLOAT_803e66b8;
  *(byte *)(iVar4 + 0x9d4) = *(byte *)(iVar4 + 0x9d4) & 0xdf;
  if ((double)FLOAT_803e6674 < (double)*(float *)(iVar4 + 0x9c4)) {
    FUN_800168a8((double)*(float *)(iVar4 + 0x9c4),param_2,param_3,param_4,param_5,param_6,param_7,
                 param_8,0x433);
    *(float *)(iVar4 + 0x9c4) = *(float *)(iVar4 + 0x9c4) - FLOAT_803dc074;
    if (*(float *)(iVar4 + 0x9c4) < FLOAT_803e6674) {
      *(float *)(iVar4 + 0x9c4) = FLOAT_803e6674;
    }
  }
  if ((*(byte *)(iVar4 + 0x9d4) & 4) != 0) {
    FUN_801e823c(param_9,iVar1,1);
  }
  *(undefined4 *)(param_9 + 4) = *(undefined4 *)(*(int *)(param_9 + 0x28) + 4);
  if (*(int *)(iVar4 + 0x9b4) == 0) {
    uVar2 = FUN_80036f50(9,param_9,local_18);
    *(undefined4 *)(iVar4 + 0x9b4) = uVar2;
  }
  uVar3 = FUN_80296ffc(iVar1);
  *(undefined2 *)(iVar4 + 0x9c8) = uVar3;
  (**(code **)(*DAT_803dd70c + 8))
            ((double)FLOAT_803dc074,(double)FLOAT_803dc074,param_9,iVar4,&DAT_803adcc8,&DAT_803de8d8
            );
  FUN_80115330();
  FUN_8003b408((int)param_9,iVar4 + 0x980);
  *(undefined *)(param_9 + 0x1b) = *(undefined *)(iVar4 + 0x9d6);
  return;
}

