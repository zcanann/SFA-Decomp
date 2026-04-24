// Function: FUN_80165634
// Entry: 80165634
// Size: 592 bytes

undefined4
FUN_80165634(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  int iVar2;
  double dVar3;
  undefined8 uVar4;
  double dVar5;
  double dVar6;
  
  iVar2 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  *(undefined *)((int)param_10 + 0x34d) = 3;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    FUN_80035ff8(param_9);
    *(float *)(param_9 + 0x24) = -*(float *)(param_9 + 0x24);
    *(float *)(param_9 + 0x28) = *(float *)(param_9 + 0x28) + FLOAT_803e3c70;
    *(float *)(param_9 + 0x2c) = -*(float *)(param_9 + 0x2c);
    FUN_8003042c((double)FLOAT_803e3c74,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,3,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(iVar2 + 0x44) = FLOAT_803e3c78;
  }
  *(undefined *)(*(int *)(param_9 + 0x54) + 0x6d) = 0;
  *param_10 = *param_10 | 0x4000;
  fVar1 = FLOAT_803e3c7c;
  *(float *)(param_9 + 0x24) = *(float *)(param_9 + 0x24) * FLOAT_803e3c7c;
  *(float *)(param_9 + 0x28) = FLOAT_803e3c80 * (*(float *)(param_9 + 0x28) - FLOAT_803e3c84);
  *(float *)(param_9 + 0x2c) = *(float *)(param_9 + 0x2c) * fVar1;
  dVar5 = (double)*(float *)(param_9 + 0x28);
  dVar6 = (double)*(float *)(param_9 + 0x2c);
  FUN_8002ba34((double)*(float *)(param_9 + 0x24),dVar5,dVar6,param_9);
  if (*(float *)(param_9 + 0xc) < *(float *)(iVar2 + 0x48)) {
    *(float *)(param_9 + 0xc) = *(float *)(iVar2 + 0x48);
    *(float *)(param_9 + 0x24) = FLOAT_803e3c88 * -*(float *)(param_9 + 0x24);
  }
  if (*(float *)(iVar2 + 0x4c) < *(float *)(param_9 + 0xc)) {
    *(float *)(param_9 + 0xc) = *(float *)(iVar2 + 0x4c);
    *(float *)(param_9 + 0x24) = FLOAT_803e3c88 * -*(float *)(param_9 + 0x24);
  }
  if (*(float *)(param_9 + 0x10) < *(float *)(iVar2 + 0x5c)) {
    *(float *)(param_9 + 0x10) = *(float *)(iVar2 + 0x5c);
    *(float *)(param_9 + 0x28) = FLOAT_803e3c88 * -*(float *)(param_9 + 0x28);
  }
  if (*(float *)(iVar2 + 0x58) < *(float *)(param_9 + 0x10)) {
    *(float *)(param_9 + 0x10) = *(float *)(iVar2 + 0x58);
    *(float *)(param_9 + 0x28) = FLOAT_803e3c88 * -*(float *)(param_9 + 0x28);
  }
  if (*(float *)(param_9 + 0x14) < *(float *)(iVar2 + 0x54)) {
    *(float *)(param_9 + 0x14) = *(float *)(iVar2 + 0x54);
    *(float *)(param_9 + 0x2c) = FLOAT_803e3c88 * -*(float *)(param_9 + 0x2c);
  }
  if (*(float *)(iVar2 + 0x50) < *(float *)(param_9 + 0x14)) {
    *(float *)(param_9 + 0x14) = *(float *)(iVar2 + 0x50);
    *(float *)(param_9 + 0x2c) = FLOAT_803e3c88 * -*(float *)(param_9 + 0x2c);
  }
  dVar3 = (double)*(float *)(param_9 + 0x98);
  if ((double)FLOAT_803e3c8c == dVar3) {
    uVar4 = FUN_800377d0(dVar3,dVar5,dVar6,param_4,param_5,param_6,param_7,param_8,0,3,param_9,
                         0xe0000,param_9,param_14,param_15,param_16);
    FUN_8002cc9c(uVar4,dVar5,dVar6,param_4,param_5,param_6,param_7,param_8,param_9);
  }
  else {
    *(char *)(param_9 + 0x36) = -1 - (char)(int)((double)FLOAT_803e3c90 * dVar3);
  }
  return 0;
}

