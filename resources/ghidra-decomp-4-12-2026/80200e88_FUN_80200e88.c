// Function: FUN_80200e88
// Entry: 80200e88
// Size: 544 bytes

undefined4
FUN_80200e88(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  short *psVar4;
  int iVar5;
  double dVar6;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  float local_24;
  float local_20;
  float local_1c;
  
  iVar5 = *(int *)(*(int *)(param_9 + 0xb8) + 0x40c);
  *(byte *)(iVar5 + 0x14) = *(byte *)(iVar5 + 0x14) | 2;
  *(byte *)(iVar5 + 0x15) = *(byte *)(iVar5 + 0x15) & 0xfb;
  fVar1 = FLOAT_803e6f88;
  *(float *)(param_10 + 0x280) = *(float *)(param_10 + 0x280) / FLOAT_803e6f88;
  *(float *)(param_10 + 0x284) = *(float *)(param_10 + 0x284) / fVar1;
  *(float *)(param_10 + 0x2a0) = FLOAT_803e6f8c;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_8003042c((double)FLOAT_803e6f40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x11,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 0x1f;
  if ((*(float *)(param_9 + 0x98) <= FLOAT_803e6f84) ||
     (*(float *)(param_9 + 0x10) < *(float *)(*(int *)(param_10 + 0x2d0) + 0x10) - FLOAT_803e6f90))
  {
    iVar3 = *(int *)(param_10 + 0x2d0);
    local_24 = *(float *)(iVar3 + 0xc) - *(float *)(param_9 + 0xc);
    local_20 = *(float *)(iVar3 + 0x10) - (*(float *)(param_9 + 0x10) + FLOAT_803e6f94);
    local_1c = *(float *)(iVar3 + 0x14) - *(float *)(param_9 + 0x14);
    dVar6 = FUN_80293900((double)(local_1c * local_1c + local_24 * local_24 + local_20 * local_20));
    if (dVar6 < (double)FLOAT_803e6f50) {
      local_40 = *(undefined4 *)(param_10 + 0x2d0);
      psVar4 = *(short **)(iVar5 + 0x24);
      local_48 = 0xe;
      local_44 = 1;
      uVar2 = FUN_800138e4(psVar4);
      if (uVar2 == 0) {
        FUN_80013978(psVar4,(uint)&local_48);
      }
      *(undefined *)(iVar5 + 0x34) = 1;
    }
  }
  else {
    psVar4 = *(short **)(iVar5 + 0x24);
    local_30 = 9;
    local_2c = 0;
    local_28 = 0x24;
    uVar2 = FUN_800138e4(psVar4);
    if (uVar2 == 0) {
      FUN_80013978(psVar4,(uint)&local_30);
    }
    *(undefined *)(iVar5 + 0x34) = 1;
    local_34 = *(undefined4 *)(param_10 + 0x2d0);
    psVar4 = *(short **)(iVar5 + 0x24);
    local_3c = 7;
    local_38 = 1;
    uVar2 = FUN_800138e4(psVar4);
    if (uVar2 == 0) {
      FUN_80013978(psVar4,(uint)&local_3c);
    }
    *(undefined *)(iVar5 + 0x34) = 1;
  }
  return 0;
}

