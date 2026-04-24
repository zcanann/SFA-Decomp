// Function: FUN_8021dd90
// Entry: 8021dd90
// Size: 292 bytes

undefined4
FUN_8021dd90(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  
  fVar1 = FLOAT_803e7740;
  iVar4 = *(int *)(param_9 + 0xb8);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(float *)(param_10 + 0x294) = FLOAT_803e7740;
    *(float *)(param_10 + 0x284) = fVar1;
    *(float *)(param_10 + 0x280) = fVar1;
    *(float *)(param_9 + 0x24) = fVar1;
    *(float *)(param_9 + 0x28) = fVar1;
    *(float *)(param_9 + 0x2c) = fVar1;
    FUN_80035f9c(param_9);
    (**(code **)(*DAT_803dd6e8 + 0x60))();
    *(byte *)(iVar4 + 0xc49) = *(byte *)(iVar4 + 0xc49) & 0xfe;
    *(byte *)(iVar4 + 0xc49) = *(byte *)(iVar4 + 0xc49) & 0xbf;
    *(undefined *)(iVar4 + 0xc4b) = 5;
    *(float *)(param_10 + 0x2a0) = FLOAT_803e7744;
    *(byte *)(iVar4 + 0x9fd) = *(byte *)(iVar4 + 0x9fd) & 0xfe;
    FUN_8003709c(param_9,10);
  }
  if ((*(char *)(param_10 + 0x346) != '\0') && (*(short *)(param_9 + 0xa0) != 0)) {
    FUN_8003042c((double)FLOAT_803e7740,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(float *)(param_10 + 0x2a0) = FLOAT_803e7760;
  }
  uVar2 = FUN_80022264(0,1000);
  if (uVar2 == 0) {
    uVar3 = 9;
  }
  else {
    uVar3 = 0;
  }
  return uVar3;
}

