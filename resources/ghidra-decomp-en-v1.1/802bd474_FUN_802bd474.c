// Function: FUN_802bd474
// Entry: 802bd474
// Size: 272 bytes

int FUN_802bd474(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                int param_9,int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13
                ,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  undefined8 uVar5;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  *(byte *)(param_9 + 0xaf) = *(byte *)(param_9 + 0xaf) | 8;
  fVar1 = FLOAT_803e8f9c;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    dVar4 = (double)FLOAT_803e8f9c;
    *(float *)(param_10 + 0x294) = FLOAT_803e8f9c;
    *(float *)(param_10 + 0x284) = fVar1;
    *(float *)(param_10 + 0x280) = fVar1;
    *(float *)(param_9 + 0x24) = fVar1;
    *(float *)(param_9 + 0x28) = fVar1;
    *(float *)(param_9 + 0x2c) = fVar1;
    if (*(char *)(iVar3 + 0x14ec) < '\0') {
      FUN_8003042c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,7,0,
                   param_12,param_13,param_14,param_15,param_16);
    }
    else {
      FUN_8003042c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,8,0,
                   param_12,param_13,param_14,param_15,param_16);
    }
    *(float *)(param_10 + 0x2a0) = FLOAT_803e8fa8;
  }
  if ((*(char *)(param_10 + 0x346) == '\0') || (*(char *)(iVar3 + 0x14e6) != '\x02')) {
    iVar3 = 0;
  }
  else {
    *(short *)(iVar3 + 0x14e2) = *(short *)(iVar3 + 0x14e2) + -1;
    if (*(short *)(iVar3 + 0x14e2) < 1) {
      *(float *)(iVar3 + 0x1444) = FLOAT_803dd3d4;
      FUN_8000faf8();
      uVar5 = FUN_8000e69c((double)FLOAT_803e8fd0);
      iVar2 = FUN_8002bac4();
      FUN_8029725c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,-1);
      *(undefined2 *)(iVar3 + 0x14e2) = 0;
    }
    iVar3 = *(int *)(iVar3 + 0x14d8) + 1;
  }
  return iVar3;
}

