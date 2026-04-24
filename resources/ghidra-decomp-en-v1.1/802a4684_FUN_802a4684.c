// Function: FUN_802a4684
// Entry: 802a4684
// Size: 616 bytes

undefined4
FUN_802a4684(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  int iVar2;
  int iVar3;
  double dVar4;
  
  iVar3 = *(int *)(param_9 + 0x5c);
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(undefined2 *)(param_10 + 0x9e) = 9;
    *(undefined4 *)(iVar3 + 0x898) = 0;
  }
  iVar2 = *(int *)(param_9 + 0x5c);
  *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) & 0xfffffffd;
  *(uint *)(iVar2 + 0x360) = *(uint *)(iVar2 + 0x360) | 0x2000;
  param_10[1] = param_10[1] | 0x100000;
  fVar1 = FLOAT_803e8b3c;
  dVar4 = (double)FLOAT_803e8b3c;
  param_10[0xa0] = (uint)FLOAT_803e8b3c;
  param_10[0xa1] = (uint)fVar1;
  *param_10 = *param_10 | 0x200000;
  *(float *)(param_9 + 0x12) = fVar1;
  *(float *)(param_9 + 0x16) = fVar1;
  param_10[1] = param_10[1] | 0x8000000;
  *(float *)(param_9 + 0x14) = fVar1;
  if (param_9[0x50] == 0x419) {
    if (*(char *)((int)param_10 + 0x346) != '\0') {
      FUN_8003042c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                   (int)DAT_80333b5c,0,param_12,param_13,param_14,param_15,param_16);
      DAT_803dd308 = 6;
      param_10[0xa8] = (uint)FLOAT_803e8cd0;
      FUN_802abd04((int)param_9,iVar3 + 4,5);
      param_10[0xc2] = 0;
      return 0xd;
    }
  }
  else {
    FUN_8003042c(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,0x419,1,
                 param_12,param_13,param_14,param_15,param_16);
    param_10[0xa8] = (uint)FLOAT_803e8b28;
    iVar2 = FUN_80021884();
    *(short *)(iVar3 + 0x478) = (short)iVar2;
    *(undefined2 *)(iVar3 + 0x484) = *(undefined2 *)(iVar3 + 0x478);
    fVar1 = FLOAT_803e8ba8;
    *(float *)(param_9 + 0xc) =
         FLOAT_803e8ba8 * *(float *)(iVar3 + 0x5c4) + *(float *)(iVar3 + 0x5d4);
    *(float *)(param_9 + 0xe) = *(float *)(iVar3 + 0x5ac) - *(float *)(iVar3 + 0x874);
    *(float *)(param_9 + 0x10) = fVar1 * *(float *)(iVar3 + 0x5cc) + *(float *)(iVar3 + 0x5dc);
    FUN_8000e054((double)*(float *)(param_9 + 0xc),(double)*(float *)(param_9 + 0xe),
                 (double)*(float *)(param_9 + 0x10),(float *)(param_9 + 6),(float *)(param_9 + 8),
                 (float *)(param_9 + 10),*(int *)(param_9 + 0x18));
    FUN_80063000(param_9,*(short **)(iVar3 + 0x4c4),1);
    if (*(int *)(iVar3 + 0x4c4) != 0) {
      FUN_8000e054((double)*(float *)(iVar3 + 0x5d4),(double)*(float *)(iVar3 + 0x5d8),
                   (double)*(float *)(iVar3 + 0x5dc),(float *)(iVar3 + 0x5d4),
                   (float *)(iVar3 + 0x5d8),(float *)(iVar3 + 0x5dc),*(int *)(iVar3 + 0x4c4));
      FUN_8000e054((double)*(float *)(iVar3 + 0x5ec),(double)*(float *)(iVar3 + 0x5f0),
                   (double)*(float *)(iVar3 + 0x5f4),(float *)(iVar3 + 0x5ec),
                   (float *)(iVar3 + 0x5f0),(float *)(iVar3 + 0x5f4),*(int *)(iVar3 + 0x4c4));
      FUN_8000e054((double)*(float *)(iVar3 + 0x5f8),(double)*(float *)(iVar3 + 0x5fc),
                   (double)*(float *)(iVar3 + 0x600),(float *)(iVar3 + 0x5f8),
                   (float *)(iVar3 + 0x5fc),(float *)(iVar3 + 0x600),*(int *)(iVar3 + 0x4c4));
      *(float *)(iVar3 + 0x5ac) =
           *(float *)(iVar3 + 0x5ac) - *(float *)(*(int *)(iVar3 + 0x4c4) + 0x10);
      *(float *)(iVar3 + 0x5b0) =
           *(float *)(iVar3 + 0x5b0) - *(float *)(*(int *)(iVar3 + 0x4c4) + 0x10);
      *(undefined *)(iVar3 + 0x609) = 0;
    }
  }
  FUN_802abd04((int)param_9,iVar3 + 4,5);
  return 0;
}

