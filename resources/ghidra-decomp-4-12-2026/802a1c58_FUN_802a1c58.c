// Function: FUN_802a1c58
// Entry: 802a1c58
// Size: 468 bytes

undefined4
FUN_802a1c58(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 *param_13,undefined4 param_14,
            undefined4 param_15,int param_16)

{
  float fVar1;
  int iVar2;
  int iVar3;
  undefined4 local_18;
  undefined4 local_14;
  
  iVar3 = *(int *)(param_9 + 0xb8);
  *(uint *)(iVar3 + 0x360) = *(uint *)(iVar3 + 0x360) & 0xfffffffd;
  *(uint *)(iVar3 + 0x360) = *(uint *)(iVar3 + 0x360) | 0x2000;
  param_10[1] = param_10[1] | 0x100000;
  fVar1 = FLOAT_803e8b3c;
  param_10[0xa0] = (uint)FLOAT_803e8b3c;
  param_10[0xa1] = (uint)fVar1;
  *param_10 = *param_10 | 0x200000;
  *(float *)(param_9 + 0x24) = fVar1;
  *(float *)(param_9 + 0x2c) = fVar1;
  param_10[1] = param_10[1] | 0x8000000;
  *(float *)(param_9 + 0x28) = fVar1;
  if (((*(char *)((int)param_10 + 0x27a) != '\0') && (DAT_803df0cc != 0)) &&
     ((*(byte *)(iVar3 + 0x3f4) >> 6 & 1) != 0)) {
    *(undefined *)(iVar3 + 0x8b4) = 1;
    *(byte *)(iVar3 + 0x3f4) = *(byte *)(iVar3 + 0x3f4) & 0xf7 | 8;
  }
  if (*(short *)(param_9 + 0xa0) == 0x41a) {
    if (*(char *)((int)param_10 + 0x346) != '\0') {
      FUN_802abd04(param_9,iVar3 + 4,5);
      param_10[0xc2] = (uint)FUN_802a0730;
      return 0xffffffed;
    }
  }
  else {
    local_18 = *(undefined4 *)(iVar3 + 0x54c);
    local_14 = *(undefined4 *)(iVar3 + 0x550);
    if ((*(char *)(iVar3 + 0x8c8) != 'H') && (*(char *)(iVar3 + 0x8c8) != 'G')) {
      param_12 = 8;
      param_13 = &local_18;
      param_14 = 0;
      param_15 = 0xff;
      param_16 = *DAT_803dd6d0;
      (**(code **)(param_16 + 0x1c))(0x4b,1,1);
    }
    FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x41a,1,param_12,param_13,param_14,param_15,param_16);
    iVar2 = FUN_80021884();
    *(short *)(iVar3 + 0x478) = (short)iVar2;
    *(undefined2 *)(iVar3 + 0x484) = *(undefined2 *)(iVar3 + 0x478);
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(iVar3 + 0x58c);
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar3 + 0x76c);
    *(undefined4 *)(param_9 + 0x14) = *(undefined4 *)(iVar3 + 0x594);
    param_10[0xa8] = (uint)FLOAT_803e8ca4;
  }
  FUN_802abd04(param_9,iVar3 + 4,5);
  return 0;
}

