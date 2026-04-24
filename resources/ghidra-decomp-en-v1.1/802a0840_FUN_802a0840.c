// Function: FUN_802a0840
// Entry: 802a0840
// Size: 732 bytes

undefined4
FUN_802a0840(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,short *param_13,undefined4 param_14,
            undefined4 param_15,int param_16)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  float fStack_28;
  short asStack_24 [4];
  float afStack_1c [2];
  float local_14;
  
  iVar4 = *(int *)(param_9 + 0xb8);
  FUN_802a1b54(param_9,(int)param_10);
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    FUN_80035f84(param_9);
    if ((*(char *)(iVar4 + 0x8c8) != 'H') && (*(char *)(iVar4 + 0x8c8) != 'G')) {
      param_12 = 0;
      param_13 = (short *)0x0;
      param_14 = 0x3c;
      param_15 = 0xff;
      param_16 = *DAT_803dd6d0;
      (**(code **)(param_16 + 0x1c))(0x42,0,1);
    }
    uVar5 = FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,(int)DAT_80333bce,1,param_12,param_13,param_14,param_15,
                         param_16);
    FUN_8002ee64(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                 (int)DAT_80333bd0,0);
    param_10[0xa8] = (uint)FLOAT_803e8bcc;
    param_13 = asStack_24;
    FUN_80027ec4((double)FLOAT_803e8b78,(double)*(float *)(param_9 + 8),
                 *(int **)(*(int *)(param_9 + 0x7c) + *(char *)(param_9 + 0xad) * 4),0,0,afStack_1c,
                 param_13);
    *(float *)(iVar4 + 0x564) = *(float *)(iVar4 + 0x56c) * local_14;
    *(float *)(iVar4 + 0x568) = *(float *)(iVar4 + 0x574) * local_14;
    *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar4 + 0x550);
    *(undefined2 *)(param_10 + 0x9e) = 0x15;
    *(code **)(iVar4 + 0x898) = FUN_802a0730;
  }
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
  FUN_8002f624(param_9,0,1,*(undefined2 *)(iVar4 + 0x5a4));
  if ((param_10[0xc5] & 0x200) != 0) {
    FUN_80014acc((double)FLOAT_803e8ba8);
  }
  dVar8 = (double)*(float *)(param_9 + 0x98);
  if (dVar8 <= (double)FLOAT_803e8c00) {
    (**(code **)(*DAT_803dd6d0 + 0x2c))
              ((double)(float)((double)*(float *)(iVar4 + 0x564) * dVar8 +
                              (double)*(float *)(param_9 + 0xc)),
               -(double)(*(float *)(iVar4 + 0x560) * (float)((double)FLOAT_803e8b78 - dVar8) -
                        *(float *)(param_9 + 0x10)),
               (double)(float)((double)*(float *)(iVar4 + 0x568) * dVar8 +
                              (double)*(float *)(param_9 + 0x14)));
    FUN_802abd04(param_9,iVar4,5);
    uVar2 = 0;
  }
  else {
    *(undefined4 *)(param_9 + 0x18) = *(undefined4 *)(iVar4 + 0x768);
    *(undefined4 *)(param_9 + 0x20) = *(undefined4 *)(iVar4 + 0x770);
    if (*(int *)(param_9 + 0x30) != 0) {
      *(float *)(param_9 + 0x18) = *(float *)(param_9 + 0x18) + FLOAT_803dda58;
      *(float *)(param_9 + 0x20) = *(float *)(param_9 + 0x20) + FLOAT_803dda5c;
    }
    dVar6 = (double)FLOAT_803e8b3c;
    dVar7 = (double)*(float *)(param_9 + 0x20);
    iVar3 = *(int *)(param_9 + 0x30);
    FUN_8000e054((double)*(float *)(param_9 + 0x18),dVar6,dVar7,(float *)(param_9 + 0xc),&fStack_28,
                 (float *)(param_9 + 0x14),iVar3);
    FUN_802abd04(param_9,iVar4,5);
    FUN_8003042c((double)FLOAT_803e8b3c,dVar6,dVar7,dVar8,param_5,param_6,param_7,param_8,param_9,
                 (int)**(short **)(iVar4 + 0x3f8),1,iVar3,param_13,param_14,param_15,param_16);
    *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) | 0x800000;
    param_10[0xc2] = (uint)FUN_802a58ac;
    uVar2 = 0xffffffff;
  }
  return uVar2;
}

