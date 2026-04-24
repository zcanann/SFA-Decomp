// Function: FUN_802c0cc0
// Entry: 802c0cc0
// Size: 736 bytes

undefined4
FUN_802c0cc0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,ushort *param_9,uint *param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  ushort uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  
  iVar7 = *(int *)(param_9 + 0x5c);
  *param_10 = *param_10 | 0x1204000;
  *(undefined *)((int)param_10 + 0x25f) = 0;
  fVar1 = FLOAT_803e903c;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    param_10[0xa5] = (uint)FLOAT_803e903c;
    param_10[0xa1] = (uint)fVar1;
    param_10[0xa0] = (uint)fVar1;
    *(float *)(param_9 + 0x12) = fVar1;
    *(float *)(param_9 + 0x14) = fVar1;
    *(float *)(param_9 + 0x16) = fVar1;
    iVar6 = *(int *)(param_9 + 0x5c);
    iVar5 = *(int *)(param_9 + 0x26);
    *(byte *)(iVar6 + 0xbc0) = *(byte *)(iVar6 + 0xbc0) & 0xfd | 2;
    (**(code **)(*DAT_803dd6e8 + 0x58))((int)*(short *)(iVar5 + 0x1a),0x5de);
    (**(code **)(*DAT_803dd6e8 + 0x5c))((int)*(short *)(iVar6 + 0xbb0));
    *(undefined2 *)(param_10 + 0xce) = 0;
    param_10[0xa8] = (uint)FLOAT_803e908c;
    param_10[0xae] = (uint)FLOAT_803e9090;
    FUN_8003042c((double)FLOAT_803e903c,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,1,0,param_12,param_13,param_14,param_15,param_16);
    *(byte *)(iVar7 + 0xbc0) = *(byte *)(iVar7 + 0xbc0) & 0xfe | 1;
  }
  fVar1 = FLOAT_803e903c;
  param_10[0xa5] = (uint)FLOAT_803e903c;
  param_10[0xa1] = (uint)fVar1;
  param_10[0xa0] = (uint)fVar1;
  *(float *)(param_9 + 0x12) = fVar1;
  *(float *)(param_9 + 0x14) = fVar1;
  *(float *)(param_9 + 0x16) = fVar1;
  *(undefined4 *)(param_9 + 6) = *(undefined4 *)(iVar7 + 0x3c4);
  *(undefined4 *)(param_9 + 8) = *(undefined4 *)(iVar7 + 0x3c8);
  *(undefined4 *)(param_9 + 10) = *(undefined4 *)(iVar7 + 0x3cc);
  uVar3 = FUN_80021884();
  FUN_80293900((double)(*(float *)(iVar7 + 0x3d0) * *(float *)(iVar7 + 0x3d0) +
                       *(float *)(iVar7 + 0x3d8) * *(float *)(iVar7 + 0x3d8)));
  uVar4 = FUN_80021884();
  uVar3 = (uVar3 & 0xffff) - (uint)*param_9;
  if (0x8000 < (int)uVar3) {
    uVar3 = uVar3 - 0xffff;
  }
  if ((int)uVar3 < -0x8000) {
    uVar3 = uVar3 + 0xffff;
  }
  dVar8 = FUN_80021434((double)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) -
                                      DOUBLE_803e9098),(double)FLOAT_803e9094,(double)FLOAT_803dc074
                      );
  *param_9 = (ushort)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                            (int)(short)*param_9 ^ 0x80000000) -
                                          DOUBLE_803e9098) + dVar8);
  uVar4 = (uVar4 & 0xffff) - (uint)param_9[1];
  if (0x8000 < (int)uVar4) {
    uVar4 = uVar4 - 0xffff;
  }
  if ((int)uVar4 < -0x8000) {
    uVar4 = uVar4 + 0xffff;
  }
  dVar8 = FUN_80021434((double)(float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) -
                                      DOUBLE_803e9098),(double)FLOAT_803e9094,(double)FLOAT_803dc074
                      );
  param_9[1] = (ushort)(int)((double)(float)((double)CONCAT44(0x43300000,
                                                              (int)(short)param_9[1] ^ 0x80000000) -
                                            DOUBLE_803e9098) + dVar8);
  param_9[2] = (ushort)((int)uVar3 >> 5);
  uVar2 = param_9[2];
  if ((short)uVar2 < -0x1000) {
    uVar2 = 0xf000;
  }
  else if (0x1000 < (short)uVar2) {
    uVar2 = 0x1000;
  }
  param_9[2] = uVar2;
  return 0;
}

