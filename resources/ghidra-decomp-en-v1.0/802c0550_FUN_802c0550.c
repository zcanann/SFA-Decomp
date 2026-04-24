// Function: FUN_802c0550
// Entry: 802c0550
// Size: 736 bytes

undefined4 FUN_802c0550(short *param_1,uint *param_2)

{
  float fVar1;
  short sVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined8 uVar8;
  double dVar9;
  
  iVar7 = *(int *)(param_1 + 0x5c);
  *param_2 = *param_2 | 0x1204000;
  *(undefined *)((int)param_2 + 0x25f) = 0;
  fVar1 = FLOAT_803e83a4;
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    param_2[0xa5] = (uint)FLOAT_803e83a4;
    param_2[0xa1] = (uint)fVar1;
    param_2[0xa0] = (uint)fVar1;
    *(float *)(param_1 + 0x12) = fVar1;
    *(float *)(param_1 + 0x14) = fVar1;
    *(float *)(param_1 + 0x16) = fVar1;
    iVar6 = *(int *)(param_1 + 0x5c);
    iVar5 = *(int *)(param_1 + 0x26);
    *(byte *)(iVar6 + 0xbc0) = *(byte *)(iVar6 + 0xbc0) & 0xfd | 2;
    (**(code **)(*DAT_803dca68 + 0x58))((int)*(short *)(iVar5 + 0x1a),0x5de);
    (**(code **)(*DAT_803dca68 + 0x5c))((int)*(short *)(iVar6 + 0xbb0));
    *(undefined2 *)(param_2 + 0xce) = 0;
    param_2[0xa8] = (uint)FLOAT_803e83f4;
    param_2[0xae] = (uint)FLOAT_803e83f8;
    FUN_80030334((double)FLOAT_803e83a4,param_1,1,0);
    *(byte *)(iVar7 + 0xbc0) = *(byte *)(iVar7 + 0xbc0) & 0xfe | 1;
  }
  fVar1 = FLOAT_803e83a4;
  param_2[0xa5] = (uint)FLOAT_803e83a4;
  param_2[0xa1] = (uint)fVar1;
  param_2[0xa0] = (uint)fVar1;
  *(float *)(param_1 + 0x12) = fVar1;
  *(float *)(param_1 + 0x14) = fVar1;
  *(float *)(param_1 + 0x16) = fVar1;
  *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar7 + 0x3c4);
  *(undefined4 *)(param_1 + 8) = *(undefined4 *)(iVar7 + 0x3c8);
  *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar7 + 0x3cc);
  uVar3 = FUN_800217c0(-(double)*(float *)(iVar7 + 0x3d0),-(double)*(float *)(iVar7 + 0x3d8));
  uVar8 = FUN_802931a0((double)(*(float *)(iVar7 + 0x3d0) * *(float *)(iVar7 + 0x3d0) +
                               *(float *)(iVar7 + 0x3d8) * *(float *)(iVar7 + 0x3d8)));
  uVar4 = FUN_800217c0((double)*(float *)(iVar7 + 0x3d4),uVar8);
  uVar3 = (uVar3 & 0xffff) - ((int)*param_1 & 0xffffU);
  if (0x8000 < (int)uVar3) {
    uVar3 = uVar3 - 0xffff;
  }
  if ((int)uVar3 < -0x8000) {
    uVar3 = uVar3 + 0xffff;
  }
  dVar9 = (double)FUN_80021370((double)(float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) -
                                              DOUBLE_803e8400),(double)FLOAT_803e83fc,
                               (double)FLOAT_803db414);
  *param_1 = (short)(int)((double)(float)((double)CONCAT44(0x43300000,(int)*param_1 ^ 0x80000000) -
                                         DOUBLE_803e8400) + dVar9);
  uVar4 = (uVar4 & 0xffff) - ((int)param_1[1] & 0xffffU);
  if (0x8000 < (int)uVar4) {
    uVar4 = uVar4 - 0xffff;
  }
  if ((int)uVar4 < -0x8000) {
    uVar4 = uVar4 + 0xffff;
  }
  dVar9 = (double)FUN_80021370((double)(float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) -
                                              DOUBLE_803e8400),(double)FLOAT_803e83fc,
                               (double)FLOAT_803db414);
  param_1[1] = (short)(int)((double)(float)((double)CONCAT44(0x43300000,(int)param_1[1] ^ 0x80000000
                                                            ) - DOUBLE_803e8400) + dVar9);
  param_1[2] = (short)((int)uVar3 >> 5);
  sVar2 = param_1[2];
  if (sVar2 < -0x1000) {
    sVar2 = -0x1000;
  }
  else if (0x1000 < sVar2) {
    sVar2 = 0x1000;
  }
  param_1[2] = sVar2;
  return 0;
}

