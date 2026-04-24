// Function: FUN_802a1874
// Entry: 802a1874
// Size: 736 bytes

undefined4
FUN_802a1874(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,uint *param_10)

{
  char cVar1;
  float fVar2;
  uint uVar3;
  int iVar4;
  undefined2 uVar5;
  int iVar6;
  short *psVar7;
  undefined4 in_r10;
  undefined4 local_38;
  undefined4 local_34;
  short asStack_30 [4];
  float fStack_28;
  undefined4 local_24;
  
  iVar6 = *(int *)(param_9 + 0xb8);
  *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) & 0xfffffffd;
  *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) | 0x2000;
  param_10[1] = param_10[1] | 0x100000;
  fVar2 = FLOAT_803e8b3c;
  param_10[0xa0] = (uint)FLOAT_803e8b3c;
  param_10[0xa1] = (uint)fVar2;
  *param_10 = *param_10 | 0x200000;
  *(float *)(param_9 + 0x24) = fVar2;
  *(float *)(param_9 + 0x2c) = fVar2;
  param_10[1] = param_10[1] | 0x8000000;
  *(float *)(param_9 + 0x28) = fVar2;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(undefined2 *)(param_10 + 0x9e) = 0x12;
    *(code **)(iVar6 + 0x898) = FUN_802a0730;
    if ((DAT_803df0cc != 0) && ((*(byte *)(iVar6 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar6 + 0x8b4) = 1;
      *(byte *)(iVar6 + 0x3f4) = *(byte *)(iVar6 + 0x3f4) & 0xf7 | 8;
    }
    FUN_80035f84(param_9);
  }
  cVar1 = *(char *)(iVar6 + 0x549);
  if (cVar1 == '\0') {
    param_10[0xa8] = (uint)FLOAT_803e8ca0;
  }
  else {
    param_10[0xa8] = (uint)FLOAT_803e8b90;
  }
  FUN_802a1b54(param_9,(int)param_10);
  fVar2 = FLOAT_803e8b3c;
  if (*(char *)((int)param_10 + 0x27a) == '\0') {
    if (FLOAT_803e8b78 <= *(float *)(param_9 + 0x98)) {
      param_10[0xc2] = (uint)FUN_802a0730;
      return 0x14;
    }
  }
  else {
    param_10[0xa0] = (uint)FLOAT_803e8b3c;
    param_10[0xa1] = (uint)fVar2;
    iVar4 = FUN_80021884();
    *(short *)(iVar6 + 0x478) = (short)iVar4;
    *(undefined2 *)(iVar6 + 0x484) = *(undefined2 *)(iVar6 + 0x478);
    *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(iVar6 + 0x58c);
    *(undefined4 *)(param_9 + 0x14) = *(undefined4 *)(iVar6 + 0x594);
    if (cVar1 == '\0') {
      psVar7 = (short *)&DAT_803dd300;
    }
    else {
      psVar7 = (short *)&DAT_803dd304;
    }
    uVar3 = 0x25;
    if (cVar1 != '\0') {
      uVar3 = 0x65;
    }
    uVar5 = FUN_802a7940((double)FLOAT_803e8b3c,(double)FLOAT_803e8b3c,param_3,param_4,param_5,
                         param_6,param_7,param_8,param_9,(int)*psVar7,(int)psVar7[1],
                         (float *)(iVar6 + 0x598),(float *)(iVar6 + 0x56c),2,uVar3,in_r10);
    *(undefined2 *)(iVar6 + 0x5a4) = uVar5;
    FUN_80027ec4((double)FLOAT_803e8b78,(double)*(float *)(param_9 + 8),
                 *(int **)(*(int *)(param_9 + 0x7c) + *(char *)(param_9 + 0xad) * 4),0,0,&fStack_28,
                 asStack_30);
    fVar2 = FLOAT_803e8b3c;
    *(float *)(iVar6 + 0x564) = FLOAT_803e8b3c;
    *(undefined4 *)(iVar6 + 0x560) = local_24;
    *(float *)(iVar6 + 0x568) = fVar2;
    local_38 = *(undefined4 *)(iVar6 + 0x54c);
    local_34 = *(undefined4 *)(iVar6 + 0x550);
    if ((*(char *)(iVar6 + 0x8c8) != 'H') && (*(char *)(iVar6 + 0x8c8) != 'G')) {
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x4b,1,1,8,&local_38,0,0);
    }
  }
  FUN_8002f624(param_9,0,1,*(undefined2 *)(iVar6 + 0x5a4));
  (**(code **)(*DAT_803dd6d0 + 0x2c))
            ((double)*(float *)(param_9 + 0xc),
             (double)(*(float *)(iVar6 + 0x560) * *(float *)(param_9 + 0x98) +
                     *(float *)(param_9 + 0x10)),(double)*(float *)(param_9 + 0x14));
  FUN_802abd04(param_9,iVar6,5);
  return 0;
}

