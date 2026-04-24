// Function: FUN_802a1114
// Entry: 802a1114
// Size: 736 bytes

undefined4 FUN_802a1114(int param_1,uint *param_2)

{
  char cVar1;
  float fVar2;
  undefined4 uVar3;
  undefined2 uVar4;
  int iVar5;
  short *psVar6;
  undefined4 local_38;
  undefined4 local_34;
  undefined auStack48 [8];
  undefined auStack40 [4];
  undefined4 local_24;
  
  iVar5 = *(int *)(param_1 + 0xb8);
  *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) & 0xfffffffd;
  *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x2000;
  param_2[1] = param_2[1] | 0x100000;
  fVar2 = FLOAT_803e7ea4;
  param_2[0xa0] = (uint)FLOAT_803e7ea4;
  param_2[0xa1] = (uint)fVar2;
  *param_2 = *param_2 | 0x200000;
  *(float *)(param_1 + 0x24) = fVar2;
  *(float *)(param_1 + 0x2c) = fVar2;
  param_2[1] = param_2[1] | 0x8000000;
  *(float *)(param_1 + 0x28) = fVar2;
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    *(undefined2 *)(param_2 + 0x9e) = 0x12;
    *(code **)(iVar5 + 0x898) = FUN_8029ffd0;
    if ((DAT_803de44c != 0) && ((*(byte *)(iVar5 + 0x3f4) >> 6 & 1) != 0)) {
      *(undefined *)(iVar5 + 0x8b4) = 1;
      *(byte *)(iVar5 + 0x3f4) = *(byte *)(iVar5 + 0x3f4) & 0xf7 | 8;
    }
    FUN_80035e8c(param_1);
  }
  cVar1 = *(char *)(iVar5 + 0x549);
  if (cVar1 == '\0') {
    param_2[0xa8] = (uint)FLOAT_803e8008;
  }
  else {
    param_2[0xa8] = (uint)FLOAT_803e7ef8;
  }
  FUN_802a13f4(param_1,param_2);
  fVar2 = FLOAT_803e7ea4;
  if (*(char *)((int)param_2 + 0x27a) == '\0') {
    if (FLOAT_803e7ee0 <= *(float *)(param_1 + 0x98)) {
      param_2[0xc2] = (uint)FUN_8029ffd0;
      return 0x14;
    }
  }
  else {
    param_2[0xa0] = (uint)FLOAT_803e7ea4;
    param_2[0xa1] = (uint)fVar2;
    uVar4 = FUN_800217c0((double)*(float *)(iVar5 + 0x56c),(double)*(float *)(iVar5 + 0x574));
    *(undefined2 *)(iVar5 + 0x478) = uVar4;
    *(undefined2 *)(iVar5 + 0x484) = *(undefined2 *)(iVar5 + 0x478);
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(iVar5 + 0x58c);
    *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(iVar5 + 0x594);
    if (cVar1 == '\0') {
      psVar6 = (short *)&DAT_803dc698;
    }
    else {
      psVar6 = (short *)&DAT_803dc69c;
    }
    uVar3 = 0x25;
    if (cVar1 != '\0') {
      uVar3 = 0x65;
    }
    uVar4 = FUN_802a71e0((double)FLOAT_803e7ea4,(double)FLOAT_803e7ea4,param_1,(int)*psVar6,
                         (int)psVar6[1],iVar5 + 0x598,iVar5 + 0x56c,2,uVar3);
    *(undefined2 *)(iVar5 + 0x5a4) = uVar4;
    FUN_80027e00((double)FLOAT_803e7ee0,(double)*(float *)(param_1 + 8),
                 *(undefined4 *)(*(int *)(param_1 + 0x7c) + *(char *)(param_1 + 0xad) * 4),0,0,
                 auStack40,auStack48);
    fVar2 = FLOAT_803e7ea4;
    *(float *)(iVar5 + 0x564) = FLOAT_803e7ea4;
    *(undefined4 *)(iVar5 + 0x560) = local_24;
    *(float *)(iVar5 + 0x568) = fVar2;
    local_38 = *(undefined4 *)(iVar5 + 0x54c);
    local_34 = *(undefined4 *)(iVar5 + 0x550);
    if ((*(char *)(iVar5 + 0x8c8) != 'H') && (*(char *)(iVar5 + 0x8c8) != 'G')) {
      (**(code **)(*DAT_803dca50 + 0x1c))(0x4b,1,1,8,&local_38,0,0);
    }
  }
  FUN_8002f52c(param_1,0,1,(int)*(short *)(iVar5 + 0x5a4));
  (**(code **)(*DAT_803dca50 + 0x2c))
            ((double)*(float *)(param_1 + 0xc),
             (double)(*(float *)(iVar5 + 0x560) * *(float *)(param_1 + 0x98) +
                     *(float *)(param_1 + 0x10)),(double)*(float *)(param_1 + 0x14));
  FUN_802ab5a4(param_1,iVar5,5);
  return 0;
}

