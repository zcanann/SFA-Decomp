// Function: FUN_802a3e4c
// Entry: 802a3e4c
// Size: 1048 bytes

undefined4
FUN_802a3e4c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
            short *param_9,uint *param_10,undefined4 param_11,undefined4 param_12,
            undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  ushort uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  
  iVar5 = *(int *)(param_9 + 0x5c);
  *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) & 0xfffffffd;
  *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x2000;
  param_10[1] = param_10[1] | 0x100000;
  fVar1 = FLOAT_803e8b3c;
  param_10[0xa0] = (uint)FLOAT_803e8b3c;
  param_10[0xa1] = (uint)fVar1;
  *param_10 = *param_10 | 0x200000;
  *(float *)(param_9 + 0x12) = fVar1;
  *(float *)(param_9 + 0x16) = fVar1;
  param_10[1] = param_10[1] | 0x8000000;
  *(float *)(param_9 + 0x14) = fVar1;
  *param_10 = *param_10 | 0x200000;
  switch(DAT_803dd308) {
  case 0xe:
  case 0x16:
    break;
  default:
    if (*(char *)(iVar5 + 0x606) == '\x10') {
      DAT_803dd308 = 0x1a;
      dVar8 = (double)FLOAT_803e8cd8;
      dVar9 = (double)FLOAT_803e8cdc;
      param_10[0xa8] = (uint)FLOAT_803e8bc0;
    }
    else {
      dVar6 = (double)FLOAT_803e8cd8;
      if ((double)*(float *)(iVar5 + 0x5a8) < dVar6) {
        dVar9 = (double)FLOAT_803e8ce0;
        if ((double)*(float *)(iVar5 + 0x5a8) < dVar9) {
          DAT_803dd308 = 0x12;
          dVar8 = (double)FLOAT_803e8cb0;
          param_10[0xa8] = (uint)FLOAT_803e8ce4;
        }
        else {
          DAT_803dd308 = 0x16;
          param_10[0xa8] = (uint)FLOAT_803e8ce4;
          dVar8 = dVar9;
          dVar9 = dVar6;
        }
      }
      else {
        DAT_803dd308 = 0xe;
        dVar9 = (double)FLOAT_803e8bc8;
        param_10[0xa8] = (uint)FLOAT_803e8ba4;
        dVar8 = dVar6;
      }
    }
    dVar7 = (double)FLOAT_803e8c44;
    dVar8 = (double)(float)((double)((float)((double)*(float *)(iVar5 + 0x5a8) - dVar8) /
                                    (float)(dVar9 - dVar8)) * dVar7);
    dVar6 = (double)FLOAT_803e8b3c;
    if ((dVar6 <= dVar8) && (dVar6 = dVar8, dVar7 < dVar8)) {
      dVar6 = dVar7;
    }
    *(short *)(iVar5 + 0x604) = (short)(int)dVar6;
    FUN_8003042c((double)FLOAT_803e8b3c,dVar8,dVar9,param_4,param_5,param_6,param_7,param_8,param_9,
                 (int)*(short *)(&DAT_80333b50 + DAT_803dd308 * 2),0,param_12,param_13,param_14,
                 param_15,param_16);
    FUN_8002f66c((int)param_9,10);
    iVar3 = FUN_80021884();
    *(short *)(iVar5 + 0x484) = (short)iVar3;
    *(short *)(iVar5 + 0x478) = (short)iVar3;
    param_3 = (double)*(float *)(param_9 + 0x10);
    FUN_8000e054((double)*(float *)(param_9 + 0xc),(double)*(float *)(param_9 + 0xe),param_3,
                 (float *)(param_9 + 6),(float *)(param_9 + 8),(float *)(param_9 + 10),
                 *(int *)(param_9 + 0x18));
    FUN_80063000(param_9,*(short **)(iVar5 + 0x4c4),1);
    *(undefined4 *)(iVar5 + 0x5b4) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(iVar5 + 0x5b8) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(iVar5 + 0x5bc) = *(undefined4 *)(param_9 + 10);
    if (*(int *)(iVar5 + 0x4c4) != 0) {
      FUN_8000e054((double)*(float *)(iVar5 + 0x5d4),(double)*(float *)(iVar5 + 0x5d8),
                   (double)*(float *)(iVar5 + 0x5dc),(float *)(iVar5 + 0x5d4),
                   (float *)(iVar5 + 0x5d8),(float *)(iVar5 + 0x5dc),*(int *)(iVar5 + 0x4c4));
      FUN_8000e054((double)*(float *)(iVar5 + 0x5ec),(double)*(float *)(iVar5 + 0x5f0),
                   (double)*(float *)(iVar5 + 0x5f4),(float *)(iVar5 + 0x5ec),
                   (float *)(iVar5 + 0x5f0),(float *)(iVar5 + 0x5f4),*(int *)(iVar5 + 0x4c4));
      param_3 = (double)*(float *)(iVar5 + 0x600);
      FUN_8000e054((double)*(float *)(iVar5 + 0x5f8),(double)*(float *)(iVar5 + 0x5fc),param_3,
                   (float *)(iVar5 + 0x5f8),(float *)(iVar5 + 0x5fc),(float *)(iVar5 + 0x600),
                   *(int *)(iVar5 + 0x4c4));
      *(float *)(iVar5 + 0x5ac) =
           *(float *)(iVar5 + 0x5ac) - *(float *)(*(int *)(iVar5 + 0x4c4) + 0x10);
      *(float *)(iVar5 + 0x5b0) =
           *(float *)(iVar5 + 0x5b0) - *(float *)(*(int *)(iVar5 + 0x4c4) + 0x10);
      *(undefined *)(iVar5 + 0x609) = 0;
    }
    goto LAB_802a41c8;
  case 0x12:
  case 0x1a:
    if ((param_10[0xc5] & 1) != 0) {
      if (*(short *)(iVar5 + 0x81a) == 0) {
        uVar2 = 0x398;
      }
      else {
        uVar2 = 0x1d;
      }
      FUN_8000bb38((uint)param_9,uVar2);
    }
    if ((((*(byte *)(iVar5 + 0x3f0) >> 5 & 1) != 0) || (DAT_803dd308 == 0x1a)) &&
       ((param_10[0xc5] & 0x80) != 0)) {
      FUN_8000bb38((uint)param_9,0x2f);
    }
  }
  if (*(char *)((int)param_10 + 0x346) == '\0') {
LAB_802a41c8:
    *(float *)(param_9 + 6) =
         *(float *)(param_9 + 0x4c) * (*(float *)(iVar5 + 0x5ec) - *(float *)(iVar5 + 0x5b4)) +
         *(float *)(iVar5 + 0x5b4);
    *(float *)(param_9 + 8) =
         *(float *)(param_9 + 0x4c) * (*(float *)(iVar5 + 0x5f0) - *(float *)(iVar5 + 0x5b8)) +
         *(float *)(iVar5 + 0x5b8);
    dVar6 = (double)*(float *)(iVar5 + 0x5bc);
    *(float *)(param_9 + 10) =
         (float)((double)*(float *)(param_9 + 0x4c) *
                 (double)(float)((double)*(float *)(iVar5 + 0x5f4) - dVar6) + dVar6);
    FUN_8002ee64((double)*(float *)(param_9 + 0x4c),dVar6,param_3,param_4,param_5,param_6,param_7,
                 param_8,(int)param_9,(int)*(short *)(&DAT_80333b54 + DAT_803dd308 * 2),
                 *(undefined2 *)(iVar5 + 0x604));
    FUN_802abd04((int)param_9,iVar5,5);
    uVar4 = 0;
  }
  else {
    param_10[1] = param_10[1] & 0xffefffff;
    FUN_802abd04((int)param_9,iVar5,5);
    *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x800000;
    param_10[0xc2] = (uint)FUN_802a58ac;
    uVar4 = 2;
  }
  return uVar4;
}

