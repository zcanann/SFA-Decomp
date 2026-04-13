// Function: FUN_802a4264
// Entry: 802a4264
// Size: 1056 bytes

undefined4
FUN_802a4264(short *param_1,uint *param_2,undefined4 param_3,undefined4 param_4,undefined4 param_5,
            undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  short sVar1;
  float fVar2;
  ushort uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  undefined2 local_18;
  undefined local_16;
  undefined local_15;
  
  iVar7 = *(int *)(param_1 + 0x5c);
  if (*(char *)((int)param_2 + 0x27a) != '\0') {
    if (*(short *)(iVar7 + 0x81a) == 0) {
      uVar3 = 0x2cb;
    }
    else {
      uVar3 = 0x29;
    }
    FUN_8000bb38((uint)param_1,uVar3);
    *(undefined2 *)(param_2 + 0x9e) = 10;
    *(undefined4 *)(iVar7 + 0x898) = 0;
    *(undefined *)(iVar7 + 0x800) = 0;
    iVar4 = *(int *)(iVar7 + 0x7f8);
    if (iVar4 != 0) {
      if ((*(short *)(iVar4 + 0x46) == 0x3cf) || (*(short *)(iVar4 + 0x46) == 0x662)) {
        FUN_80182a5c(iVar4);
      }
      else {
        FUN_800ea9f8(iVar4);
      }
      *(ushort *)(*(int *)(iVar7 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar7 + 0x7f8) + 6) & 0xbfff;
      *(undefined4 *)(*(int *)(iVar7 + 0x7f8) + 0xf8) = 0;
      *(undefined4 *)(iVar7 + 0x7f8) = 0;
    }
  }
  fVar2 = FLOAT_803e8b3c;
  *(float *)(iVar7 + 0x778) = FLOAT_803e8b3c;
  iVar4 = *(int *)(param_1 + 0x5c);
  *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) & 0xfffffffd;
  *(uint *)(iVar4 + 0x360) = *(uint *)(iVar4 + 0x360) | 0x2000;
  param_2[1] = param_2[1] | 0x100000;
  param_2[0xa0] = (uint)fVar2;
  param_2[0xa1] = (uint)fVar2;
  *param_2 = *param_2 | 0x200000;
  *(float *)(param_1 + 0x12) = fVar2;
  *(float *)(param_1 + 0x16) = fVar2;
  param_2[1] = param_2[1] | 0x8000000;
  *(float *)(param_1 + 0x14) = fVar2;
  sVar1 = param_1[0x50];
  if ((sVar1 == 0x22) || ((sVar1 < 0x22 && (sVar1 == 0xd)))) {
    dVar9 = (double)(*(float *)(param_1 + 0x4c) / FLOAT_803e8bdc);
    dVar8 = (double)FLOAT_803e8b3c;
    if ((dVar8 <= dVar9) && (dVar8 = dVar9, (double)FLOAT_803e8b78 < dVar9)) {
      dVar8 = (double)FLOAT_803e8b78;
    }
    *(float *)(param_1 + 6) =
         (float)(dVar8 * (double)(float)((double)*(float *)(iVar7 + 0x5f8) -
                                        (double)*(float *)(iVar7 + 0x5b4)) +
                (double)*(float *)(iVar7 + 0x5b4));
    dVar9 = (double)*(float *)(iVar7 + 0x5b8);
    *(float *)(param_1 + 8) =
         -(float)((double)*(float *)(param_1 + 0x4c) *
                  (double)(float)(dVar9 - (double)(*(float *)(iVar7 + 0x5ac) -
                                                  *(float *)(iVar7 + 0x874))) - dVar9);
    *(float *)(param_1 + 10) =
         (float)(dVar8 * (double)(float)((double)*(float *)(iVar7 + 0x600) -
                                        (double)*(float *)(iVar7 + 0x5bc)) +
                (double)*(float *)(iVar7 + 0x5bc));
    if (*(char *)((int)param_2 + 0x346) != '\0') {
      FUN_8003042c((double)FLOAT_803e8b3c,(double)*(float *)(param_1 + 0x4c),dVar8,dVar9,in_f5,in_f6
                   ,in_f7,in_f8,param_1,(int)DAT_80333b5c,0,param_4,param_5,param_6,param_7,param_8)
      ;
      param_2[0xa8] = (uint)FLOAT_803e8cd0;
      DAT_803dd308 = 6;
      FUN_802abd04((int)param_1,iVar7 + 4,5);
      param_2[0xc2] = 0;
      return 0xd;
    }
  }
  else {
    uVar5 = FUN_80021884();
    iVar4 = (uVar5 & 0xffff) - (int)*(short *)(iVar7 + 0x478);
    if (0x8000 < iVar4) {
      iVar4 = iVar4 + -0xffff;
    }
    if (iVar4 < -0x8000) {
      iVar4 = iVar4 + 0xffff;
    }
    if (*(char *)(iVar7 + 0x607) == '\x01') {
      iVar6 = 0xb;
    }
    else {
      iVar6 = 10;
    }
    *(short *)(iVar7 + 0x478) = *(short *)(iVar7 + 0x478) + (short)iVar4;
    *(undefined2 *)(iVar7 + 0x484) = *(undefined2 *)(iVar7 + 0x478);
    dVar8 = (double)*(float *)(param_1 + 0xe);
    dVar9 = (double)*(float *)(param_1 + 0x10);
    iVar4 = *(int *)(param_1 + 0x18);
    FUN_8000e054((double)*(float *)(param_1 + 0xc),dVar8,dVar9,(float *)(param_1 + 6),
                 (float *)(param_1 + 8),(float *)(param_1 + 10),iVar4);
    FUN_80063000(param_1,*(short **)(iVar7 + 0x4c4),1);
    *(undefined4 *)(iVar7 + 0x5b4) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(iVar7 + 0x5b8) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(iVar7 + 0x5bc) = *(undefined4 *)(param_1 + 10);
    FUN_8003042c((double)FLOAT_803e8b3c,dVar8,dVar9,in_f4,in_f5,in_f6,in_f7,in_f8,param_1,
                 (int)*(short *)(&DAT_80333b50 + iVar6 * 2),4,iVar4,param_5,param_6,param_7,param_8)
    ;
    param_2[0xa8] = (uint)FLOAT_803e8bcc;
    if ((*(char *)(iVar7 + 0x8c8) != 'H') && (*(char *)(iVar7 + 0x8c8) != 'G')) {
      local_18 = 0;
      local_16 = 0;
      local_15 = 1;
      (**(code **)(*DAT_803dd6d0 + 0x1c))(0x43,1,0,4,&local_18,0,0xff);
    }
    if (*(int *)(iVar7 + 0x4c4) != 0) {
      FUN_8000e054((double)*(float *)(iVar7 + 0x5d4),(double)*(float *)(iVar7 + 0x5d8),
                   (double)*(float *)(iVar7 + 0x5dc),(float *)(iVar7 + 0x5d4),
                   (float *)(iVar7 + 0x5d8),(float *)(iVar7 + 0x5dc),*(int *)(iVar7 + 0x4c4));
      FUN_8000e054((double)*(float *)(iVar7 + 0x5ec),(double)*(float *)(iVar7 + 0x5f0),
                   (double)*(float *)(iVar7 + 0x5f4),(float *)(iVar7 + 0x5ec),
                   (float *)(iVar7 + 0x5f0),(float *)(iVar7 + 0x5f4),*(int *)(iVar7 + 0x4c4));
      FUN_8000e054((double)*(float *)(iVar7 + 0x5f8),(double)*(float *)(iVar7 + 0x5fc),
                   (double)*(float *)(iVar7 + 0x600),(float *)(iVar7 + 0x5f8),
                   (float *)(iVar7 + 0x5fc),(float *)(iVar7 + 0x600),*(int *)(iVar7 + 0x4c4));
      *(float *)(iVar7 + 0x5ac) =
           *(float *)(iVar7 + 0x5ac) - *(float *)(*(int *)(iVar7 + 0x4c4) + 0x10);
      *(float *)(iVar7 + 0x5b0) =
           *(float *)(iVar7 + 0x5b0) - *(float *)(*(int *)(iVar7 + 0x4c4) + 0x10);
      *(undefined *)(iVar7 + 0x609) = 0;
    }
  }
  *(byte *)(iVar7 + 0x8c9) = *(byte *)(iVar7 + 0x8c9) | 4;
  FUN_802abd04((int)param_1,iVar7 + 4,5);
  return 0;
}

