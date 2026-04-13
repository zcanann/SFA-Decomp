// Function: FUN_802a3640
// Entry: 802a3640
// Size: 2060 bytes

/* WARNING: Removing unreachable block (ram,0x802a3e28) */
/* WARNING: Removing unreachable block (ram,0x802a3e20) */
/* WARNING: Removing unreachable block (ram,0x802a3658) */
/* WARNING: Removing unreachable block (ram,0x802a3650) */

undefined4
FUN_802a3640(double param_1,undefined8 param_2,double param_3,double param_4,double param_5,
            double param_6,undefined8 param_7,undefined8 param_8,short *param_9,uint *param_10,
            undefined4 param_11,int param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  float fVar2;
  float fVar3;
  ushort uVar4;
  undefined2 uVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  double in_f30;
  double dVar10;
  
  iVar7 = *(int *)(param_9 + 0x5c);
  fVar2 = *(float *)(iVar7 + 0x5ac);
  fVar1 = (float)((double)fVar2 - (double)*(float *)(iVar7 + 0x874));
  dVar10 = (double)fVar1;
  if (*(char *)((int)param_10 + 0x27a) != '\0') {
    *(undefined2 *)(param_10 + 0x9e) = 0xc;
    *(undefined4 *)(iVar7 + 0x898) = 0;
    *(float *)(param_9 + 0x14) = FLOAT_803e8b3c;
  }
  fVar3 = FLOAT_803e8b3c;
  dVar8 = (double)FLOAT_803e8b3c;
  *(float *)(iVar7 + 0x778) = FLOAT_803e8b3c;
  iVar6 = *(int *)(param_9 + 0x5c);
  *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) & 0xfffffffd;
  *(uint *)(iVar6 + 0x360) = *(uint *)(iVar6 + 0x360) | 0x2000;
  param_10[1] = param_10[1] | 0x100000;
  param_10[0xa0] = (uint)fVar3;
  param_10[0xa1] = (uint)fVar3;
  *param_10 = *param_10 | 0x200000;
  *(float *)(param_9 + 0x12) = fVar3;
  *(float *)(param_9 + 0x16) = fVar3;
  param_10[1] = param_10[1] | 0x8000000;
  DAT_803dd30a = DAT_803dd308;
  switch(DAT_803dd308) {
  case 0:
    param_3 = (double)((float)((double)*(float *)(param_9 + 8) - (double)*(float *)(iVar7 + 0x5b8))
                      / (float)(dVar10 - (double)*(float *)(iVar7 + 0x5b8)));
    *(float *)(param_9 + 6) =
         (float)(param_3 * (double)(float)((double)*(float *)(iVar7 + 0x5f8) -
                                          (double)*(float *)(iVar7 + 0x5b4)) +
                (double)*(float *)(iVar7 + 0x5b4));
    *(float *)(param_9 + 10) =
         (float)(param_3 * (double)(float)((double)*(float *)(iVar7 + 0x600) -
                                          (double)*(float *)(iVar7 + 0x5bc)) +
                (double)*(float *)(iVar7 + 0x5bc));
    param_12 = *DAT_803dd70c;
    (**(code **)(param_12 + 0x20))(param_9,param_10,0x14);
    dVar9 = (double)(float)param_10[0xad];
    *(float *)(param_9 + 8) =
         (float)(dVar9 * (double)FLOAT_803dc074 + (double)*(float *)(param_9 + 8));
    if (*(char *)((int)param_10 + 0x346) != '\0') {
      DAT_803dd308 = 2;
      in_f30 = (double)FLOAT_803e8b90;
      dVar10 = (double)(FLOAT_803e8cc8 *
                       -((float)((double)FLOAT_803e8ba8 + dVar10) - *(float *)(param_9 + 8)));
      if (dVar10 < (double)FLOAT_803e8b3c) {
        *(float *)(param_9 + 0x14) = FLOAT_803e8b3c;
      }
      else {
        dVar10 = FUN_80293900(dVar10);
        *(float *)(param_9 + 0x14) = (float)dVar10;
      }
      if (*(short *)(iVar7 + 0x81a) == 0) {
        uVar4 = 0x2d5;
      }
      else {
        uVar4 = 0x2d4;
      }
      FUN_8000bb38((uint)param_9,uVar4);
    }
    break;
  default:
    DAT_803dd308 = 0;
    DAT_803dd30a = 0;
    param_10[0xa8] = (uint)FLOAT_803e8cd4;
    FUN_8003042c((double)FLOAT_803e8b3c,(double)fVar2,param_3,param_4,param_5,param_6,param_7,
                 param_8,param_9,(int)*(short *)(&DAT_80333b50 + DAT_803dd308 * 2),0,param_12,
                 param_13,param_14,param_15,param_16);
    FUN_8002f66c((int)param_9,10);
    iVar6 = FUN_80021884();
    *(short *)(iVar7 + 0x484) = (short)iVar6;
    *(short *)(iVar7 + 0x478) = (short)iVar6;
    *(float *)(param_9 + 0x14) = FLOAT_803e8b3c;
    dVar9 = (double)*(float *)(param_9 + 0xe);
    param_3 = (double)*(float *)(param_9 + 0x10);
    FUN_8000e054((double)*(float *)(param_9 + 0xc),dVar9,param_3,(float *)(param_9 + 6),
                 (float *)(param_9 + 8),(float *)(param_9 + 10),*(int *)(param_9 + 0x18));
    FUN_80063000(param_9,*(short **)(iVar7 + 0x4c4),1);
    *(undefined4 *)(iVar7 + 0x5b4) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(iVar7 + 0x5b8) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(iVar7 + 0x5bc) = *(undefined4 *)(param_9 + 10);
    param_12 = *(int *)(iVar7 + 0x4c4);
    if (param_12 != 0) {
      FUN_8000e054((double)*(float *)(iVar7 + 0x5d4),(double)*(float *)(iVar7 + 0x5d8),
                   (double)*(float *)(iVar7 + 0x5dc),(float *)(iVar7 + 0x5d4),
                   (float *)(iVar7 + 0x5d8),(float *)(iVar7 + 0x5dc),param_12);
      FUN_8000e054((double)*(float *)(iVar7 + 0x5ec),(double)*(float *)(iVar7 + 0x5f0),
                   (double)*(float *)(iVar7 + 0x5f4),(float *)(iVar7 + 0x5ec),
                   (float *)(iVar7 + 0x5f0),(float *)(iVar7 + 0x5f4),*(int *)(iVar7 + 0x4c4));
      dVar9 = (double)*(float *)(iVar7 + 0x5fc);
      param_3 = (double)*(float *)(iVar7 + 0x600);
      param_12 = *(int *)(iVar7 + 0x4c4);
      FUN_8000e054((double)*(float *)(iVar7 + 0x5f8),dVar9,param_3,(float *)(iVar7 + 0x5f8),
                   (float *)(iVar7 + 0x5fc),(float *)(iVar7 + 0x600),param_12);
      *(float *)(iVar7 + 0x5ac) =
           *(float *)(iVar7 + 0x5ac) - *(float *)(*(int *)(iVar7 + 0x4c4) + 0x10);
      *(float *)(iVar7 + 0x5b0) =
           *(float *)(iVar7 + 0x5b0) - *(float *)(*(int *)(iVar7 + 0x4c4) + 0x10);
      *(undefined *)(iVar7 + 0x609) = 0;
    }
    break;
  case 2:
    dVar9 = (double)*(float *)(param_9 + 8);
    if (dVar9 < dVar10) {
      *(float *)(param_9 + 0x14) =
           (float)((double)FLOAT_803e8b20 * param_1 + (double)*(float *)(param_9 + 0x14));
      dVar9 = (double)((float)((double)*(float *)(param_9 + 8) - (double)*(float *)(iVar7 + 0x5b8))
                      / (float)(dVar10 - (double)*(float *)(iVar7 + 0x5b8)));
      *(float *)(param_9 + 6) =
           (float)(dVar9 * (double)(float)((double)*(float *)(iVar7 + 0x5f8) -
                                          (double)*(float *)(iVar7 + 0x5b4)) +
                  (double)*(float *)(iVar7 + 0x5b4));
      *(float *)(param_9 + 10) =
           (float)(dVar9 * (double)(float)((double)*(float *)(iVar7 + 0x600) -
                                          (double)*(float *)(iVar7 + 0x5bc)) +
                  (double)*(float *)(iVar7 + 0x5bc));
    }
    else {
      DAT_803dd308 = 3;
      in_f30 = (double)FLOAT_803e8ca4;
      *(float *)(param_9 + 0x14) = fVar3;
      *(undefined4 *)(param_9 + 6) = *(undefined4 *)(iVar7 + 0x5f8);
      *(float *)(param_9 + 8) = fVar1;
      *(undefined4 *)(param_9 + 10) = *(undefined4 *)(iVar7 + 0x600);
    }
    break;
  case 3:
    *(undefined4 *)(iVar7 + 0x5b4) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(iVar7 + 0x5b8) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(iVar7 + 0x5bc) = *(undefined4 *)(param_9 + 10);
    dVar9 = (double)*(float *)(param_9 + 0x4c);
    if ((double)FLOAT_803e8be0 < dVar9) {
      dVar9 = (double)(float)param_10[0xa3];
      if (dVar9 <= (double)FLOAT_803e8ba8) {
        if ((double)FLOAT_803e8cb4 <= dVar9) {
          if (*(char *)((int)param_10 + 0x346) != '\0') {
            DAT_803dd308 = 6;
            in_f30 = (double)FLOAT_803e8cd0;
          }
        }
        else {
          *(int *)(iVar7 + 0x5c0) = (int)*param_9;
          DAT_803dd308 = 7;
          in_f30 = (double)FLOAT_803e8ccc;
          *(float *)(param_9 + 0x14) = fVar3;
        }
      }
      else {
        DAT_803dd308 = 5;
        in_f30 = (double)FLOAT_803e8cbc;
        if (*(short *)(iVar7 + 0x81a) == 0) {
          uVar4 = 0x398;
        }
        else {
          uVar4 = 0x1d;
        }
        FUN_8000bb38((uint)param_9,uVar4);
        if (*(char *)(iVar7 + 0x608) == '\x05') {
          FUN_8000bb38((uint)param_9,0x2f);
        }
      }
    }
    break;
  case 5:
    dVar10 = (double)(*(float *)(param_9 + 0x4c) / FLOAT_803e8c00);
    if ((dVar8 <= dVar10) && (dVar8 = dVar10, (double)FLOAT_803e8b78 < dVar10)) {
      dVar8 = (double)FLOAT_803e8b78;
    }
    *(float *)(param_9 + 6) =
         (float)(dVar8 * (double)(float)((double)*(float *)(iVar7 + 0x5ec) -
                                        (double)*(float *)(iVar7 + 0x5b4)) +
                (double)*(float *)(iVar7 + 0x5b4));
    *(float *)(param_9 + 8) =
         (float)(dVar8 * (double)(float)((double)*(float *)(iVar7 + 0x5f0) -
                                        (double)*(float *)(iVar7 + 0x5b8)) +
                (double)*(float *)(iVar7 + 0x5b8));
    dVar9 = (double)*(float *)(iVar7 + 0x5bc);
    *(float *)(param_9 + 10) =
         (float)(dVar8 * (double)(float)((double)*(float *)(iVar7 + 0x5f4) - dVar9) + dVar9);
    if (FLOAT_803e8c00 < *(float *)(param_9 + 0x4c)) {
      param_10[1] = param_10[1] & 0xffefffff;
      FUN_802abd04((int)param_9,iVar7,5);
      *(uint *)(iVar7 + 0x360) = *(uint *)(iVar7 + 0x360) | 0x800000;
      param_10[0xc2] = (uint)FUN_802a58ac;
      return 2;
    }
    break;
  case 6:
    *(undefined4 *)(iVar7 + 0x5b4) = *(undefined4 *)(param_9 + 6);
    *(undefined4 *)(iVar7 + 0x5b8) = *(undefined4 *)(param_9 + 8);
    *(undefined4 *)(iVar7 + 0x5bc) = *(undefined4 *)(param_9 + 10);
    dVar9 = (double)(float)param_10[0xa3];
    if (dVar9 <= (double)FLOAT_803e8ba8) {
      if (dVar9 < (double)FLOAT_803e8cb4) {
        *(int *)(iVar7 + 0x5c0) = (int)*param_9;
        DAT_803dd308 = 7;
        in_f30 = (double)FLOAT_803e8ccc;
        *(float *)(param_9 + 0x14) = fVar3;
      }
    }
    else {
      DAT_803dd308 = 5;
      in_f30 = (double)FLOAT_803e8cbc;
      if (*(short *)(iVar7 + 0x81a) == 0) {
        uVar4 = 0x398;
      }
      else {
        uVar4 = 0x1d;
      }
      FUN_8000bb38((uint)param_9,uVar4);
      if (*(char *)(iVar7 + 0x608) == '\x05') {
        FUN_8000bb38((uint)param_9,0x2f);
      }
    }
    break;
  case 7:
    param_6 = (double)(*(float *)(iVar7 + 0x5cc) * (FLOAT_803e8b30 + FLOAT_803dd328) +
                      *(float *)(iVar7 + 0x5dc));
    param_5 = (double)*(float *)(iVar7 + 0x5b4);
    *(float *)(param_9 + 6) =
         (float)((double)*(float *)(param_9 + 0x4c) *
                 (double)(float)((double)(*(float *)(iVar7 + 0x5c4) *
                                          (FLOAT_803e8b30 + FLOAT_803dd328) +
                                         *(float *)(iVar7 + 0x5d4)) - param_5) + param_5);
    *(float *)(param_9 + 10) =
         (float)((double)*(float *)(param_9 + 0x4c) *
                 (double)(float)(param_6 - (double)*(float *)(iVar7 + 0x5bc)) +
                (double)*(float *)(iVar7 + 0x5bc));
    *(float *)(param_9 + 0x14) = -(FLOAT_803e8c04 * FLOAT_803dc074 - *(float *)(param_9 + 0x14));
    dVar9 = DOUBLE_803e8b58;
    param_4 = (double)FLOAT_803e8c30;
    param_3 = (double)*(float *)(param_9 + 0x4c);
    uVar5 = (undefined2)
            (int)-(float)(param_4 * param_3 -
                         (double)(float)((double)CONCAT44(0x43300000,
                                                          *(uint *)(iVar7 + 0x5c0) ^ 0x80000000) -
                                        DOUBLE_803e8b58));
    *(undefined2 *)(iVar7 + 0x484) = uVar5;
    *(undefined2 *)(iVar7 + 0x478) = uVar5;
    if (*(char *)((int)param_10 + 0x346) != '\0') {
      param_10[0xa5] = (uint)fVar3;
      param_10[0xa0] = (uint)fVar3;
      param_10[0xa1] = (uint)fVar3;
      *(float *)(param_9 + 0x12) = fVar3;
      *(float *)(param_9 + 0x16) = fVar3;
      param_10[1] = param_10[1] & 0xffefffff;
      FUN_802abd04((int)param_9,iVar7,5);
      *(byte *)(iVar7 + 0x3f0) = *(byte *)(iVar7 + 0x3f0) & 0x7f;
      *(byte *)(iVar7 + 0x3f0) = *(byte *)(iVar7 + 0x3f0) & 0xef;
      *(byte *)(iVar7 + 0x3f0) = *(byte *)(iVar7 + 0x3f0) & 0xf7;
      FUN_8017082c();
      *(byte *)(iVar7 + 0x3f0) = *(byte *)(iVar7 + 0x3f0) & 0xfd;
      *(uint *)(iVar7 + 0x360) = *(uint *)(iVar7 + 0x360) | 0x800000;
      FUN_80035f9c((int)param_9);
      *(byte *)(iVar7 + 0x3f0) = *(byte *)(iVar7 + 0x3f0) & 0xbf;
      *(byte *)(iVar7 + 0x3f0) = *(byte *)(iVar7 + 0x3f0) & 0xfb | 4;
      *(byte *)(iVar7 + 0x3f4) = *(byte *)(iVar7 + 0x3f4) & 0xef | 0x10;
      *(undefined *)(iVar7 + 0x800) = 0;
      iVar6 = *(int *)(iVar7 + 0x7f8);
      if (iVar6 != 0) {
        if ((*(short *)(iVar6 + 0x46) == 0x3cf) || (*(short *)(iVar6 + 0x46) == 0x662)) {
          FUN_80182a5c(iVar6);
        }
        else {
          FUN_800ea9f8(iVar6);
        }
        *(ushort *)(*(int *)(iVar7 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar7 + 0x7f8) + 6) & 0xbfff
        ;
        *(undefined4 *)(*(int *)(iVar7 + 0x7f8) + 0xf8) = 0;
        *(undefined4 *)(iVar7 + 0x7f8) = 0;
      }
      param_10[0xc2] = (uint)FUN_802a58ac;
      return 3;
    }
  }
  if ((int)DAT_803dd30a != (int)DAT_803dd308) {
    FUN_8003042c((double)FLOAT_803e8b3c,dVar9,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,(int)*(short *)(&DAT_80333b50 + DAT_803dd308 * 2),0,param_12,param_13,
                 param_14,param_15,param_16);
    param_10[0xa8] = (uint)(float)in_f30;
  }
  FUN_802abd04((int)param_9,iVar7,5);
  return 0;
}

