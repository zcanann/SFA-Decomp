// Function: FUN_802a2ee0
// Entry: 802a2ee0
// Size: 2060 bytes

/* WARNING: Removing unreachable block (ram,0x802a36c0) */
/* WARNING: Removing unreachable block (ram,0x802a36c8) */

undefined4 FUN_802a2ee0(double param_1,short *param_2,uint *param_3)

{
  float fVar1;
  float fVar2;
  short sVar3;
  float fVar4;
  float fVar5;
  undefined2 uVar7;
  undefined4 uVar6;
  int iVar8;
  int iVar9;
  undefined4 uVar10;
  double in_f30;
  undefined8 in_f31;
  double dVar11;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,SUB84(in_f30,0),0);
  iVar9 = *(int *)(param_2 + 0x5c);
  fVar1 = *(float *)(iVar9 + 0x5ac) - *(float *)(iVar9 + 0x874);
  dVar11 = (double)fVar1;
  if (*(char *)((int)param_3 + 0x27a) != '\0') {
    *(undefined2 *)(param_3 + 0x9e) = 0xc;
    *(undefined4 *)(iVar9 + 0x898) = 0;
    *(float *)(param_2 + 0x14) = FLOAT_803e7ea4;
  }
  fVar5 = FLOAT_803e7ea4;
  *(float *)(iVar9 + 0x778) = FLOAT_803e7ea4;
  iVar8 = *(int *)(param_2 + 0x5c);
  *(uint *)(iVar8 + 0x360) = *(uint *)(iVar8 + 0x360) & 0xfffffffd;
  *(uint *)(iVar8 + 0x360) = *(uint *)(iVar8 + 0x360) | 0x2000;
  param_3[1] = param_3[1] | 0x100000;
  param_3[0xa0] = (uint)fVar5;
  param_3[0xa1] = (uint)fVar5;
  *param_3 = *param_3 | 0x200000;
  *(float *)(param_2 + 0x12) = fVar5;
  *(float *)(param_2 + 0x16) = fVar5;
  param_3[1] = param_3[1] | 0x8000000;
  DAT_803dc6a2 = DAT_803dc6a0;
  switch(DAT_803dc6a0) {
  case 0:
    fVar1 = (float)((double)*(float *)(param_2 + 8) - (double)*(float *)(iVar9 + 0x5b8)) /
            (float)(dVar11 - (double)*(float *)(iVar9 + 0x5b8));
    *(float *)(param_2 + 6) =
         fVar1 * (*(float *)(iVar9 + 0x5f8) - *(float *)(iVar9 + 0x5b4)) + *(float *)(iVar9 + 0x5b4)
    ;
    *(float *)(param_2 + 10) =
         fVar1 * (*(float *)(iVar9 + 0x600) - *(float *)(iVar9 + 0x5bc)) + *(float *)(iVar9 + 0x5bc)
    ;
    (**(code **)(*DAT_803dca8c + 0x20))(param_2,param_3,0x14);
    *(float *)(param_2 + 8) = (float)param_3[0xad] * FLOAT_803db414 + *(float *)(param_2 + 8);
    if (*(char *)((int)param_3 + 0x346) != '\0') {
      DAT_803dc6a0 = 2;
      in_f30 = (double)FLOAT_803e7ef8;
      if (FLOAT_803e8030 * -((float)((double)FLOAT_803e7f10 + dVar11) - *(float *)(param_2 + 8)) <
          FLOAT_803e7ea4) {
        *(float *)(param_2 + 0x14) = FLOAT_803e7ea4;
      }
      else {
        dVar11 = (double)FUN_802931a0();
        *(float *)(param_2 + 0x14) = (float)dVar11;
      }
      if (*(short *)(iVar9 + 0x81a) == 0) {
        uVar6 = 0x2d5;
      }
      else {
        uVar6 = 0x2d4;
      }
      FUN_8000bb18(param_2,uVar6);
    }
    break;
  default:
    DAT_803dc6a0 = 0;
    DAT_803dc6a2 = 0;
    param_3[0xa8] = (uint)FLOAT_803e803c;
    FUN_80030334((double)FLOAT_803e7ea4,param_2,(int)*(short *)(&DAT_80332ef0 + DAT_803dc6a0 * 2),0)
    ;
    FUN_8002f574(param_2,10);
    uVar7 = FUN_800217c0((double)*(float *)(iVar9 + 0x5c4),(double)*(float *)(iVar9 + 0x5cc));
    *(undefined2 *)(iVar9 + 0x484) = uVar7;
    *(undefined2 *)(iVar9 + 0x478) = uVar7;
    *(float *)(param_2 + 0x14) = FLOAT_803e7ea4;
    FUN_8000e034((double)*(float *)(param_2 + 0xc),(double)*(float *)(param_2 + 0xe),
                 (double)*(float *)(param_2 + 0x10),param_2 + 6,param_2 + 8,param_2 + 10,
                 *(undefined4 *)(param_2 + 0x18));
    FUN_80062e84(param_2,*(undefined4 *)(iVar9 + 0x4c4),1);
    *(undefined4 *)(iVar9 + 0x5b4) = *(undefined4 *)(param_2 + 6);
    *(undefined4 *)(iVar9 + 0x5b8) = *(undefined4 *)(param_2 + 8);
    *(undefined4 *)(iVar9 + 0x5bc) = *(undefined4 *)(param_2 + 10);
    if (*(int *)(iVar9 + 0x4c4) != 0) {
      FUN_8000e034((double)*(float *)(iVar9 + 0x5d4),(double)*(float *)(iVar9 + 0x5d8),
                   (double)*(float *)(iVar9 + 0x5dc),iVar9 + 0x5d4,iVar9 + 0x5d8,iVar9 + 0x5dc);
      FUN_8000e034((double)*(float *)(iVar9 + 0x5ec),(double)*(float *)(iVar9 + 0x5f0),
                   (double)*(float *)(iVar9 + 0x5f4),iVar9 + 0x5ec,iVar9 + 0x5f0,iVar9 + 0x5f4,
                   *(undefined4 *)(iVar9 + 0x4c4));
      FUN_8000e034((double)*(float *)(iVar9 + 0x5f8),(double)*(float *)(iVar9 + 0x5fc),
                   (double)*(float *)(iVar9 + 0x600),iVar9 + 0x5f8,iVar9 + 0x5fc,iVar9 + 0x600,
                   *(undefined4 *)(iVar9 + 0x4c4));
      *(float *)(iVar9 + 0x5ac) =
           *(float *)(iVar9 + 0x5ac) - *(float *)(*(int *)(iVar9 + 0x4c4) + 0x10);
      *(float *)(iVar9 + 0x5b0) =
           *(float *)(iVar9 + 0x5b0) - *(float *)(*(int *)(iVar9 + 0x4c4) + 0x10);
      *(undefined *)(iVar9 + 0x609) = 0;
    }
    break;
  case 2:
    if ((double)*(float *)(param_2 + 8) < dVar11) {
      *(float *)(param_2 + 0x14) =
           (float)((double)FLOAT_803e7e88 * param_1 + (double)*(float *)(param_2 + 0x14));
      fVar1 = (float)((double)*(float *)(param_2 + 8) - (double)*(float *)(iVar9 + 0x5b8)) /
              (float)(dVar11 - (double)*(float *)(iVar9 + 0x5b8));
      *(float *)(param_2 + 6) =
           fVar1 * (*(float *)(iVar9 + 0x5f8) - *(float *)(iVar9 + 0x5b4)) +
           *(float *)(iVar9 + 0x5b4);
      *(float *)(param_2 + 10) =
           fVar1 * (*(float *)(iVar9 + 0x600) - *(float *)(iVar9 + 0x5bc)) +
           *(float *)(iVar9 + 0x5bc);
    }
    else {
      DAT_803dc6a0 = 3;
      in_f30 = (double)FLOAT_803e800c;
      *(float *)(param_2 + 0x14) = fVar5;
      *(undefined4 *)(param_2 + 6) = *(undefined4 *)(iVar9 + 0x5f8);
      *(float *)(param_2 + 8) = fVar1;
      *(undefined4 *)(param_2 + 10) = *(undefined4 *)(iVar9 + 0x600);
    }
    break;
  case 3:
    *(undefined4 *)(iVar9 + 0x5b4) = *(undefined4 *)(param_2 + 6);
    *(undefined4 *)(iVar9 + 0x5b8) = *(undefined4 *)(param_2 + 8);
    *(undefined4 *)(iVar9 + 0x5bc) = *(undefined4 *)(param_2 + 10);
    if (FLOAT_803e7f48 < *(float *)(param_2 + 0x4c)) {
      if ((float)param_3[0xa3] <= FLOAT_803e7f10) {
        if (FLOAT_803e801c <= (float)param_3[0xa3]) {
          if (*(char *)((int)param_3 + 0x346) != '\0') {
            DAT_803dc6a0 = 6;
            in_f30 = (double)FLOAT_803e8038;
          }
        }
        else {
          *(int *)(iVar9 + 0x5c0) = (int)*param_2;
          DAT_803dc6a0 = 7;
          in_f30 = (double)FLOAT_803e8034;
          *(float *)(param_2 + 0x14) = fVar5;
        }
      }
      else {
        DAT_803dc6a0 = 5;
        in_f30 = (double)FLOAT_803e8024;
        if (*(short *)(iVar9 + 0x81a) == 0) {
          uVar6 = 0x398;
        }
        else {
          uVar6 = 0x1d;
        }
        FUN_8000bb18(param_2,uVar6);
        if (*(char *)(iVar9 + 0x608) == '\x05') {
          FUN_8000bb18(param_2,0x2f);
        }
      }
    }
    break;
  case 5:
    fVar1 = *(float *)(param_2 + 0x4c) / FLOAT_803e7f68;
    if ((fVar5 <= fVar1) && (fVar5 = fVar1, FLOAT_803e7ee0 < fVar1)) {
      fVar5 = FLOAT_803e7ee0;
    }
    *(float *)(param_2 + 6) =
         fVar5 * (*(float *)(iVar9 + 0x5ec) - *(float *)(iVar9 + 0x5b4)) + *(float *)(iVar9 + 0x5b4)
    ;
    *(float *)(param_2 + 8) =
         fVar5 * (*(float *)(iVar9 + 0x5f0) - *(float *)(iVar9 + 0x5b8)) + *(float *)(iVar9 + 0x5b8)
    ;
    *(float *)(param_2 + 10) =
         fVar5 * (*(float *)(iVar9 + 0x5f4) - *(float *)(iVar9 + 0x5bc)) + *(float *)(iVar9 + 0x5bc)
    ;
    if (FLOAT_803e7f68 < *(float *)(param_2 + 0x4c)) {
      param_3[1] = param_3[1] & 0xffefffff;
      FUN_802ab5a4(param_2,iVar9,5);
      *(uint *)(iVar9 + 0x360) = *(uint *)(iVar9 + 0x360) | 0x800000;
      param_3[0xc2] = (uint)FUN_802a514c;
      uVar6 = 2;
      goto LAB_802a36c0;
    }
    break;
  case 6:
    *(undefined4 *)(iVar9 + 0x5b4) = *(undefined4 *)(param_2 + 6);
    *(undefined4 *)(iVar9 + 0x5b8) = *(undefined4 *)(param_2 + 8);
    *(undefined4 *)(iVar9 + 0x5bc) = *(undefined4 *)(param_2 + 10);
    if ((float)param_3[0xa3] <= FLOAT_803e7f10) {
      if ((float)param_3[0xa3] < FLOAT_803e801c) {
        *(int *)(iVar9 + 0x5c0) = (int)*param_2;
        DAT_803dc6a0 = 7;
        in_f30 = (double)FLOAT_803e8034;
        *(float *)(param_2 + 0x14) = fVar5;
      }
    }
    else {
      DAT_803dc6a0 = 5;
      in_f30 = (double)FLOAT_803e8024;
      if (*(short *)(iVar9 + 0x81a) == 0) {
        uVar6 = 0x398;
      }
      else {
        uVar6 = 0x1d;
      }
      FUN_8000bb18(param_2,uVar6);
      if (*(char *)(iVar9 + 0x608) == '\x05') {
        FUN_8000bb18(param_2,0x2f);
      }
    }
    break;
  case 7:
    fVar1 = *(float *)(iVar9 + 0x5cc);
    fVar4 = FLOAT_803e7e98 + FLOAT_803dc6c0;
    fVar2 = *(float *)(iVar9 + 0x5dc);
    *(float *)(param_2 + 6) =
         *(float *)(param_2 + 0x4c) *
         ((*(float *)(iVar9 + 0x5c4) * fVar4 + *(float *)(iVar9 + 0x5d4)) -
         *(float *)(iVar9 + 0x5b4)) + *(float *)(iVar9 + 0x5b4);
    *(float *)(param_2 + 10) =
         *(float *)(param_2 + 0x4c) * ((fVar1 * fVar4 + fVar2) - *(float *)(iVar9 + 0x5bc)) +
         *(float *)(iVar9 + 0x5bc);
    *(float *)(param_2 + 0x14) = -(FLOAT_803e7f6c * FLOAT_803db414 - *(float *)(param_2 + 0x14));
    uVar7 = (undefined2)
            (int)-(FLOAT_803e7f98 * *(float *)(param_2 + 0x4c) -
                  (float)((double)CONCAT44(0x43300000,*(uint *)(iVar9 + 0x5c0) ^ 0x80000000) -
                         DOUBLE_803e7ec0));
    *(undefined2 *)(iVar9 + 0x484) = uVar7;
    *(undefined2 *)(iVar9 + 0x478) = uVar7;
    if (*(char *)((int)param_3 + 0x346) != '\0') {
      param_3[0xa5] = (uint)fVar5;
      param_3[0xa0] = (uint)fVar5;
      param_3[0xa1] = (uint)fVar5;
      *(float *)(param_2 + 0x12) = fVar5;
      *(float *)(param_2 + 0x16) = fVar5;
      param_3[1] = param_3[1] & 0xffefffff;
      FUN_802ab5a4(param_2,iVar9,5);
      *(byte *)(iVar9 + 0x3f0) = *(byte *)(iVar9 + 0x3f0) & 0x7f;
      *(byte *)(iVar9 + 0x3f0) = *(byte *)(iVar9 + 0x3f0) & 0xef;
      *(byte *)(iVar9 + 0x3f0) = *(byte *)(iVar9 + 0x3f0) & 0xf7;
      FUN_80170380(DAT_803de450,2);
      *(byte *)(iVar9 + 0x3f0) = *(byte *)(iVar9 + 0x3f0) & 0xfd;
      *(uint *)(iVar9 + 0x360) = *(uint *)(iVar9 + 0x360) | 0x800000;
      FUN_80035ea4(param_2);
      *(byte *)(iVar9 + 0x3f0) = *(byte *)(iVar9 + 0x3f0) & 0xbf;
      *(byte *)(iVar9 + 0x3f0) = *(byte *)(iVar9 + 0x3f0) & 0xfb | 4;
      *(byte *)(iVar9 + 0x3f4) = *(byte *)(iVar9 + 0x3f4) & 0xef | 0x10;
      *(undefined *)(iVar9 + 0x800) = 0;
      if (*(int *)(iVar9 + 0x7f8) != 0) {
        sVar3 = *(short *)(*(int *)(iVar9 + 0x7f8) + 0x46);
        if ((sVar3 == 0x3cf) || (sVar3 == 0x662)) {
          FUN_80182504();
        }
        else {
          FUN_800ea774();
        }
        *(ushort *)(*(int *)(iVar9 + 0x7f8) + 6) = *(ushort *)(*(int *)(iVar9 + 0x7f8) + 6) & 0xbfff
        ;
        *(undefined4 *)(*(int *)(iVar9 + 0x7f8) + 0xf8) = 0;
        *(undefined4 *)(iVar9 + 0x7f8) = 0;
      }
      param_3[0xc2] = (uint)FUN_802a514c;
      uVar6 = 3;
      goto LAB_802a36c0;
    }
  }
  if ((int)DAT_803dc6a2 != (int)DAT_803dc6a0) {
    FUN_80030334((double)FLOAT_803e7ea4,param_2,(int)*(short *)(&DAT_80332ef0 + DAT_803dc6a0 * 2),0)
    ;
    param_3[0xa8] = (uint)(float)in_f30;
  }
  FUN_802ab5a4(param_2,iVar9,5);
  uVar6 = 0;
LAB_802a36c0:
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  __psq_l0(auStack24,uVar10);
  __psq_l1(auStack24,uVar10);
  return uVar6;
}

