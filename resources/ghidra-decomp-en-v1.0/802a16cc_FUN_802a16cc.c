// Function: FUN_802a16cc
// Entry: 802a16cc
// Size: 1500 bytes

/* WARNING: Removing unreachable block (ram,0x802a1c7c) */
/* WARNING: Removing unreachable block (ram,0x802a1c84) */

undefined4 FUN_802a16cc(double param_1,int param_2,uint *param_3)

{
  char cVar1;
  short sVar2;
  float fVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 uVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  undefined8 in_f30;
  undefined8 in_f31;
  undefined auStack56 [12];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  iVar5 = *(int *)(param_2 + 0xb8);
  if (*(char *)((int)param_3 + 0x27a) != '\0') {
    FUN_80035e8c();
    FLOAT_803de498 = FLOAT_803e7ea4;
    FUN_80030334(param_2,0x35,1);
    param_3[0xa8] = (uint)FLOAT_803e7f20;
    *(undefined4 *)(iVar5 + 0x500) = *(undefined4 *)(param_2 + 0x10);
    *(undefined4 *)(param_2 + 0x10) = *(undefined4 *)(iVar5 + 0x76c);
    FUN_802ab5a4(param_2,iVar5,5);
  }
  if (FLOAT_803e7fa0 < *(float *)(iVar5 + 0x838)) {
    FUN_802ab5a4(param_2,iVar5,5);
    FUN_802ae83c(param_2,iVar5,param_3);
    param_3[0xc2] = (uint)FUN_802a514c;
    uVar4 = 2;
    goto LAB_802a1c7c;
  }
  param_3[1] = param_3[1] | 0x100000;
  param_3[1] = param_3[1] | 0x8000000;
  *param_3 = *param_3 | 0x200000;
  sVar2 = *(short *)(param_2 + 0xa0);
  if (sVar2 == 0x36) {
LAB_802a1814:
    dVar7 = (double)(FLOAT_803e7ed8 * -FLOAT_803de498);
    if ((param_3[0xc5] & 1) != 0) {
      FUN_8000bb18(param_2,0x210);
    }
    dVar10 = (double)(*(float *)(param_2 + 0x10) - (FLOAT_803e8010 + *(float *)(iVar5 + 0x4ec)));
    if (dVar10 < (double)FLOAT_803e7ea4) {
      dVar10 = (double)FLOAT_803e7ea4;
    }
    if (dVar7 <= dVar10) {
      if ((double)FLOAT_803e8014 < (double)*(float *)(param_2 + 0x28)) {
        *(float *)(param_2 + 0x28) =
             -(float)((double)FLOAT_803e7f6c * param_1 - (double)*(float *)(param_2 + 0x28));
      }
      if (*(float *)(param_2 + 0x28) < FLOAT_803e8014) {
        *(float *)(param_2 + 0x28) = FLOAT_803e8014;
      }
      if (*(float *)(param_2 + 0x28) < FLOAT_803de498) {
        FLOAT_803de498 = *(float *)(param_2 + 0x28);
      }
    }
    else {
      dVar7 = (double)FUN_802931a0((double)(float)((double)(float)((double)FLOAT_803e7ed4 *
                                                                  (double)((FLOAT_803de498 *
                                                                           FLOAT_803de498) /
                                                                          (float)((double)
                                                  FLOAT_803e7ed4 * dVar7))) * dVar10));
      *(float *)(param_2 + 0x28) = (float)-dVar7;
      if (FLOAT_803e7fec <= *(float *)(param_2 + 0x28)) {
        cVar1 = *(char *)(iVar5 + 0x8c8);
        if (((cVar1 != 'H') && (cVar1 != 'G')) && (cVar1 != 'B')) {
          (**(code **)(*DAT_803dca50 + 0x1c))(0x42,0,1,0,0,0,0xff);
          *(undefined *)(iVar5 + 0x8c8) = 0x42;
        }
        *(undefined4 *)(iVar5 + 0x500) = *(undefined4 *)(param_2 + 0x10);
        uVar4 = *(undefined4 *)(iVar5 + 0x4ec);
        *(undefined4 *)(param_2 + 0x1c) = uVar4;
        *(undefined4 *)(param_2 + 0x10) = uVar4;
        fVar3 = FLOAT_803e7ea4;
        if (-1 < *(char *)(iVar5 + 0x547)) {
          param_3[0xa5] = (uint)FLOAT_803e7ea4;
          param_3[0xa1] = (uint)fVar3;
          param_3[0xa0] = (uint)fVar3;
          *(float *)(param_2 + 0x24) = fVar3;
          *(float *)(param_2 + 0x28) = fVar3;
          *(float *)(param_2 + 0x2c) = fVar3;
          FUN_802ab5a4(param_2,iVar5,5);
          *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0x7f;
          *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xef;
          *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xf7;
          FUN_80170380(DAT_803de450,2);
          *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xfd;
          *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x800000;
          FUN_80035ea4(param_2);
          *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xbf;
          *(byte *)(iVar5 + 0x3f0) = *(byte *)(iVar5 + 0x3f0) & 0xfb | 4;
          *(byte *)(iVar5 + 0x3f4) = *(byte *)(iVar5 + 0x3f4) & 0xef | 0x10;
          *(undefined *)(iVar5 + 0x800) = 0;
          if (*(int *)(iVar5 + 0x7f8) != 0) {
            sVar2 = *(short *)(*(int *)(iVar5 + 0x7f8) + 0x46);
            if ((sVar2 == 0x3cf) || (sVar2 == 0x662)) {
              FUN_80182504();
            }
            else {
              FUN_800ea774();
            }
            *(ushort *)(*(int *)(iVar5 + 0x7f8) + 6) =
                 *(ushort *)(*(int *)(iVar5 + 0x7f8) + 6) & 0xbfff;
            *(undefined4 *)(*(int *)(iVar5 + 0x7f8) + 0xf8) = 0;
            *(undefined4 *)(iVar5 + 0x7f8) = 0;
          }
          param_3[0xc2] = (uint)FUN_802a514c;
          uVar4 = 3;
          goto LAB_802a1c7c;
        }
        FUN_80030334((double)FLOAT_803e7ea4,param_2,0x37,1);
        param_3[0xa8] = (uint)FLOAT_803e7fcc;
        *(float *)(param_2 + 0x28) = FLOAT_803e7ea4;
      }
    }
  }
  else if (sVar2 < 0x36) {
    if (0x34 < sVar2) {
      if (*(char *)((int)param_3 + 0x346) != '\0') {
        FUN_80030334((double)FLOAT_803e7ea4,param_2,0x36,0);
        param_3[0xa8] = (uint)FLOAT_803e7f20;
      }
      goto LAB_802a1814;
    }
  }
  else if (sVar2 < 0x38) {
    if ((param_3[0xc5] & 1) != 0) {
      uVar4 = FUN_8006ed24(*(undefined *)(iVar5 + 0x86c),*(undefined *)(iVar5 + 0x8a5));
      FUN_8000bb18(param_2,uVar4);
      FUN_80014aa0((double)FLOAT_803e7f10);
      if (FLOAT_803e7ea4 < *(float *)(iVar5 + 0x838)) {
        (**(code **)(*DAT_803dca98 + 0x10))
                  ((double)*(float *)(param_2 + 0xc),(double)*(float *)(param_2 + 0x10),
                   (double)*(float *)(param_2 + 0x14),(double)FLOAT_803e8018,param_2);
      }
    }
    if (*(char *)((int)param_3 + 0x346) != '\0') {
      *(undefined4 *)(param_2 + 0x18) = *(undefined4 *)(iVar5 + 0x768);
      *(undefined4 *)(param_2 + 0x20) = *(undefined4 *)(iVar5 + 0x770);
      if (*(int *)(param_2 + 0x30) != 0) {
        *(float *)(param_2 + 0x18) = *(float *)(param_2 + 0x18) + FLOAT_803dcdd8;
        *(float *)(param_2 + 0x20) = *(float *)(param_2 + 0x20) + FLOAT_803dcddc;
      }
      FUN_8000e034((double)*(float *)(param_2 + 0x18),(double)FLOAT_803e7ea4,
                   (double)*(float *)(param_2 + 0x20),param_2 + 0xc,auStack56,param_2 + 0x14,
                   *(undefined4 *)(param_2 + 0x30));
      FUN_802ab5a4(param_2,iVar5,5);
      FUN_80030334((double)FLOAT_803e7ea4,param_2,(int)**(short **)(iVar5 + 0x3f8),1);
      *(uint *)(iVar5 + 0x360) = *(uint *)(iVar5 + 0x360) | 0x800000;
      param_3[0xc2] = (uint)FUN_802a514c;
      uVar4 = 2;
      goto LAB_802a1c7c;
    }
  }
  dVar7 = (double)*(float *)(param_2 + 0xc);
  dVar10 = (double)*(float *)(param_2 + 0x14);
  sVar2 = *(short *)(param_2 + 0xa0);
  if (sVar2 == 0x36) {
LAB_802a1c50:
    dVar8 = (double)*(float *)(param_2 + 0x10);
  }
  else if (sVar2 < 0x36) {
    if (sVar2 < 0x35) goto LAB_802a1c50;
    dVar8 = (double)(*(float *)(param_2 + 0x98) *
                     (*(float *)(param_2 + 0x10) - *(float *)(iVar5 + 0x500)) +
                    *(float *)(iVar5 + 0x500));
  }
  else {
    if (0x37 < sVar2) goto LAB_802a1c50;
    dVar9 = (double)*(float *)(param_2 + 0x98);
    dVar7 = (double)(float)(dVar9 * (double)(float)((double)*(float *)(iVar5 + 0x768) - dVar7) +
                           dVar7);
    dVar8 = (double)((float)((double)FLOAT_803e7ee0 - dVar9) *
                     (*(float *)(iVar5 + 0x500) - *(float *)(param_2 + 0x10)) +
                    *(float *)(param_2 + 0x10));
    dVar10 = (double)(float)(dVar9 * (double)(float)((double)*(float *)(iVar5 + 0x770) - dVar10) +
                            dVar10);
  }
  (**(code **)(*DAT_803dca50 + 0x2c))(dVar7,dVar8,dVar10);
  FUN_802ab5a4(param_2,iVar5,5);
  uVar4 = 0;
LAB_802a1c7c:
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  return uVar4;
}

