// Function: FUN_80112cc4
// Entry: 80112cc4
// Size: 856 bytes

/* WARNING: Removing unreachable block (ram,0x80112ffc) */
/* WARNING: Removing unreachable block (ram,0x80112ff4) */
/* WARNING: Removing unreachable block (ram,0x80112fec) */
/* WARNING: Removing unreachable block (ram,0x80112ce4) */
/* WARNING: Removing unreachable block (ram,0x80112cdc) */
/* WARNING: Removing unreachable block (ram,0x80112cd4) */

void FUN_80112cc4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  undefined4 uVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint in_r6;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined2 *unaff_r30;
  int iVar7;
  undefined8 extraout_f1;
  double in_f29;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar11;
  float local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar11 = FUN_80286840();
  iVar4 = (int)((ulonglong)uVar11 >> 0x20);
  uVar6 = (uint)uVar11;
  iVar7 = *(int *)(iVar4 + 0x4c);
  dVar8 = (double)FLOAT_803e28ac;
  local_5c = DAT_803e2898;
  local_58 = DAT_803e289c;
  local_64 = DAT_803e28a0;
  local_60 = DAT_803e28a4;
  if ((uVar6 != 0) && (uVar11 = extraout_f1, uVar5 = FUN_8002e144(), (uVar5 & 0xff) != 0)) {
    if ((*(ushort *)(iVar7 + 0x22) & 0xf00) != 0) {
      iVar3 = ((int)(uVar6 & 0xf00) >> 8) + -1;
      if (3 < iVar3) {
        iVar3 = 3;
      }
      unaff_r30 = FUN_8002becc(0x30,*(undefined2 *)((int)&local_5c + iVar3 * 2));
      dVar8 = (double)FLOAT_803e28d4;
    }
    if (((int)*(short *)(iVar7 + 0x22) & 0xf000U) != 0) {
      iVar3 = ((int)(uVar6 & 0xf000) >> 0xc) + -1;
      if (3 < iVar3) {
        iVar3 = 3;
      }
      unaff_r30 = FUN_8002becc(0x30,*(undefined2 *)((int)&local_64 + iVar3 * 2));
      dVar8 = (double)FLOAT_803e28d4;
    }
    if ((*(ushort *)(iVar7 + 0x22) & 0xff) != 0) {
      if (uVar6 == 4) {
        unaff_r30 = FUN_8002becc(0x30,0x2cd);
        dVar8 = (double)FLOAT_803e28d4;
      }
      else if ((int)uVar6 < 4) {
        if (uVar6 == 2) {
          unaff_r30 = FUN_8002becc(0x30,9);
          dVar8 = (double)FLOAT_803e28d4;
        }
        else if ((int)uVar6 < 2) {
          if ((int)uVar6 < 1) goto LAB_80112fec;
          unaff_r30 = FUN_8002becc(0x30,0x2cd);
          dVar8 = (double)FLOAT_803e28d4;
        }
        else {
          unaff_r30 = FUN_8002becc(0x30,0xb);
          dVar8 = (double)FLOAT_803e28d4;
        }
      }
      else {
        if (uVar6 != 6) {
          if ((int)uVar6 < 6) {
            dVar10 = (double)*(float *)(iVar4 + 0x18);
            dVar9 = (double)*(float *)(iVar4 + 0x1c);
            dVar8 = (double)*(float *)(iVar4 + 0x20);
            iVar7 = *(int *)(iVar4 + 0x4c);
            if (iVar7 != 0) {
              *(undefined4 *)(iVar4 + 0x18) = *(undefined4 *)(iVar7 + 8);
              *(undefined4 *)(iVar4 + 0x1c) = *(undefined4 *)(iVar7 + 0xc);
              *(undefined4 *)(iVar4 + 0x20) = *(undefined4 *)(iVar7 + 0x10);
            }
            local_68 = FLOAT_803e28d8;
            DAT_803de25c = FUN_80036f50(4,iVar4,&local_68);
            *(float *)(iVar4 + 0x18) = (float)dVar10;
            *(float *)(iVar4 + 0x1c) = (float)dVar9;
            *(float *)(iVar4 + 0x20) = (float)dVar8;
            if (DAT_803de25c != 0) {
              uVar1 = *(undefined4 *)(iVar4 + 0xc);
              *(undefined4 *)(DAT_803de25c + 0x18) = uVar1;
              *(undefined4 *)(DAT_803de25c + 0xc) = uVar1;
              fVar2 = *(float *)(iVar4 + 0x10) + FLOAT_803e28dc;
              *(float *)(DAT_803de25c + 0x1c) = fVar2;
              *(float *)(DAT_803de25c + 0x10) = fVar2;
              uVar1 = *(undefined4 *)(iVar4 + 0x14);
              *(undefined4 *)(DAT_803de25c + 0x20) = uVar1;
              *(undefined4 *)(DAT_803de25c + 0x14) = uVar1;
            }
          }
          goto LAB_80112fec;
        }
        unaff_r30 = FUN_8002becc(0x30,0x6a6);
        *(undefined *)((int)unaff_r30 + 0x1b) = 0;
        *(undefined *)(unaff_r30 + 0x11) = 0;
        *(undefined *)((int)unaff_r30 + 0x23) = 0x40;
        dVar8 = (double)FLOAT_803e28e0;
      }
    }
    *(undefined *)(unaff_r30 + 0xd) = 0x14;
    unaff_r30[0x16] = 0xffff;
    unaff_r30[0xe] = 0xffff;
    unaff_r30[0x12] = 0xffff;
    *(undefined4 *)(unaff_r30 + 4) = *(undefined4 *)(iVar4 + 0xc);
    *(float *)(unaff_r30 + 6) = (float)((double)*(float *)(iVar4 + 0x10) + dVar8);
    *(undefined4 *)(unaff_r30 + 8) = *(undefined4 *)(iVar4 + 0x14);
    if ((in_r6 & 0xff) == 0) {
      unaff_r30[0x17] = 1;
    }
    else {
      unaff_r30[0x17] = 2;
    }
    *(undefined *)(unaff_r30 + 2) = *(undefined *)(iVar7 + 4);
    *(undefined *)(unaff_r30 + 3) = *(undefined *)(iVar7 + 6);
    *(undefined *)((int)unaff_r30 + 5) = *(undefined *)(iVar7 + 5);
    *(undefined *)((int)unaff_r30 + 7) = *(undefined *)(iVar7 + 7);
    DAT_803de25c = FUN_8002e088(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                unaff_r30,5,*(undefined *)(iVar4 + 0xac),0xffffffff,
                                *(uint **)(iVar4 + 0x30),in_r8,in_r9,in_r10);
  }
LAB_80112fec:
  FUN_8028688c();
  return;
}

