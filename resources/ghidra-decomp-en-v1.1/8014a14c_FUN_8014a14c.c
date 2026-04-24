// Function: FUN_8014a14c
// Entry: 8014a14c
// Size: 876 bytes

/* WARNING: Removing unreachable block (ram,0x8014a498) */
/* WARNING: Removing unreachable block (ram,0x8014a490) */
/* WARNING: Removing unreachable block (ram,0x8014a488) */
/* WARNING: Removing unreachable block (ram,0x8014a16c) */
/* WARNING: Removing unreachable block (ram,0x8014a164) */
/* WARNING: Removing unreachable block (ram,0x8014a15c) */

void FUN_8014a14c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,uint param_11,uint param_12,uint param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)

{
  undefined4 uVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined2 *unaff_r30;
  int iVar6;
  double dVar7;
  double in_f29;
  double in_f30;
  double dVar8;
  double in_f31;
  double dVar9;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined2 local_5c;
  undefined4 local_58;
  undefined4 local_54;
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
  iVar4 = FUN_8028683c();
  iVar6 = *(int *)(iVar4 + 0x4c);
  local_58 = DAT_803e31e8;
  local_54 = DAT_803e31ec;
  local_68 = DAT_803e31f0;
  local_60 = DAT_803e31f4;
  local_5c = DAT_803e31f8;
  if ((param_11 == 0) || (uVar5 = FUN_8002e144(), (uVar5 & 0xff) == 0)) goto LAB_8014a488;
  uVar5 = param_13 & 0xff;
  if (uVar5 == 1) {
    iVar3 = ((int)(param_11 & 0xf00) >> 8) + -1;
    if (3 < iVar3) {
      iVar3 = 3;
    }
    unaff_r30 = FUN_8002becc(0x30,*(undefined2 *)((int)&local_58 + iVar3 * 2));
  }
  else if (uVar5 == 2) {
    iVar3 = ((int)(param_11 & 0xf000) >> 0xc) + -1;
    if (1 < iVar3) {
      iVar3 = 1;
    }
    unaff_r30 = FUN_8002becc(0x30,*(undefined2 *)((int)&local_68 + iVar3 * 2));
  }
  else if (uVar5 == 3) {
    if (param_11 == 3) {
      unaff_r30 = FUN_8002becc(0x30,0xb);
    }
    else if ((int)param_11 < 3) {
      if (param_11 != 1) goto LAB_8014a488;
      unaff_r30 = FUN_8002becc(0x30,0x2cd);
    }
    else {
      if (param_11 == 5) {
        dVar9 = (double)*(float *)(iVar4 + 0x18);
        dVar8 = (double)*(float *)(iVar4 + 0x1c);
        dVar7 = (double)*(float *)(iVar4 + 0x20);
        iVar6 = *(int *)(iVar4 + 0x4c);
        if (iVar6 != 0) {
          *(undefined4 *)(iVar4 + 0x18) = *(undefined4 *)(iVar6 + 8);
          *(undefined4 *)(iVar4 + 0x1c) = *(undefined4 *)(iVar6 + 0xc);
          *(undefined4 *)(iVar4 + 0x20) = *(undefined4 *)(iVar6 + 0x10);
        }
        local_64 = FLOAT_803e323c;
        DAT_803de6d4 = FUN_80036f50(4,iVar4,(float *)&local_64);
        *(float *)(iVar4 + 0x18) = (float)dVar9;
        *(float *)(iVar4 + 0x1c) = (float)dVar8;
        *(float *)(iVar4 + 0x20) = (float)dVar7;
        if (DAT_803de6d4 != 0) {
          uVar1 = *(undefined4 *)(iVar4 + 0xc);
          *(undefined4 *)(DAT_803de6d4 + 0x18) = uVar1;
          *(undefined4 *)(DAT_803de6d4 + 0xc) = uVar1;
          fVar2 = FLOAT_803e3240 + *(float *)(iVar4 + 0x10);
          *(float *)(DAT_803de6d4 + 0x1c) = fVar2;
          *(float *)(DAT_803de6d4 + 0x10) = fVar2;
          uVar1 = *(undefined4 *)(iVar4 + 0x14);
          *(undefined4 *)(DAT_803de6d4 + 0x20) = uVar1;
          *(undefined4 *)(DAT_803de6d4 + 0x14) = uVar1;
        }
        goto LAB_8014a488;
      }
      if (4 < (int)param_11) goto LAB_8014a488;
      unaff_r30 = FUN_8002becc(0x30,0x2cd);
    }
  }
  else if (uVar5 == 4) {
    if (3 < (int)param_11) {
      param_11 = 3;
    }
    if ((int)param_11 < 1) goto LAB_8014a488;
    unaff_r30 = FUN_8002becc(0x30,*(undefined2 *)((int)&local_64 + param_11 * 2 + 2));
  }
  *(undefined *)(unaff_r30 + 0xd) = 0x14;
  unaff_r30[0x16] = 0xffff;
  unaff_r30[0xe] = 0xffff;
  unaff_r30[0x12] = 0xffff;
  *(undefined4 *)(unaff_r30 + 4) = *(undefined4 *)(iVar4 + 0xc);
  dVar7 = (double)FLOAT_803e322c;
  *(float *)(unaff_r30 + 6) = (float)(dVar7 + (double)*(float *)(iVar4 + 0x10));
  *(undefined4 *)(unaff_r30 + 8) = *(undefined4 *)(iVar4 + 0x14);
  if ((param_12 & 0xff) == 0) {
    unaff_r30[0x17] = 1;
  }
  else {
    unaff_r30[0x17] = 2;
  }
  *(undefined *)(unaff_r30 + 2) = *(undefined *)(iVar6 + 4);
  *(undefined *)(unaff_r30 + 3) = *(undefined *)(iVar6 + 6);
  *(undefined *)((int)unaff_r30 + 5) = *(undefined *)(iVar6 + 5);
  *(undefined *)((int)unaff_r30 + 7) = *(undefined *)(iVar6 + 7);
  DAT_803de6d4 = FUN_8002e088(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                              unaff_r30,5,*(undefined *)(iVar4 + 0xac),0xffffffff,
                              *(uint **)(iVar4 + 0x30),param_14,param_15,param_16);
  if ((*(short *)(DAT_803de6d4 + 0x46) == 0x3cd) || (*(short *)(DAT_803de6d4 + 0x46) == 0xb)) {
    (**(code **)(**(int **)(DAT_803de6d4 + 0x68) + 0x2c))
              ((double)FLOAT_803e31fc,(double)FLOAT_803e3200,(double)FLOAT_803e31fc);
  }
LAB_8014a488:
  FUN_80286888();
  return;
}

