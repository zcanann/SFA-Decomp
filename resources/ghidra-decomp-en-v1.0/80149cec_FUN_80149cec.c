// Function: FUN_80149cec
// Entry: 80149cec
// Size: 876 bytes

/* WARNING: Removing unreachable block (ram,0x8014a030) */
/* WARNING: Removing unreachable block (ram,0x8014a028) */
/* WARNING: Removing unreachable block (ram,0x8014a038) */

void FUN_80149cec(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4,uint param_5)

{
  undefined4 uVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  char cVar5;
  int unaff_r30;
  int iVar6;
  undefined4 uVar7;
  undefined8 in_f29;
  double dVar8;
  undefined8 in_f30;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined2 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar4 = FUN_802860d8();
  iVar6 = *(int *)(iVar4 + 0x4c);
  local_58 = DAT_803e2558;
  local_54 = DAT_803e255c;
  local_68 = DAT_803e2560;
  local_60 = DAT_803e2564;
  local_5c = DAT_803e2568;
  if (param_3 == 0) {
    iVar6 = 0;
    goto LAB_8014a028;
  }
  cVar5 = FUN_8002e04c();
  if (cVar5 == '\0') {
    iVar6 = 0;
    goto LAB_8014a028;
  }
  param_5 = param_5 & 0xff;
  if (param_5 == 1) {
    iVar3 = ((int)(param_3 & 0xf00) >> 8) + -1;
    if (3 < iVar3) {
      iVar3 = 3;
    }
    unaff_r30 = FUN_8002bdf4(0x30,*(undefined2 *)((int)&local_58 + iVar3 * 2));
  }
  else if (param_5 == 2) {
    iVar3 = ((int)(param_3 & 0xf000) >> 0xc) + -1;
    if (1 < iVar3) {
      iVar3 = 1;
    }
    unaff_r30 = FUN_8002bdf4(0x30,*(undefined2 *)((int)&local_68 + iVar3 * 2));
  }
  else if (param_5 == 3) {
    if (param_3 == 3) {
      unaff_r30 = FUN_8002bdf4(0x30,0xb);
    }
    else if ((int)param_3 < 3) {
      if (param_3 != 1) {
LAB_80149f10:
        iVar6 = 0;
        goto LAB_8014a028;
      }
      unaff_r30 = FUN_8002bdf4(0x30,0x2cd);
    }
    else {
      if (param_3 == 5) {
        dVar10 = (double)*(float *)(iVar4 + 0x18);
        dVar9 = (double)*(float *)(iVar4 + 0x1c);
        dVar8 = (double)*(float *)(iVar4 + 0x20);
        iVar6 = *(int *)(iVar4 + 0x4c);
        if (iVar6 != 0) {
          *(undefined4 *)(iVar4 + 0x18) = *(undefined4 *)(iVar6 + 8);
          *(undefined4 *)(iVar4 + 0x1c) = *(undefined4 *)(iVar6 + 0xc);
          *(undefined4 *)(iVar4 + 0x20) = *(undefined4 *)(iVar6 + 0x10);
        }
        local_64 = FLOAT_803e25a8;
        DAT_803dda54 = FUN_80036e58(4,iVar4,&local_64);
        *(float *)(iVar4 + 0x18) = (float)dVar10;
        *(float *)(iVar4 + 0x1c) = (float)dVar9;
        *(float *)(iVar4 + 0x20) = (float)dVar8;
        iVar6 = DAT_803dda54;
        if (DAT_803dda54 != 0) {
          uVar1 = *(undefined4 *)(iVar4 + 0xc);
          *(undefined4 *)(DAT_803dda54 + 0x18) = uVar1;
          *(undefined4 *)(DAT_803dda54 + 0xc) = uVar1;
          fVar2 = FLOAT_803e25ac + *(float *)(iVar4 + 0x10);
          *(float *)(DAT_803dda54 + 0x1c) = fVar2;
          *(float *)(DAT_803dda54 + 0x10) = fVar2;
          uVar1 = *(undefined4 *)(iVar4 + 0x14);
          *(undefined4 *)(DAT_803dda54 + 0x20) = uVar1;
          *(undefined4 *)(DAT_803dda54 + 0x14) = uVar1;
          iVar6 = DAT_803dda54;
        }
        goto LAB_8014a028;
      }
      if (4 < (int)param_3) goto LAB_80149f10;
      unaff_r30 = FUN_8002bdf4(0x30,0x2cd);
    }
  }
  else if (param_5 == 4) {
    if (3 < (int)param_3) {
      param_3 = 3;
    }
    if ((int)param_3 < 1) {
      iVar6 = 0;
      goto LAB_8014a028;
    }
    unaff_r30 = FUN_8002bdf4(0x30,*(undefined2 *)((int)&local_64 + param_3 * 2 + 2));
  }
  *(undefined *)(unaff_r30 + 0x1a) = 0x14;
  *(undefined2 *)(unaff_r30 + 0x2c) = 0xffff;
  *(undefined2 *)(unaff_r30 + 0x1c) = 0xffff;
  *(undefined2 *)(unaff_r30 + 0x24) = 0xffff;
  *(undefined4 *)(unaff_r30 + 8) = *(undefined4 *)(iVar4 + 0xc);
  *(float *)(unaff_r30 + 0xc) = FLOAT_803e2598 + *(float *)(iVar4 + 0x10);
  *(undefined4 *)(unaff_r30 + 0x10) = *(undefined4 *)(iVar4 + 0x14);
  if ((param_4 & 0xff) == 0) {
    *(undefined2 *)(unaff_r30 + 0x2e) = 1;
  }
  else {
    *(undefined2 *)(unaff_r30 + 0x2e) = 2;
  }
  *(undefined *)(unaff_r30 + 4) = *(undefined *)(iVar6 + 4);
  *(undefined *)(unaff_r30 + 6) = *(undefined *)(iVar6 + 6);
  *(undefined *)(unaff_r30 + 5) = *(undefined *)(iVar6 + 5);
  *(undefined *)(unaff_r30 + 7) = *(undefined *)(iVar6 + 7);
  DAT_803dda54 = FUN_8002df90(unaff_r30,5,(int)*(char *)(iVar4 + 0xac),0xffffffff,
                              *(undefined4 *)(iVar4 + 0x30));
  if ((*(short *)(DAT_803dda54 + 0x46) == 0x3cd) ||
     (iVar6 = DAT_803dda54, *(short *)(DAT_803dda54 + 0x46) == 0xb)) {
    (**(code **)(**(int **)(DAT_803dda54 + 0x68) + 0x2c))
              ((double)FLOAT_803e2574,(double)FLOAT_803e256c,(double)FLOAT_803e2574);
    iVar6 = DAT_803dda54;
  }
LAB_8014a028:
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  FUN_80286124(iVar6);
  return;
}

