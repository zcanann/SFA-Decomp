// Function: FUN_8023f468
// Entry: 8023f468
// Size: 1932 bytes

/* WARNING: Removing unreachable block (ram,0x8023fbc8) */
/* WARNING: Removing unreachable block (ram,0x8023fbd0) */

void FUN_8023f468(short *param_1)

{
  bool bVar1;
  short *psVar2;
  undefined4 uVar3;
  int iVar4;
  short **ppsVar5;
  undefined4 uVar6;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  undefined4 local_58;
  uint uStack84;
  undefined4 local_50;
  uint uStack76;
  undefined4 local_48;
  uint uStack68;
  longlong local_40;
  undefined4 local_38;
  uint uStack52;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar6 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  dVar8 = (double)FLOAT_803dc4f8;
  ppsVar5 = *(short ***)(param_1 + 0x5c);
  if (*ppsVar5 == (short *)0x0) {
    psVar2 = (short *)FUN_8002e0b4(0x47b77);
    *ppsVar5 = psVar2;
  }
  if (ppsVar5[1] == (short *)0x0) {
    psVar2 = (short *)FUN_8022d768();
    ppsVar5[1] = psVar2;
  }
  if (*(char *)((int)ppsVar5 + 0x27) == '\0') {
    *(undefined *)(param_1 + 0x1b) = 0xff;
    param_1[2] = 0;
    param_1[1] = 0;
    FUN_80035df4(param_1,5,2,0xffffffff);
    FUN_80035f20(param_1);
    if (*ppsVar5 != (short *)0x0) {
      *param_1 = **ppsVar5;
      dVar7 = DOUBLE_803e75a0;
      if (*(char *)((int)ppsVar5 + 0x22) != '\0') {
        dVar8 = (double)(float)(dVar8 * (double)FLOAT_803e75b4);
      }
      uStack84 = DAT_803dc4fc ^ 0x80000000;
      local_58 = 0x43300000;
      uStack76 = DAT_803dc500 ^ 0x80000000;
      local_50 = 0x43300000;
      ppsVar5[7] = (short *)((float)ppsVar5[7] +
                            (-(float)ppsVar5[6] /
                             (float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e75a0) -
                            (float)ppsVar5[7]) /
                            (float)((double)CONCAT44(0x43300000,uStack76) - DOUBLE_803e75a0));
      ppsVar5[6] = (short *)((float)ppsVar5[6] + (float)ppsVar5[7]);
      uStack68 = (int)**ppsVar5 ^ 0x80000000;
      local_48 = 0x43300000;
      iVar4 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack68) - dVar7) + dVar8);
      local_40 = (longlong)iVar4;
      uStack52 = (int)(short)iVar4 ^ 0x80000000;
      local_38 = 0x43300000;
      dVar7 = (double)((FLOAT_803e75b8 * (float)((double)CONCAT44(0x43300000,uStack52) - dVar7)) /
                      FLOAT_803e75bc);
      dVar8 = (double)FUN_80293e80(dVar7);
      dVar7 = (double)FUN_80294204(dVar7);
      *(float *)(param_1 + 6) =
           (float)((double)FLOAT_803dc4f0 * dVar8 + (double)*(float *)(*ppsVar5 + 6));
      *(float *)(param_1 + 8) = *(float *)(*ppsVar5 + 8) + FLOAT_803dc4f4;
      *(float *)(param_1 + 10) =
           (float)ppsVar5[6] +
           (float)((double)FLOAT_803dc4f0 * dVar7 + (double)*(float *)(*ppsVar5 + 10));
    }
    bVar1 = *(char *)((int)ppsVar5 + 0x23) != *(char *)(ppsVar5 + 9);
    *(char *)(ppsVar5 + 9) = *(char *)((int)ppsVar5 + 0x23);
    switch(*(undefined *)((int)ppsVar5 + 0x23)) {
    case 0:
      if (bVar1) {
        iVar4 = *(int *)(param_1 + 0x5c);
        FUN_80030334((double)FLOAT_803e75ac,param_1,0,0);
        *(undefined4 *)(iVar4 + 0x14) = DAT_8032c270;
      }
      break;
    case 1:
      if (bVar1) {
        iVar4 = *(int *)(param_1 + 0x5c);
        FUN_80030334((double)FLOAT_803e75ac,param_1,5,0);
        *(undefined4 *)(iVar4 + 0x14) = DAT_8032c284;
      }
      if (FLOAT_803e75b0 <= *(float *)(param_1 + 0x4c)) {
        *(undefined *)((int)ppsVar5 + 0x23) = 3;
      }
      break;
    case 2:
      if (bVar1) {
        iVar4 = *(int *)(param_1 + 0x5c);
        FUN_80030334((double)FLOAT_803e75ac,param_1,4,0);
        *(undefined4 *)(iVar4 + 0x14) = DAT_8032c280;
      }
      if (FLOAT_803e75b0 <= *(float *)(param_1 + 0x4c)) {
        *(undefined *)((int)ppsVar5 + 0x23) = 3;
        *(undefined *)(ppsVar5 + 9) = 3;
      }
      break;
    case 3:
      if (bVar1) {
        iVar4 = *(int *)(param_1 + 0x5c);
        FUN_80030334((double)FLOAT_803e75ac,param_1,0,0);
        *(undefined4 *)(iVar4 + 0x14) = DAT_8032c270;
      }
      break;
    case 4:
      if (bVar1) {
        *(undefined *)((int)ppsVar5 + 0x29) = 0;
        iVar4 = *(int *)(param_1 + 0x5c);
        FUN_80030334((double)FLOAT_803e75ac,param_1,1,0);
        *(undefined4 *)(iVar4 + 0x14) = DAT_8032c274;
      }
      if (*(int *)(*(int *)(param_1 + 0x2a) + 0x50) != 0) {
        local_7c = FLOAT_803e75c4;
        if (*(char *)((int)ppsVar5 + 0x22) != '\0') {
          local_7c = FLOAT_803e75c0;
        }
        local_60 = FLOAT_803e75ac;
        local_5c = FLOAT_803e75ac;
        local_78 = FLOAT_803e75ac;
        local_74 = FLOAT_803e75ac;
        local_64 = local_7c;
        FUN_8022d4ac(ppsVar5[1],&local_7c);
        FUN_80014aa0((double)FLOAT_803e75c8);
      }
      if (DOUBLE_803e75d0 <= (double)*(float *)(param_1 + 0x4c)) {
        ppsVar5[5] = (short *)FLOAT_803e75dc;
      }
      else {
        ppsVar5[5] = (short *)FLOAT_803e75d8;
      }
      if ((FLOAT_803e75e0 <= *(float *)(param_1 + 0x4c)) && (*(char *)((int)ppsVar5 + 0x29) == '\0')
         ) {
        *(undefined *)((int)ppsVar5 + 0x29) = 1;
        FUN_8000bb18(param_1,0x471);
      }
      if (FLOAT_803e75b0 <= *(float *)(param_1 + 0x4c)) {
        FUN_8023a688(*ppsVar5,1);
        *(undefined *)((int)ppsVar5 + 0x23) = 3;
      }
      FUN_8023f1fc(param_1,ppsVar5);
      break;
    case 5:
      if (bVar1) {
        *(undefined *)((int)ppsVar5 + 0x29) = 0;
        iVar4 = *(int *)(param_1 + 0x5c);
        FUN_80030334((double)FLOAT_803e75ac,param_1,2,0);
        *(undefined4 *)(iVar4 + 0x14) = DAT_8032c278;
      }
      if ((*(char *)((int)ppsVar5 + 0x22) != '\0') && (FLOAT_803e75b0 <= *(float *)(param_1 + 0x4c))
         ) {
        FUN_8023a688(*ppsVar5,1);
        *(undefined *)((int)ppsVar5 + 0x23) = 3;
      }
      if (DOUBLE_803e75e8 <= (double)*(float *)(param_1 + 0x4c)) {
        ppsVar5[5] = (short *)FLOAT_803e75dc;
      }
      else {
        ppsVar5[5] = (short *)FLOAT_803e75f0;
      }
      if (*(int *)(*(int *)(param_1 + 0x2a) + 0x50) != 0) {
        local_70 = FLOAT_803e75ac;
        local_6c = FLOAT_803e75f4;
        local_68 = FLOAT_803e75ac;
        local_88 = FLOAT_803e75ac;
        local_84 = FLOAT_803e75f4;
        local_80 = FLOAT_803e75ac;
        FUN_8022d4ac(ppsVar5[1],&local_88);
        FUN_80014aa0((double)FLOAT_803e75c8);
      }
      if (((FLOAT_803e75e0 <= *(float *)(param_1 + 0x4c)) &&
          (*(float *)(param_1 + 0x4c) < FLOAT_803e75f8)) && (*(char *)((int)ppsVar5 + 0x29) == '\0')
         ) {
        *(undefined *)((int)ppsVar5 + 0x29) = 1;
        FUN_8000bb18(param_1,0x472);
      }
      if ((FLOAT_803e75f8 <= *(float *)(param_1 + 0x4c)) && (*(char *)((int)ppsVar5 + 0x29) != '\0')
         ) {
        *(undefined *)((int)ppsVar5 + 0x29) = 0;
        FUN_8000bb18(param_1,0x473);
      }
      if (FLOAT_803e75b0 <= *(float *)(param_1 + 0x4c)) {
        if (*(char *)((int)ppsVar5 + 0x22) != '\0') {
          FUN_8023a688(*ppsVar5,1);
        }
        *(undefined *)((int)ppsVar5 + 0x23) = 3;
      }
      FUN_8023f1fc(param_1,ppsVar5);
      break;
    case 6:
      if (bVar1) {
        iVar4 = *(int *)(param_1 + 0x5c);
        FUN_80030334((double)FLOAT_803e75ac,param_1,3,0);
        *(undefined4 *)(iVar4 + 0x14) = DAT_8032c27c;
        *(undefined2 *)(ppsVar5 + 8) = 0xffff;
      }
      *(ushort *)(ppsVar5 + 8) = *(short *)(ppsVar5 + 8) - (ushort)DAT_803db410;
      if (DOUBLE_803e75d0 <= (double)*(float *)(param_1 + 0x4c)) {
        FUN_8000da58(param_1,0x467);
        ppsVar5[5] = (short *)FLOAT_803e75f0;
        if (*(short *)(ppsVar5 + 8) < 0) {
          FUN_8023f05c(param_1,ppsVar5,0);
          *(short *)(ppsVar5 + 8) = (short)DAT_803dc504;
        }
      }
      else {
        ppsVar5[5] = (short *)FLOAT_803e75f0;
      }
      if (FLOAT_803e75b0 <= *(float *)(param_1 + 0x4c)) {
        FUN_8023a688(*ppsVar5,1);
        *(undefined *)((int)ppsVar5 + 0x23) = 3;
      }
      FUN_8023f1fc(param_1,ppsVar5);
      break;
    case 9:
      if (*(char *)((int)ppsVar5 + 0x22) == '\0') {
        uVar3 = 2;
      }
      else {
        uVar3 = 4;
      }
      FUN_8023a688(*ppsVar5,uVar3);
    }
    if (*(char *)((int)ppsVar5 + 0x23) == '\t') {
      param_1[3] = param_1[3] | 0x4000;
    }
    else {
      param_1[3] = param_1[3] & 0xbfff;
    }
    FUN_8002fa48((double)(float)ppsVar5[5],(double)FLOAT_803db414,param_1,0);
  }
  else {
    *(char *)((int)ppsVar5 + 0x27) = *(char *)((int)ppsVar5 + 0x27) + -1;
  }
  __psq_l0(auStack8,uVar6);
  __psq_l1(auStack8,uVar6);
  __psq_l0(auStack24,uVar6);
  __psq_l1(auStack24,uVar6);
  return;
}

