// Function: FUN_802abfbc
// Entry: 802abfbc
// Size: 880 bytes

/* WARNING: Removing unreachable block (ram,0x802ac300) */
/* WARNING: Removing unreachable block (ram,0x802ac2f8) */
/* WARNING: Removing unreachable block (ram,0x802ac308) */

void FUN_802abfbc(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  undefined8 uVar6;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar7;
  undefined8 in_f31;
  double dVar8;
  float local_a8;
  float local_a4;
  float local_a0;
  float local_9c;
  float local_98;
  float local_94;
  double local_90;
  double local_88;
  undefined4 local_80;
  uint uStack124;
  undefined4 local_78;
  uint uStack116;
  longlong local_70;
  double local_50;
  double local_48;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  dVar5 = (double)FUN_80292b44((double)FLOAT_803e7ff4,(double)FLOAT_803db414);
  local_90 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x4d0) ^ 0x80000000);
  iVar3 = (int)((double)(float)(local_90 - DOUBLE_803e7ec0) * dVar5);
  local_88 = (double)(longlong)iVar3;
  *(short *)(param_3 + 0x4d0) = (short)iVar3;
  iVar3 = *(int *)(param_3 + 0x4b8);
  if ((iVar3 == 0) || (*(char *)(*(int *)(iVar3 + 0x50) + 0x58) == '\0')) {
    dVar5 = (double)FUN_80292b44((double)FLOAT_803e7f1c,(double)FLOAT_803db414);
    local_48 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x4d6) ^ 0x80000000);
    *(short *)(param_3 + 0x4d6) = (short)(int)((double)(float)(local_48 - DOUBLE_803e7ec0) * dVar5);
  }
  else {
    FUN_8003842c(param_1,5,&local_a0,&local_a4,&local_a8,0);
    iVar1 = FUN_800395d8(iVar3,0);
    if (iVar1 == 0) {
      local_9c = *(float *)(iVar3 + 0xc);
      local_98 = *(float *)(iVar3 + 0x10);
      local_94 = *(float *)(iVar3 + 0x14);
    }
    else {
      FUN_80039510(iVar3,0,&local_9c);
    }
    dVar8 = (double)(local_9c - local_a0);
    dVar7 = (double)(local_98 - local_a4);
    dVar5 = (double)(local_94 - local_a8);
    uVar6 = FUN_802931a0((double)(float)(dVar8 * dVar8 + (double)(float)(dVar5 * dVar5)));
    uVar2 = FUN_800217c0(-dVar7,uVar6);
    uVar2 = (uVar2 & 0xffff) - ((int)*(short *)(param_3 + 0x4d6) & 0xffffU);
    if (0x8000 < (int)uVar2) {
      uVar2 = uVar2 - 0xffff;
    }
    if ((int)uVar2 < -0x8000) {
      uVar2 = uVar2 + 0xffff;
    }
    local_88 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    uStack124 = (uint)((float)(local_88 - DOUBLE_803e7ec0) * FLOAT_803e7eb4);
    local_90 = (double)(longlong)(int)uStack124;
    uStack124 = uStack124 ^ 0x80000000;
    local_80 = 0x43300000;
    uStack116 = (int)*(short *)(param_3 + 0x4d6) ^ 0x80000000;
    local_78 = 0x43300000;
    iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e7ec0) * FLOAT_803db414
                 + (float)((double)CONCAT44(0x43300000,uStack116) - DOUBLE_803e7ec0));
    local_70 = (longlong)iVar3;
    *(short *)(param_3 + 0x4d6) = (short)iVar3;
    uVar2 = FUN_800217c0(-dVar8,-dVar5);
    iVar3 = (uVar2 & 0xffff) - ((int)*(short *)(param_3 + 0x478) & 0xffffU);
    if (0x8000 < iVar3) {
      iVar3 = iVar3 + -0xffff;
    }
    if (iVar3 < -0x8000) {
      iVar3 = iVar3 + 0xffff;
    }
    if (iVar3 < -0x1c70) {
      iVar3 = -0x1c70;
    }
    else if (0x1c70 < iVar3) {
      iVar3 = 0x1c70;
    }
    uVar2 = iVar3 - ((int)*(short *)(param_3 + 0x4d4) & 0xffffU);
    if (0x8000 < (int)uVar2) {
      uVar2 = uVar2 - 0xffff;
    }
    if ((int)uVar2 < -0x8000) {
      uVar2 = uVar2 + 0xffff;
    }
    local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(param_3 + 0x4d4) ^ 0x80000000);
    *(short *)(param_3 + 0x4d4) =
         (short)(int)((float)((double)CONCAT44(0x43300000,
                                               (int)((float)((double)CONCAT44(0x43300000,
                                                                              uVar2 ^ 0x80000000) -
                                                            DOUBLE_803e7ec0) * FLOAT_803e7eb4) ^
                                               0x80000000) - DOUBLE_803e7ec0) * FLOAT_803db414 +
                     (float)(local_50 - DOUBLE_803e7ec0));
    *(short *)(param_3 + 0x4d2) = *(short *)(param_3 + 0x4d4) / 2;
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  __psq_l0(auStack24,uVar4);
  __psq_l1(auStack24,uVar4);
  __psq_l0(auStack40,uVar4);
  __psq_l1(auStack40,uVar4);
  return;
}

