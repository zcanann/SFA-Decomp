// Function: FUN_8013fbe4
// Entry: 8013fbe4
// Size: 732 bytes

/* WARNING: Removing unreachable block (ram,0x8013fe90) */
/* WARNING: Removing unreachable block (ram,0x8013fc30) */
/* WARNING: Removing unreachable block (ram,0x8013fe98) */

void FUN_8013fbe4(int param_1,char **param_2)

{
  byte bVar1;
  bool bVar2;
  float fVar3;
  uint uVar4;
  float *pfVar5;
  char *pcVar6;
  int iVar7;
  undefined4 uVar8;
  double dVar9;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  double dVar11;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  if (*(char *)((int)param_2 + 10) != '\x01') {
    if (*(char *)((int)param_2 + 10) != '\0') goto LAB_8013fe90;
    uVar4 = FUN_8001ffb4(0x48b);
    *(byte *)(param_2 + 0x1c0) = (byte)((uVar4 & 0xff) << 4) | *(byte *)(param_2 + 0x1c0) & 0xf;
    param_2[0x1c4] = (char *)0x0;
    *(undefined *)((int)param_2 + 10) = 1;
  }
  uVar4 = FUN_8001ffb4(0x48b);
  bVar1 = *(byte *)(param_2 + 0x1c0) >> 4;
  if (bVar1 != uVar4) {
    *(byte *)(param_2 + 0x1c0) = (bVar1 + 1) * '\x10' | *(byte *)(param_2 + 0x1c0) & 0xf;
    **param_2 = **param_2 + -2;
  }
  pfVar5 = (float *)FUN_801cde70(param_2[9]);
  pcVar6 = (char *)FUN_801638bc();
  if ((pcVar6 == (char *)0x0) || (**param_2 == '\0')) {
    *(undefined *)(param_2 + 2) = 1;
    *(undefined *)((int)param_2 + 10) = 0;
    fVar3 = FLOAT_803e23dc;
    param_2[0x1c7] = (char *)FLOAT_803e23dc;
    param_2[0x1c8] = (char *)fVar3;
    param_2[0x15] = (char *)((uint)param_2[0x15] & 0xffffffef);
    param_2[0x15] = (char *)((uint)param_2[0x15] & 0xfffeffff);
    param_2[0x15] = (char *)((uint)param_2[0x15] & 0xfffdffff);
    param_2[0x15] = (char *)((uint)param_2[0x15] & 0xfffbffff);
    *(undefined *)((int)param_2 + 0xd) = 0xff;
  }
  else {
    if ((pcVar6 != param_2[0x1c4]) && ((char **)param_2[10] != param_2 + 0x1c1)) {
      param_2[10] = (char *)(param_2 + 0x1c1);
      param_2[0x15] = (char *)((uint)param_2[0x15] & 0xfffffbff);
      *(undefined2 *)((int)param_2 + 0xd2) = 0;
    }
    dVar11 = (double)(*pfVar5 - *(float *)(param_1 + 0x18));
    dVar10 = (double)(pfVar5[2] - *(float *)(param_1 + 0x20));
    dVar9 = (double)FUN_802931a0((double)(float)(dVar11 * dVar11 + (double)(float)(dVar10 * dVar10))
                                );
    if ((double)FLOAT_803e23dc != dVar9) {
      dVar11 = (double)(float)(dVar11 / dVar9);
      dVar10 = (double)(float)(dVar10 / dVar9);
    }
    dVar9 = (double)FLOAT_803e24d4;
    param_2[0x1c1] = (char *)-(float)(dVar9 * dVar11 - (double)*(float *)(pcVar6 + 0x18));
    param_2[0x1c2] = *(char **)(pcVar6 + 0x1c);
    param_2[0x1c3] = (char *)-(float)(dVar9 * dVar10 - (double)*(float *)(pcVar6 + 0x20));
    iVar7 = FUN_8013b368((double)FLOAT_803e2488,param_1,param_2);
    if (iVar7 == 0) {
      if (FLOAT_803e23dc == (float)param_2[0xab]) {
        bVar2 = false;
      }
      else if (FLOAT_803e2410 == (float)param_2[0xac]) {
        bVar2 = true;
      }
      else if ((float)param_2[0xad] - (float)param_2[0xac] <= FLOAT_803e2414) {
        bVar2 = false;
      }
      else {
        bVar2 = true;
      }
      if (bVar2) {
        FUN_8013a3f0((double)FLOAT_803e243c,param_1,8,0);
        param_2[0x1e7] = (char *)FLOAT_803e2440;
        param_2[0x20e] = (char *)FLOAT_803e23dc;
        FUN_80148bc8(s_in_water_8031d46c);
      }
      else {
        FUN_8013a3f0((double)FLOAT_803e2444,param_1,0,0);
        FUN_80148bc8(s_out_of_water_8031d478);
      }
    }
  }
LAB_8013fe90:
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  return;
}

