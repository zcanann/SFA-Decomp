// Function: FUN_800d980c
// Entry: 800d980c
// Size: 1328 bytes

/* WARNING: Removing unreachable block (ram,0x800d9d14) */
/* WARNING: Removing unreachable block (ram,0x800d9d04) */
/* WARNING: Removing unreachable block (ram,0x800d9cfc) */
/* WARNING: Removing unreachable block (ram,0x800d9d0c) */
/* WARNING: Removing unreachable block (ram,0x800d9d1c) */

void FUN_800d980c(undefined8 param_1,undefined8 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6)

{
  float fVar1;
  float fVar2;
  bool bVar3;
  undefined2 *puVar4;
  uint uVar5;
  int iVar6;
  uint *puVar7;
  undefined4 uVar8;
  double extraout_f1;
  double dVar9;
  double dVar10;
  undefined8 in_f27;
  undefined8 in_f28;
  double dVar11;
  undefined8 in_f29;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  undefined8 uVar14;
  undefined2 local_d8;
  undefined2 local_d6;
  undefined2 local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float local_c4;
  undefined auStack192 [64];
  undefined4 local_80;
  uint uStack124;
  longlong local_78;
  undefined4 local_70;
  uint uStack108;
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar8 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  __psq_st0(auStack56,(int)((ulonglong)in_f28 >> 0x20),0);
  __psq_st1(auStack56,(int)in_f28,0);
  __psq_st0(auStack72,(int)((ulonglong)in_f27 >> 0x20),0);
  __psq_st1(auStack72,(int)in_f27,0);
  uVar14 = FUN_802860dc();
  puVar4 = (undefined2 *)((ulonglong)uVar14 >> 0x20);
  puVar7 = (uint *)uVar14;
  bVar3 = true;
  DAT_803dd44e = 0;
  uVar5 = puVar7[0xb4];
  dVar11 = extraout_f1;
  if (uVar5 == 0) {
    puVar7[0xb0] = (uint)FLOAT_803e0570;
  }
  else {
    fVar1 = *(float *)(uVar5 + 0xc) - *(float *)(puVar4 + 6);
    fVar2 = *(float *)(uVar5 + 0x14) - *(float *)(puVar4 + 10);
    dVar9 = (double)FUN_802931a0((double)(fVar1 * fVar1 + fVar2 * fVar2));
    puVar7[0xb0] = (uint)(float)dVar9;
  }
  if (((*puVar7 & 0x8000) != 0) && (*(int *)(puVar4 + 0x60) == 0)) {
    FUN_800d915c(dVar11,puVar4,puVar7,param_6);
    dVar9 = DOUBLE_803e0598;
    uStack124 = (int)*(short *)((int)puVar7 + 0x32e) ^ 0x80000000;
    local_80 = 0x43300000;
    iVar6 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack124) - DOUBLE_803e0598) + dVar11
                 );
    local_78 = (longlong)iVar6;
    *(short *)((int)puVar7 + 0x32e) = (short)iVar6;
    uStack108 = (int)*(short *)((int)puVar7 + 0x32e) ^ 0x80000000;
    local_70 = 0x43300000;
    if (FLOAT_803e05c4 < (float)((double)CONCAT44(0x43300000,uStack108) - dVar9)) {
      *(undefined2 *)((int)puVar7 + 0x32e) = 10000;
    }
  }
  *puVar7 = *puVar7 | 0x8000;
  if (puVar7[0x9f] != 0) {
    local_d8 = *puVar4;
    local_d6 = puVar4[1];
    local_d4 = puVar4[2];
    local_d0 = FLOAT_803e0588;
    local_cc = FLOAT_803e0570;
    local_c8 = FLOAT_803e0570;
    local_c4 = FLOAT_803e0570;
    FUN_80021ee8(auStack192,&local_d8);
    uVar5 = puVar7[0x9f];
    FUN_800226cc((double)FLOAT_803e0570,(double)FLOAT_803e0570,(double)FLOAT_803e0588,auStack192,
                 uVar5,uVar5 + 4,uVar5 + 8);
    uVar5 = puVar7[0x9f];
    FUN_800226cc((double)FLOAT_803e0570,(double)FLOAT_803e0588,(double)FLOAT_803e0570,auStack192,
                 uVar5 + 0xc,uVar5 + 0x10,uVar5 + 0x14);
    uVar5 = puVar7[0x9f];
    FUN_800226cc((double)FLOAT_803e0588,(double)FLOAT_803e0570,(double)FLOAT_803e0570,auStack192,
                 uVar5 + 0x18,uVar5 + 0x1c,uVar5 + 0x20);
  }
  if ((*puVar7 & 0x1000000) == 0) {
    FUN_800d8414(puVar4,puVar7);
  }
  *puVar7 = *puVar7 & 0xffdfffff;
  *(undefined *)((int)puVar7 + 0x34d) = 0;
  DAT_803dd434 = 0;
  *puVar7 = *puVar7 & 0xfff7ffff;
  *(undefined *)(puVar7 + 0xd3) = 0;
  DAT_803dd44f = 0;
  FUN_800d92d0(dVar11,puVar4,puVar7,param_5);
  dVar9 = DOUBLE_803e0598;
  uStack108 = (int)*(short *)(puVar7 + 0xce) ^ 0x80000000;
  local_70 = 0x43300000;
  iVar6 = (int)((double)(float)((double)CONCAT44(0x43300000,uStack108) - DOUBLE_803e0598) + dVar11);
  local_78 = (longlong)iVar6;
  *(short *)(puVar7 + 0xce) = (short)iVar6;
  uStack124 = (int)*(short *)(puVar7 + 0xce) ^ 0x80000000;
  local_80 = 0x43300000;
  if (FLOAT_803e05c4 < (float)((double)CONCAT44(0x43300000,uStack124) - dVar9)) {
    *(undefined2 *)(puVar7 + 0xce) = 10000;
  }
  FLOAT_803dd448 = *(float *)(puVar4 + 6);
  FLOAT_803dd444 = *(float *)(puVar4 + 10);
  iVar6 = FUN_8005b2fc((double)*(float *)(puVar4 + 0xc),(double)*(float *)(puVar4 + 0xe),
                       (double)*(float *)(puVar4 + 0x10));
  if ((iVar6 == -1) && (*(int *)(puVar4 + 0x18) == 0)) {
    *puVar7 = *puVar7 | 0x200000;
    bVar3 = false;
  }
  if ((*puVar7 & 0x1000000) == 0) {
    FUN_800d82a8(dVar11,puVar4,puVar7);
  }
  iVar6 = DAT_803dd430;
  if (DAT_803dd430 != 0) {
    dVar13 = (double)(*(float *)(DAT_803dd430 + 0xc) - FLOAT_803dd448);
    dVar12 = (double)(*(float *)(DAT_803dd430 + 0x14) - FLOAT_803dd444);
    dVar9 = (double)FUN_802931a0((double)(float)(dVar13 * dVar13 + (double)(float)(dVar12 * dVar12))
                                );
    if (dVar9 < (double)FLOAT_803e05bc) {
      dVar10 = (double)FUN_802931a0((double)((*(float *)(puVar4 + 6) - FLOAT_803dd448) *
                                             (*(float *)(puVar4 + 6) - FLOAT_803dd448) +
                                            (*(float *)(puVar4 + 10) - FLOAT_803dd444) *
                                            (*(float *)(puVar4 + 10) - FLOAT_803dd444)));
      if (dVar10 < (double)FLOAT_803e05b4) {
        dVar10 = (double)FLOAT_803e05b4;
      }
      if ((double)FLOAT_803e0588 <= dVar9) {
        if (dVar9 < dVar10) {
          dVar10 = dVar9;
        }
        *(float *)(puVar4 + 6) =
             (float)((double)(float)(dVar13 / dVar9) * dVar10 + (double)FLOAT_803dd448);
        *(float *)(puVar4 + 10) =
             (float)((double)(float)(dVar12 / dVar9) * dVar10 + (double)FLOAT_803dd444);
      }
      else {
        *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(iVar6 + 0xc);
        *(undefined4 *)(puVar4 + 10) = *(undefined4 *)(iVar6 + 0x14);
      }
    }
  }
  DAT_803dd430 = 0;
  if ((((*puVar7 & 0x1000000) == 0) && ((*puVar7 & 0x400000) == 0)) && (bVar3)) {
    (**(code **)(*DAT_803dcaa8 + 0x10))(dVar11,puVar4,puVar7 + 1);
    (**(code **)(*DAT_803dcaa8 + 0x14))(puVar4,puVar7 + 1);
    (**(code **)(*DAT_803dcaa8 + 0x18))(param_2,puVar4,puVar7 + 1);
    if ((*(byte *)(puVar7 + 0x99) & 0x10) == 0) {
      *puVar7 = *puVar7 & 0xfffbffff;
    }
    else {
      *puVar7 = *puVar7 | 0x40000;
    }
    if ((*puVar7 & 0x800000) != 0) {
      if (((*(byte *)(puVar7 + 0x99) & 2) != 0) || (*(char *)((int)puVar7 + 0x262) != '\0')) {
        *(float *)(puVar4 + 0x12) =
             (float)((double)(*(float *)(puVar4 + 6) - *(float *)(*(int *)(puVar4 + 0x2a) + 0x10)) /
                    dVar11);
        *(float *)(puVar4 + 0x16) =
             (float)((double)(*(float *)(puVar4 + 10) - *(float *)(*(int *)(puVar4 + 0x2a) + 0x18))
                    / dVar11);
      }
      *puVar7 = *puVar7 & 0xff7fffff;
    }
  }
  __psq_l0(auStack8,uVar8);
  __psq_l1(auStack8,uVar8);
  __psq_l0(auStack24,uVar8);
  __psq_l1(auStack24,uVar8);
  __psq_l0(auStack40,uVar8);
  __psq_l1(auStack40,uVar8);
  __psq_l0(auStack56,uVar8);
  __psq_l1(auStack56,uVar8);
  __psq_l0(auStack72,uVar8);
  __psq_l1(auStack72,uVar8);
  FUN_80286128();
  return;
}

