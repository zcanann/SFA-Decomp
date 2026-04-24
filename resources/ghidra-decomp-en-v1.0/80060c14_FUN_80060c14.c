// Function: FUN_80060c14
// Entry: 80060c14
// Size: 1152 bytes

/* WARNING: Removing unreachable block (ram,0x8006106c) */
/* WARNING: Removing unreachable block (ram,0x80060d54) */
/* WARNING: Removing unreachable block (ram,0x80060f5c) */
/* WARNING: Removing unreachable block (ram,0x80060d08) */
/* WARNING: Removing unreachable block (ram,0x80060f20) */
/* WARNING: Removing unreachable block (ram,0x80060d3c) */
/* WARNING: Removing unreachable block (ram,0x80060cf0) */
/* WARNING: Removing unreachable block (ram,0x80060d88) */
/* WARNING: Removing unreachable block (ram,0x80060f0c) */
/* WARNING: Removing unreachable block (ram,0x80060f48) */
/* WARNING: Removing unreachable block (ram,0x80060d24) */
/* WARNING: Removing unreachable block (ram,0x80060f70) */
/* WARNING: Removing unreachable block (ram,0x80060fac) */
/* WARNING: Removing unreachable block (ram,0x80060d70) */
/* WARNING: Removing unreachable block (ram,0x80061074) */
/* WARNING: Removing unreachable block (ram,0x80060f98) */
/* WARNING: Removing unreachable block (ram,0x80060f34) */
/* WARNING: Removing unreachable block (ram,0x80060da0) */
/* WARNING: Removing unreachable block (ram,0x80060f84) */
/* WARNING: Removing unreachable block (ram,0x80060dbc) */

void FUN_80060c14(undefined8 param_1,double param_2,undefined4 param_3,undefined4 param_4,
                 int param_5,float *param_6,undefined4 param_7,undefined4 param_8,int param_9)

{
  undefined8 *puVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  undefined4 *puVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  float *pfVar12;
  byte bVar13;
  int iVar14;
  int *piVar15;
  int iVar16;
  undefined4 uVar17;
  undefined4 uVar18;
  undefined4 uVar19;
  double extraout_f1;
  double dVar20;
  double dVar21;
  undefined8 in_f30;
  double dVar22;
  undefined8 in_f31;
  undefined8 uVar23;
  int local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  float local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  float local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  float local_58;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar18 = 0x70007;
  uVar17 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  uVar23 = FUN_802860c8();
  iVar5 = (int)((ulonglong)uVar23 >> 0x20);
  iVar9 = (int)uVar23;
  dVar22 = extraout_f1;
  piVar6 = (int *)FUN_80069944(&local_88);
  piVar15 = piVar6 + local_88 * 6;
  iVar16 = 0;
  iVar11 = 0;
  local_88 = 0;
  iVar14 = 0;
  if (param_9 == 0) {
    bVar13 = 8;
  }
  else {
    bVar13 = 4;
  }
  for (; piVar6 < piVar15; piVar6 = piVar6 + 6) {
    iVar7 = *piVar6;
    bVar2 = (byte)((uint)uVar18 >> 0x10);
    bVar4 = (byte)((uint)uVar18 >> 0x18);
    if ((iVar7 == 0) || (iVar7 == *(int *)(iVar5 + 0x30))) {
      dVar20 = (double)*(float *)(iVar5 + 0xc);
      dVar21 = (double)*(float *)(iVar5 + 0x14);
      if (iVar7 == 0) {
        dVar20 = (double)(float)(dVar20 - dVar22);
        dVar21 = (double)(float)(dVar21 - param_2);
      }
      local_88 = (int)*(short *)(piVar6 + 1);
      puVar8 = (undefined4 *)(param_5 + iVar11);
      while (((pfVar12 = param_6, iVar7 = iVar14, local_88 < *(short *)(piVar6 + 7) &&
              (iVar16 < 0x4b0)) && (iVar14 < 0xe10))) {
        iVar7 = iVar9 + local_88 * 0x4c;
        if ((bVar13 & *(byte *)(iVar7 + 0x49)) != 0) {
          uVar19 = __psq_l0(iVar7 + 0x10,uVar18);
          *param_6 = (float)((double)CONCAT44(uVar19,0x3f800000) - dVar20);
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x16);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          param_6[1] = (float)((double)CONCAT44(uVar19,0x3f800000) -
                              (double)*(float *)(iVar5 + 0x10));
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x1c);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          param_6[2] = (float)((double)CONCAT44(uVar19,0x3f800000) - dVar21);
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x12);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          param_6[3] = (float)((double)CONCAT44(uVar19,0x3f800000) - dVar20);
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x18);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          param_6[4] = (float)((double)CONCAT44(uVar19,0x3f800000) -
                              (double)*(float *)(iVar5 + 0x10));
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x1e);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          param_6[5] = (float)((double)CONCAT44(uVar19,0x3f800000) - dVar21);
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x14);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          param_6[6] = (float)((double)CONCAT44(uVar19,0x3f800000) - dVar20);
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x1a);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          param_6[7] = (float)((double)CONCAT44(uVar19,0x3f800000) -
                              (double)*(float *)(iVar5 + 0x10));
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x20);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          param_6[8] = (float)((double)CONCAT44(uVar19,0x3f800000) - dVar21);
          *puVar8 = *(undefined4 *)(iVar9 + local_88 * 0x4c + 4);
          puVar8[1] = *(undefined4 *)(iVar9 + local_88 * 0x4c + 8);
          puVar8[2] = *(undefined4 *)(iVar9 + local_88 * 0x4c + 0xc);
          *(undefined *)(puVar8 + 4) = *(undefined *)(iVar9 + local_88 * 0x4c + 0x49);
          param_6 = param_6 + 9;
          iVar14 = iVar14 + 3;
          puVar8 = puVar8 + 5;
          iVar16 = iVar16 + 1;
          iVar11 = iVar11 + 0x14;
        }
        local_88 = local_88 + 1;
      }
    }
    else {
      puVar8 = (undefined4 *)piVar6[3];
      local_84 = *puVar8;
      local_80 = puVar8[4];
      local_7c = puVar8[8];
      local_78 = (float)puVar8[0xc] - *(float *)(iVar5 + 0xc);
      local_74 = puVar8[1];
      local_70 = puVar8[5];
      local_6c = puVar8[9];
      local_68 = (float)puVar8[0xd] - *(float *)(iVar5 + 0x10);
      local_64 = puVar8[2];
      local_60 = puVar8[6];
      local_5c = puVar8[10];
      local_58 = (float)puVar8[0xe] - *(float *)(iVar5 + 0x14);
      local_88 = (int)*(short *)(piVar6 + 1);
      puVar8 = (undefined4 *)(param_5 + iVar11);
      pfVar12 = param_6;
      iVar7 = iVar14;
      while (((local_88 < *(short *)(piVar6 + 7) && (iVar16 < 0x4b0)) && (iVar7 < 0xe10))) {
        iVar10 = iVar9 + local_88 * 0x4c;
        if ((bVar13 & *(byte *)(iVar10 + 0x49)) != 0) {
          uVar19 = __psq_l0(iVar10 + 0x10,uVar18);
          *pfVar12 = (float)(double)CONCAT44(uVar19,0x3f800000);
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x16);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          pfVar12[1] = (float)(double)CONCAT44(uVar19,0x3f800000);
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x1c);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          pfVar12[2] = (float)(double)CONCAT44(uVar19,0x3f800000);
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x12);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          pfVar12[3] = (float)(double)CONCAT44(uVar19,0x3f800000);
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x18);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          pfVar12[4] = (float)(double)CONCAT44(uVar19,0x3f800000);
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x1e);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          pfVar12[5] = (float)(double)CONCAT44(uVar19,0x3f800000);
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x14);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          pfVar12[6] = (float)(double)CONCAT44(uVar19,0x3f800000);
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x1a);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          pfVar12[7] = (float)(double)CONCAT44(uVar19,0x3f800000);
          puVar1 = (undefined8 *)(iVar9 + local_88 * 0x4c + 0x20);
          bVar3 = bVar2 & 7;
          if (bVar3 == 4 || bVar3 == 6) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else if (bVar3 == 5 || bVar3 == 7) {
            uVar19 = dequantize(puVar1,bVar3,bVar4 & 0x3f);
          }
          else {
            uVar19 = (undefined4)((ulonglong)*puVar1 >> 0x20);
          }
          pfVar12[8] = (float)(double)CONCAT44(uVar19,0x3f800000);
          *puVar8 = *(undefined4 *)(iVar9 + local_88 * 0x4c + 4);
          puVar8[1] = *(undefined4 *)(iVar9 + local_88 * 0x4c + 8);
          puVar8[2] = *(undefined4 *)(iVar9 + local_88 * 0x4c + 0xc);
          *(undefined *)(puVar8 + 4) = *(undefined *)(iVar9 + local_88 * 0x4c + 0x49);
          pfVar12 = pfVar12 + 9;
          iVar7 = iVar7 + 3;
          puVar8 = puVar8 + 5;
          iVar16 = iVar16 + 1;
          iVar11 = iVar11 + 0x14;
        }
        local_88 = local_88 + 1;
      }
      if (iVar14 < iVar7) {
        FUN_802474e8(&local_84,param_6,param_6,iVar7 - iVar14);
      }
    }
    param_6 = pfVar12;
    iVar14 = iVar7;
  }
  __psq_l0(auStack8,uVar17);
  __psq_l1(auStack8,uVar17);
  __psq_l0(auStack24,uVar17);
  __psq_l1(auStack24,uVar17);
  FUN_80286114(iVar16);
  return;
}

