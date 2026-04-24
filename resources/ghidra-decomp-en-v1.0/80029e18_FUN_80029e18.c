// Function: FUN_80029e18
// Entry: 80029e18
// Size: 388 bytes

/* WARNING: Removing unreachable block (ram,0x80029f44) */
/* WARNING: Removing unreachable block (ram,0x80029ef0) */
/* WARNING: Removing unreachable block (ram,0x80029ee4) */
/* WARNING: Removing unreachable block (ram,0x80029ec4) */
/* WARNING: Removing unreachable block (ram,0x80029ebc) */
/* WARNING: Removing unreachable block (ram,0x80029eac) */
/* WARNING: Removing unreachable block (ram,0x80029ea4) */
/* WARNING: Removing unreachable block (ram,0x80029e94) */
/* WARNING: Removing unreachable block (ram,0x80029e88) */
/* WARNING: Removing unreachable block (ram,0x80029e78) */
/* WARNING: Removing unreachable block (ram,0x80029e6c) */
/* WARNING: Removing unreachable block (ram,0x80029e5c) */
/* WARNING: Removing unreachable block (ram,0x80029e64) */
/* WARNING: Removing unreachable block (ram,0x80029e74) */
/* WARNING: Removing unreachable block (ram,0x80029e7c) */
/* WARNING: Removing unreachable block (ram,0x80029e80) */
/* WARNING: Removing unreachable block (ram,0x80029e90) */
/* WARNING: Removing unreachable block (ram,0x80029e9c) */
/* WARNING: Removing unreachable block (ram,0x80029ea8) */
/* WARNING: Removing unreachable block (ram,0x80029eb4) */
/* WARNING: Removing unreachable block (ram,0x80029ec0) */
/* WARNING: Removing unreachable block (ram,0x80029ecc) */
/* WARNING: Removing unreachable block (ram,0x80029f08) */
/* WARNING: Removing unreachable block (ram,0x80029f38) */
/* WARNING: Removing unreachable block (ram,0x80029f58) */
/* WARNING: Removing unreachable block (ram,0x80029f1c) */

void FUN_80029e18(int param_1,int param_2,int param_3,float *param_4,int param_5,int param_6)

{
  float *pfVar1;
  float *pfVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  byte bVar8;
  undefined uVar9;
  undefined2 uVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  float fVar15;
  float fVar16;
  float fVar17;
  float fVar18;
  float fVar19;
  float fVar20;
  float fVar21;
  float *pfVar22;
  undefined4 in_GQR7;
  float fVar23;
  float fVar24;
  float fVar25;
  float fVar26;
  float fVar27;
  float fVar28;
  float fVar29;
  float fVar30;
  float fVar31;
  float fVar32;
  float fVar33;
  float fVar34;
  float fVar35;
  float fVar36;
  float fVar37;
  float fVar38;
  float fVar39;
  float fVar40;
  float fVar41;
  float fVar42;
  float fVar43;
  float fVar44;
  float fVar45;
  float fVar46;
  float fVar47;
  float fVar48;
  float fVar49;
  float fVar50;
  float fVar51;
  float fVar52;
  float fVar53;
  float fVar54;
  float fVar55;
  float fVar56;
  float fVar57;
  float fVar58;
  
  param_6 = param_6 + -1;
  fVar23 = (float)__psq_l0(param_1,0);
  fVar24 = (float)__psq_l1(param_1,0);
  fVar25 = (float)__psq_l0(param_1 + 8,0);
  fVar32 = (float)__psq_l0(param_1 + 0x24,0);
  fVar33 = (float)__psq_l1(param_1 + 0x24,0);
  bVar3 = (byte)((uint)in_GQR7 >> 0x10);
  bVar4 = bVar3 & 7;
  bVar5 = (byte)((uint)in_GQR7 >> 0x18);
  bVar6 = bVar5 & 0x3f;
  if (bVar4 == 4 || bVar4 == 6) {
    fVar35 = (float)dequantize(param_4,bVar4,bVar6);
    fVar37 = (float)dequantize((int)param_4 + 1,bVar4,bVar6);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    fVar35 = (float)dequantize(param_4,bVar4,bVar6);
    fVar37 = (float)dequantize((int)param_4 + 2,bVar4,bVar6);
  }
  else {
    fVar35 = *param_4;
    fVar37 = param_4[1];
  }
  fVar34 = (float)__psq_l0(param_1 + 0x2c,0);
  pfVar1 = param_4 + 1;
  bVar4 = bVar3 & 7;
  if (bVar4 == 4 || bVar4 == 6) {
    fVar39 = (float)dequantize(pfVar1,bVar4,bVar5 & 0x3f);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    fVar39 = (float)dequantize(pfVar1,bVar4,bVar5 & 0x3f);
  }
  else {
    fVar39 = *pfVar1;
  }
  fVar55 = (float)dequantize(param_3,4,0x3d);
  fVar57 = (float)dequantize(param_3 + 1,4,0x3d);
  fVar26 = (float)__psq_l0(param_1 + 0xc,0);
  fVar27 = (float)__psq_l1(param_1 + 0xc,0);
  fVar28 = (float)__psq_l0(param_1 + 0x14,0);
  fVar31 = (float)__psq_l0(param_1 + 0x20,0);
  fVar43 = (float)__psq_l0(param_2,0);
  fVar44 = (float)__psq_l1(param_2,0);
  fVar29 = (float)__psq_l0(param_1 + 0x18,0);
  fVar30 = (float)__psq_l1(param_1 + 0x18,0);
  fVar45 = (float)__psq_l0(param_2 + 8,0);
  fVar46 = (float)__psq_l0(param_2 + 0xc,0);
  fVar47 = (float)__psq_l1(param_2 + 0xc,0);
  fVar48 = (float)__psq_l0(param_2 + 0x14,0);
  fVar49 = (float)__psq_l0(param_2 + 0x18,0);
  fVar50 = (float)__psq_l1(param_2 + 0x18,0);
  fVar51 = (float)__psq_l0(param_2 + 0x20,0);
  fVar52 = (float)__psq_l0(param_2 + 0x24,0);
  fVar53 = (float)__psq_l1(param_2 + 0x24,0);
  fVar54 = (float)__psq_l0(param_2 + 0x2c,0);
  pfVar1 = (float *)((int)param_4 + 6);
  bVar4 = bVar3 & 7;
  bVar6 = bVar5 & 0x3f;
  if (bVar4 == 4 || bVar4 == 6) {
    fVar36 = (float)dequantize(pfVar1,bVar4,bVar6);
    fVar38 = (float)dequantize((int)param_4 + 7,bVar4,bVar6);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    fVar36 = (float)dequantize(pfVar1,bVar4,bVar6);
    fVar38 = (float)dequantize(param_4 + 2,bVar4,bVar6);
  }
  else {
    fVar36 = *pfVar1;
    fVar38 = *(float *)((int)param_4 + 10);
  }
  param_4 = (float *)((int)param_4 + 10);
  bVar4 = bVar3 & 7;
  if (bVar4 == 4 || bVar4 == 6) {
    fVar40 = (float)dequantize(param_4,bVar4,bVar5 & 0x3f);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    fVar40 = (float)dequantize(param_4,bVar4,bVar5 & 0x3f);
  }
  else {
    fVar40 = *param_4;
  }
  fVar41 = (fVar49 * fVar39 + fVar46 * fVar37 + fVar43 * fVar35 + fVar52) * fVar57 +
           (fVar29 * fVar39 + fVar26 * fVar37 + fVar23 * fVar35 + fVar32) * fVar55;
  fVar42 = (fVar50 * fVar39 + fVar47 * fVar37 + fVar44 * fVar35 + fVar53) * fVar57 +
           (fVar30 * fVar39 + fVar27 * fVar37 + fVar24 * fVar35 + fVar33) * fVar55;
  fVar35 = (fVar51 * fVar39 + fVar48 * fVar37 + fVar45 * fVar35 + fVar54) * fVar57 +
           (fVar31 * fVar39 + fVar28 * fVar37 + fVar25 * fVar35 + fVar34) * fVar55;
  pfVar1 = (float *)(param_5 + -2);
  do {
    pfVar22 = pfVar1;
    fVar37 = fVar23 * fVar36;
    fVar39 = fVar24 * fVar36;
    pfVar1 = (float *)((int)pfVar22 + 2);
    bVar4 = (byte)in_GQR7;
    bVar6 = bVar4 & 7;
    bVar7 = (byte)((uint)in_GQR7 >> 8);
    bVar8 = bVar7 & 0x3f;
    if (bVar6 == 4 || bVar6 == 6) {
      uVar9 = quantize(fVar41,bVar6,bVar8);
      *(undefined *)pfVar1 = uVar9;
      uVar9 = quantize(fVar42,bVar6,bVar8);
      *(undefined *)((int)pfVar22 + 3) = uVar9;
    }
    else if (bVar6 == 5 || bVar6 == 7) {
      uVar10 = quantize(fVar41,bVar6,bVar8);
      *(undefined2 *)pfVar1 = uVar10;
      uVar10 = quantize(fVar42,bVar6,bVar8);
      *(undefined2 *)(pfVar22 + 1) = uVar10;
    }
    else {
      *pfVar1 = fVar41;
      *(float *)((int)pfVar22 + 6) = fVar42;
    }
    fVar55 = fVar25 * fVar36;
    pfVar1 = (float *)((int)pfVar22 + 6);
    bVar6 = bVar4 & 7;
    if (bVar6 == 4 || bVar6 == 6) {
      uVar9 = quantize(fVar35,bVar6,bVar7 & 0x3f);
      *(undefined *)pfVar1 = uVar9;
    }
    else if (bVar6 == 5 || bVar6 == 7) {
      uVar10 = quantize(fVar35,bVar6,bVar7 & 0x3f);
      *(undefined2 *)pfVar1 = uVar10;
    }
    else {
      *pfVar1 = fVar35;
    }
    fVar16 = fVar26 * fVar38;
    fVar20 = fVar27 * fVar38;
    fVar17 = fVar28 * fVar38;
    fVar35 = fVar29 * fVar40;
    fVar42 = fVar30 * fVar40;
    fVar57 = fVar31 * fVar40;
    fVar56 = (float)dequantize(param_3 + 2,4,0x3d);
    fVar58 = (float)dequantize(param_3 + 3,4,0x3d);
    fVar41 = fVar43 * fVar36;
    fVar14 = fVar44 * fVar36;
    fVar11 = fVar45 * fVar36;
    fVar18 = fVar46 * fVar38;
    fVar21 = fVar47 * fVar38;
    fVar19 = fVar48 * fVar38;
    pfVar2 = (float *)((int)param_4 + 2);
    bVar6 = bVar3 & 7;
    bVar8 = bVar5 & 0x3f;
    if (bVar6 == 4 || bVar6 == 6) {
      fVar36 = (float)dequantize(pfVar2,bVar6,bVar8);
      fVar38 = (float)dequantize((int)param_4 + 3,bVar6,bVar8);
    }
    else if (bVar6 == 5 || bVar6 == 7) {
      fVar36 = (float)dequantize(pfVar2,bVar6,bVar8);
      fVar38 = (float)dequantize(param_4 + 1,bVar6,bVar8);
    }
    else {
      fVar36 = *pfVar2;
      fVar38 = *(float *)((int)param_4 + 6);
    }
    fVar12 = fVar49 * fVar40;
    fVar15 = fVar50 * fVar40;
    fVar13 = fVar51 * fVar40;
    param_4 = (float *)((int)param_4 + 6);
    bVar6 = bVar3 & 7;
    if (bVar6 == 4 || bVar6 == 6) {
      fVar40 = (float)dequantize(param_4,bVar6,bVar5 & 0x3f);
    }
    else if (bVar6 == 5 || bVar6 == 7) {
      fVar40 = (float)dequantize(param_4,bVar6,bVar5 & 0x3f);
    }
    else {
      fVar40 = *param_4;
    }
    fVar41 = (fVar12 + fVar18 + fVar41 + fVar52) * fVar58 +
             (fVar35 + fVar16 + fVar37 + fVar32) * fVar56;
    fVar42 = (fVar15 + fVar21 + fVar14 + fVar53) * fVar58 +
             (fVar42 + fVar20 + fVar39 + fVar33) * fVar56;
    fVar35 = (fVar13 + fVar19 + fVar11 + fVar54) * fVar58 +
             (fVar57 + fVar17 + fVar55 + fVar34) * fVar56;
    param_6 = param_6 + -1;
    param_3 = param_3 + 2;
  } while (param_6 != 0);
  pfVar1 = pfVar22 + 2;
  bVar3 = bVar4 & 7;
  bVar5 = bVar7 & 0x3f;
  if (bVar3 == 4 || bVar3 == 6) {
    uVar9 = quantize(fVar41,bVar3,bVar5);
    *(undefined *)pfVar1 = uVar9;
    uVar9 = quantize(fVar42,bVar3,bVar5);
    *(undefined *)((int)pfVar22 + 9) = uVar9;
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    uVar10 = quantize(fVar41,bVar3,bVar5);
    *(undefined2 *)pfVar1 = uVar10;
    uVar10 = quantize(fVar42,bVar3,bVar5);
    *(undefined2 *)((int)pfVar22 + 10) = uVar10;
  }
  else {
    *pfVar1 = fVar41;
    pfVar22[3] = fVar42;
  }
  pfVar22 = pfVar22 + 3;
  bVar4 = bVar4 & 7;
  if (bVar4 == 4 || bVar4 == 6) {
    uVar9 = quantize(fVar35,bVar4,bVar7 & 0x3f);
    *(undefined *)pfVar22 = uVar9;
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    uVar10 = quantize(fVar35,bVar4,bVar7 & 0x3f);
    *(undefined2 *)pfVar22 = uVar10;
  }
  else {
    *pfVar22 = fVar35;
  }
  return;
}

