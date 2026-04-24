// Function: FUN_8002a110
// Entry: 8002a110
// Size: 692 bytes

/* WARNING: Removing unreachable block (ram,0x8002a380) */
/* WARNING: Removing unreachable block (ram,0x8002a36c) */
/* WARNING: Removing unreachable block (ram,0x8002a2a4) */
/* WARNING: Removing unreachable block (ram,0x8002a31c) */
/* WARNING: Removing unreachable block (ram,0x8002a290) */
/* WARNING: Removing unreachable block (ram,0x8002a334) */
/* WARNING: Removing unreachable block (ram,0x8002a278) */
/* WARNING: Removing unreachable block (ram,0x8002a26c) */
/* WARNING: Removing unreachable block (ram,0x8002a240) */
/* WARNING: Removing unreachable block (ram,0x8002a228) */
/* WARNING: Removing unreachable block (ram,0x8002a21c) */
/* WARNING: Removing unreachable block (ram,0x8002a1f0) */
/* WARNING: Removing unreachable block (ram,0x8002a1d8) */
/* WARNING: Removing unreachable block (ram,0x8002a1cc) */
/* WARNING: Removing unreachable block (ram,0x8002a1ac) */
/* WARNING: Removing unreachable block (ram,0x8002a19c) */
/* WARNING: Removing unreachable block (ram,0x8002a194) */
/* WARNING: Removing unreachable block (ram,0x8002a184) */
/* WARNING: Removing unreachable block (ram,0x8002a178) */
/* WARNING: Removing unreachable block (ram,0x8002a168) */
/* WARNING: Removing unreachable block (ram,0x8002a154) */
/* WARNING: Removing unreachable block (ram,0x8002a15c) */
/* WARNING: Removing unreachable block (ram,0x8002a16c) */
/* WARNING: Removing unreachable block (ram,0x8002a170) */
/* WARNING: Removing unreachable block (ram,0x8002a180) */
/* WARNING: Removing unreachable block (ram,0x8002a18c) */
/* WARNING: Removing unreachable block (ram,0x8002a198) */
/* WARNING: Removing unreachable block (ram,0x8002a1a4) */
/* WARNING: Removing unreachable block (ram,0x8002a1b0) */
/* WARNING: Removing unreachable block (ram,0x8002a2c0) */
/* WARNING: Removing unreachable block (ram,0x8002a2e4) */
/* WARNING: Removing unreachable block (ram,0x8002a2cc) */
/* WARNING: Removing unreachable block (ram,0x8002a310) */
/* WARNING: Removing unreachable block (ram,0x8002a360) */

void FUN_8002a110(int param_1,int param_2,int param_3,float *param_4,float *param_5,int param_6)

{
  float *pfVar1;
  byte bVar2;
  byte bVar3;
  byte bVar4;
  byte bVar5;
  byte bVar6;
  byte bVar7;
  undefined uVar8;
  undefined2 uVar9;
  float *pfVar10;
  undefined4 in_GQR7;
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
  float fVar22;
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
  
  param_6 = param_6 + -1;
  fVar11 = (float)__psq_l0(param_1,0);
  fVar12 = (float)__psq_l1(param_1,0);
  fVar13 = (float)__psq_l0(param_1 + 8,0);
  bVar2 = (byte)((uint)in_GQR7 >> 0x10);
  bVar3 = bVar2 & 7;
  bVar4 = (byte)((uint)in_GQR7 >> 0x18);
  bVar5 = bVar4 & 0x3f;
  if (bVar3 == 4 || bVar3 == 6) {
    fVar20 = (float)dequantize(param_4,bVar3,bVar5);
    fVar23 = (float)dequantize((int)param_4 + 1,bVar3,bVar5);
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    fVar20 = (float)dequantize(param_4,bVar3,bVar5);
    fVar23 = (float)dequantize((int)param_4 + 2,bVar3,bVar5);
  }
  else {
    fVar20 = *param_4;
    fVar23 = param_4[1];
  }
  pfVar1 = (float *)((int)param_4 + 2);
  bVar3 = bVar2 & 7;
  if (bVar3 == 4 || bVar3 == 6) {
    fVar26 = (float)dequantize(pfVar1,bVar3,bVar4 & 0x3f);
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    fVar26 = (float)dequantize(pfVar1,bVar3,bVar4 & 0x3f);
  }
  else {
    fVar26 = *pfVar1;
  }
  fVar40 = (float)dequantize(param_3,4,0x3d);
  fVar41 = (float)dequantize(param_3 + 1,4,0x3d);
  fVar14 = (float)__psq_l0(param_1 + 0xc,0);
  fVar15 = (float)__psq_l1(param_1 + 0xc,0);
  fVar16 = (float)__psq_l0(param_1 + 0x14,0);
  fVar19 = (float)__psq_l0(param_1 + 0x20,0);
  fVar31 = (float)__psq_l0(param_2,0);
  fVar32 = (float)__psq_l1(param_2,0);
  fVar17 = (float)__psq_l0(param_1 + 0x18,0);
  fVar18 = (float)__psq_l1(param_1 + 0x18,0);
  fVar33 = (float)__psq_l0(param_2 + 8,0);
  fVar34 = (float)__psq_l0(param_2 + 0xc,0);
  fVar35 = (float)__psq_l1(param_2 + 0xc,0);
  fVar36 = (float)__psq_l0(param_2 + 0x14,0);
  fVar37 = (float)__psq_l0(param_2 + 0x18,0);
  fVar38 = (float)__psq_l1(param_2 + 0x18,0);
  fVar39 = (float)__psq_l0(param_2 + 0x20,0);
  pfVar1 = (float *)((int)param_4 + 3);
  bVar3 = bVar2 & 7;
  bVar5 = bVar4 & 0x3f;
  if (bVar3 == 4 || bVar3 == 6) {
    fVar21 = (float)dequantize(pfVar1,bVar3,bVar5);
    fVar24 = (float)dequantize(param_4 + 1,bVar3,bVar5);
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    fVar21 = (float)dequantize(pfVar1,bVar3,bVar5);
    fVar24 = (float)dequantize((int)param_4 + 5,bVar3,bVar5);
  }
  else {
    fVar21 = *pfVar1;
    fVar24 = *(float *)((int)param_4 + 7);
  }
  pfVar1 = (float *)((int)param_4 + 5);
  bVar3 = bVar2 & 7;
  if (bVar3 == 4 || bVar3 == 6) {
    fVar27 = (float)dequantize(pfVar1,bVar3,bVar4 & 0x3f);
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    fVar27 = (float)dequantize(pfVar1,bVar3,bVar4 & 0x3f);
  }
  else {
    fVar27 = *pfVar1;
  }
  fVar29 = (fVar37 * fVar26 + fVar34 * fVar23 + fVar31 * fVar20) * fVar41 +
           (fVar17 * fVar26 + fVar14 * fVar23 + fVar11 * fVar20) * fVar40;
  fVar30 = (fVar38 * fVar26 + fVar35 * fVar23 + fVar32 * fVar20) * fVar41 +
           (fVar18 * fVar26 + fVar15 * fVar23 + fVar12 * fVar20) * fVar40;
  fVar20 = (fVar39 * fVar26 + fVar36 * fVar23 + fVar33 * fVar20) * fVar41 +
           (fVar19 * fVar26 + fVar16 * fVar23 + fVar13 * fVar20) * fVar40;
  bVar3 = (byte)in_GQR7;
  bVar5 = bVar3 & 7;
  bVar6 = (byte)((uint)in_GQR7 >> 8);
  bVar7 = bVar6 & 0x3f;
  if (bVar5 == 4 || bVar5 == 6) {
    uVar8 = quantize(fVar29,bVar5,bVar7);
    *(undefined *)param_5 = uVar8;
    uVar8 = quantize(fVar30,bVar5,bVar7);
    *(undefined *)((int)param_5 + 1) = uVar8;
  }
  else if (bVar5 == 5 || bVar5 == 7) {
    uVar9 = quantize(fVar29,bVar5,bVar7);
    *(undefined2 *)param_5 = uVar9;
    uVar9 = quantize(fVar30,bVar5,bVar7);
    *(undefined2 *)((int)param_5 + 2) = uVar9;
  }
  else {
    *param_5 = fVar29;
    param_5[1] = fVar30;
  }
  pfVar1 = (float *)((int)param_5 + 2);
  bVar5 = bVar3 & 7;
  if (bVar5 == 4 || bVar5 == 6) {
    uVar8 = quantize(fVar20,bVar5,bVar6 & 0x3f);
    *(undefined *)pfVar1 = uVar8;
  }
  else if (bVar5 == 5 || bVar5 == 7) {
    uVar9 = quantize(fVar20,bVar5,bVar6 & 0x3f);
    *(undefined2 *)pfVar1 = uVar9;
  }
  else {
    *pfVar1 = fVar20;
  }
  pfVar1 = (float *)((int)param_4 + 6);
  bVar5 = bVar2 & 7;
  bVar7 = bVar4 & 0x3f;
  if (bVar5 == 4 || bVar5 == 6) {
    fVar20 = (float)dequantize(pfVar1,bVar5,bVar7);
    fVar23 = (float)dequantize((int)param_4 + 7,bVar5,bVar7);
  }
  else if (bVar5 == 5 || bVar5 == 7) {
    fVar20 = (float)dequantize(pfVar1,bVar5,bVar7);
    fVar23 = (float)dequantize(param_4 + 2,bVar5,bVar7);
  }
  else {
    fVar20 = *pfVar1;
    fVar23 = *(float *)((int)param_4 + 10);
  }
  pfVar1 = param_4 + 2;
  bVar5 = bVar2 & 7;
  if (bVar5 == 4 || bVar5 == 6) {
    fVar26 = (float)dequantize(pfVar1,bVar5,bVar4 & 0x3f);
  }
  else if (bVar5 == 5 || bVar5 == 7) {
    fVar26 = (float)dequantize(pfVar1,bVar5,bVar4 & 0x3f);
  }
  else {
    fVar26 = *pfVar1;
  }
  fVar29 = (fVar37 * fVar27 + fVar34 * fVar24 + fVar31 * fVar21) * fVar41 +
           (fVar17 * fVar27 + fVar14 * fVar24 + fVar11 * fVar21) * fVar40;
  fVar30 = (fVar38 * fVar27 + fVar35 * fVar24 + fVar32 * fVar21) * fVar41 +
           (fVar18 * fVar27 + fVar15 * fVar24 + fVar12 * fVar21) * fVar40;
  fVar21 = (fVar39 * fVar27 + fVar36 * fVar24 + fVar33 * fVar21) * fVar41 +
           (fVar19 * fVar27 + fVar16 * fVar24 + fVar13 * fVar21) * fVar40;
  pfVar1 = (float *)((int)param_5 + 3);
  bVar5 = bVar3 & 7;
  bVar7 = bVar6 & 0x3f;
  if (bVar5 == 4 || bVar5 == 6) {
    uVar8 = quantize(fVar29,bVar5,bVar7);
    *(undefined *)pfVar1 = uVar8;
    uVar8 = quantize(fVar30,bVar5,bVar7);
    *(undefined *)(param_5 + 1) = uVar8;
  }
  else if (bVar5 == 5 || bVar5 == 7) {
    uVar9 = quantize(fVar29,bVar5,bVar7);
    *(undefined2 *)pfVar1 = uVar9;
    uVar9 = quantize(fVar30,bVar5,bVar7);
    *(undefined2 *)((int)param_5 + 5) = uVar9;
  }
  else {
    *pfVar1 = fVar29;
    *(float *)((int)param_5 + 7) = fVar30;
  }
  param_5 = (float *)((int)param_5 + 5);
  bVar5 = bVar3 & 7;
  if (bVar5 == 4 || bVar5 == 6) {
    uVar8 = quantize(fVar21,bVar5,bVar6 & 0x3f);
    *(undefined *)param_5 = uVar8;
  }
  else if (bVar5 == 5 || bVar5 == 7) {
    uVar9 = quantize(fVar21,bVar5,bVar6 & 0x3f);
    *(undefined2 *)param_5 = uVar9;
  }
  else {
    *param_5 = fVar21;
  }
  pfVar1 = (float *)((int)param_4 + 9);
  bVar5 = bVar2 & 7;
  bVar7 = bVar4 & 0x3f;
  if (bVar5 == 4 || bVar5 == 6) {
    fVar21 = (float)dequantize(pfVar1,bVar5,bVar7);
    fVar24 = (float)dequantize((int)param_4 + 10,bVar5,bVar7);
  }
  else if (bVar5 == 5 || bVar5 == 7) {
    fVar21 = (float)dequantize(pfVar1,bVar5,bVar7);
    fVar24 = (float)dequantize((int)param_4 + 0xb,bVar5,bVar7);
  }
  else {
    fVar21 = *pfVar1;
    fVar24 = *(float *)((int)param_4 + 0xd);
  }
  param_4 = (float *)((int)param_4 + 0xb);
  bVar5 = bVar2 & 7;
  if (bVar5 == 4 || bVar5 == 6) {
    fVar27 = (float)dequantize(param_4,bVar5,bVar4 & 0x3f);
  }
  else if (bVar5 == 5 || bVar5 == 7) {
    fVar27 = (float)dequantize(param_4,bVar5,bVar4 & 0x3f);
  }
  else {
    fVar27 = *param_4;
  }
  fVar29 = (fVar37 * fVar26 + fVar34 * fVar23 + fVar31 * fVar20) * fVar41 +
           (fVar17 * fVar26 + fVar14 * fVar23 + fVar11 * fVar20) * fVar40;
  fVar30 = (fVar38 * fVar26 + fVar35 * fVar23 + fVar32 * fVar20) * fVar41 +
           (fVar18 * fVar26 + fVar15 * fVar23 + fVar12 * fVar20) * fVar40;
  fVar20 = (fVar39 * fVar26 + fVar36 * fVar23 + fVar33 * fVar20) * fVar41 +
           (fVar19 * fVar26 + fVar16 * fVar23 + fVar13 * fVar20) * fVar40;
  do {
    pfVar10 = param_5;
    pfVar1 = (float *)((int)pfVar10 + 1);
    bVar5 = bVar3 & 7;
    bVar7 = bVar6 & 0x3f;
    if (bVar5 == 4 || bVar5 == 6) {
      uVar8 = quantize(fVar29,bVar5,bVar7);
      *(undefined *)pfVar1 = uVar8;
      uVar8 = quantize(fVar30,bVar5,bVar7);
      *(undefined *)((int)pfVar10 + 2) = uVar8;
    }
    else if (bVar5 == 5 || bVar5 == 7) {
      uVar9 = quantize(fVar29,bVar5,bVar7);
      *(undefined2 *)pfVar1 = uVar9;
      uVar9 = quantize(fVar30,bVar5,bVar7);
      *(undefined2 *)((int)pfVar10 + 3) = uVar9;
    }
    else {
      *pfVar1 = fVar29;
      *(float *)((int)pfVar10 + 5) = fVar30;
    }
    pfVar1 = (float *)((int)pfVar10 + 3);
    bVar5 = bVar3 & 7;
    if (bVar5 == 4 || bVar5 == 6) {
      uVar8 = quantize(fVar20,bVar5,bVar6 & 0x3f);
      *(undefined *)pfVar1 = uVar8;
    }
    else if (bVar5 == 5 || bVar5 == 7) {
      uVar9 = quantize(fVar20,bVar5,bVar6 & 0x3f);
      *(undefined2 *)pfVar1 = uVar9;
    }
    else {
      *pfVar1 = fVar20;
    }
    fVar20 = (float)dequantize(param_3 + 2,4,0x3d);
    fVar23 = (float)dequantize(param_3 + 3,4,0x3d);
    pfVar1 = (float *)((int)param_4 + 1);
    bVar5 = bVar2 & 7;
    bVar7 = bVar4 & 0x3f;
    if (bVar5 == 4 || bVar5 == 6) {
      fVar26 = (float)dequantize(pfVar1,bVar5,bVar7);
      fVar40 = (float)dequantize((int)param_4 + 2,bVar5,bVar7);
    }
    else if (bVar5 == 5 || bVar5 == 7) {
      fVar26 = (float)dequantize(pfVar1,bVar5,bVar7);
      fVar40 = (float)dequantize((int)param_4 + 3,bVar5,bVar7);
    }
    else {
      fVar26 = *pfVar1;
      fVar40 = *(float *)((int)param_4 + 5);
    }
    pfVar1 = (float *)((int)param_4 + 3);
    bVar5 = bVar2 & 7;
    if (bVar5 == 4 || bVar5 == 6) {
      fVar41 = (float)dequantize(pfVar1,bVar5,bVar4 & 0x3f);
    }
    else if (bVar5 == 5 || bVar5 == 7) {
      fVar41 = (float)dequantize(pfVar1,bVar5,bVar4 & 0x3f);
    }
    else {
      fVar41 = *pfVar1;
    }
    fVar29 = (fVar37 * fVar27 + fVar34 * fVar24 + fVar31 * fVar21) * fVar23 +
             (fVar17 * fVar27 + fVar14 * fVar24 + fVar11 * fVar21) * fVar20;
    fVar30 = (fVar38 * fVar27 + fVar35 * fVar24 + fVar32 * fVar21) * fVar23 +
             (fVar18 * fVar27 + fVar15 * fVar24 + fVar12 * fVar21) * fVar20;
    fVar21 = (fVar39 * fVar27 + fVar36 * fVar24 + fVar33 * fVar21) * fVar23 +
             (fVar19 * fVar27 + fVar16 * fVar24 + fVar13 * fVar21) * fVar20;
    pfVar1 = pfVar10 + 1;
    bVar5 = bVar3 & 7;
    bVar7 = bVar6 & 0x3f;
    if (bVar5 == 4 || bVar5 == 6) {
      uVar8 = quantize(fVar29,bVar5,bVar7);
      *(undefined *)pfVar1 = uVar8;
      uVar8 = quantize(fVar30,bVar5,bVar7);
      *(undefined *)((int)pfVar10 + 5) = uVar8;
    }
    else if (bVar5 == 5 || bVar5 == 7) {
      uVar9 = quantize(fVar29,bVar5,bVar7);
      *(undefined2 *)pfVar1 = uVar9;
      uVar9 = quantize(fVar30,bVar5,bVar7);
      *(undefined2 *)((int)pfVar10 + 6) = uVar9;
    }
    else {
      *pfVar1 = fVar29;
      pfVar10[2] = fVar30;
    }
    pfVar1 = (float *)((int)pfVar10 + 6);
    bVar5 = bVar3 & 7;
    if (bVar5 == 4 || bVar5 == 6) {
      uVar8 = quantize(fVar21,bVar5,bVar6 & 0x3f);
      *(undefined *)pfVar1 = uVar8;
    }
    else if (bVar5 == 5 || bVar5 == 7) {
      uVar9 = quantize(fVar21,bVar5,bVar6 & 0x3f);
      *(undefined2 *)pfVar1 = uVar9;
    }
    else {
      *pfVar1 = fVar21;
    }
    pfVar1 = param_4 + 1;
    bVar5 = bVar2 & 7;
    bVar7 = bVar4 & 0x3f;
    if (bVar5 == 4 || bVar5 == 6) {
      fVar22 = (float)dequantize(pfVar1,bVar5,bVar7);
      fVar25 = (float)dequantize((int)param_4 + 5,bVar5,bVar7);
    }
    else if (bVar5 == 5 || bVar5 == 7) {
      fVar22 = (float)dequantize(pfVar1,bVar5,bVar7);
      fVar25 = (float)dequantize((int)param_4 + 6,bVar5,bVar7);
    }
    else {
      fVar22 = *pfVar1;
      fVar25 = param_4[2];
    }
    pfVar1 = (float *)((int)param_4 + 6);
    bVar5 = bVar2 & 7;
    if (bVar5 == 4 || bVar5 == 6) {
      fVar28 = (float)dequantize(pfVar1,bVar5,bVar4 & 0x3f);
    }
    else if (bVar5 == 5 || bVar5 == 7) {
      fVar28 = (float)dequantize(pfVar1,bVar5,bVar4 & 0x3f);
    }
    else {
      fVar28 = *pfVar1;
    }
    fVar21 = (fVar37 * fVar41 + fVar34 * fVar40 + fVar31 * fVar26) * fVar23 +
             (fVar17 * fVar41 + fVar14 * fVar40 + fVar11 * fVar26) * fVar20;
    fVar24 = (fVar38 * fVar41 + fVar35 * fVar40 + fVar32 * fVar26) * fVar23 +
             (fVar18 * fVar41 + fVar15 * fVar40 + fVar12 * fVar26) * fVar20;
    fVar26 = (fVar39 * fVar41 + fVar36 * fVar40 + fVar33 * fVar26) * fVar23 +
             (fVar19 * fVar41 + fVar16 * fVar40 + fVar13 * fVar26) * fVar20;
    pfVar1 = (float *)((int)pfVar10 + 7);
    bVar5 = bVar3 & 7;
    bVar7 = bVar6 & 0x3f;
    if (bVar5 == 4 || bVar5 == 6) {
      uVar8 = quantize(fVar21,bVar5,bVar7);
      *(undefined *)pfVar1 = uVar8;
      uVar8 = quantize(fVar24,bVar5,bVar7);
      *(undefined *)(pfVar10 + 2) = uVar8;
    }
    else if (bVar5 == 5 || bVar5 == 7) {
      uVar9 = quantize(fVar21,bVar5,bVar7);
      *(undefined2 *)pfVar1 = uVar9;
      uVar9 = quantize(fVar24,bVar5,bVar7);
      *(undefined2 *)((int)pfVar10 + 9) = uVar9;
    }
    else {
      *pfVar1 = fVar21;
      *(float *)((int)pfVar10 + 0xb) = fVar24;
    }
    param_5 = (float *)((int)pfVar10 + 9);
    bVar5 = bVar3 & 7;
    if (bVar5 == 4 || bVar5 == 6) {
      uVar8 = quantize(fVar26,bVar5,bVar6 & 0x3f);
      *(undefined *)param_5 = uVar8;
    }
    else if (bVar5 == 5 || bVar5 == 7) {
      uVar9 = quantize(fVar26,bVar5,bVar6 & 0x3f);
      *(undefined2 *)param_5 = uVar9;
    }
    else {
      *param_5 = fVar26;
    }
    pfVar1 = (float *)((int)param_4 + 7);
    bVar5 = bVar2 & 7;
    bVar7 = bVar4 & 0x3f;
    if (bVar5 == 4 || bVar5 == 6) {
      fVar21 = (float)dequantize(pfVar1,bVar5,bVar7);
      fVar24 = (float)dequantize(param_4 + 2,bVar5,bVar7);
    }
    else if (bVar5 == 5 || bVar5 == 7) {
      fVar21 = (float)dequantize(pfVar1,bVar5,bVar7);
      fVar24 = (float)dequantize((int)param_4 + 9,bVar5,bVar7);
    }
    else {
      fVar21 = *pfVar1;
      fVar24 = *(float *)((int)param_4 + 0xb);
    }
    param_4 = (float *)((int)param_4 + 9);
    bVar5 = bVar2 & 7;
    if (bVar5 == 4 || bVar5 == 6) {
      fVar27 = (float)dequantize(param_4,bVar5,bVar4 & 0x3f);
    }
    else if (bVar5 == 5 || bVar5 == 7) {
      fVar27 = (float)dequantize(param_4,bVar5,bVar4 & 0x3f);
    }
    else {
      fVar27 = *param_4;
    }
    fVar29 = (fVar37 * fVar28 + fVar34 * fVar25 + fVar31 * fVar22) * fVar23 +
             (fVar17 * fVar28 + fVar14 * fVar25 + fVar11 * fVar22) * fVar20;
    fVar30 = (fVar38 * fVar28 + fVar35 * fVar25 + fVar32 * fVar22) * fVar23 +
             (fVar18 * fVar28 + fVar15 * fVar25 + fVar12 * fVar22) * fVar20;
    fVar20 = (fVar39 * fVar28 + fVar36 * fVar25 + fVar33 * fVar22) * fVar23 +
             (fVar19 * fVar28 + fVar16 * fVar25 + fVar13 * fVar22) * fVar20;
    param_6 = param_6 + -1;
    param_3 = param_3 + 2;
  } while (param_6 != 0);
  pfVar1 = (float *)((int)pfVar10 + 10);
  bVar2 = bVar3 & 7;
  bVar4 = bVar6 & 0x3f;
  if (bVar2 == 4 || bVar2 == 6) {
    uVar8 = quantize(fVar29,bVar2,bVar4);
    *(undefined *)pfVar1 = uVar8;
    uVar8 = quantize(fVar30,bVar2,bVar4);
    *(undefined *)((int)pfVar10 + 0xb) = uVar8;
  }
  else if (bVar2 == 5 || bVar2 == 7) {
    uVar9 = quantize(fVar29,bVar2,bVar4);
    *(undefined2 *)pfVar1 = uVar9;
    uVar9 = quantize(fVar30,bVar2,bVar4);
    *(undefined2 *)(pfVar10 + 3) = uVar9;
  }
  else {
    *pfVar1 = fVar29;
    *(float *)((int)pfVar10 + 0xe) = fVar30;
  }
  pfVar10 = pfVar10 + 3;
  bVar3 = bVar3 & 7;
  if (bVar3 == 4 || bVar3 == 6) {
    uVar8 = quantize(fVar20,bVar3,bVar6 & 0x3f);
    *(undefined *)pfVar10 = uVar8;
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    uVar9 = quantize(fVar20,bVar3,bVar6 & 0x3f);
    *(undefined2 *)pfVar10 = uVar9;
  }
  else {
    *pfVar10 = fVar20;
  }
  return;
}

