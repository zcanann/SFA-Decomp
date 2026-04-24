// Function: FUN_80029f9c
// Entry: 80029f9c
// Size: 372 bytes

/* WARNING: Removing unreachable block (ram,0x8002a0b8) */
/* WARNING: Removing unreachable block (ram,0x8002a064) */
/* WARNING: Removing unreachable block (ram,0x8002a058) */
/* WARNING: Removing unreachable block (ram,0x8002a038) */
/* WARNING: Removing unreachable block (ram,0x8002a028) */
/* WARNING: Removing unreachable block (ram,0x8002a020) */
/* WARNING: Removing unreachable block (ram,0x8002a010) */
/* WARNING: Removing unreachable block (ram,0x8002a004) */
/* WARNING: Removing unreachable block (ram,0x80029ff4) */
/* WARNING: Removing unreachable block (ram,0x80029fe0) */
/* WARNING: Removing unreachable block (ram,0x80029fe8) */
/* WARNING: Removing unreachable block (ram,0x80029ff8) */
/* WARNING: Removing unreachable block (ram,0x80029ffc) */
/* WARNING: Removing unreachable block (ram,0x8002a00c) */
/* WARNING: Removing unreachable block (ram,0x8002a018) */
/* WARNING: Removing unreachable block (ram,0x8002a024) */
/* WARNING: Removing unreachable block (ram,0x8002a030) */
/* WARNING: Removing unreachable block (ram,0x8002a03c) */
/* WARNING: Removing unreachable block (ram,0x8002a07c) */
/* WARNING: Removing unreachable block (ram,0x8002a0ac) */
/* WARNING: Removing unreachable block (ram,0x8002a0cc) */
/* WARNING: Removing unreachable block (ram,0x8002a090) */

void FUN_80029f9c(int param_1,int param_2,int param_3,float *param_4,int param_5,int param_6)

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
  float *pfVar19;
  undefined4 in_GQR7;
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
  
  param_6 = param_6 + -1;
  fVar20 = (float)__psq_l0(param_1,0);
  fVar21 = (float)__psq_l1(param_1,0);
  fVar22 = (float)__psq_l0(param_1 + 8,0);
  bVar3 = (byte)((uint)in_GQR7 >> 0x10);
  bVar4 = bVar3 & 7;
  bVar5 = (byte)((uint)in_GQR7 >> 0x18);
  bVar6 = bVar5 & 0x3f;
  if (bVar4 == 4 || bVar4 == 6) {
    fVar29 = (float)dequantize(param_4,bVar4,bVar6);
    fVar31 = (float)dequantize((int)param_4 + 1,bVar4,bVar6);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    fVar29 = (float)dequantize(param_4,bVar4,bVar6);
    fVar31 = (float)dequantize((int)param_4 + 2,bVar4,bVar6);
  }
  else {
    fVar29 = *param_4;
    fVar31 = param_4[1];
  }
  pfVar1 = (float *)((int)param_4 + 2);
  bVar4 = bVar3 & 7;
  if (bVar4 == 4 || bVar4 == 6) {
    fVar33 = (float)dequantize(pfVar1,bVar4,bVar5 & 0x3f);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    fVar33 = (float)dequantize(pfVar1,bVar4,bVar5 & 0x3f);
  }
  else {
    fVar33 = *pfVar1;
  }
  fVar49 = (float)dequantize(param_3,4,0x3d);
  fVar51 = (float)dequantize(param_3 + 1,4,0x3d);
  fVar23 = (float)__psq_l0(param_1 + 0xc,0);
  fVar24 = (float)__psq_l1(param_1 + 0xc,0);
  fVar25 = (float)__psq_l0(param_1 + 0x14,0);
  fVar28 = (float)__psq_l0(param_1 + 0x20,0);
  fVar40 = (float)__psq_l0(param_2,0);
  fVar41 = (float)__psq_l1(param_2,0);
  fVar26 = (float)__psq_l0(param_1 + 0x18,0);
  fVar27 = (float)__psq_l1(param_1 + 0x18,0);
  fVar42 = (float)__psq_l0(param_2 + 8,0);
  fVar43 = (float)__psq_l0(param_2 + 0xc,0);
  fVar44 = (float)__psq_l1(param_2 + 0xc,0);
  fVar45 = (float)__psq_l0(param_2 + 0x14,0);
  fVar46 = (float)__psq_l0(param_2 + 0x18,0);
  fVar47 = (float)__psq_l1(param_2 + 0x18,0);
  fVar48 = (float)__psq_l0(param_2 + 0x20,0);
  pfVar1 = (float *)((int)param_4 + 3);
  bVar4 = bVar3 & 7;
  bVar6 = bVar5 & 0x3f;
  if (bVar4 == 4 || bVar4 == 6) {
    fVar30 = (float)dequantize(pfVar1,bVar4,bVar6);
    fVar32 = (float)dequantize(param_4 + 1,bVar4,bVar6);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    fVar30 = (float)dequantize(pfVar1,bVar4,bVar6);
    fVar32 = (float)dequantize((int)param_4 + 5,bVar4,bVar6);
  }
  else {
    fVar30 = *pfVar1;
    fVar32 = *(float *)((int)param_4 + 7);
  }
  param_4 = (float *)((int)param_4 + 5);
  bVar4 = bVar3 & 7;
  if (bVar4 == 4 || bVar4 == 6) {
    fVar34 = (float)dequantize(param_4,bVar4,bVar5 & 0x3f);
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    fVar34 = (float)dequantize(param_4,bVar4,bVar5 & 0x3f);
  }
  else {
    fVar34 = *param_4;
  }
  fVar35 = (fVar46 * fVar33 + fVar43 * fVar31 + fVar40 * fVar29) * fVar51 +
           (fVar26 * fVar33 + fVar23 * fVar31 + fVar20 * fVar29) * fVar49;
  fVar37 = (fVar47 * fVar33 + fVar44 * fVar31 + fVar41 * fVar29) * fVar51 +
           (fVar27 * fVar33 + fVar24 * fVar31 + fVar21 * fVar29) * fVar49;
  fVar29 = (fVar48 * fVar33 + fVar45 * fVar31 + fVar42 * fVar29) * fVar51 +
           (fVar28 * fVar33 + fVar25 * fVar31 + fVar22 * fVar29) * fVar49;
  pfVar1 = (float *)(param_5 + -1);
  do {
    pfVar19 = pfVar1;
    fVar31 = fVar20 * fVar30;
    fVar33 = fVar21 * fVar30;
    pfVar1 = (float *)((int)pfVar19 + 1);
    bVar4 = (byte)in_GQR7;
    bVar6 = bVar4 & 7;
    bVar7 = (byte)((uint)in_GQR7 >> 8);
    bVar8 = bVar7 & 0x3f;
    if (bVar6 == 4 || bVar6 == 6) {
      uVar9 = quantize(fVar35,bVar6,bVar8);
      *(undefined *)pfVar1 = uVar9;
      uVar9 = quantize(fVar37,bVar6,bVar8);
      *(undefined *)((int)pfVar19 + 2) = uVar9;
    }
    else if (bVar6 == 5 || bVar6 == 7) {
      uVar10 = quantize(fVar35,bVar6,bVar8);
      *(undefined2 *)pfVar1 = uVar10;
      uVar10 = quantize(fVar37,bVar6,bVar8);
      *(undefined2 *)((int)pfVar19 + 3) = uVar10;
    }
    else {
      *pfVar1 = fVar35;
      *(float *)((int)pfVar19 + 5) = fVar37;
    }
    fVar49 = fVar22 * fVar30;
    pfVar1 = (float *)((int)pfVar19 + 3);
    bVar6 = bVar4 & 7;
    if (bVar6 == 4 || bVar6 == 6) {
      uVar9 = quantize(fVar29,bVar6,bVar7 & 0x3f);
      *(undefined *)pfVar1 = uVar9;
    }
    else if (bVar6 == 5 || bVar6 == 7) {
      uVar10 = quantize(fVar29,bVar6,bVar7 & 0x3f);
      *(undefined2 *)pfVar1 = uVar10;
    }
    else {
      *pfVar1 = fVar29;
    }
    fVar35 = fVar23 * fVar32;
    fVar17 = fVar24 * fVar32;
    fVar14 = fVar25 * fVar32;
    fVar29 = fVar26 * fVar34;
    fVar37 = fVar27 * fVar34;
    fVar51 = fVar28 * fVar34;
    fVar50 = (float)dequantize(param_3 + 2,4,0x3d);
    fVar52 = (float)dequantize(param_3 + 3,4,0x3d);
    fVar36 = fVar40 * fVar30;
    fVar38 = fVar41 * fVar30;
    fVar39 = fVar42 * fVar30;
    fVar15 = fVar43 * fVar32;
    fVar18 = fVar44 * fVar32;
    fVar16 = fVar45 * fVar32;
    pfVar2 = (float *)((int)param_4 + 1);
    bVar6 = bVar3 & 7;
    bVar8 = bVar5 & 0x3f;
    if (bVar6 == 4 || bVar6 == 6) {
      fVar30 = (float)dequantize(pfVar2,bVar6,bVar8);
      fVar32 = (float)dequantize((int)param_4 + 2,bVar6,bVar8);
    }
    else if (bVar6 == 5 || bVar6 == 7) {
      fVar30 = (float)dequantize(pfVar2,bVar6,bVar8);
      fVar32 = (float)dequantize((int)param_4 + 3,bVar6,bVar8);
    }
    else {
      fVar30 = *pfVar2;
      fVar32 = *(float *)((int)param_4 + 5);
    }
    fVar11 = fVar46 * fVar34;
    fVar13 = fVar47 * fVar34;
    fVar12 = fVar48 * fVar34;
    param_4 = (float *)((int)param_4 + 3);
    bVar6 = bVar3 & 7;
    if (bVar6 == 4 || bVar6 == 6) {
      fVar34 = (float)dequantize(param_4,bVar6,bVar5 & 0x3f);
    }
    else if (bVar6 == 5 || bVar6 == 7) {
      fVar34 = (float)dequantize(param_4,bVar6,bVar5 & 0x3f);
    }
    else {
      fVar34 = *param_4;
    }
    fVar35 = (fVar11 + fVar15 + fVar36) * fVar52 + (fVar29 + fVar35 + fVar31) * fVar50;
    fVar37 = (fVar13 + fVar18 + fVar38) * fVar52 + (fVar37 + fVar17 + fVar33) * fVar50;
    fVar29 = (fVar12 + fVar16 + fVar39) * fVar52 + (fVar51 + fVar14 + fVar49) * fVar50;
    param_6 = param_6 + -1;
    param_3 = param_3 + 2;
  } while (param_6 != 0);
  pfVar1 = pfVar19 + 1;
  bVar3 = bVar4 & 7;
  bVar5 = bVar7 & 0x3f;
  if (bVar3 == 4 || bVar3 == 6) {
    uVar9 = quantize(fVar35,bVar3,bVar5);
    *(undefined *)pfVar1 = uVar9;
    uVar9 = quantize(fVar37,bVar3,bVar5);
    *(undefined *)((int)pfVar19 + 5) = uVar9;
  }
  else if (bVar3 == 5 || bVar3 == 7) {
    uVar10 = quantize(fVar35,bVar3,bVar5);
    *(undefined2 *)pfVar1 = uVar10;
    uVar10 = quantize(fVar37,bVar3,bVar5);
    *(undefined2 *)((int)pfVar19 + 6) = uVar10;
  }
  else {
    *pfVar1 = fVar35;
    pfVar19[2] = fVar37;
  }
  pfVar19 = (float *)((int)pfVar19 + 6);
  bVar4 = bVar4 & 7;
  if (bVar4 == 4 || bVar4 == 6) {
    uVar9 = quantize(fVar29,bVar4,bVar7 & 0x3f);
    *(undefined *)pfVar19 = uVar9;
  }
  else if (bVar4 == 5 || bVar4 == 7) {
    uVar10 = quantize(fVar29,bVar4,bVar7 & 0x3f);
    *(undefined2 *)pfVar19 = uVar10;
  }
  else {
    *pfVar19 = fVar29;
  }
  return;
}

