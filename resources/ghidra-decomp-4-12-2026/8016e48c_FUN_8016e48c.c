// Function: FUN_8016e48c
// Entry: 8016e48c
// Size: 1780 bytes

/* WARNING: Removing unreachable block (ram,0x8016eb60) */
/* WARNING: Removing unreachable block (ram,0x8016eb58) */
/* WARNING: Removing unreachable block (ram,0x8016eb50) */
/* WARNING: Removing unreachable block (ram,0x8016eb48) */
/* WARNING: Removing unreachable block (ram,0x8016eb40) */
/* WARNING: Removing unreachable block (ram,0x8016eb38) */
/* WARNING: Removing unreachable block (ram,0x8016eb30) */
/* WARNING: Removing unreachable block (ram,0x8016e4cc) */
/* WARNING: Removing unreachable block (ram,0x8016e4c4) */
/* WARNING: Removing unreachable block (ram,0x8016e4bc) */
/* WARNING: Removing unreachable block (ram,0x8016e4b4) */
/* WARNING: Removing unreachable block (ram,0x8016e4ac) */
/* WARNING: Removing unreachable block (ram,0x8016e4a4) */
/* WARNING: Removing unreachable block (ram,0x8016e49c) */

void FUN_8016e48c(void)

{
  uint uVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  int extraout_r4;
  int iVar6;
  int *piVar7;
  short *in_r6;
  float *pfVar8;
  float *pfVar9;
  float *pfVar10;
  float *pfVar11;
  float *pfVar12;
  float *pfVar13;
  uint uVar14;
  uint uVar15;
  int iVar16;
  int *piVar17;
  int iVar18;
  double dVar19;
  double dVar20;
  double dVar21;
  double dVar22;
  double dVar23;
  double in_f25;
  double dVar24;
  double in_f26;
  double in_f27;
  double dVar25;
  double in_f28;
  double dVar26;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_138 [4];
  float local_128 [4];
  float local_118 [4];
  float local_108 [4];
  float local_f8 [4];
  float local_e8 [4];
  int local_d8 [4];
  undefined8 local_c8;
  undefined4 local_c0;
  uint uStack_bc;
  undefined8 local_b8;
  undefined8 local_b0;
  undefined8 local_a8;
  undefined4 local_a0;
  uint uStack_9c;
  float local_68;
  float fStack_64;
  float local_58;
  float fStack_54;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
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
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_58 = (float)in_f26;
  fStack_54 = (float)in_ps26_1;
  local_68 = (float)in_f25;
  fStack_64 = (float)in_ps25_1;
  FUN_8028682c();
  if ((*(int *)(extraout_r4 + 0x48) != 0) && (*(char *)(extraout_r4 + 0xbc) == '\0')) {
    iVar6 = (int)*in_r6;
    if (*(short **)(in_r6 + 0x18) != (short *)0x0) {
      iVar6 = iVar6 + **(short **)(in_r6 + 0x18);
    }
    local_c8 = (double)CONCAT44(0x43300000,-iVar6 ^ 0x80000000);
    dVar19 = (double)FUN_802945e0();
    dVar20 = (double)FUN_80294964();
    iVar6 = FUN_8002b660((int)in_r6);
    iVar6 = *(int *)(iVar6 + 0x2c);
    if ((*(int **)(in_r6 + 0x2e) != (int *)0x0) && (0 < **(int **)(in_r6 + 0x2e))) {
      piVar17 = *(int **)(extraout_r4 + 0x48);
      uVar1 = (uint)(FLOAT_803e3fa4 * *(float *)(iVar6 + 0x14));
      local_c8 = (double)(longlong)(int)uVar1;
      dVar24 = (double)((float)piVar17[2] * *(float *)(iVar6 + 0x14));
      if ((*(byte *)(piVar17 + 5) & 1) != 0) {
        *(undefined4 *)(extraout_r4 + 0x8c) = *(undefined4 *)(in_r6 + 0xc);
        *(undefined4 *)(extraout_r4 + 0x90) = *(undefined4 *)(in_r6 + 0xe);
        *(undefined4 *)(extraout_r4 + 0x94) = *(undefined4 *)(in_r6 + 0x10);
        *(float *)(extraout_r4 + 0x98) = FLOAT_803e3f4c;
        *(byte *)(piVar17 + 5) = *(byte *)(piVar17 + 5) & 0xfe;
      }
      if (dVar24 < (double)*(float *)(extraout_r4 + 0x98)) {
        *(undefined4 *)(extraout_r4 + 0x98) = *(undefined4 *)(iVar6 + 4);
        goto LAB_8016eb30;
      }
      iVar16 = *(int *)(*(int *)(in_r6 + 0x2e) + 4);
      if ((double)FLOAT_803e3f4c <= (double)*(float *)(extraout_r4 + 0x98)) {
        dVar21 = (double)FUN_802925a0();
        dVar25 = (double)((float)(dVar21 / (double)FLOAT_803e3f3c) * FLOAT_803e3fa4);
        dVar21 = (double)FUN_802925a0();
        dVar26 = (double)((float)(dVar21 / (double)FLOAT_803e3f3c) * FLOAT_803e3fa4);
        uVar14 = (uint)dVar25;
        local_c8 = (double)(longlong)(int)uVar14;
        uStack_bc = uVar14 ^ 0x80000000;
        local_c0 = 0x43300000;
        dVar21 = (double)(float)(dVar25 - (double)(float)((double)CONCAT44(0x43300000,
                                                                           uVar14 ^ 0x80000000) -
                                                         DOUBLE_803e3fb0));
        uVar15 = (uint)((float)(dVar26 - dVar25) / FLOAT_803e3f44);
        local_b8 = (double)(longlong)(int)uVar15;
        if (uVar15 == 0) {
          if (dVar24 < (double)*(float *)(iVar6 + 4)) {
            *(float *)(extraout_r4 + 0x98) = *(float *)(iVar6 + 4);
          }
          goto LAB_8016eb30;
        }
        dVar24 = (double)FLOAT_803e3f4c;
        local_b8 = (double)CONCAT44(0x43300000,uVar15 ^ 0x80000000);
        dVar25 = (double)(FLOAT_803e3f20 / (float)(local_b8 - DOUBLE_803e3fb0));
        bVar4 = true;
        while (uVar15 != 0) {
          if (*(short *)((int)piVar17 + 0xe) == 0xbb6) {
            uVar15 = 0;
          }
          else {
            dVar21 = (double)(float)(dVar21 + (double)FLOAT_803e3f44);
            if ((double)FLOAT_803e3f20 <= dVar21) {
              dVar21 = (double)(float)(dVar21 - (double)FLOAT_803e3f20);
              uVar14 = uVar14 + 1;
              bVar4 = true;
            }
            dVar24 = (double)(float)(dVar24 + dVar25);
            if (bVar4) {
              local_d8[0] = uVar14 - 1;
              local_d8[1] = uVar14;
              local_d8[2] = uVar14 + 1;
              local_d8[3] = uVar14 + 2;
              if ((int)(uVar14 - 1) < 0) {
                local_d8[0] = 0;
              }
              if ((int)uVar1 <= (int)uVar14) {
                local_d8[1] = uVar1;
              }
              if ((int)uVar1 <= (int)(uVar14 + 1)) {
                local_d8[2] = uVar1;
              }
              if ((int)uVar1 <= (int)(uVar14 + 2)) {
                local_d8[3] = uVar1;
              }
              piVar7 = local_d8;
              pfVar13 = local_e8;
              pfVar8 = local_f8;
              pfVar9 = local_108;
              pfVar10 = local_118;
              pfVar11 = local_128;
              pfVar12 = local_138;
              iVar18 = 4;
              do {
                iVar5 = *piVar7 * 0xc;
                local_b8 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar16 + iVar5) ^ 0x80000000)
                ;
                *pfVar13 = (float)(local_b8 - DOUBLE_803e3fb0) / FLOAT_803e3f8c;
                uStack_bc = (int)*(short *)(iVar16 + iVar5 + 2) ^ 0x80000000;
                local_c0 = 0x43300000;
                *pfVar8 = (float)((double)CONCAT44(0x43300000,uStack_bc) - DOUBLE_803e3fb0) /
                          FLOAT_803e3f8c;
                local_c8 = (double)CONCAT44(0x43300000,
                                            (int)*(short *)(iVar16 + iVar5 + 4) ^ 0x80000000);
                *pfVar9 = (float)(local_c8 - DOUBLE_803e3fb0) / FLOAT_803e3f8c;
                local_b0 = (double)CONCAT44(0x43300000,
                                            (int)*(short *)(iVar16 + iVar5 + 6) ^ 0x80000000);
                *pfVar10 = (float)(local_b0 - DOUBLE_803e3fb0) / FLOAT_803e3f8c;
                local_a8 = (double)CONCAT44(0x43300000,
                                            (int)*(short *)(iVar16 + iVar5 + 8) ^ 0x80000000);
                *pfVar11 = (float)(local_a8 - DOUBLE_803e3fb0) / FLOAT_803e3f8c;
                uStack_9c = (int)*(short *)(iVar16 + iVar5 + 10) ^ 0x80000000;
                local_a0 = 0x43300000;
                *pfVar12 = (float)((double)CONCAT44(0x43300000,uStack_9c) - DOUBLE_803e3fb0) /
                           FLOAT_803e3f8c;
                fVar2 = *pfVar13;
                fVar3 = *pfVar9;
                *pfVar13 = (float)(dVar20 * (double)fVar2 - (double)(float)(dVar19 * (double)fVar3))
                ;
                *pfVar9 = (float)(dVar19 * (double)fVar2 + (double)(float)(dVar20 * (double)fVar3));
                fVar2 = *pfVar10;
                fVar3 = *pfVar12;
                *pfVar10 = (float)(dVar20 * (double)fVar2 - (double)(float)(dVar19 * (double)fVar3))
                ;
                *pfVar12 = (float)(dVar19 * (double)fVar2 + (double)(float)(dVar20 * (double)fVar3))
                ;
                piVar7 = piVar7 + 1;
                pfVar13 = pfVar13 + 1;
                pfVar8 = pfVar8 + 1;
                pfVar9 = pfVar9 + 1;
                pfVar10 = pfVar10 + 1;
                pfVar11 = pfVar11 + 1;
                pfVar12 = pfVar12 + 1;
                iVar18 = iVar18 + -1;
              } while (iVar18 != 0);
              bVar4 = false;
            }
            pfVar13 = (float *)(*piVar17 + (uint)*(ushort *)((int)piVar17 + 0xe) * 0x14);
            dVar22 = FUN_80010f00(dVar21,local_118,(float *)0x0);
            *pfVar13 = (float)dVar22;
            dVar22 = FUN_80010f00(dVar21,local_128,(float *)0x0);
            pfVar13[1] = (float)dVar22;
            dVar22 = FUN_80010f00(dVar21,local_138,(float *)0x0);
            pfVar13[2] = (float)dVar22;
            *pfVar13 = *pfVar13 +
                       (float)(dVar24 * (double)(float)((double)*(float *)(in_r6 + 0xc) -
                                                       (double)*(float *)(extraout_r4 + 0x8c)) +
                              (double)*(float *)(extraout_r4 + 0x8c));
            pfVar13[1] = pfVar13[1] +
                         (float)(dVar24 * (double)(float)((double)*(float *)(in_r6 + 0xe) -
                                                         (double)*(float *)(extraout_r4 + 0x90)) +
                                (double)*(float *)(extraout_r4 + 0x90));
            pfVar13[2] = pfVar13[2] +
                         (float)(dVar24 * (double)(float)((double)*(float *)(in_r6 + 0x10) -
                                                         (double)*(float *)(extraout_r4 + 0x94)) +
                                (double)*(float *)(extraout_r4 + 0x94));
            uStack_9c = uVar14 ^ 0x80000000;
            local_a0 = 0x43300000;
            fVar2 = (float)((double)(float)((double)CONCAT44(0x43300000,uStack_9c) - DOUBLE_803e3fb0
                                           ) + dVar21);
            dVar22 = (double)fVar2;
            pfVar13[3] = fVar2;
            fVar2 = FLOAT_803e3f8c * (float)(dVar26 - (double)pfVar13[3]) * FLOAT_803e3fa8;
            fVar3 = FLOAT_803e3f4c;
            if ((FLOAT_803e3f4c <= fVar2) && (fVar3 = fVar2, FLOAT_803e3f8c < fVar2)) {
              fVar3 = FLOAT_803e3f8c;
            }
            local_a8 = (double)(longlong)(int)(FLOAT_803e3f8c - fVar3);
            *(short *)(pfVar13 + 4) = (short)(int)(FLOAT_803e3f8c - fVar3);
            dVar23 = FUN_80010f00(dVar21,local_e8,(float *)0x0);
            pfVar13[5] = (float)dVar23;
            dVar23 = FUN_80010f00(dVar21,local_f8,(float *)0x0);
            pfVar13[6] = (float)dVar23;
            dVar23 = FUN_80010f00(dVar21,local_108,(float *)0x0);
            pfVar13[7] = (float)dVar23;
            pfVar13[5] = pfVar13[5] +
                         (float)(dVar24 * (double)(float)((double)*(float *)(in_r6 + 0xc) -
                                                         (double)*(float *)(extraout_r4 + 0x8c)) +
                                (double)*(float *)(extraout_r4 + 0x8c));
            pfVar13[6] = pfVar13[6] +
                         (float)(dVar24 * (double)(float)((double)*(float *)(in_r6 + 0xe) -
                                                         (double)*(float *)(extraout_r4 + 0x90)) +
                                (double)*(float *)(extraout_r4 + 0x90));
            pfVar13[7] = pfVar13[7] +
                         (float)(dVar24 * (double)(float)((double)*(float *)(in_r6 + 0x10) -
                                                         (double)*(float *)(extraout_r4 + 0x94)) +
                                (double)*(float *)(extraout_r4 + 0x94));
            pfVar13[8] = (float)dVar22;
            fVar2 = FLOAT_803e3f8c * (float)(dVar26 - (double)pfVar13[8]) * FLOAT_803e3fa8;
            fVar3 = FLOAT_803e3f4c;
            if ((FLOAT_803e3f4c <= fVar2) && (fVar3 = fVar2, FLOAT_803e3f8c < fVar2)) {
              fVar3 = FLOAT_803e3f8c;
            }
            local_b0 = (double)(longlong)(int)(FLOAT_803e3f8c - fVar3);
            *(short *)(pfVar13 + 9) = (short)(int)(FLOAT_803e3f8c - fVar3);
            *(short *)((int)piVar17 + 0x12) = *(short *)((int)piVar17 + 0x12) + 2;
            *(short *)((int)piVar17 + 0xe) = *(short *)((int)piVar17 + 0xe) + 2;
            uVar15 = uVar15 - 1;
          }
        }
      }
    }
    *(undefined4 *)(extraout_r4 + 0x8c) = *(undefined4 *)(in_r6 + 0xc);
    *(undefined4 *)(extraout_r4 + 0x90) = *(undefined4 *)(in_r6 + 0xe);
    *(undefined4 *)(extraout_r4 + 0x94) = *(undefined4 *)(in_r6 + 0x10);
    *(undefined4 *)(extraout_r4 + 0x98) = *(undefined4 *)(iVar6 + 4);
  }
LAB_8016eb30:
  FUN_80286878();
  return;
}

