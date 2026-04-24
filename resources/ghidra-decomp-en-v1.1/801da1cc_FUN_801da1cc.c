// Function: FUN_801da1cc
// Entry: 801da1cc
// Size: 1704 bytes

/* WARNING: Removing unreachable block (ram,0x801da854) */
/* WARNING: Removing unreachable block (ram,0x801da84c) */
/* WARNING: Removing unreachable block (ram,0x801da844) */
/* WARNING: Removing unreachable block (ram,0x801da83c) */
/* WARNING: Removing unreachable block (ram,0x801da834) */
/* WARNING: Removing unreachable block (ram,0x801da1fc) */
/* WARNING: Removing unreachable block (ram,0x801da1f4) */
/* WARNING: Removing unreachable block (ram,0x801da1ec) */
/* WARNING: Removing unreachable block (ram,0x801da1e4) */
/* WARNING: Removing unreachable block (ram,0x801da1dc) */

void FUN_801da1cc(void)

{
  byte bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  ushort *puVar5;
  int iVar6;
  float *pfVar7;
  char *pcVar8;
  uint uVar9;
  char in_r8;
  char *pcVar10;
  int iVar11;
  double in_f27;
  double dVar12;
  double in_f28;
  double dVar13;
  double in_f29;
  double dVar14;
  double in_f30;
  double dVar15;
  double in_f31;
  double dVar16;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_f8;
  float local_f4;
  float local_f0;
  float local_ec;
  float local_e8;
  float local_e4;
  float afStack_e0 [12];
  float afStack_b0 [12];
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
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
  puVar5 = (ushort *)FUN_80286834();
  pcVar10 = *(char **)(puVar5 + 0x5c);
  iVar6 = FUN_8002bac4();
  if (in_r8 != '\0') {
    if (*pcVar10 == '\x03') {
      FUN_8002b554(puVar5,afStack_b0,'\0');
      pfVar7 = (float *)FUN_80038498(iVar6,0);
      FUN_80247734(pfVar7,afStack_e0);
      FUN_80247618(afStack_e0,afStack_b0,(float *)(pcVar10 + 8));
      *pcVar10 = '\x05';
    }
    if (*pcVar10 == '\x04') {
      FUN_80038428(iVar6,0,(float *)(pcVar10 + 8));
      *pcVar10 = '\x05';
    }
    if (*pcVar10 == '\x05') {
      pfVar7 = (float *)FUN_80038498(iVar6,0);
      FUN_80247618(pfVar7,(float *)(pcVar10 + 8),afStack_b0);
      FUN_800413cc(afStack_b0);
      FUN_80041bbc((int)puVar5);
    }
    else {
      FUN_8003b9ec((int)puVar5);
    }
    FUN_80038524(puVar5,0,&local_ec,&local_e8,&local_e4,0);
    FUN_80038524(puVar5,1,&local_f8,&local_f4,&local_f0,0);
    dVar16 = (double)(local_f8 - local_ec);
    dVar15 = (double)(local_f4 - local_e8);
    dVar14 = (double)(local_f0 - local_e4);
    if (((pcVar10[2] & 1U) != 0) && ((pcVar10[2] & 2U) == 0)) {
      iVar6 = 2;
      iVar11 = 4;
      pcVar8 = pcVar10;
      do {
        if (*(int *)(pcVar8 + 0x40) == 0) {
          pcVar10[iVar6 + 0x60] = '\x01';
          break;
        }
        iVar6 = iVar6 + 2;
        iVar11 = iVar11 + -1;
        pcVar8 = pcVar8 + 8;
      } while (iVar11 != 0);
      if (9 < iVar6) {
        pcVar10[2] = pcVar10[2] | 2;
      }
    }
    if (((pcVar10[2] & 4U) != 0) && ((pcVar10[2] & 8U) == 0)) {
      iVar6 = 1;
      pcVar8 = pcVar10 + 4;
      iVar11 = 5;
      do {
        if (*(int *)(pcVar8 + 0x38) == 0) {
          pcVar10[iVar6 + 0x60] = '\x01';
          break;
        }
        pcVar8 = pcVar8 + 8;
        iVar6 = iVar6 + 2;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
      if (9 < iVar6) {
        pcVar10[2] = pcVar10[2] | 8;
      }
    }
    fVar3 = FLOAT_803e6190;
    fVar2 = FLOAT_803e616c;
    bVar1 = pcVar10[2];
    if (bVar1 == 0) {
      if (*(float *)(pcVar10 + 4) != FLOAT_803e616c) {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - FLOAT_803dc074;
        if (fVar2 < *(float *)(pcVar10 + 4)) {
          fVar3 = FLOAT_803e617c * *(float *)(pcVar10 + 4);
        }
        else {
          iVar6 = *(int *)(pcVar10 + 0x38);
          if (iVar6 != 0) {
            *(ushort *)(iVar6 + 6) = *(ushort *)(iVar6 + 6) | 0x4000;
            pcVar10[0x38] = '\0';
            pcVar10[0x39] = '\0';
            pcVar10[0x3a] = '\0';
            pcVar10[0x3b] = '\0';
            *(float *)(pcVar10 + 4) = fVar2;
          }
        }
      }
      if (*(int *)(pcVar10 + 0x38) != 0) {
        *(float *)(*(int *)(pcVar10 + 0x38) + 0xc) =
             (float)(dVar16 * (double)*(float *)(pcVar10 + 0x6c) + (double)local_ec);
        *(float *)(*(int *)(pcVar10 + 0x38) + 0x10) =
             (float)(dVar15 * (double)*(float *)(pcVar10 + 0x6c) + (double)local_e8);
        *(float *)(*(int *)(pcVar10 + 0x38) + 0x14) =
             (float)(dVar14 * (double)*(float *)(pcVar10 + 0x6c) + (double)local_e4);
        *(float *)(*(int *)(pcVar10 + 0x38) + 8) = fVar3;
      }
    }
    else if ((bVar1 & 0x20) == 0) {
      dVar13 = (double)FLOAT_803e6170;
      if ((bVar1 & 0x10) != 0) {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - FLOAT_803dc074;
        if (FLOAT_803e616c < *(float *)(pcVar10 + 4)) {
          dVar13 = (double)(FLOAT_803e617c * *(float *)(pcVar10 + 4));
        }
        else {
          pcVar10[2] = pcVar10[2] & 0xef;
        }
      }
      uVar9 = 0;
      do {
        if (*(int *)(pcVar10 + 0x38) != 0) {
          uStack_7c = uVar9 ^ 0x80000000;
          local_80 = 0x43300000;
          dVar12 = (double)(FLOAT_803e6188 *
                           (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e6198));
          uStack_74 = FUN_80022264(0xffffffce,0x32);
          uStack_74 = uStack_74 ^ 0x80000000;
          local_78 = 0x43300000;
          dVar12 = (double)(float)(dVar12 + (double)((float)((double)CONCAT44(0x43300000,uStack_74)
                                                            - DOUBLE_803e6198) / FLOAT_803e618c));
          *(float *)(*(int *)(pcVar10 + 0x38) + 0xc) = (float)(dVar16 * dVar12 + (double)local_ec);
          *(float *)(*(int *)(pcVar10 + 0x38) + 0x10) = (float)(dVar15 * dVar12 + (double)local_e8);
          *(float *)(*(int *)(pcVar10 + 0x38) + 0x14) = (float)(dVar14 * dVar12 + (double)local_e4);
          *(float *)(*(int *)(pcVar10 + 0x38) + 8) = (float)dVar13;
        }
        pcVar10 = pcVar10 + 4;
        uVar9 = uVar9 + 1;
      } while ((int)uVar9 < 10);
    }
    else {
      pcVar8 = pcVar10 + 0x14;
      for (iVar6 = 5; iVar6 < 5; iVar6 = iVar6 + 1) {
        iVar11 = *(int *)(pcVar8 + 0x38);
        if (iVar11 != 0) {
          *(ushort *)(iVar11 + 6) = *(ushort *)(iVar11 + 6) | 0x4000;
          pcVar8[0x38] = '\0';
          pcVar8[0x39] = '\0';
          pcVar8[0x3a] = '\0';
          pcVar8[0x3b] = '\0';
        }
        pcVar8 = pcVar8 + 4;
      }
      if ((pcVar10[2] & 0x10U) == 0) {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) + FLOAT_803dc074;
        if (FLOAT_803e6178 <= *(float *)(pcVar10 + 4)) {
          *(float *)(pcVar10 + 4) = FLOAT_803e6178;
        }
        fVar3 = FLOAT_803e617c * *(float *)(pcVar10 + 4);
      }
      else {
        *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - FLOAT_803dc074;
        fVar3 = FLOAT_803e6170;
        if (FLOAT_803e616c < *(float *)(pcVar10 + 4)) {
          *(float *)(pcVar10 + 4) = *(float *)(pcVar10 + 4) - FLOAT_803dc074;
          fVar3 = FLOAT_803e6174 * *(float *)(pcVar10 + 4);
        }
      }
      uVar9 = 0;
      iVar6 = 5;
      pcVar8 = pcVar10;
      do {
        if ((*(int *)(pcVar8 + 0x38) != 0) && (*(int *)(pcVar10 + 0x48) != 0)) {
          uStack_7c = uVar9 ^ 0x80000000;
          local_80 = 0x43300000;
          fVar4 = FLOAT_803e6180 +
                  (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e6198) / FLOAT_803e6184
          ;
          fVar2 = *(float *)(*(int *)(pcVar10 + 0x48) + 0xc);
          *(float *)(*(int *)(pcVar8 + 0x38) + 0xc) = fVar4 * (local_ec - fVar2) + fVar2;
          *(float *)(*(int *)(pcVar8 + 0x38) + 0x10) =
               fVar4 * (local_e8 - *(float *)(*(int *)(pcVar10 + 0x48) + 0x10)) +
               *(float *)(*(int *)(pcVar10 + 0x48) + 0x10);
          *(float *)(*(int *)(pcVar8 + 0x38) + 0x14) =
               fVar4 * (local_e4 - *(float *)(*(int *)(pcVar10 + 0x48) + 0x14)) +
               *(float *)(*(int *)(pcVar10 + 0x48) + 0x14);
          *(float *)(*(int *)(pcVar8 + 0x38) + 8) = fVar3;
        }
        pcVar8 = pcVar8 + 4;
        uVar9 = uVar9 + 1;
        iVar6 = iVar6 + -1;
      } while (iVar6 != 0);
      iVar6 = 9;
      pcVar8 = pcVar10 + 0x24;
      iVar11 = 5;
      do {
        if ((*(int *)(pcVar8 + 0x38) != 0) && (*(int *)(pcVar10 + 0x4c) != 0)) {
          uStack_7c = 9U - iVar6 ^ 0x80000000;
          local_80 = 0x43300000;
          fVar4 = FLOAT_803e6180 +
                  (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e6198) / FLOAT_803e6184
          ;
          fVar2 = *(float *)(*(int *)(pcVar10 + 0x4c) + 0xc);
          *(float *)(*(int *)(pcVar8 + 0x38) + 0xc) = fVar4 * (local_f8 - fVar2) + fVar2;
          *(float *)(*(int *)(pcVar8 + 0x38) + 0x10) =
               fVar4 * (local_f4 - *(float *)(*(int *)(pcVar10 + 0x4c) + 0x10)) +
               *(float *)(*(int *)(pcVar10 + 0x4c) + 0x10);
          *(float *)(*(int *)(pcVar8 + 0x38) + 0x14) =
               fVar4 * (local_f0 - *(float *)(*(int *)(pcVar10 + 0x4c) + 0x14)) +
               *(float *)(*(int *)(pcVar10 + 0x4c) + 0x14);
          *(float *)(*(int *)(pcVar8 + 0x38) + 8) = fVar3;
        }
        pcVar8 = pcVar8 + -4;
        iVar6 = iVar6 + -1;
        iVar11 = iVar11 + -1;
      } while (iVar11 != 0);
    }
  }
  FUN_80286880();
  return;
}

