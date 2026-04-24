// Function: FUN_80139e14
// Entry: 80139e14
// Size: 2404 bytes

/* WARNING: Removing unreachable block (ram,0x8013a758) */
/* WARNING: Removing unreachable block (ram,0x8013a750) */
/* WARNING: Removing unreachable block (ram,0x80139e2c) */
/* WARNING: Removing unreachable block (ram,0x80139e24) */

void FUN_80139e14(void)

{
  float fVar1;
  ushort uVar2;
  float fVar3;
  ushort *puVar4;
  int iVar5;
  bool bVar9;
  uint uVar6;
  ushort *puVar7;
  short sVar8;
  int iVar10;
  float *pfVar11;
  int unaff_r28;
  int iVar12;
  double dVar13;
  double in_f30;
  double dVar14;
  double in_f31;
  double dVar15;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar16;
  undefined4 local_78;
  undefined2 local_74;
  float local_70;
  undefined4 local_6c;
  float local_68;
  float local_64;
  undefined4 local_60;
  float local_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar16 = FUN_80286838();
  puVar4 = (ushort *)((ulonglong)uVar16 >> 0x20);
  pfVar11 = (float *)uVar16;
  iVar12 = *(int *)(puVar4 + 0x5c);
  dVar15 = (double)*(float *)(iVar12 + 0x14);
  FUN_80148ff0();
  *(float *)(iVar12 + 0x2c) = *pfVar11 - *(float *)(puVar4 + 0xc);
  *(float *)(iVar12 + 0x30) = pfVar11[2] - *(float *)(puVar4 + 0x10);
  dVar13 = FUN_80293900((double)(*(float *)(iVar12 + 0x2c) * *(float *)(iVar12 + 0x2c) +
                                *(float *)(iVar12 + 0x30) * *(float *)(iVar12 + 0x30)));
  if ((double)FLOAT_803e306c != dVar13) {
    *(float *)(iVar12 + 0x2c) = (float)((double)*(float *)(iVar12 + 0x2c) / dVar13);
    *(float *)(iVar12 + 0x30) = (float)((double)*(float *)(iVar12 + 0x30) / dVar13);
  }
  dVar13 = (double)FLOAT_803e30b0;
  if (dVar13 <= dVar15) {
    local_64 = FLOAT_803dc074 * (float)((double)*(float *)(iVar12 + 0x2c) * dVar15) +
               *(float *)(puVar4 + 0xc);
    local_60 = *(undefined4 *)(puVar4 + 0xe);
    local_5c = FLOAT_803dc074 * (float)((double)*(float *)(iVar12 + 0x30) * dVar15) +
               *(float *)(puVar4 + 0x10);
  }
  else {
    local_64 = (float)(dVar13 * (double)*(float *)(iVar12 + 0x2c)) * FLOAT_803dc074 +
               *(float *)(puVar4 + 0xc);
    local_60 = *(undefined4 *)(puVar4 + 0xe);
    local_5c = (float)(dVar13 * (double)*(float *)(iVar12 + 0x30)) * FLOAT_803dc074 +
               *(float *)(puVar4 + 0x10);
  }
  local_70 = local_64;
  local_6c = local_60;
  local_68 = local_5c;
  FUN_8013b568(puVar4 + 0xc,&local_70,pfVar11);
  dVar13 = FUN_80021794(&local_64,&local_70);
  if ((double)FLOAT_803e30f8 < dVar13) {
    *(float *)(iVar12 + 0x2c) = local_70 - *(float *)(puVar4 + 0xc);
    *(float *)(iVar12 + 0x30) = local_68 - *(float *)(puVar4 + 0x10);
    dVar13 = FUN_80293900((double)(*(float *)(iVar12 + 0x2c) * *(float *)(iVar12 + 0x2c) +
                                  *(float *)(iVar12 + 0x30) * *(float *)(iVar12 + 0x30)));
    if ((double)FLOAT_803e306c != dVar13) {
      *(float *)(iVar12 + 0x2c) = (float)((double)*(float *)(iVar12 + 0x2c) / dVar13);
      *(float *)(iVar12 + 0x30) = (float)((double)*(float *)(iVar12 + 0x30) / dVar13);
    }
  }
  if (dVar15 < (double)FLOAT_803e30b0) {
    uVar2 = *puVar4;
    sVar8 = 0;
    iVar10 = *(int *)(puVar4 + 0x5c);
    if (FLOAT_803e307c <
        *(float *)(iVar10 + 0x2c) * *(float *)(iVar10 + 0x2c) +
        *(float *)(iVar10 + 0x30) * *(float *)(iVar10 + 0x30)) {
      iVar5 = FUN_80021884();
      puVar7 = puVar4;
      FUN_80139cb8(puVar4,(ushort)iVar5);
      sVar8 = (short)puVar7;
      uStack_4c = (int)(short)*puVar4 ^ 0x80000000;
      local_50 = 0x43300000;
      dVar13 = (double)FUN_802945e0();
      *(float *)(iVar10 + 0x2c) = (float)-dVar13;
      uStack_54 = (int)(short)*puVar4 ^ 0x80000000;
      local_58 = 0x43300000;
      dVar13 = (double)FUN_80294964();
      *(float *)(iVar10 + 0x30) = (float)-dVar13;
    }
    iVar10 = (int)sVar8;
    if ((*(uint *)(iVar12 + 0x54) & 0x100000) != 0) {
      if (FLOAT_803e306c == *(float *)(iVar12 + 0x2ac)) {
        bVar9 = false;
      }
      else if (FLOAT_803e30a0 == *(float *)(iVar12 + 0x2b0)) {
        bVar9 = true;
      }
      else if (*(float *)(iVar12 + 0x2b4) - *(float *)(iVar12 + 0x2b0) <= FLOAT_803e30a4) {
        bVar9 = false;
      }
      else {
        bVar9 = true;
      }
      if (bVar9) {
        FUN_80148ff0();
        FUN_8013a778((double)FLOAT_803e30cc,(int)puVar4,8,0);
        *(float *)(iVar12 + 0x79c) = FLOAT_803e30d0;
        *(float *)(iVar12 + 0x838) = FLOAT_803e306c;
      }
      else {
        FUN_80148ff0();
        if ((*(uint *)(iVar12 + 0x54) & 0x400000) == 0) {
          if ((*(uint *)(iVar12 + 0x54) & 0x800000) != 0) {
            iVar5 = iVar10;
            if (iVar10 < 0) {
              iVar5 = -iVar10;
            }
            if (iVar5 < 0x3556) {
              if (iVar10 < 0) {
                iVar10 = -iVar10;
              }
              if (iVar10 < 0x2001) {
                unaff_r28 = 10;
              }
              else {
                unaff_r28 = 0xc;
              }
            }
            else {
              unaff_r28 = 0x28;
            }
          }
        }
        else {
          iVar5 = iVar10;
          if (iVar10 < 0) {
            iVar5 = -iVar10;
          }
          if (iVar5 < 0x3556) {
            if (iVar10 < 0) {
              iVar10 = -iVar10;
            }
            if (iVar10 < 0x2001) {
              unaff_r28 = 9;
            }
            else {
              unaff_r28 = 0xb;
            }
          }
          else {
            unaff_r28 = 0x27;
          }
        }
        *puVar4 = uVar2;
        FUN_8013a778((double)FLOAT_803e3108,(int)puVar4,unaff_r28,0x1000100);
      }
    }
    *(float *)(iVar12 + 0x14) = FLOAT_803e30b0;
  }
  else {
    iVar10 = *(int *)(puVar4 + 0x5c);
    if (FLOAT_803e307c <
        *(float *)(iVar10 + 0x2c) * *(float *)(iVar10 + 0x2c) +
        *(float *)(iVar10 + 0x30) * *(float *)(iVar10 + 0x30)) {
      iVar5 = FUN_80021884();
      FUN_80139cb8(puVar4,(ushort)iVar5);
      uStack_54 = (int)(short)*puVar4 ^ 0x80000000;
      local_58 = 0x43300000;
      dVar13 = (double)FUN_802945e0();
      *(float *)(iVar10 + 0x2c) = (float)-dVar13;
      uStack_4c = (int)(short)*puVar4 ^ 0x80000000;
      local_50 = 0x43300000;
      dVar13 = (double)FUN_80294964();
      *(float *)(iVar10 + 0x30) = (float)-dVar13;
    }
    if (FLOAT_803e306c == *(float *)(iVar12 + 0x2ac)) {
      bVar9 = false;
    }
    else if (FLOAT_803e30a0 == *(float *)(iVar12 + 0x2b0)) {
      bVar9 = true;
    }
    else if (*(float *)(iVar12 + 0x2b4) - *(float *)(iVar12 + 0x2b0) <= FLOAT_803e30a4) {
      bVar9 = false;
    }
    else {
      bVar9 = true;
    }
    if (bVar9) {
      FUN_8013a778((double)FLOAT_803e30f8,(int)puVar4,7,0x2000000);
      *(float *)(iVar12 + 0x79c) = FLOAT_803e30d0;
      *(float *)(iVar12 + 0x838) = FLOAT_803e306c;
      FUN_80148ff0();
    }
    else {
      if (*(char *)(iVar12 + 8) == '\x01') {
        iVar10 = *(int *)(puVar4 + 0x5c);
        pfVar11 = *(float **)(iVar10 + 0x28);
        fVar1 = FLOAT_803e306c;
        if (pfVar11 == *(float **)(iVar10 + 0x6f0)) {
          fVar1 = *(float *)(iVar10 + 0x6f4) - *(float *)(puVar4 + 0xc);
          fVar3 = *(float *)(iVar10 + 0x6fc) - *(float *)(puVar4 + 0x10);
          dVar13 = FUN_80293900((double)(fVar1 * fVar1 + fVar3 * fVar3));
          dVar14 = (double)(float)((double)FLOAT_803dc078 * dVar13);
          dVar13 = FUN_80293900((double)((*pfVar11 - *(float *)(puVar4 + 0xc)) *
                                         (*pfVar11 - *(float *)(puVar4 + 0xc)) +
                                        (pfVar11[2] - *(float *)(puVar4 + 0x10)) *
                                        (pfVar11[2] - *(float *)(puVar4 + 0x10))));
          fVar1 = (float)((double)(float)((double)FLOAT_803dc078 * dVar13) - dVar14);
        }
        if (fVar1 < FLOAT_803e306c) {
          iVar10 = *(int *)(puVar4 + 0x5c);
          pfVar11 = *(float **)(iVar10 + 0x28);
          fVar1 = FLOAT_803e306c;
          if (pfVar11 == *(float **)(iVar10 + 0x6f0)) {
            fVar1 = *(float *)(iVar10 + 0x6f4) - *(float *)(puVar4 + 0xc);
            fVar3 = *(float *)(iVar10 + 0x6fc) - *(float *)(puVar4 + 0x10);
            dVar13 = FUN_80293900((double)(fVar1 * fVar1 + fVar3 * fVar3));
            dVar14 = (double)(float)((double)FLOAT_803dc078 * dVar13);
            dVar13 = FUN_80293900((double)((*pfVar11 - *(float *)(puVar4 + 0xc)) *
                                           (*pfVar11 - *(float *)(puVar4 + 0xc)) +
                                          (pfVar11[2] - *(float *)(puVar4 + 0x10)) *
                                          (pfVar11[2] - *(float *)(puVar4 + 0x10))));
            fVar1 = (float)((double)(float)((double)FLOAT_803dc078 * dVar13) - dVar14);
          }
          fVar1 = -fVar1;
        }
        else {
          iVar10 = *(int *)(puVar4 + 0x5c);
          pfVar11 = *(float **)(iVar10 + 0x28);
          fVar1 = FLOAT_803e306c;
          if (pfVar11 == *(float **)(iVar10 + 0x6f0)) {
            fVar1 = *(float *)(iVar10 + 0x6f4) - *(float *)(puVar4 + 0xc);
            fVar3 = *(float *)(iVar10 + 0x6fc) - *(float *)(puVar4 + 0x10);
            dVar13 = FUN_80293900((double)(fVar1 * fVar1 + fVar3 * fVar3));
            dVar14 = (double)(float)((double)FLOAT_803dc078 * dVar13);
            dVar13 = FUN_80293900((double)((*pfVar11 - *(float *)(puVar4 + 0xc)) *
                                           (*pfVar11 - *(float *)(puVar4 + 0xc)) +
                                          (pfVar11[2] - *(float *)(puVar4 + 0x10)) *
                                          (pfVar11[2] - *(float *)(puVar4 + 0x10))));
            fVar1 = (float)((double)(float)((double)FLOAT_803dc078 * dVar13) - dVar14);
          }
        }
        fVar3 = FLOAT_803e306c;
        if ((FLOAT_803e306c < fVar1) &&
           (*(float *)(iVar12 + 0x7a4) = *(float *)(iVar12 + 0x7a4) - FLOAT_803dc074,
           *(float *)(iVar12 + 0x7a4) <= fVar3)) {
          uStack_4c = FUN_80022264(600,0x4b0);
          uStack_4c = uStack_4c ^ 0x80000000;
          local_50 = 0x43300000;
          *(float *)(iVar12 + 0x7a4) =
               (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e30f0);
          bVar9 = FUN_8000b598((int)puVar4,0x10);
          if (!bVar9) {
            if (dVar15 <= (double)FLOAT_803e3078) {
              local_78 = DAT_803e3064;
              local_74 = DAT_803e3068;
              uVar6 = FUN_80020078(0x25);
              if (uVar6 == 0) {
                FUN_80022264(0,1);
              }
              else {
                FUN_80022264(0,2);
              }
              uVar6 = FUN_80022264(0,2);
              uVar2 = *(ushort *)((int)&local_78 + uVar6 * 2);
              iVar10 = *(int *)(puVar4 + 0x5c);
              if (((*(byte *)(iVar10 + 0x58) >> 6 & 1) == 0) &&
                 (((0x2f < (short)puVar4[0x50] || ((short)puVar4[0x50] < 0x29)) &&
                  (bVar9 = FUN_8000b598((int)puVar4,0x10), !bVar9)))) {
                FUN_800394f0(puVar4,iVar10 + 0x3a8,uVar2,0x500,0xffffffff,0);
              }
            }
            else {
              uVar6 = FUN_80022264(0x34d,0x34e);
              iVar10 = *(int *)(puVar4 + 0x5c);
              if ((((*(byte *)(iVar10 + 0x58) >> 6 & 1) == 0) &&
                  ((0x2f < (short)puVar4[0x50] || ((short)puVar4[0x50] < 0x29)))) &&
                 (bVar9 = FUN_8000b598((int)puVar4,0x10), !bVar9)) {
                FUN_800394f0(puVar4,iVar10 + 0x3a8,(ushort)uVar6,0x500,0xffffffff,0);
              }
            }
          }
        }
      }
      if (dVar15 <= (double)FLOAT_803e30fc) {
        if (dVar15 <= (double)FLOAT_803e3078) {
          if (dVar15 <= (double)FLOAT_803e3100) {
            if (dVar15 <= (double)FLOAT_803e3104) {
              FUN_8013a778((double)FLOAT_803e30f8,(int)puVar4,1,0x3000000);
            }
            else {
              FUN_8013a778((double)FLOAT_803e30f8,(int)puVar4,2,0x3000000);
            }
          }
          else {
            FUN_8013a778((double)FLOAT_803e30f8,(int)puVar4,4,0x3000000);
          }
        }
        else {
          FUN_8013a778((double)FLOAT_803e30f8,(int)puVar4,5,0x3000000);
        }
      }
      else {
        *(float *)(iVar12 + 0x7a0) = FLOAT_803e30d0;
        FUN_8013a778((double)FLOAT_803e30f8,(int)puVar4,0x30,0x3000000);
      }
      FUN_80148ff0();
    }
  }
  FUN_80286884();
  return;
}

