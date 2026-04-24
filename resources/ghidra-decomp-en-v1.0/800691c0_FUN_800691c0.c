// Function: FUN_800691c0
// Entry: 800691c0
// Size: 1116 bytes

/* WARNING: Removing unreachable block (ram,0x800695f4) */
/* WARNING: Removing unreachable block (ram,0x800695e4) */
/* WARNING: Removing unreachable block (ram,0x800695d4) */
/* WARNING: Removing unreachable block (ram,0x800695dc) */
/* WARNING: Removing unreachable block (ram,0x800695ec) */
/* WARNING: Removing unreachable block (ram,0x800695fc) */

void FUN_800691c0(undefined4 param_1,undefined4 param_2,uint param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  float fVar11;
  int iVar12;
  int *piVar13;
  int iVar14;
  uint uVar15;
  uint uVar16;
  int *piVar17;
  int *piVar18;
  short sVar19;
  undefined4 uVar20;
  undefined8 in_f26;
  double dVar21;
  undefined8 in_f27;
  double dVar22;
  undefined8 in_f28;
  double dVar23;
  undefined8 in_f29;
  double dVar24;
  undefined8 in_f30;
  double dVar25;
  undefined8 in_f31;
  double dVar26;
  undefined8 uVar27;
  int local_f0 [2];
  undefined4 local_e8;
  uint uStack228;
  undefined4 local_e0;
  uint uStack220;
  undefined4 local_d8;
  uint uStack212;
  undefined4 local_d0;
  uint uStack204;
  undefined4 local_c8;
  uint uStack196;
  undefined4 local_c0;
  uint uStack188;
  longlong local_b8;
  longlong local_b0;
  longlong local_a8;
  longlong local_a0;
  longlong local_98;
  double local_90;
  undefined auStack88 [16];
  undefined auStack72 [16];
  undefined auStack56 [16];
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar20 = 0;
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
  __psq_st0(auStack88,(int)((ulonglong)in_f26 >> 0x20),0);
  __psq_st1(auStack88,(int)in_f26,0);
  uVar27 = FUN_802860cc();
  piVar17 = (int *)uVar27;
  uStack228 = *piVar17 - 5U ^ 0x80000000;
  local_e8 = 0x43300000;
  dVar5 = (double)CONCAT44(0x43300000,uStack228) - DOUBLE_803decd8;
  dVar26 = (double)(float)dVar5;
  uStack220 = piVar17[3] + 5U ^ 0x80000000;
  local_e0 = 0x43300000;
  dVar6 = (double)CONCAT44(0x43300000,uStack220) - DOUBLE_803decd8;
  dVar25 = (double)(float)dVar6;
  uStack212 = piVar17[1] - 5U ^ 0x80000000;
  local_d8 = 0x43300000;
  dVar7 = (double)CONCAT44(0x43300000,uStack212) - DOUBLE_803decd8;
  dVar24 = (double)(float)dVar7;
  uStack204 = piVar17[4] + 5U ^ 0x80000000;
  local_d0 = 0x43300000;
  dVar8 = (double)CONCAT44(0x43300000,uStack204) - DOUBLE_803decd8;
  dVar23 = (double)(float)dVar8;
  uStack196 = piVar17[2] - 5U ^ 0x80000000;
  local_c8 = 0x43300000;
  dVar9 = (double)CONCAT44(0x43300000,uStack196) - DOUBLE_803decd8;
  dVar22 = (double)(float)dVar9;
  uStack188 = piVar17[5] + 5U ^ 0x80000000;
  local_c0 = 0x43300000;
  dVar10 = (double)CONCAT44(0x43300000,uStack188) - DOUBLE_803decd8;
  dVar21 = (double)(float)dVar10;
  DAT_8038dc64 = 0;
  DAT_8038dc68 = 0;
  piVar17 = &DAT_8038dc7c;
  DAT_803dcf70 = DAT_803dcf30 + 0x16440;
  uVar16 = DAT_803dcf30;
  if ((param_3 & 0x10) == 0) {
    iVar12 = (int)dVar5;
    local_b8 = (longlong)iVar12;
    iVar14 = (int)dVar7;
    local_b0 = (longlong)iVar14;
    iVar1 = (int)dVar9;
    local_a8 = (longlong)iVar1;
    iVar2 = (int)dVar6;
    local_a0 = (longlong)iVar2;
    iVar3 = (int)dVar8;
    local_98 = (longlong)iVar3;
    iVar4 = (int)dVar10;
    local_90 = (double)(longlong)iVar4;
    uVar16 = FUN_800685cc(DAT_803dcf30,iVar12,iVar14,iVar1,iVar2,iVar3,iVar4,param_3,param_4);
  }
  if (((uVar16 < DAT_803dcf70) && ((param_3 & 1) != 0)) && ((int)((ulonglong)uVar27 >> 0x20) != 0))
  {
    piVar13 = (int *)FUN_80036afc(local_f0);
    for (sVar19 = 0; sVar19 < local_f0[0]; sVar19 = sVar19 + 1) {
      iVar12 = *piVar13;
      if ((((((param_3 & 0x80) == 0) ||
            ((*(uint *)(*(int *)(iVar12 + 0x50) + 0x44) & 0x1000000) == 0)) &&
           ((*(int *)(iVar12 + 0x54) != 0 &&
            ((iVar14 = *(int *)(iVar12 + 0x58), iVar14 != 0 && (*(char *)(iVar14 + 0x10d) == '\0')))
            ))) && (*(char *)(iVar14 + 0x10e) == '\0')) &&
         ((piVar18 = *(int **)(*(int *)(iVar12 + 0x7c) +
                              *(char *)(*(int *)(iVar12 + 0x54) + 0xb0) * 4), piVar18 != (int *)0x0
          && (*(short *)(*piVar18 + 0xf0) != 0)))) {
        uVar15 = FUN_80028434();
        local_90 = (double)CONCAT44(0x43300000,uVar15 & 0xffff);
        fVar11 = (float)(local_90 - DOUBLE_803ded00);
        if (((double)(*(float *)(iVar12 + 0x18) - fVar11) <= dVar25) &&
           ((((dVar26 <= (double)(*(float *)(iVar12 + 0x18) + fVar11) &&
              ((double)(*(float *)(iVar12 + 0x1c) - fVar11) <= dVar23)) &&
             (dVar24 <= (double)(*(float *)(iVar12 + 0x1c) + fVar11))) &&
            (((double)(*(float *)(iVar12 + 0x20) - fVar11) <= dVar21 &&
             (dVar22 <= (double)(*(float *)(iVar12 + 0x20) + fVar11))))))) {
          piVar17[3] = *(int *)(iVar12 + 0x58) +
                       (*(byte *)(*(int *)(iVar12 + 0x58) + 0x10c) + 2) * 0x40;
          piVar17[2] = *(int *)(iVar12 + 0x58) +
                       (uint)*(byte *)(*(int *)(iVar12 + 0x58) + 0x10c) * 0x40;
          piVar17[5] = *(int *)(iVar12 + 0x58) +
                       ((*(byte *)(*(int *)(iVar12 + 0x58) + 0x10c) ^ 1) + 2) * 0x40;
          piVar17[4] = *(int *)(iVar12 + 0x58) +
                       (*(byte *)(*(int *)(iVar12 + 0x58) + 0x10c) ^ 1) * 0x40;
          iVar14 = (int)(uVar16 - DAT_803dcf30) / 0x4c + ((int)(uVar16 - DAT_803dcf30) >> 0x1f);
          *(short *)(piVar17 + 1) = (short)iVar14 - (short)(iVar14 >> 0x1f);
          *piVar17 = iVar12;
          uVar16 = FUN_80067b84((double)FLOAT_803decc4,dVar26,dVar24,dVar22,dVar25,dVar23,dVar21,
                                uVar16,piVar17,piVar18,param_3 & 0xff);
          piVar17 = piVar17 + 6;
          if ((DAT_803dcf70 <= uVar16) || ((int *)0x8038de43 < piVar17)) break;
        }
      }
      piVar13 = piVar13 + 1;
    }
  }
  iVar12 = (int)(uVar16 - DAT_803dcf30) / 0x4c + ((int)(uVar16 - DAT_803dcf30) >> 0x1f);
  DAT_803dcf6e = (short)iVar12 - (short)(iVar12 >> 0x1f);
  iVar12 = (int)(piVar17 + 0x1ff1c8e7) / 0x18 + ((int)(piVar17 + 0x1ff1c8e7) >> 0x1f);
  DAT_803dcf6c = (char)iVar12 - (char)(iVar12 >> 0x1f);
  *(short *)(piVar17 + 1) = DAT_803dcf6e;
  __psq_l0(auStack8,uVar20);
  __psq_l1(auStack8,uVar20);
  __psq_l0(auStack24,uVar20);
  __psq_l1(auStack24,uVar20);
  __psq_l0(auStack40,uVar20);
  __psq_l1(auStack40,uVar20);
  __psq_l0(auStack56,uVar20);
  __psq_l1(auStack56,uVar20);
  __psq_l0(auStack72,uVar20);
  __psq_l1(auStack72,uVar20);
  __psq_l0(auStack88,uVar20);
  __psq_l1(auStack88,uVar20);
  FUN_80286118();
  return;
}

