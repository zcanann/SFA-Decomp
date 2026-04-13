// Function: FUN_8006933c
// Entry: 8006933c
// Size: 1116 bytes

/* WARNING: Removing unreachable block (ram,0x80069778) */
/* WARNING: Removing unreachable block (ram,0x80069770) */
/* WARNING: Removing unreachable block (ram,0x80069768) */
/* WARNING: Removing unreachable block (ram,0x80069760) */
/* WARNING: Removing unreachable block (ram,0x80069758) */
/* WARNING: Removing unreachable block (ram,0x80069750) */
/* WARNING: Removing unreachable block (ram,0x80069374) */
/* WARNING: Removing unreachable block (ram,0x8006936c) */
/* WARNING: Removing unreachable block (ram,0x80069364) */
/* WARNING: Removing unreachable block (ram,0x8006935c) */
/* WARNING: Removing unreachable block (ram,0x80069354) */
/* WARNING: Removing unreachable block (ram,0x8006934c) */

void FUN_8006933c(undefined4 param_1,undefined4 param_2,uint param_3,char param_4)

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
  ushort uVar16;
  uint uVar15;
  int *piVar17;
  int *piVar18;
  short sVar19;
  double in_f26;
  double dVar20;
  double in_f27;
  double dVar21;
  double in_f28;
  double dVar22;
  double in_f29;
  double dVar23;
  double in_f30;
  double dVar24;
  double in_f31;
  double dVar25;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar26;
  int local_f0 [2];
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_e0;
  uint uStack_dc;
  undefined4 local_d8;
  uint uStack_d4;
  undefined4 local_d0;
  uint uStack_cc;
  undefined4 local_c8;
  uint uStack_c4;
  undefined4 local_c0;
  uint uStack_bc;
  longlong local_b8;
  longlong local_b0;
  longlong local_a8;
  longlong local_a0;
  longlong local_98;
  undefined8 local_90;
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
  uVar26 = FUN_80286830();
  piVar17 = (int *)uVar26;
  uStack_e4 = *piVar17 - 5U ^ 0x80000000;
  local_e8 = 0x43300000;
  dVar5 = (double)CONCAT44(0x43300000,uStack_e4) - DOUBLE_803df958;
  dVar25 = (double)(float)dVar5;
  uStack_dc = piVar17[3] + 5U ^ 0x80000000;
  local_e0 = 0x43300000;
  dVar6 = (double)CONCAT44(0x43300000,uStack_dc) - DOUBLE_803df958;
  dVar24 = (double)(float)dVar6;
  uStack_d4 = piVar17[1] - 5U ^ 0x80000000;
  local_d8 = 0x43300000;
  dVar7 = (double)CONCAT44(0x43300000,uStack_d4) - DOUBLE_803df958;
  dVar23 = (double)(float)dVar7;
  uStack_cc = piVar17[4] + 5U ^ 0x80000000;
  local_d0 = 0x43300000;
  dVar8 = (double)CONCAT44(0x43300000,uStack_cc) - DOUBLE_803df958;
  dVar22 = (double)(float)dVar8;
  uStack_c4 = piVar17[2] - 5U ^ 0x80000000;
  local_c8 = 0x43300000;
  dVar9 = (double)CONCAT44(0x43300000,uStack_c4) - DOUBLE_803df958;
  dVar21 = (double)(float)dVar9;
  uStack_bc = piVar17[5] + 5U ^ 0x80000000;
  local_c0 = 0x43300000;
  dVar10 = (double)CONCAT44(0x43300000,uStack_bc) - DOUBLE_803df958;
  dVar20 = (double)(float)dVar10;
  DAT_8038e8c4 = 0;
  DAT_8038e8c8 = 0;
  piVar17 = &DAT_8038e8dc;
  DAT_803ddbf0 = DAT_803ddbb0 + 0x16440;
  uVar15 = DAT_803ddbb0;
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
    uVar15 = FUN_80068748(DAT_803ddbb0,iVar12,iVar14,iVar1,iVar2,iVar3,iVar4,param_3,param_4);
  }
  if (((uVar15 < DAT_803ddbf0) && ((param_3 & 1) != 0)) && ((int)((ulonglong)uVar26 >> 0x20) != 0))
  {
    piVar13 = (int *)FUN_80036bf4(local_f0);
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
        uVar16 = FUN_800284f8(*piVar18);
        local_90 = (double)CONCAT44(0x43300000,(uint)uVar16);
        fVar11 = (float)(local_90 - DOUBLE_803df980);
        if (((double)(*(float *)(iVar12 + 0x18) - fVar11) <= dVar24) &&
           ((((dVar25 <= (double)(*(float *)(iVar12 + 0x18) + fVar11) &&
              ((double)(*(float *)(iVar12 + 0x1c) - fVar11) <= dVar22)) &&
             (dVar23 <= (double)(*(float *)(iVar12 + 0x1c) + fVar11))) &&
            (((double)(*(float *)(iVar12 + 0x20) - fVar11) <= dVar20 &&
             (dVar21 <= (double)(*(float *)(iVar12 + 0x20) + fVar11))))))) {
          piVar17[3] = *(int *)(iVar12 + 0x58) +
                       (*(byte *)(*(int *)(iVar12 + 0x58) + 0x10c) + 2) * 0x40;
          piVar17[2] = *(int *)(iVar12 + 0x58) +
                       (uint)*(byte *)(*(int *)(iVar12 + 0x58) + 0x10c) * 0x40;
          piVar17[5] = *(int *)(iVar12 + 0x58) +
                       ((*(byte *)(*(int *)(iVar12 + 0x58) + 0x10c) ^ 1) + 2) * 0x40;
          piVar17[4] = *(int *)(iVar12 + 0x58) +
                       (*(byte *)(*(int *)(iVar12 + 0x58) + 0x10c) ^ 1) * 0x40;
          iVar14 = (int)(uVar15 - DAT_803ddbb0) / 0x4c + ((int)(uVar15 - DAT_803ddbb0) >> 0x1f);
          *(short *)(piVar17 + 1) = (short)iVar14 - (short)(iVar14 >> 0x1f);
          *piVar17 = iVar12;
          uVar15 = FUN_80067d00((double)FLOAT_803df944,dVar25,dVar23,dVar21,dVar24,dVar22,dVar20,
                                uVar15,piVar17,piVar18,param_3 & 0xff);
          piVar17 = piVar17 + 6;
          if ((DAT_803ddbf0 <= uVar15) || ((int *)0x8038eaa3 < piVar17)) break;
        }
      }
      piVar13 = piVar13 + 1;
    }
  }
  iVar12 = (int)(uVar15 - DAT_803ddbb0) / 0x4c + ((int)(uVar15 - DAT_803ddbb0) >> 0x1f);
  DAT_803ddbee = (short)iVar12 - (short)(iVar12 >> 0x1f);
  iVar12 = (int)(piVar17 + 0x1ff1c5cf) / 0x18 + ((int)(piVar17 + 0x1ff1c5cf) >> 0x1f);
  DAT_803ddbec = (char)iVar12 - (char)(iVar12 >> 0x1f);
  *(short *)(piVar17 + 1) = DAT_803ddbee;
  FUN_8028687c();
  return;
}

