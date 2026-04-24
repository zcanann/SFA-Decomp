#include "ghidra_import.h"
#include "main/dll/df_partfx.h"

extern undefined4 FUN_8000bb38();
extern undefined4 FUN_8000f3f8();
extern undefined4 FUN_80013e4c();
extern undefined4 FUN_80013ee8();
extern int FUN_80021884();
extern undefined4 FUN_80021fac();
extern undefined4 FUN_80022790();
extern undefined4 FUN_8002ba34();
extern undefined4 fn_8002EE64();
extern int FUN_8002f6cc();
extern undefined4 FUN_8003042c();
extern undefined4 FUN_80070538();
extern undefined4 FUN_80075534();
extern int FUN_800d57bc();
extern undefined4 FUN_8025da88();
extern undefined4 FUN_8025db38();
extern undefined8 FUN_8028682c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_802945e0();
extern undefined4 FUN_80294964();

extern undefined4 DAT_8039d0b8;
extern undefined4 DAT_8039d0bc;
extern undefined4 DAT_803dd5d0;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd71c;
extern undefined4 DAT_803de090;
extern undefined4 DAT_803de0ac;
extern undefined4 DAT_803de0ad;
extern undefined4 DAT_803de0ae;
extern undefined4 DAT_803de0af;
extern undefined4 DAT_803de0b4;
extern undefined4 DAT_803de0b8;
extern undefined4 DAT_803de0bc;
extern undefined4 DAT_803de0cc;
extern f64 DOUBLE_803e1178;
extern f64 DOUBLE_803e11a0;
extern f64 DOUBLE_803e11d0;
extern f64 DOUBLE_803e1218;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803de0a0;
extern f32 FLOAT_803de0a4;
extern f32 FLOAT_803de0a8;
extern f32 FLOAT_803e1168;
extern f32 FLOAT_803e1184;
extern f32 FLOAT_803e118c;
extern f32 FLOAT_803e1190;
extern f32 FLOAT_803e1194;
extern f32 FLOAT_803e1198;
extern f32 FLOAT_803e119c;
extern f32 FLOAT_803e11a8;
extern f32 FLOAT_803e11ac;
extern f32 FLOAT_803e11b0;
extern f32 FLOAT_803e11b4;
extern f32 FLOAT_803e11b8;
extern f32 FLOAT_803e11c0;
extern f32 FLOAT_803e11c4;
extern f32 FLOAT_803e11c8;
extern f32 FLOAT_803e11d8;
extern f32 FLOAT_803e11dc;
extern f32 FLOAT_803e11e0;
extern f32 FLOAT_803e11e4;
extern f32 FLOAT_803e11e8;
extern f32 FLOAT_803e11f0;
extern f32 FLOAT_803e11f4;
extern f32 FLOAT_803e11f8;
extern f32 FLOAT_803e11fc;
extern f32 FLOAT_803e1200;
extern f32 FLOAT_803e1204;
extern f32 FLOAT_803e1208;
extern f32 FLOAT_803e120c;
extern f32 FLOAT_803e1210;
extern f32 FLOAT_803e1214;
extern f32 FLOAT_803e1220;
extern f32 FLOAT_803e122c;
extern f32 FLOAT_803e1230;

/*
 * --INFO--
 *
 * Function: FUN_800d6844
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D6844
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d6844(int param_1)
{
  int iVar1;
  int aiStack_18 [5];
  
  iVar1 = FUN_800d57bc(*(uint *)(param_1 + 0x10),aiStack_18);
  if (iVar1 == 0) {
    *(undefined4 *)(param_1 + 0x18) = 0;
    *(float *)(param_1 + 0xc) = FLOAT_803e1168;
  }
  else {
    while (-1 < (int)*(uint *)(iVar1 + 0x18)) {
      iVar1 = FUN_800d57bc(*(uint *)(iVar1 + 0x18),aiStack_18);
      *(int *)(param_1 + 0x1c) = *(int *)(param_1 + 0x1c) + 1;
    }
    *(undefined4 *)(param_1 + 0x18) = *(undefined4 *)(param_1 + 0x10);
    *(float *)(param_1 + 0xc) = FLOAT_803e1168;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d68ec
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D68EC
 * EN v1.1 Size: 1136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d68ec(void)
{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double in_f22;
  double in_f23;
  double dVar15;
  double in_f24;
  double in_f25;
  double in_f26;
  double dVar16;
  double in_f27;
  double dVar17;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps22_1;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar18;
  int iStack_d8;
  int aiStack_d4 [3];
  undefined4 local_c8;
  uint uStack_c4;
  float local_98;
  float fStack_94;
  float local_88;
  float fStack_84;
  float local_78;
  float fStack_74;
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
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  local_98 = (float)in_f22;
  fStack_94 = (float)in_ps22_1;
  uVar18 = FUN_80286840();
  iVar3 = (int)((ulonglong)uVar18 >> 0x20);
  iVar6 = (int)uVar18;
  if (*(int *)(iVar6 + 0x18) < 0) {
    *(undefined4 *)(iVar6 + 0x1c) = 0;
    *(float *)(iVar6 + 0xc) = FLOAT_803e1168;
    if (*(int *)(iVar6 + 0x10) < 0) goto LAB_800d6cf4;
    *(int *)(iVar6 + 0x18) = *(int *)(iVar6 + 0x10);
  }
  iVar4 = FUN_800d57bc(*(uint *)(iVar6 + 0x18),&iStack_d8);
  if (iVar4 == 0) {
    *(undefined4 *)(iVar6 + 0x18) = 0xffffffff;
  }
  else {
    aiStack_d4[2] = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
    aiStack_d4[1] = 0x43300000;
    dVar7 = (double)FUN_802945e0();
    uStack_c4 = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
    local_c8 = 0x43300000;
    dVar8 = (double)FUN_80294964();
    dVar15 = -(double)(float)((double)*(float *)(iVar4 + 8) * dVar7 +
                             (double)(float)((double)*(float *)(iVar4 + 0x10) * dVar8));
    dVar17 = (double)(float)(dVar15 + (double)(float)(dVar7 * (double)*(float *)(iVar3 + 0xc) +
                                                     (double)(float)(dVar8 * (double)*(float *)(
                                                  iVar3 + 0x14))));
    if ((*(int *)(iVar4 + 0x18) < 0) || (dVar17 < (double)FLOAT_803e1168)) {
      if (-1 < (int)*(uint *)(iVar4 + 0x20)) {
        iVar5 = FUN_800d57bc(*(uint *)(iVar4 + 0x20),aiStack_d4);
        FUN_80021884();
        uStack_c4 = (uint)*(byte *)(iVar5 + 0x29) << 8 ^ 0x80000000;
        local_c8 = 0x43300000;
        dVar9 = (double)FUN_802945e0();
        aiStack_d4[2] = (uint)*(byte *)(iVar5 + 0x29) << 8 ^ 0x80000000;
        aiStack_d4[1] = 0x43300000;
        dVar10 = (double)FUN_80294964();
        fVar2 = FLOAT_803e1168;
        dVar13 = (double)*(float *)(iVar5 + 8);
        dVar12 = (double)*(float *)(iVar5 + 0x10);
        fVar1 = -(float)(dVar13 * dVar9 + (double)(float)(dVar12 * dVar10));
        dVar16 = (double)(fVar1 + (float)(dVar9 * (double)*(float *)(iVar3 + 0xc) +
                                         (double)(float)(dVar10 * (double)*(float *)(iVar3 + 0x14)))
                         );
        dVar11 = (double)FLOAT_803e1168;
        if (dVar11 <= dVar16) {
          dVar15 = (double)(float)(dVar15 + (double)(float)(dVar7 * dVar13 +
                                                           (double)(float)(dVar8 * dVar12)));
          dVar14 = (double)(fVar1 + (float)(dVar9 * (double)*(float *)(iVar4 + 8) +
                                           (double)(float)(dVar10 * (double)*(float *)(iVar4 + 0x10)
                                                          )));
          if ((((dVar15 < dVar11) && (dVar17 < dVar11)) ||
              (((double)FLOAT_803e1168 <= dVar15 && ((double)FLOAT_803e1168 <= dVar17)))) &&
             (((dVar14 <= (double)FLOAT_803e1168 && (dVar16 <= (double)FLOAT_803e1168)) ||
              (((double)FLOAT_803e1168 < dVar14 && ((double)FLOAT_803e1168 < dVar16)))))) {
            dVar13 = (double)(float)((double)*(float *)(iVar4 + 8) - dVar13);
            fVar1 = *(float *)(iVar4 + 0xc) - *(float *)(iVar5 + 0xc);
            dVar11 = (double)(float)((double)*(float *)(iVar4 + 0x10) - dVar12);
            dVar15 = FUN_80293900((double)(float)(dVar11 * dVar11 +
                                                 (double)(float)(dVar13 * dVar13 +
                                                                (double)(fVar1 * fVar1))));
            if ((double)FLOAT_803e1168 < dVar15) {
              in_f25 = (double)(float)(dVar13 * (double)(float)((double)FLOAT_803e1184 / dVar15));
              in_f24 = (double)(float)(dVar11 * (double)(float)((double)FLOAT_803e1184 / dVar15));
            }
            dVar7 = (double)(float)(dVar7 * in_f25 + (double)(float)(dVar8 * in_f24));
            if ((dVar7 <= (double)FLOAT_803e1190) || ((double)FLOAT_803e1194 <= dVar7)) {
              dVar8 = (double)(float)(dVar9 * in_f25 + (double)(float)(dVar10 * in_f24));
              if ((dVar8 <= (double)FLOAT_803e1190) || ((double)FLOAT_803e1194 <= dVar8)) {
                fVar1 = (float)(-dVar17 / dVar7) + (float)(dVar16 / dVar8);
                fVar2 = FLOAT_803e1168;
                if (FLOAT_803e1168 != fVar1) {
                  fVar2 = (float)(-dVar17 / dVar7) / fVar1;
                }
                *(float *)(iVar6 + 0xc) = fVar2;
                if (*(float *)(iVar6 + 0xc) < FLOAT_803e1168) {
                  *(float *)(iVar6 + 0xc) = FLOAT_803e1168;
                }
                if (FLOAT_803e1198 <= *(float *)(iVar6 + 0xc)) {
                  *(float *)(iVar6 + 0xc) = FLOAT_803e1198;
                }
              }
            }
          }
        }
        else {
          *(undefined4 *)(iVar6 + 0x18) = *(undefined4 *)(iVar4 + 0x20);
          *(float *)(iVar6 + 0xc) = fVar2;
          *(int *)(iVar6 + 0x1c) = *(int *)(iVar6 + 0x1c) + 1;
        }
      }
    }
    else {
      *(int *)(iVar6 + 0x18) = *(int *)(iVar4 + 0x18);
      *(float *)(iVar6 + 0xc) = FLOAT_803e118c;
      *(int *)(iVar6 + 0x1c) = *(int *)(iVar6 + 0x1c) + -1;
    }
  }
LAB_800d6cf4:
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d6d5c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D6D5C
 * EN v1.1 Size: 2712b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d6d5c(undefined4 param_1,undefined4 param_2,int param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  float *pfVar8;
  char *pcVar9;
  int iVar10;
  char *pcVar11;
  undefined4 *puVar12;
  int iVar13;
  uint uVar14;
  double dVar15;
  double dVar16;
  double dVar17;
  double dVar18;
  double dVar19;
  double dVar20;
  double dVar21;
  double in_f21;
  double dVar22;
  double in_f22;
  double in_f23;
  double in_f24;
  double in_f25;
  double in_f26;
  double dVar23;
  double in_f27;
  double dVar24;
  double in_f28;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps21_1;
  double in_ps22_1;
  double in_ps23_1;
  double in_ps24_1;
  double in_ps25_1;
  double in_ps26_1;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar25;
  int local_2c8;
  int local_2c4;
  char local_2c0 [200];
  int local_1f8 [64];
  undefined4 local_f8;
  uint uStack_f4;
  undefined4 local_f0;
  uint uStack_ec;
  undefined4 local_e8;
  uint uStack_e4;
  undefined4 local_e0;
  uint uStack_dc;
  float local_a8;
  float fStack_a4;
  float local_98;
  float fStack_94;
  float local_88;
  float fStack_84;
  float local_78;
  float fStack_74;
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
  local_78 = (float)in_f24;
  fStack_74 = (float)in_ps24_1;
  local_88 = (float)in_f23;
  fStack_84 = (float)in_ps23_1;
  local_98 = (float)in_f22;
  fStack_94 = (float)in_ps22_1;
  local_a8 = (float)in_f21;
  fStack_a4 = (float)in_ps21_1;
  uVar25 = FUN_8028682c();
  iVar6 = (int)((ulonglong)uVar25 >> 0x20);
  pfVar8 = (float *)uVar25;
  iVar10 = 0;
  if (0 < DAT_803de090) {
    if (8 < DAT_803de090) {
      pcVar9 = local_2c0;
      uVar14 = DAT_803de090 - 1U >> 3;
      if (0 < DAT_803de090 + -8) {
        do {
          *pcVar9 = '\0';
          pcVar9[1] = '\0';
          pcVar9[2] = '\0';
          pcVar9[3] = '\0';
          pcVar9[4] = '\0';
          pcVar9[5] = '\0';
          pcVar9[6] = '\0';
          pcVar9[7] = '\0';
          pcVar9 = pcVar9 + 8;
          iVar10 = iVar10 + 8;
          uVar14 = uVar14 - 1;
        } while (uVar14 != 0);
      }
    }
    pcVar9 = local_2c0 + iVar10;
    iVar4 = DAT_803de090 - iVar10;
    if (iVar10 < DAT_803de090) {
      do {
        *pcVar9 = '\0';
        pcVar9 = pcVar9 + 1;
        iVar4 = iVar4 + -1;
      } while (iVar4 != 0);
    }
  }
  iVar10 = FUN_800d57bc((uint)pfVar8[4],&local_2c4);
  if (iVar10 == 0) {
    iVar4 = 0;
    puVar12 = &DAT_8039d0b8;
    pcVar9 = local_2c0;
    iVar10 = 0;
    for (iVar5 = 0; iVar5 < DAT_803de090; iVar5 = iVar5 + 1) {
      iVar7 = puVar12[1];
      iVar13 = iVar10;
      if ((*pcVar9 == '\0') && ((param_3 == -1 || (*(char *)(iVar7 + 0x28) == param_3)))) {
        in_f25 = (double)(*(float *)(iVar7 + 8) - *(float *)(iVar6 + 0xc));
        fVar1 = *(float *)(iVar7 + 0xc) - *(float *)(iVar6 + 0x10);
        in_f24 = (double)(*(float *)(iVar7 + 0x10) - *(float *)(iVar6 + 0x14));
        if ((float)(in_f24 * in_f24 + (double)(float)(in_f25 * in_f25 + (double)(fVar1 * fVar1))) <
            FLOAT_803e119c) {
          iVar13 = iVar10 + 1;
          local_1f8[iVar10] = iVar5;
          iVar7 = (int)&DAT_8039d0b8 + iVar4;
          pcVar11 = local_2c0 + iVar5;
          iVar10 = DAT_803de090 - iVar5;
          if (iVar5 < DAT_803de090) {
            do {
              if (param_3 == *(char *)(*(int *)(iVar7 + 4) + 0x28)) {
                *pcVar11 = '\x01';
              }
              iVar7 = iVar7 + 8;
              pcVar11 = pcVar11 + 1;
              iVar10 = iVar10 + -1;
            } while (iVar10 != 0);
          }
        }
      }
      puVar12 = puVar12 + 2;
      pcVar9 = pcVar9 + 1;
      iVar4 = iVar4 + 8;
      iVar10 = iVar13;
    }
  }
  else {
    iVar10 = 1;
    local_1f8[0] = local_2c4;
  }
  iVar4 = 0;
  if (0 < DAT_803de090) {
    if (8 < DAT_803de090) {
      pcVar9 = local_2c0;
      uVar14 = DAT_803de090 - 1U >> 3;
      if (0 < DAT_803de090 + -8) {
        do {
          *pcVar9 = '\0';
          pcVar9[1] = '\0';
          pcVar9[2] = '\0';
          pcVar9[3] = '\0';
          pcVar9[4] = '\0';
          pcVar9[5] = '\0';
          pcVar9[6] = '\0';
          pcVar9[7] = '\0';
          pcVar9 = pcVar9 + 8;
          iVar4 = iVar4 + 8;
          uVar14 = uVar14 - 1;
        } while (uVar14 != 0);
      }
    }
    pcVar9 = local_2c0 + iVar4;
    iVar5 = DAT_803de090 - iVar4;
    if (iVar4 < DAT_803de090) {
      do {
        *pcVar9 = '\0';
        pcVar9 = pcVar9 + 1;
        iVar5 = iVar5 + -1;
      } while (iVar5 != 0);
    }
  }
  while (0 < iVar10) {
    iVar10 = iVar10 + -1;
    local_2c4 = local_1f8[iVar10];
    iVar4 = (&DAT_8039d0bc)[local_2c4 * 2];
    if (iVar4 == 0) goto LAB_800d74c0;
    iVar13 = 0;
    iVar5 = iVar4;
    do {
      iVar7 = FUN_800d57bc(*(uint *)(iVar5 + 0x20),&local_2c8);
      if (iVar7 != 0) {
        uStack_f4 = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
        local_f8 = 0x43300000;
        dVar15 = (double)FUN_802945e0();
        uStack_ec = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
        local_f0 = 0x43300000;
        dVar16 = (double)FUN_80294964();
        dVar22 = -(double)(float)((double)*(float *)(iVar4 + 8) * dVar15 +
                                 (double)(float)((double)*(float *)(iVar4 + 0x10) * dVar16));
        uStack_e4 = (uint)*(byte *)(iVar7 + 0x29) << 8 ^ 0x80000000;
        local_e8 = 0x43300000;
        dVar17 = (double)FUN_802945e0();
        uStack_dc = (uint)*(byte *)(iVar7 + 0x29) << 8 ^ 0x80000000;
        local_e0 = 0x43300000;
        dVar18 = (double)FUN_80294964();
        dVar20 = (double)*(float *)(iVar7 + 8);
        dVar19 = (double)*(float *)(iVar7 + 0x10);
        fVar1 = -(float)(dVar20 * dVar17 + (double)(float)(dVar19 * dVar18));
        dVar24 = (double)(float)(dVar22 + (double)(float)(dVar15 * (double)*(float *)(iVar6 + 0xc) +
                                                         (double)(float)(dVar16 * (double)*(float *)
                                                  (iVar6 + 0x14))));
        dVar23 = (double)(fVar1 + (float)(dVar17 * (double)*(float *)(iVar6 + 0xc) +
                                         (double)(float)(dVar18 * (double)*(float *)(iVar6 + 0x14)))
                         );
        dVar22 = (double)(float)(dVar22 + (double)(float)(dVar15 * dVar20 +
                                                         (double)(float)(dVar16 * dVar19)));
        dVar21 = (double)(fVar1 + (float)(dVar17 * (double)*(float *)(iVar4 + 8) +
                                         (double)(float)(dVar18 * (double)*(float *)(iVar4 + 0x10)))
                         );
        if ((((dVar22 <= (double)FLOAT_803e1168) && (dVar24 <= (double)FLOAT_803e1168)) ||
            (((double)FLOAT_803e1168 < dVar22 && ((double)FLOAT_803e1168 < dVar24)))) &&
           (((dVar21 <= (double)FLOAT_803e1168 && (dVar23 <= (double)FLOAT_803e1168)) ||
            (((double)FLOAT_803e1168 < dVar21 && ((double)FLOAT_803e1168 < dVar23)))))) {
          dVar21 = (double)(float)((double)*(float *)(iVar4 + 8) - dVar20);
          dVar22 = (double)(*(float *)(iVar4 + 0xc) - *(float *)(iVar7 + 0xc));
          dVar20 = (double)(float)((double)*(float *)(iVar4 + 0x10) - dVar19);
          dVar19 = FUN_80293900((double)(float)(dVar20 * dVar20 +
                                               (double)(float)(dVar21 * dVar21 +
                                                              (double)(float)(dVar22 * dVar22))));
          if (DOUBLE_803e11a0 < dVar19) {
            in_f25 = (double)(float)(dVar21 * (double)(float)((double)FLOAT_803e1184 / dVar19));
            in_f24 = (double)(float)(dVar20 * (double)(float)((double)FLOAT_803e1184 / dVar19));
          }
          fVar1 = (float)(-dVar24 /
                         (double)(float)(dVar15 * in_f25 + (double)(float)(dVar16 * in_f24)));
          fVar2 = fVar1 + (float)(dVar23 / (double)(float)(dVar17 * in_f25 +
                                                          (double)(float)(dVar18 * in_f24)));
          if ((FLOAT_803e11a8 < fVar2) || (fVar3 = FLOAT_803e1168, fVar2 < FLOAT_803e11ac)) {
            fVar3 = fVar1 / fVar2;
          }
          dVar15 = (double)fVar3;
          if ((double)fVar3 < (double)FLOAT_803e1168) {
            dVar15 = (double)FLOAT_803e1168;
          }
          if ((double)FLOAT_803e1198 <= dVar15) {
            dVar15 = (double)FLOAT_803e1198;
          }
          uStack_dc = (uint)*(byte *)(iVar4 + 0x2a);
          local_e0 = 0x43300000;
          dVar16 = (double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar4 + 0x2a)) -
                                  DOUBLE_803e1178);
          uStack_e4 = (uint)*(byte *)(iVar7 + 0x2a);
          local_e8 = 0x43300000;
          fVar1 = (float)(dVar15 * (double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                    (uint)*(byte *)(
                                                  iVar7 + 0x2a)) - DOUBLE_803e1178) - dVar16) +
                         dVar16);
          fVar2 = (*(float *)(iVar6 + 0x10) -
                  -(float)(dVar22 * dVar15 - (double)*(float *)(iVar4 + 0xc))) / fVar1;
          fVar1 = (-(float)(-(double)(float)(dVar21 * dVar15 - (double)*(float *)(iVar4 + 8)) *
                            in_f24 - (double)(float)(-(double)(float)(dVar20 * dVar15 -
                                                                     (double)*(float *)(iVar4 + 0x10
                                                                                       )) * in_f25))
                  + (float)((double)*(float *)(iVar6 + 0xc) * in_f24 -
                           (double)(float)((double)*(float *)(iVar6 + 0x14) * in_f25))) / fVar1;
          if ((((FLOAT_803e11b0 <= fVar1) && (fVar1 <= FLOAT_803e11b4)) && (FLOAT_803e11b8 <= fVar2)
              ) && (fVar2 <= FLOAT_803e11b4)) {
            pfVar8[4] = *(float *)(iVar4 + 0x14);
            pfVar8[5] = *(float *)(iVar4 + 0x14);
            *pfVar8 = fVar1;
            pfVar8[1] = fVar2;
            pfVar8[2] = (float)dVar15;
            *(short *)(pfVar8 + 8) = (short)*(char *)(iVar4 + 0x28);
            goto LAB_800d74c0;
          }
        }
      }
      iVar5 = iVar5 + 4;
      iVar13 = iVar13 + 1;
    } while (iVar13 < 2);
    if (local_2c0[local_2c4] == '\0') {
      iVar5 = 1;
      iVar4 = iVar4 + 4;
      do {
        iVar7 = FUN_800d57bc(*(uint *)(iVar4 + 0x18),&local_2c8);
        iVar13 = iVar10;
        if (((iVar7 != 0) && (local_2c0[local_2c8] == '\0')) && (iVar10 < 0x3c)) {
          iVar13 = iVar10 + 1;
          local_1f8[iVar10] = local_2c8;
        }
        iVar7 = FUN_800d57bc(*(uint *)(iVar4 + 0x20),&local_2c8);
        iVar10 = iVar13;
        if (((iVar7 != 0) && (local_2c0[local_2c8] == '\0')) && (iVar13 < 0x3c)) {
          iVar10 = iVar13 + 1;
          local_1f8[iVar13] = local_2c8;
        }
        iVar4 = iVar4 + -4;
        iVar5 = iVar5 + -1;
      } while (-1 < iVar5);
      local_2c0[local_2c4] = '\x01';
    }
  }
  pfVar8[4] = -NAN;
LAB_800d74c0:
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d77f4
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D77F4
 * EN v1.1 Size: 1288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d77f4(void)
{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined in_r6;
  undefined in_r7;
  undefined in_r8;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  undefined4 local_a8;
  int local_a4;
  int local_a0;
  int local_9c;
  int local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  int local_64;
  int local_60;
  int local_5c;
  int local_58;
  int local_54;
  uint local_50;
  int local_4c;
  int local_48 [2];
  undefined8 local_40;
  undefined8 local_38;
  
  FUN_8028682c();
  FUN_8025db38(&local_58,&local_5c,&local_60,&local_64);
  FUN_8000f3f8(local_48,&local_4c,&local_50,&local_54);
  uVar5 = local_54 - local_4c & 0xffff;
  if (FLOAT_803de0a0 <= FLOAT_803e11c0) {
    uVar12 = (uint)(FLOAT_803e11c4 * FLOAT_803de0a0);
    uVar11 = 0;
  }
  else {
    uVar12 = 0xff;
    uVar11 = (uint)(FLOAT_803de0a0 - FLOAT_803e11c0);
  }
  uVar1 = (local_50 - local_48[0] & 0xffff) >> 1;
  local_40 = (double)CONCAT44(0x43300000,(uVar11 & 0xffff) * uVar1 ^ 0x80000000);
  uVar7 = (uint)((float)(local_40 - DOUBLE_803e11d0) * FLOAT_803e11c8);
  local_38 = (double)(longlong)(int)uVar7;
  uVar7 = uVar7 & 0xffff;
  if (uVar7 == uVar1) {
    FUN_8025db38(&local_a4,&local_a0,&local_9c,&local_98);
    FUN_8025da88(0,0,0x280,0x1e0);
    local_38 = (double)(longlong)(int)FLOAT_803de0a0;
    local_a8 = CONCAT31(CONCAT21(CONCAT11(in_r6,in_r8),in_r7),(char)(int)FLOAT_803de0a0);
    local_94 = local_a8;
    FUN_80075534(local_a4,local_a0,local_9c,local_98,&local_94);
    FUN_8025da88(local_a4,local_a0,local_9c,local_98);
  }
  else {
    uVar10 = uVar1 - uVar7 & 0xffff;
    uVar8 = uVar1 + uVar7 & 0xffff;
    uVar7 = (uVar1 - 1) - uVar7 & 0xffff;
    FUN_8025da88(local_48[0],local_4c,local_50 - local_48[0],local_54 - local_4c);
    local_68 = CONCAT31(0xffffff,(char)uVar12);
    local_6c = local_68;
    FUN_80075534(local_48[0] + uVar7 + 1,local_4c,local_48[0] + uVar8,local_54,&local_6c);
    uVar4 = uVar10 / (uVar1 / 6) & 0xff;
    if (uVar4 == 0) {
      uVar4 = 1;
    }
    uVar2 = uVar12 & 0xff;
    for (uVar9 = 0; uVar3 = uVar9 & 0xffff, (int)uVar3 < (int)(uVar10 - uVar4);
        uVar9 = uVar9 + uVar4) {
      local_68 = CONCAT31(0xffffff,(char)((int)(uVar2 * (uVar1 - uVar3)) / (int)uVar1));
      local_70 = local_68;
      iVar6 = local_48[0] + (uVar8 & 0xffff);
      FUN_80075534(iVar6,local_4c,uVar4 + iVar6,local_54,&local_70);
      local_74 = local_68;
      iVar6 = local_48[0] + (uVar7 & 0xffff);
      FUN_80075534((iVar6 - uVar4) + 1,local_4c,iVar6 + 1,local_54,&local_74);
      uVar8 = uVar8 + uVar4;
      uVar7 = uVar7 - uVar4;
    }
    local_68 = CONCAT31(0xffffff,(char)((int)(uVar2 * (uVar1 - uVar3)) / (int)uVar1));
    local_78 = local_68;
    FUN_80075534(local_48[0] + (uVar8 & 0xffff),local_4c,local_50,local_54,&local_78);
    local_7c = local_68;
    FUN_80075534(local_48[0],local_4c,local_48[0] + (uVar7 & 0xffff) + 1,local_54,&local_7c);
    uVar7 = uVar5 >> 1;
    local_38 = (double)CONCAT44(0x43300000,(uVar11 & 0xffff) * uVar7 ^ 0x80000000);
    uVar11 = (uint)((float)(local_38 - DOUBLE_803e11d0) * FLOAT_803e11c8);
    local_40 = (double)(longlong)(int)uVar11;
    uVar11 = uVar11 & 0xffff;
    uVar1 = uVar7 - uVar11 & 0xffff;
    uVar10 = uVar7 + uVar11 & 0xffff;
    uVar11 = (uVar7 - 1) - uVar11 & 0xffff;
    local_68 = CONCAT31(0xffffff,(char)uVar12);
    local_80 = local_68;
    FUN_80075534(local_48[0],local_4c + uVar11 + 1,local_50,local_4c + uVar10,&local_80);
    uVar5 = uVar1 / (uVar5 >> 4) & 0xff;
    if (uVar5 == 0) {
      uVar5 = 1;
    }
    for (uVar12 = 0; uVar8 = uVar12 & 0xffff, (int)uVar8 < (int)(uVar1 - uVar5);
        uVar12 = uVar12 + uVar5) {
      local_68 = CONCAT31(0xffffff,(char)((int)(uVar2 * (uVar7 - uVar8)) / (int)uVar7));
      local_84 = local_68;
      iVar6 = local_4c + (uVar10 & 0xffff);
      FUN_80075534(local_48[0],iVar6,local_50,uVar5 + iVar6,&local_84);
      local_88 = local_68;
      iVar6 = local_4c + (uVar11 & 0xffff);
      FUN_80075534(local_48[0],(iVar6 - uVar5) + 1,local_50,iVar6 + 1,&local_88);
      uVar10 = uVar10 + uVar5;
      uVar11 = uVar11 - uVar5;
    }
    local_68 = CONCAT31(0xffffff,(char)((int)(uVar2 * (uVar7 - uVar8)) / (int)uVar7));
    local_8c = local_68;
    FUN_80075534(local_48[0],local_4c + (uVar10 & 0xffff),local_50,local_54,&local_8c);
    local_90 = local_68;
    FUN_80075534(local_48[0],local_4c,local_50,local_4c + (uVar11 & 0xffff) + 1,&local_90);
    FUN_8025da88(local_58,local_5c,local_60,local_64);
  }
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d7cfc
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D7CFC
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d7cfc(undefined param_1)
{
  DAT_803de0af = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d7d18
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D7D18
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d7d18(double param_1,uint param_2,undefined param_3)
{
  FLOAT_803de0a0 = (float)((double)FLOAT_803e11d8 * param_1);
  FLOAT_803de0a4 =
       -(float)((double)FLOAT_803e11dc * param_1) /
       (float)((double)CONCAT44(0x43300000,param_2 ^ 0x80000000) - DOUBLE_803e11d0);
  FLOAT_803de0a8 = FLOAT_803e11e0;
  DAT_803de0ac = param_3;
  DAT_803de0ae = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d7d78
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D7D78
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800d7d78(void)
{
  return ((uint)(byte)((FLOAT_803e11d8 == FLOAT_803de0a0) << 1) << 0x1c) >> 0x1d;
}

/*
 * --INFO--
 *
 * Function: FUN_800d7d90
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D7D90
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d7d90(uint param_1,undefined param_2)
{
  FLOAT_803de0a0 = FLOAT_803e11d8;
  FLOAT_803de0a4 =
       FLOAT_803e11e4 / (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803e11d0)
  ;
  FLOAT_803de0a8 = FLOAT_803e11e0;
  DAT_803de0ac = param_2;
  DAT_803de0ae = 5;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d7de4
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D7DE4
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d7de4(uint param_1,undefined param_2)
{
  if ((FLOAT_803e11e0 <= FLOAT_803de0a4) || (FLOAT_803e11e0 == FLOAT_803de0a0)) {
    FLOAT_803de0a0 = FLOAT_803e11d8;
  }
  FLOAT_803de0a4 =
       FLOAT_803e11e4 / (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803e11d0)
  ;
  FLOAT_803de0a8 = FLOAT_803e11e0;
  DAT_803de0ac = param_2;
  DAT_803de0ae = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d7e58
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D7E58
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d7e58(uint param_1,undefined param_2)
{
  if ((FLOAT_803de0a4 <= FLOAT_803e11e0) || (FLOAT_803e11d8 == FLOAT_803de0a0)) {
    FLOAT_803de0a0 = FLOAT_803e11e0;
  }
  FLOAT_803de0a4 =
       FLOAT_803e11dc / (float)((double)CONCAT44(0x43300000,param_1 ^ 0x80000000) - DOUBLE_803e11d0)
  ;
  FLOAT_803de0a8 = FLOAT_803e11e0;
  DAT_803de0ac = param_2;
  DAT_803de0ae = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d7ed0
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D7ED0
 * EN v1.1 Size: 988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d7ed0(void)
{
  undefined4 local_68;
  int local_64;
  int local_60;
  int local_5c;
  int local_58;
  undefined4 local_54;
  undefined4 local_50;
  int local_4c;
  int local_48;
  int local_44;
  int local_40;
  undefined4 local_3c;
  uint local_38;
  int local_34;
  int local_30;
  int local_2c;
  int local_28;
  uint local_24;
  longlong local_20;
  
  if (DAT_803de0ae == '\0') {
    if ((DAT_803de0af == '\0') && (FLOAT_803e11e8 <= FLOAT_803de0a8)) {
      (**(code **)(*DAT_803dd6cc + 0xc))(0x1e,DAT_803de0ac);
      FLOAT_803de0a8 = FLOAT_803e11e0;
    }
    FLOAT_803de0a0 = FLOAT_803de0a4 * FLOAT_803dc074 + FLOAT_803de0a0;
    if (FLOAT_803de0a0 < FLOAT_803e11e0) {
      FLOAT_803de0a0 = FLOAT_803e11e0;
      DAT_803de0ad = 1;
      if (DAT_803de0ac != 5) {
        DAT_803de0ad = 1;
        return;
      }
      FUN_80070538(0xff);
      return;
    }
    if (FLOAT_803de0a0 <= FLOAT_803e11d8) {
      DAT_803de0ad = 0;
    }
    else {
      FLOAT_803de0a0 = FLOAT_803e11d8;
      DAT_803de0ad = 1;
      if (DAT_803de0af == '\0') {
        FLOAT_803de0a8 = FLOAT_803de0a8 + FLOAT_803dc074;
      }
      if (DAT_803de0ac != 5) {
        FUN_80070538(0xff);
      }
    }
  }
  else {
    DAT_803de0ae = DAT_803de0ae + -1;
  }
  if (DAT_803dd5d0 == '\0') {
    if (DAT_803de0ac == 3) {
      FUN_800d77f4();
    }
    else if (DAT_803de0ac < 3) {
      if (DAT_803de0ac == 1) {
        FUN_8025db38(&local_34,&local_30,&local_2c,&local_28);
        FUN_8025da88(0,0,0x280,0x1e0);
        local_20 = (longlong)(int)FLOAT_803de0a0;
        local_38 = (int)FLOAT_803de0a0 & 0xff;
        local_24 = local_38;
        FUN_80075534(local_34,local_30,local_2c,local_28,&local_24);
        FUN_8025da88(local_34,local_30,local_2c,local_28);
      }
      else if (DAT_803de0ac != 0) {
        FUN_8025db38(&local_4c,&local_48,&local_44,&local_40);
        FUN_8025da88(0,0,0x280,0x1e0);
        local_20 = (longlong)(int)FLOAT_803de0a0;
        local_50 = CONCAT31(0xffffff,(char)(int)FLOAT_803de0a0);
        local_3c = local_50;
        FUN_80075534(local_4c,local_48,local_44,local_40,&local_3c);
        FUN_8025da88(local_4c,local_48,local_44,local_40);
      }
    }
    else if ((DAT_803de0ac != 5) && (DAT_803de0ac < 5)) {
      FUN_8025db38(&local_64,&local_60,&local_5c,&local_58);
      FUN_8025da88(0,0,0x280,0x1e0);
      local_20 = (longlong)(int)FLOAT_803de0a0;
      local_68 = CONCAT31(0xff0000,(char)(int)FLOAT_803de0a0);
      local_54 = local_68;
      FUN_80075534(local_64,local_60,local_5c,local_58,&local_54);
      FUN_8025da88(local_64,local_60,local_5c,local_58);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d82ac
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D82AC
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d82ac(double param_1,double param_2,double param_3,double param_4,double param_5,
                 int param_6,int param_7)
{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  
  dVar4 = (double)(float)((double)*(float *)(param_6 + 0xc) - param_1);
  dVar3 = (double)(float)((double)*(float *)(param_6 + 0x14) - param_2);
  dVar2 = FUN_80293900((double)(float)(dVar4 * dVar4 + (double)(float)(dVar3 * dVar3)));
  *(float *)(param_7 + 700) = (float)dVar2;
  if ((double)FLOAT_803e11f0 != dVar2) {
    dVar4 = (double)(float)(dVar4 / dVar2);
    dVar3 = (double)(float)(dVar3 / dVar2);
  }
  if (*(float *)(param_7 + 700) <= (float)(param_3 + param_4)) {
    *(float *)(param_7 + 0x294) = *(float *)(param_7 + 0x294) * FLOAT_803e11f4;
    fVar1 = FLOAT_803e11f0;
    *(float *)(param_7 + 0x290) = FLOAT_803e11f0;
    *(float *)(param_7 + 0x28c) = fVar1;
  }
  else {
    *(float *)(param_7 + 0x290) = (float)(dVar4 * param_5);
    *(float *)(param_7 + 0x28c) = (float)(-dVar3 * param_5);
  }
  if (FLOAT_803e11f8 < *(float *)(param_7 + 0x290)) {
    *(float *)(param_7 + 0x290) = FLOAT_803e11f8;
  }
  if (*(float *)(param_7 + 0x290) < FLOAT_803e11fc) {
    *(float *)(param_7 + 0x290) = FLOAT_803e11fc;
  }
  if (FLOAT_803e11f8 < *(float *)(param_7 + 0x28c)) {
    *(float *)(param_7 + 0x28c) = FLOAT_803e11f8;
  }
  if (*(float *)(param_7 + 0x28c) < FLOAT_803e11fc) {
    *(float *)(param_7 + 0x28c) = FLOAT_803e11fc;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d83f8
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D83F8
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d83f8(double param_1,double param_2,double param_3,int param_4,uint *param_5)
{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  
  *param_5 = *param_5 & 0xffefffff;
  dVar4 = (double)(float)((double)*(float *)(param_4 + 0xc) - param_1);
  dVar3 = (double)(float)((double)*(float *)(param_4 + 0x14) - param_2);
  dVar2 = FUN_80293900((double)(float)(dVar4 * dVar4 + (double)(float)(dVar3 * dVar3)));
  param_5[0xaf] = (uint)(float)dVar2;
  fVar1 = FLOAT_803e11f8;
  if ((float)param_5[0xaf] < FLOAT_803e1200) {
    fVar1 = FLOAT_803e1204 * (float)param_5[0xaf];
    param_5[0xa5] = (uint)((float)param_5[0xa5] * FLOAT_803e11f4);
  }
  if ((double)fVar1 < dVar2) {
    dVar2 = (double)(float)(dVar2 / (double)fVar1);
    dVar4 = (double)(float)(dVar4 / dVar2);
    dVar3 = (double)(float)(dVar3 / dVar2);
  }
  param_5[0xa4] = (uint)(float)dVar4;
  param_5[0xa3] = (uint)(float)-dVar3;
  param_5[0xa4] = (uint)(float)((double)(float)param_5[0xa4] * param_3);
  param_5[0xa3] = (uint)(float)((double)(float)param_5[0xa3] * param_3);
  if (FLOAT_803e11f8 < (float)param_5[0xa4]) {
    param_5[0xa4] = (uint)FLOAT_803e11f8;
  }
  if ((float)param_5[0xa4] < FLOAT_803e11fc) {
    param_5[0xa4] = (uint)FLOAT_803e11fc;
  }
  if (FLOAT_803e11f8 < (float)param_5[0xa3]) {
    param_5[0xa3] = (uint)FLOAT_803e11f8;
  }
  if ((float)param_5[0xa3] < FLOAT_803e11fc) {
    param_5[0xa3] = (uint)FLOAT_803e11fc;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d8534
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D8534
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8534(double param_1,ushort *param_2,uint *param_3)
{
  float local_88;
  float local_84;
  float fStack_80;
  ushort local_7c;
  ushort local_7a;
  undefined2 local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float afStack_64 [19];
  
  if ((*param_3 & 0x2000000) == 0) {
    if ((*param_3 & 0x200000) == 0) {
      *(float *)(param_2 + 0x14) = *(float *)(param_2 + 0x14) * FLOAT_803e120c;
      *(float *)(param_2 + 0x14) =
           -(float)((double)(float)param_3[0xa9] * param_1 - (double)*(float *)(param_2 + 0x14));
    }
    if (((*(byte *)(param_3 + 0xd3) & 1) == 0) || ((*(byte *)(param_3 + 0xd3) & 4) != 0)) {
      local_7c = *param_2;
      local_7a = param_2[1];
      local_78 = 0;
      local_74 = FLOAT_803e1208;
      local_70 = FLOAT_803e11f0;
      local_6c = FLOAT_803e11f0;
      local_68 = FLOAT_803e11f0;
      FUN_80021fac(afStack_64,&local_7c);
      if ((*param_3 & 0x10000) == 0) {
        FUN_80022790((double)(float)param_3[0xa1],(double)FLOAT_803e11f0,
                     -(double)(float)param_3[0xa0],afStack_64,&local_84,&fStack_80,&local_88);
      }
      else {
        FUN_80022790((double)(float)param_3[0xa1],(double)(float)param_3[0xa2],
                     -(double)(float)param_3[0xa0],afStack_64,&local_84,(float *)(param_2 + 0x14),
                     &local_88);
      }
      *(float *)(param_2 + 0x12) = local_84;
      *(float *)(param_2 + 0x16) = local_88;
    }
    FUN_8002ba34((double)(float)((double)*(float *)(param_2 + 0x12) * param_1),
                 (double)(float)((double)*(float *)(param_2 + 0x14) * param_1),
                 (double)(float)((double)*(float *)(param_2 + 0x16) * param_1),(int)param_2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d86a0
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D86A0
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d86a0(ushort *param_1,int param_2)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  double dVar4;
  
  *(undefined4 *)(param_2 + 0x29c) = *(undefined4 *)(param_2 + 0x298);
  dVar4 = FUN_80293900((double)(*(float *)(param_2 + 0x290) * *(float *)(param_2 + 0x290) +
                               *(float *)(param_2 + 0x28c) * *(float *)(param_2 + 0x28c)));
  *(float *)(param_2 + 0x298) = (float)dVar4;
  if (FLOAT_803e11f8 < *(float *)(param_2 + 0x298)) {
    *(float *)(param_2 + 0x298) = FLOAT_803e11f8;
  }
  *(float *)(param_2 + 0x298) = *(float *)(param_2 + 0x298) / FLOAT_803e11f8;
  iVar1 = FUN_80021884();
  DAT_803de0cc = (short)iVar1 - *(short *)(param_2 + 0x330);
  uVar2 = (int)DAT_803de0cc - (uint)*param_1;
  if (0x8000 < (int)uVar2) {
    uVar2 = uVar2 - 0xffff;
  }
  if ((int)uVar2 < -0x8000) {
    uVar2 = uVar2 + 0xffff;
  }
  *(short *)(param_2 + 0x336) =
       (short)(int)((float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e1218) /
                   FLOAT_803e1210);
  if ((int)uVar2 < 0) {
    *(short *)(param_2 + 0x334) = -*(short *)(param_2 + 0x336);
  }
  else {
    *(undefined2 *)(param_2 + 0x334) = *(undefined2 *)(param_2 + 0x336);
  }
  if (FLOAT_803e1214 <= *(float *)(param_2 + 0x298)) {
    uVar3 = uVar2 + 0xa000;
    if ((int)uVar3 < 0) {
      uVar3 = uVar2 + 0x19fff;
    }
    if (0xffff < (int)uVar3) {
      uVar3 = uVar3 - 0xffff;
    }
    *(char *)(param_2 + 0x34b) =
         '\x04' - ((char)((int)uVar3 >> 0xe) + ((int)uVar3 < 0 && (uVar3 & 0x3fff) != 0));
  }
  else {
    *(undefined *)(param_2 + 0x34b) = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d8830
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D8830
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8830(int param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5)
{
  while ((param_4 != 0 && (param_1 != 0))) {
    if (param_5 == 0) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,param_3,0,2,0xffffffff,0);
    }
    else if (param_5 == 1) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,param_3,0,2,0xffffffff,0);
    }
    else if (param_5 == 2) {
      (**(code **)(*DAT_803dd708 + 8))(param_1,param_3,0,4,0xffffffff,0);
    }
    param_4 = param_4 + -1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d8938
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D8938
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8938(undefined4 param_1,undefined4 param_2,int param_3,int param_4,undefined4 param_5,
                 int param_6)
{
  int *piVar1;
  
  piVar1 = (int *)FUN_80013ee8(param_3 + 0x58U & 0xffff);
  for (; param_4 != 0; param_4 = param_4 + -1) {
    if (param_6 == 0) {
      (**(code **)(*piVar1 + 4))(param_1,0,0,1,0xffffffff,0);
    }
    else if (param_6 == 1) {
      (**(code **)(*piVar1 + 4))(param_1,0,0,2,0xffffffff,0);
    }
    else if (param_6 == 2) {
      (**(code **)(*piVar1 + 4))(param_1,0,0,4,0xffffffff,0);
    }
  }
  FUN_80013e4c((undefined *)piVar1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d8a44
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D8A44
 * EN v1.1 Size: 460b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8a44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,uint param_11,uint param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  double dVar3;
  double dVar4;
  float local_38 [2];
  longlong local_30;
  undefined4 local_28;
  uint uStack_24;
  
  if (DAT_803de0b4 != '\0') {
    if ((*(float *)(param_10 + 0x280) <= FLOAT_803e11f0) ||
       (*(short *)(param_9 + 0xa0) == DAT_803de0bc)) {
      if ((*(float *)(param_10 + 0x280) < FLOAT_803e11f0) &&
         (*(short *)(param_9 + 0xa0) != DAT_803de0b8)) {
        FUN_8003042c((double)*(float *)(param_9 + 0x98),param_2,param_3,param_4,param_5,param_6,
                     param_7,param_8,param_9,DAT_803de0b8,0,param_12,param_13,param_14,param_15,
                     param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else {
      FUN_8003042c((double)*(float *)(param_9 + 0x98),param_2,param_3,param_4,param_5,param_6,
                   param_7,param_8,param_9,DAT_803de0bc,0,param_12,param_13,param_14,param_15,
                   param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    dVar4 = FUN_80293900((double)(*(float *)(param_10 + 0x280) * *(float *)(param_10 + 0x280) +
                                 *(float *)(param_10 + 0x284) * *(float *)(param_10 + 0x284)));
    iVar1 = FUN_8002f6cc(dVar4,param_9,local_38);
    if (iVar1 != 0) {
      *(float *)(param_10 + 0x2a0) = local_38[0];
    }
    dVar3 = (double)FLOAT_803e11f0;
    if (dVar3 != dVar4) {
      dVar3 = (double)(float)((double)*(float *)(param_10 + 0x284) / dVar4);
    }
    local_38[0] = (float)dVar3;
    uVar2 = (uint)(FLOAT_803e1220 * (float)dVar3);
    local_30 = (longlong)(int)uVar2;
    if ((int)uVar2 < 0) {
      uVar2 = -uVar2;
    }
    uStack_24 = uVar2 ^ 0x80000000;
    local_28 = 0x43300000;
    if (FLOAT_803e1220 < (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803e1218)) {
      uVar2 = 0x4000;
    }
    dVar4 = (double)*(float *)(param_10 + 0x284);
    if (dVar4 <= (double)FLOAT_803e11f0) {
      fn_8002EE64(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_11,
                  (short)uVar2);
    }
    else {
      fn_8002EE64(dVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_12,
                  (short)uVar2);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d8c10
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D8C10
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8c10(double param_1,double param_2,int param_3,int param_4)
{
  float fVar1;
  double dVar2;
  double dVar3;
  
  *(byte *)(param_4 + 0x34c) = *(byte *)(param_4 + 0x34c) | 1;
  if (DAT_803de0b4 == '\0') {
    dVar2 = (double)FUN_802945e0();
    dVar2 = (double)(float)(param_2 * (double)(float)((double)*(float *)(param_4 + 0x298) * -dVar2))
    ;
    dVar3 = (double)FUN_80294964();
    dVar3 = (double)(float)(param_2 * (double)(float)((double)*(float *)(param_4 + 0x298) * -dVar3))
    ;
    if ((double)*(float *)(param_4 + 0x298) < (double)FLOAT_803e122c) {
      dVar3 = (double)FLOAT_803e11f0;
      dVar2 = dVar3;
    }
    *(float *)(param_3 + 0x24) =
         (float)((double)*(float *)(param_3 + 0x24) +
                (double)((float)(param_1 *
                                (double)(float)(dVar2 - (double)*(float *)(param_3 + 0x24))) /
                        *(float *)(param_4 + 0x2b8)));
    *(float *)(param_3 + 0x2c) =
         (float)((double)*(float *)(param_3 + 0x2c) +
                (double)((float)(param_1 *
                                (double)(float)(dVar3 - (double)*(float *)(param_3 + 0x2c))) /
                        *(float *)(param_4 + 0x2b8)));
  }
  else {
    *(byte *)(param_4 + 0x34c) = *(byte *)(param_4 + 0x34c) & 0xfe;
  }
  dVar2 = FUN_80293900((double)(*(float *)(param_3 + 0x24) * *(float *)(param_3 + 0x24) +
                               *(float *)(param_3 + 0x2c) * *(float *)(param_3 + 0x2c)));
  *(float *)(param_4 + 0x294) = (float)dVar2;
  fVar1 = FLOAT_803e11f0;
  if (*(float *)(param_4 + 0x294) < FLOAT_803e1230) {
    *(float *)(param_4 + 0x294) = FLOAT_803e11f0;
    *(float *)(param_3 + 0x24) = fVar1;
    *(float *)(param_3 + 0x2c) = fVar1;
  }
  dVar2 = (double)FUN_802945e0();
  dVar3 = (double)FUN_80294964();
  *(float *)(param_4 + 0x284) =
       (float)((double)*(float *)(param_3 + 0x24) * dVar3 -
              (double)(float)((double)*(float *)(param_3 + 0x2c) * dVar2));
  *(float *)(param_4 + 0x280) =
       (float)(-(double)*(float *)(param_3 + 0x2c) * dVar3 -
              (double)(float)((double)*(float *)(param_3 + 0x24) * dVar2));
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d8e40
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D8E40
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8e40(double param_1,int param_2,uint *param_3)
{
  int iVar1;
  
  if (param_3[0xcf] == 0xffffffff) {
    param_3[0xaf] = (uint)FLOAT_803e11f0;
  }
  else {
    iVar1 = (**(code **)(*DAT_803dd71c + 0x1c))();
    if (iVar1 == 0) {
      param_3[0xaf] = (uint)FLOAT_803e11f0;
    }
    else {
      FUN_800d83f8((double)*(float *)(iVar1 + 8),(double)*(float *)(iVar1 + 0x10),param_1,param_2,
                   param_3);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d8ee8
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D8EE8
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8ee8(int param_1,int param_2,undefined4 param_3)
{
  undefined4 uVar1;
  undefined4 local_18 [5];
  
  local_18[0] = param_3;
  uVar1 = (**(code **)(*DAT_803dd71c + 0x14))
                    ((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                     (double)*(float *)(param_1 + 0x14),local_18,1,(int)*(char *)(param_2 + 0x344));
  *(undefined4 *)(param_2 + 0x33c) = uVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d8f48
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D8F48
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8f48(uint param_1,int param_2,int param_3,int param_4,int param_5)
{
  if ((*(uint *)(param_2 + 0x314) & 1 << param_3) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & ~(1 << param_3);
    FUN_8000bb38(param_1,(ushort)*(undefined4 *)(param_5 + param_4 * 4));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d8f94
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x800D8F94
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8f94(uint param_1,int param_2,int param_3,int param_4,int param_5)
{
  if ((*(uint *)(param_2 + 0x314) & 1 << param_3) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & ~(1 << param_3);
    FUN_8000bb38(param_1,(ushort)*(undefined4 *)(param_5 + param_4 * 4));
  }
  return;
}
