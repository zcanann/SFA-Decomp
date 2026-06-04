#include "ghidra_import.h"
#include "main/dll/df_partfx.h"
#include "main/objanim.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80006950();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern int FUN_80017730();
extern undefined4 FUN_80017754();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017a88();
extern undefined4 FUN_8006f9a8();
extern undefined4 FUN_8006fd90();
extern int FUN_800c9030();
extern undefined4 FUN_8025da88();
extern undefined4 FUN_8025db38();
extern undefined8 FUN_8028682c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
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
extern f32 lbl_803DC074;
extern f32 lbl_803DE0A0;
extern f32 lbl_803DE0A4;
extern f32 lbl_803DE0A8;
extern f32 lbl_803E1168;
extern f32 lbl_803E1184;
extern f32 lbl_803E118C;
extern f32 lbl_803E1190;
extern f32 lbl_803E1194;
extern f32 lbl_803E1198;
extern f32 lbl_803E119C;
extern f32 lbl_803E11A8;
extern f32 lbl_803E11AC;
extern f32 lbl_803E11B0;
extern f32 lbl_803E11B4;
extern f32 lbl_803E11B8;
extern f32 lbl_803E11C0;
extern f32 lbl_803E11C4;
extern f32 lbl_803E11C8;
extern f32 lbl_803E11D8;
extern f32 lbl_803E11DC;
extern f32 lbl_803E11E0;
extern f32 lbl_803E11E4;
extern f32 lbl_803E11E8;
extern f32 lbl_803E11F0;
extern f32 lbl_803E11F4;
extern f32 lbl_803E11F8;
extern f32 lbl_803E11FC;
extern f32 lbl_803E1200;
extern f32 lbl_803E1204;
extern f32 lbl_803E1208;
extern f32 lbl_803E120C;
extern f32 lbl_803E1210;
extern f32 lbl_803E1214;
extern f32 lbl_803E1220;
extern f32 lbl_803E122C;
extern f32 lbl_803E1230;

/*
 * --INFO--
 *
 * Function: Checkpoint_func07
 * EN v1.0 Address: 0x800D6660
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x800D6844
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int* Checkpoint_find(int id, int* slot);
extern int getAngle(f32 dx, f32 dz);
extern f32 sin(f32 x);
extern f32 fn_80293E80(f32 x);
extern f32 sqrtf(f32 x);
extern f32 lbl_803E04D8;
extern f32 lbl_803E04DC;
extern f32 lbl_803E04E8;
extern f32 lbl_803E0504;
extern f32 lbl_803E050C;
extern f32 lbl_803E0510;
extern f32 lbl_803E0514;
extern f32 lbl_803E0518;

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
int Checkpoint_func07(int* obj, int* state)
{
    int slotC;
    int slot8;
    char* cp;
    char* cp2;
    short ang;
    f32 cosv, sinv, cos2, sin2;
    f32 dist, dist2, nx, nz, offs, dz;
    f32 offs2, distA, distB, dx, dy, len, q, proj, proj2, t0, sum, frac, zero;

    if (*(int*)((char*)state + 0x18) < 0) {
        *(int*)((char*)state + 0x1c) = 0;
        *(f32*)((char*)state + 0xc) = lbl_803E04E8;
        if (*(int*)((char*)state + 0x10) < 0) {
            return 0;
        }
        *(int*)((char*)state + 0x18) = *(int*)((char*)state + 0x10);
    }
    cp = (char*)Checkpoint_find(*(int*)((char*)state + 0x18), &slot8);
    if (cp == NULL) {
        *(int*)((char*)state + 0x18) = -1;
        return 0;
    }
    cosv = fn_80293E80((lbl_803E04D8 * (f32)(*(u8*)(cp + 0x29) << 8)) / lbl_803E04DC);
    sinv = sin((lbl_803E04D8 * (f32)(*(u8*)(cp + 0x29) << 8)) / lbl_803E04DC);
    offs = -(*(f32*)(cp + 8) * cosv + *(f32*)(cp + 0x10) * sinv);
    dist = offs + (cosv * *(f32*)((char*)obj + 0xc) + sinv * *(f32*)((char*)obj + 0x14));
    if (*(int*)(cp + 0x18) > -1 && dist >= lbl_803E04E8) {
        *(int*)((char*)state + 0x18) = *(int*)(cp + 0x18);
        *(f32*)((char*)state + 0xc) = lbl_803E050C;
        *(int*)((char*)state + 0x1c) = *(int*)((char*)state + 0x1c) - 1;
        return *(u8*)(cp + 0x29);
    }
    if (*(int*)(cp + 0x20) < 0) {
        return *(u8*)(cp + 0x29);
    }
    cp2 = (char*)Checkpoint_find(*(int*)(cp + 0x20), &slotC);
    ang = getAngle(*(f32*)(cp2 + 8) - *(f32*)(cp + 8), *(f32*)(cp2 + 0x10) - *(f32*)(cp + 0x10));
    cos2 = fn_80293E80((lbl_803E04D8 * (f32)(*(u8*)(cp2 + 0x29) << 8)) / lbl_803E04DC);
    sin2 = sin((lbl_803E04D8 * (f32)(*(u8*)(cp2 + 0x29) << 8)) / lbl_803E04DC);
    offs2 = -(*(f32*)(cp2 + 8) * cos2 + *(f32*)(cp2 + 0x10) * sin2);
    dist2 = offs2 + (cos2 * *(f32*)((char*)obj + 0xc) + sin2 * *(f32*)((char*)obj + 0x14));
    zero = lbl_803E04E8;
    if (dist2 < zero) {
        *(int*)((char*)state + 0x18) = *(int*)(cp + 0x20);
        *(f32*)((char*)state + 0xc) = zero;
        *(int*)((char*)state + 0x1c) = *(int*)((char*)state + 0x1c) + 1;
        return ang;
    }
    distA = offs + (cosv * *(f32*)(cp2 + 8) + sinv * *(f32*)(cp2 + 0x10));
    distB = offs2 + (cos2 * *(f32*)(cp + 8) + sin2 * *(f32*)(cp + 0x10));
    if (((distA < zero && dist < zero) || (distA >= lbl_803E04E8 && dist >= lbl_803E04E8)) &&
        ((distB <= lbl_803E04E8 && dist2 <= lbl_803E04E8) || (distB > lbl_803E04E8 && dist2 > lbl_803E04E8))) {
        dx = *(f32*)(cp + 8) - *(f32*)(cp2 + 8);
        dy = *(f32*)(cp + 0xc) - *(f32*)(cp2 + 0xc);
        dz = *(f32*)(cp + 0x10) - *(f32*)(cp2 + 0x10);
        len = sqrtf(dz * dz + (dx * dx + dy * dy));
        if (len > lbl_803E04E8) {
            q = lbl_803E0504 / len;
            nx = dx * q;
            nz = dz * q;
        }
        proj = cosv * nx + sinv * nz;
        if (proj > lbl_803E0510 && proj < lbl_803E0514) {
            return ang;
        }
        t0 = -dist / proj;
        proj2 = cos2 * nx + sin2 * nz;
        if (proj2 > lbl_803E0510 && proj2 < lbl_803E0514) {
            return ang;
        }
        sum = t0 + dist2 / proj2;
        frac = lbl_803E04E8;
        if (lbl_803E04E8 != sum) {
            frac = t0 / sum;
        }
        *(f32*)((char*)state + 0xc) = frac;
        if (*(f32*)((char*)state + 0xc) < lbl_803E04E8) {
            *(f32*)((char*)state + 0xc) = lbl_803E04E8;
        }
        if (*(f32*)((char*)state + 0xc) >= lbl_803E0518) {
            *(f32*)((char*)state + 0xc) = lbl_803E0518;
        }
    }
    return ang;
}
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800d66e4
 * EN v1.0 Address: 0x800D66E4
 * EN v1.0 Size: 1108b
 * EN v1.1 Address: 0x800D68EC
 * EN v1.1 Size: 1136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d66e4(void)
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
    *(float *)(iVar6 + 0xc) = lbl_803E1168;
    if (*(int *)(iVar6 + 0x10) < 0) goto LAB_800d6cf4;
    *(int *)(iVar6 + 0x18) = *(int *)(iVar6 + 0x10);
  }
  iVar4 = FUN_800c9030(*(uint *)(iVar6 + 0x18),&iStack_d8);
  if (iVar4 == 0) {
    *(undefined4 *)(iVar6 + 0x18) = 0xffffffff;
  }
  else {
    aiStack_d4[2] = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
    aiStack_d4[1] = 0x43300000;
    dVar7 = (double)FUN_80293f90();
    uStack_c4 = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
    local_c8 = 0x43300000;
    dVar8 = (double)FUN_80294964();
    dVar15 = -(double)(float)((double)*(float *)(iVar4 + 8) * dVar7 +
                             (double)(float)((double)*(float *)(iVar4 + 0x10) * dVar8));
    dVar17 = (double)(float)(dVar15 + (double)(float)(dVar7 * (double)*(float *)(iVar3 + 0xc) +
                                                     (double)(float)(dVar8 * (double)*(float *)(
                                                  iVar3 + 0x14))));
    if ((*(int *)(iVar4 + 0x18) < 0) || (dVar17 < (double)lbl_803E1168)) {
      if (-1 < (int)*(uint *)(iVar4 + 0x20)) {
        iVar5 = FUN_800c9030(*(uint *)(iVar4 + 0x20),aiStack_d4);
        FUN_80017730();
        uStack_c4 = (uint)*(byte *)(iVar5 + 0x29) << 8 ^ 0x80000000;
        local_c8 = 0x43300000;
        dVar9 = (double)FUN_80293f90();
        aiStack_d4[2] = (uint)*(byte *)(iVar5 + 0x29) << 8 ^ 0x80000000;
        aiStack_d4[1] = 0x43300000;
        dVar10 = (double)FUN_80294964();
        fVar2 = lbl_803E1168;
        dVar13 = (double)*(float *)(iVar5 + 8);
        dVar12 = (double)*(float *)(iVar5 + 0x10);
        fVar1 = -(float)(dVar13 * dVar9 + (double)(float)(dVar12 * dVar10));
        dVar16 = (double)(fVar1 + (float)(dVar9 * (double)*(float *)(iVar3 + 0xc) +
                                         (double)(float)(dVar10 * (double)*(float *)(iVar3 + 0x14)))
                         );
        dVar11 = (double)lbl_803E1168;
        if (dVar11 <= dVar16) {
          dVar15 = (double)(float)(dVar15 + (double)(float)(dVar7 * dVar13 +
                                                           (double)(float)(dVar8 * dVar12)));
          dVar14 = (double)(fVar1 + (float)(dVar9 * (double)*(float *)(iVar4 + 8) +
                                           (double)(float)(dVar10 * (double)*(float *)(iVar4 + 0x10)
                                                          )));
          if ((((dVar15 < dVar11) && (dVar17 < dVar11)) ||
              (((double)lbl_803E1168 <= dVar15 && ((double)lbl_803E1168 <= dVar17)))) &&
             (((dVar14 <= (double)lbl_803E1168 && (dVar16 <= (double)lbl_803E1168)) ||
              (((double)lbl_803E1168 < dVar14 && ((double)lbl_803E1168 < dVar16)))))) {
            dVar13 = (double)(float)((double)*(float *)(iVar4 + 8) - dVar13);
            fVar1 = *(float *)(iVar4 + 0xc) - *(float *)(iVar5 + 0xc);
            dVar11 = (double)(float)((double)*(float *)(iVar4 + 0x10) - dVar12);
            dVar15 = FUN_80293900((double)(float)(dVar11 * dVar11 +
                                                 (double)(float)(dVar13 * dVar13 +
                                                                (double)(fVar1 * fVar1))));
            if ((double)lbl_803E1168 < dVar15) {
              in_f25 = (double)(float)(dVar13 * (double)(float)((double)lbl_803E1184 / dVar15));
              in_f24 = (double)(float)(dVar11 * (double)(float)((double)lbl_803E1184 / dVar15));
            }
            dVar7 = (double)(float)(dVar7 * in_f25 + (double)(float)(dVar8 * in_f24));
            if ((dVar7 <= (double)lbl_803E1190) || ((double)lbl_803E1194 <= dVar7)) {
              dVar8 = (double)(float)(dVar9 * in_f25 + (double)(float)(dVar10 * in_f24));
              if ((dVar8 <= (double)lbl_803E1190) || ((double)lbl_803E1194 <= dVar8)) {
                fVar1 = (float)(-dVar17 / dVar7) + (float)(dVar16 / dVar8);
                fVar2 = lbl_803E1168;
                if (lbl_803E1168 != fVar1) {
                  fVar2 = (float)(-dVar17 / dVar7) / fVar1;
                }
                *(float *)(iVar6 + 0xc) = fVar2;
                if (*(float *)(iVar6 + 0xc) < lbl_803E1168) {
                  *(float *)(iVar6 + 0xc) = lbl_803E1168;
                }
                if (lbl_803E1198 <= *(float *)(iVar6 + 0xc)) {
                  *(float *)(iVar6 + 0xc) = lbl_803E1198;
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
      *(float *)(iVar6 + 0xc) = lbl_803E118C;
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
 * Function: FUN_800d6b38
 * EN v1.0 Address: 0x800D6B38
 * EN v1.0 Size: 1996b
 * EN v1.1 Address: 0x800D6D5C
 * EN v1.1 Size: 2712b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d6b38(undefined4 param_1,undefined4 param_2,int param_3)
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
  iVar10 = FUN_800c9030((uint)pfVar8[4],&local_2c4);
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
            lbl_803E119C) {
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
      iVar7 = FUN_800c9030(*(uint *)(iVar5 + 0x20),&local_2c8);
      if (iVar7 != 0) {
        uStack_f4 = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
        local_f8 = 0x43300000;
        dVar15 = (double)FUN_80293f90();
        uStack_ec = (uint)*(byte *)(iVar4 + 0x29) << 8 ^ 0x80000000;
        local_f0 = 0x43300000;
        dVar16 = (double)FUN_80294964();
        dVar22 = -(double)(float)((double)*(float *)(iVar4 + 8) * dVar15 +
                                 (double)(float)((double)*(float *)(iVar4 + 0x10) * dVar16));
        uStack_e4 = (uint)*(byte *)(iVar7 + 0x29) << 8 ^ 0x80000000;
        local_e8 = 0x43300000;
        dVar17 = (double)FUN_80293f90();
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
        if ((((dVar22 <= (double)lbl_803E1168) && (dVar24 <= (double)lbl_803E1168)) ||
            (((double)lbl_803E1168 < dVar22 && ((double)lbl_803E1168 < dVar24)))) &&
           (((dVar21 <= (double)lbl_803E1168 && (dVar23 <= (double)lbl_803E1168)) ||
            (((double)lbl_803E1168 < dVar21 && ((double)lbl_803E1168 < dVar23)))))) {
          dVar21 = (double)(float)((double)*(float *)(iVar4 + 8) - dVar20);
          dVar22 = (double)(*(float *)(iVar4 + 0xc) - *(float *)(iVar7 + 0xc));
          dVar20 = (double)(float)((double)*(float *)(iVar4 + 0x10) - dVar19);
          dVar19 = FUN_80293900((double)(float)(dVar20 * dVar20 +
                                               (double)(float)(dVar21 * dVar21 +
                                                              (double)(float)(dVar22 * dVar22))));
          if (DOUBLE_803e11a0 < dVar19) {
            in_f25 = (double)(float)(dVar21 * (double)(float)((double)lbl_803E1184 / dVar19));
            in_f24 = (double)(float)(dVar20 * (double)(float)((double)lbl_803E1184 / dVar19));
          }
          fVar1 = (float)(-dVar24 /
                         (double)(float)(dVar15 * in_f25 + (double)(float)(dVar16 * in_f24)));
          fVar2 = fVar1 + (float)(dVar23 / (double)(float)(dVar17 * in_f25 +
                                                          (double)(float)(dVar18 * in_f24)));
          if ((lbl_803E11A8 < fVar2) || (fVar3 = lbl_803E1168, fVar2 < lbl_803E11AC)) {
            fVar3 = fVar1 / fVar2;
          }
          dVar15 = (double)fVar3;
          if ((double)fVar3 < (double)lbl_803E1168) {
            dVar15 = (double)lbl_803E1168;
          }
          if ((double)lbl_803E1198 <= dVar15) {
            dVar15 = (double)lbl_803E1198;
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
          if ((((lbl_803E11B0 <= fVar1) && (fVar1 <= lbl_803E11B4)) && (lbl_803E11B8 <= fVar2)
              ) && (fVar2 <= lbl_803E11B4)) {
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
        iVar7 = FUN_800c9030(*(uint *)(iVar4 + 0x18),&local_2c8);
        iVar13 = iVar10;
        if (((iVar7 != 0) && (local_2c0[local_2c8] == '\0')) && (iVar10 < 0x3c)) {
          iVar13 = iVar10 + 1;
          local_1f8[iVar10] = local_2c8;
        }
        iVar7 = FUN_800c9030(*(uint *)(iVar4 + 0x20),&local_2c8);
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
 * Function: FUN_800d7304
 * EN v1.0 Address: 0x800D7304
 * EN v1.0 Size: 1148b
 * EN v1.1 Address: 0x800D77F4
 * EN v1.1 Size: 1288b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d7304(void)
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
  FUN_80006950(local_48,&local_4c,&local_50,&local_54);
  uVar5 = local_54 - local_4c & 0xffff;
  if (lbl_803DE0A0 <= lbl_803E11C0) {
    uVar12 = (uint)(lbl_803E11C4 * lbl_803DE0A0);
    uVar11 = 0;
  }
  else {
    uVar12 = 0xff;
    uVar11 = (uint)(lbl_803DE0A0 - lbl_803E11C0);
  }
  uVar1 = (local_50 - local_48[0] & 0xffff) >> 1;
  uVar7 = (uint)((f32)(s32)((uVar11 & 0xffff) * uVar1) * lbl_803E11C8);
  local_38 = (double)(longlong)(int)uVar7;
  uVar7 = uVar7 & 0xffff;
  if (uVar7 == uVar1) {
    FUN_8025db38(&local_a4,&local_a0,&local_9c,&local_98);
    FUN_8025da88(0,0,0x280,0x1e0);
    local_38 = (double)(longlong)(int)lbl_803DE0A0;
    local_a8 = CONCAT31(CONCAT21(CONCAT11(in_r6,in_r8),in_r7),(char)(int)lbl_803DE0A0);
    local_94 = local_a8;
    FUN_8006fd90(local_a4,local_a0,local_9c,local_98,&local_94);
    FUN_8025da88(local_a4,local_a0,local_9c,local_98);
  }
  else {
    uVar10 = uVar1 - uVar7 & 0xffff;
    uVar8 = uVar1 + uVar7 & 0xffff;
    uVar7 = (uVar1 - 1) - uVar7 & 0xffff;
    FUN_8025da88(local_48[0],local_4c,local_50 - local_48[0],local_54 - local_4c);
    local_68 = CONCAT31(0xffffff,(char)uVar12);
    local_6c = local_68;
    FUN_8006fd90(local_48[0] + uVar7 + 1,local_4c,local_48[0] + uVar8,local_54,&local_6c);
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
      FUN_8006fd90(iVar6,local_4c,uVar4 + iVar6,local_54,&local_70);
      local_74 = local_68;
      iVar6 = local_48[0] + (uVar7 & 0xffff);
      FUN_8006fd90((iVar6 - uVar4) + 1,local_4c,iVar6 + 1,local_54,&local_74);
      uVar8 = uVar8 + uVar4;
      uVar7 = uVar7 - uVar4;
    }
    local_68 = CONCAT31(0xffffff,(char)((int)(uVar2 * (uVar1 - uVar3)) / (int)uVar1));
    local_78 = local_68;
    FUN_8006fd90(local_48[0] + (uVar8 & 0xffff),local_4c,local_50,local_54,&local_78);
    local_7c = local_68;
    FUN_8006fd90(local_48[0],local_4c,local_48[0] + (uVar7 & 0xffff) + 1,local_54,&local_7c);
    uVar7 = uVar5 >> 1;
    uVar11 = (uint)((f32)(s32)((uVar11 & 0xffff) * uVar7) * lbl_803E11C8);
    local_40 = (double)(longlong)(int)uVar11;
    uVar11 = uVar11 & 0xffff;
    uVar1 = uVar7 - uVar11 & 0xffff;
    uVar10 = uVar7 + uVar11 & 0xffff;
    uVar11 = (uVar7 - 1) - uVar11 & 0xffff;
    local_68 = CONCAT31(0xffffff,(char)uVar12);
    local_80 = local_68;
    FUN_8006fd90(local_48[0],local_4c + uVar11 + 1,local_50,local_4c + uVar10,&local_80);
    uVar5 = uVar1 / (uVar5 >> 4) & 0xff;
    if (uVar5 == 0) {
      uVar5 = 1;
    }
    for (uVar12 = 0; uVar8 = uVar12 & 0xffff, (int)uVar8 < (int)(uVar1 - uVar5);
        uVar12 = uVar12 + uVar5) {
      local_68 = CONCAT31(0xffffff,(char)((int)(uVar2 * (uVar7 - uVar8)) / (int)uVar7));
      local_84 = local_68;
      iVar6 = local_4c + (uVar10 & 0xffff);
      FUN_8006fd90(local_48[0],iVar6,local_50,uVar5 + iVar6,&local_84);
      local_88 = local_68;
      iVar6 = local_4c + (uVar11 & 0xffff);
      FUN_8006fd90(local_48[0],(iVar6 - uVar5) + 1,local_50,iVar6 + 1,&local_88);
      uVar10 = uVar10 + uVar5;
      uVar11 = uVar11 - uVar5;
    }
    local_68 = CONCAT31(0xffffff,(char)((int)(uVar2 * (uVar7 - uVar8)) / (int)uVar7));
    local_8c = local_68;
    FUN_8006fd90(local_48[0],local_4c + (uVar10 & 0xffff),local_50,local_54,&local_8c);
    local_90 = local_68;
    FUN_8006fd90(local_48[0],local_4c,local_50,local_4c + (uVar11 & 0xffff) + 1,&local_90);
    FUN_8025da88(local_58,local_5c,local_60,local_64);
  }
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d7780
 * EN v1.0 Address: 0x800D7780
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x800D7CFC
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d7780(undefined param_1)
{
  DAT_803de0af = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d778c
 * EN v1.0 Address: 0x800D778C
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x800D7D18
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d778c(double param_1,uint param_2,undefined param_3)
{
  lbl_803DE0A0 = (float)((double)lbl_803E11D8 * param_1);
  lbl_803DE0A4 =
       -(float)((double)lbl_803E11DC * param_1) /
       (f32)(s32)(param_2);
  lbl_803DE0A8 = lbl_803E11E0;
  DAT_803de0ac = param_3;
  DAT_803de0ae = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d7824
 * EN v1.0 Address: 0x800D7824
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x800D7D78
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800d7824(void)
{
  return ((uint)(byte)((lbl_803E11D8 == lbl_803DE0A0) << 1) << 0x1c) >> 0x1d;
}

/*
 * --INFO--
 *
 * Function: FUN_800d783c
 * EN v1.0 Address: 0x800D783C
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x800D7D90
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d783c(uint param_1,undefined param_2)
{
  lbl_803DE0A0 = lbl_803E11D8;
  lbl_803DE0A4 =
       lbl_803E11E4 / (f32)(s32)(param_1)
  ;
  lbl_803DE0A8 = lbl_803E11E0;
  DAT_803de0ac = param_2;
  DAT_803de0ae = 5;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d78ac
 * EN v1.0 Address: 0x800D78AC
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x800D7DE4
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d78ac(uint param_1,undefined param_2)
{
  if ((lbl_803E11E0 <= lbl_803DE0A4) || (lbl_803E11E0 == lbl_803DE0A0)) {
    lbl_803DE0A0 = lbl_803E11D8;
  }
  lbl_803DE0A4 =
       lbl_803E11E4 / (f32)(s32)(param_1)
  ;
  lbl_803DE0A8 = lbl_803E11E0;
  DAT_803de0ac = param_2;
  DAT_803de0ae = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d7944
 * EN v1.0 Address: 0x800D7944
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x800D7E58
 * EN v1.1 Size: 120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d7944(uint param_1,undefined param_2)
{
  if ((lbl_803DE0A4 <= lbl_803E11E0) || (lbl_803E11D8 == lbl_803DE0A0)) {
    lbl_803DE0A0 = lbl_803E11E0;
  }
  lbl_803DE0A4 =
       lbl_803E11DC / (f32)(s32)(param_1)
  ;
  lbl_803DE0A8 = lbl_803E11E0;
  DAT_803de0ac = param_2;
  DAT_803de0ae = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d79dc
 * EN v1.0 Address: 0x800D79DC
 * EN v1.0 Size: 692b
 * EN v1.1 Address: 0x800D7ED0
 * EN v1.1 Size: 988b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d79dc(void)
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
    if ((DAT_803de0af == '\0') && (lbl_803E11E8 <= lbl_803DE0A8)) {
      (**(code **)(*DAT_803dd6cc + 0xc))(0x1e,DAT_803de0ac);
      lbl_803DE0A8 = lbl_803E11E0;
    }
    lbl_803DE0A0 = lbl_803DE0A4 * lbl_803DC074 + lbl_803DE0A0;
    if (lbl_803DE0A0 < lbl_803E11E0) {
      lbl_803DE0A0 = lbl_803E11E0;
      DAT_803de0ad = 1;
      if (DAT_803de0ac != 5) {
        DAT_803de0ad = 1;
        return;
      }
      FUN_8006f9a8(0xff);
      return;
    }
    if (lbl_803DE0A0 <= lbl_803E11D8) {
      DAT_803de0ad = 0;
    }
    else {
      lbl_803DE0A0 = lbl_803E11D8;
      DAT_803de0ad = 1;
      if (DAT_803de0af == '\0') {
        lbl_803DE0A8 = lbl_803DE0A8 + lbl_803DC074;
      }
      if (DAT_803de0ac != 5) {
        FUN_8006f9a8(0xff);
      }
    }
  }
  else {
    DAT_803de0ae = DAT_803de0ae + -1;
  }
  if (DAT_803dd5d0 == '\0') {
    if (DAT_803de0ac == 3) {
      FUN_800d7304();
    }
    else if (DAT_803de0ac < 3) {
      if (DAT_803de0ac == 1) {
        FUN_8025db38(&local_34,&local_30,&local_2c,&local_28);
        FUN_8025da88(0,0,0x280,0x1e0);
        local_20 = (longlong)(int)lbl_803DE0A0;
        local_38 = (int)lbl_803DE0A0 & 0xff;
        local_24 = local_38;
        FUN_8006fd90(local_34,local_30,local_2c,local_28,&local_24);
        FUN_8025da88(local_34,local_30,local_2c,local_28);
      }
      else if (DAT_803de0ac != 0) {
        FUN_8025db38(&local_4c,&local_48,&local_44,&local_40);
        FUN_8025da88(0,0,0x280,0x1e0);
        local_20 = (longlong)(int)lbl_803DE0A0;
        local_50 = CONCAT31(0xffffff,(char)(int)lbl_803DE0A0);
        local_3c = local_50;
        FUN_8006fd90(local_4c,local_48,local_44,local_40,&local_3c);
        FUN_8025da88(local_4c,local_48,local_44,local_40);
      }
    }
    else if ((DAT_803de0ac != 5) && (DAT_803de0ac < 5)) {
      FUN_8025db38(&local_64,&local_60,&local_5c,&local_58);
      FUN_8025da88(0,0,0x280,0x1e0);
      local_20 = (longlong)(int)lbl_803DE0A0;
      local_68 = CONCAT31(0xff0000,(char)(int)lbl_803DE0A0);
      local_54 = local_68;
      FUN_8006fd90(local_64,local_60,local_5c,local_58,&local_54);
      FUN_8025da88(local_64,local_60,local_5c,local_58);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d7c90
 * EN v1.0 Address: 0x800D7C90
 * EN v1.0 Size: 376b
 * EN v1.1 Address: 0x800D82AC
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d7c90(double param_1,double param_2,double param_3,double param_4,double param_5,
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
  if ((double)lbl_803E11F0 != dVar2) {
    dVar4 = (double)(float)(dVar4 / dVar2);
    dVar3 = (double)(float)(dVar3 / dVar2);
  }
  if (*(float *)(param_7 + 700) <= (float)(param_3 + param_4)) {
    *(float *)(param_7 + 0x294) = *(float *)(param_7 + 0x294) * lbl_803E11F4;
    fVar1 = lbl_803E11F0;
    *(float *)(param_7 + 0x290) = lbl_803E11F0;
    *(float *)(param_7 + 0x28c) = fVar1;
  }
  else {
    *(float *)(param_7 + 0x290) = (float)(dVar4 * param_5);
    *(float *)(param_7 + 0x28c) = (float)(-dVar3 * param_5);
  }
  if (lbl_803E11F8 < *(float *)(param_7 + 0x290)) {
    *(float *)(param_7 + 0x290) = lbl_803E11F8;
  }
  if (*(float *)(param_7 + 0x290) < lbl_803E11FC) {
    *(float *)(param_7 + 0x290) = lbl_803E11FC;
  }
  if (lbl_803E11F8 < *(float *)(param_7 + 0x28c)) {
    *(float *)(param_7 + 0x28c) = lbl_803E11F8;
  }
  if (*(float *)(param_7 + 0x28c) < lbl_803E11FC) {
    *(float *)(param_7 + 0x28c) = lbl_803E11FC;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d7e08
 * EN v1.0 Address: 0x800D7E08
 * EN v1.0 Size: 640b
 * EN v1.1 Address: 0x800D83F8
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d7e08(double param_1,double param_2,double param_3,int param_4,uint *param_5)
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
  fVar1 = lbl_803E11F8;
  if ((float)param_5[0xaf] < lbl_803E1200) {
    fVar1 = lbl_803E1204 * (float)param_5[0xaf];
    param_5[0xa5] = (uint)((float)param_5[0xa5] * lbl_803E11F4);
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
  if (lbl_803E11F8 < (float)param_5[0xa4]) {
    param_5[0xa4] = (uint)lbl_803E11F8;
  }
  if ((float)param_5[0xa4] < lbl_803E11FC) {
    param_5[0xa4] = (uint)lbl_803E11FC;
  }
  if (lbl_803E11F8 < (float)param_5[0xa3]) {
    param_5[0xa3] = (uint)lbl_803E11F8;
  }
  if ((float)param_5[0xa3] < lbl_803E11FC) {
    param_5[0xa3] = (uint)lbl_803E11FC;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d8088
 * EN v1.0 Address: 0x800D8088
 * EN v1.0 Size: 440b
 * EN v1.1 Address: 0x800D8534
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8088(double param_1,ushort *param_2,uint *param_3)
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
      *(float *)(param_2 + 0x14) = *(float *)(param_2 + 0x14) * lbl_803E120C;
      *(float *)(param_2 + 0x14) =
           -(float)((double)(float)param_3[0xa9] * param_1 - (double)*(float *)(param_2 + 0x14));
    }
    if (((*(byte *)(param_3 + 0xd3) & 1) == 0) || ((*(byte *)(param_3 + 0xd3) & 4) != 0)) {
      local_7c = *param_2;
      local_7a = param_2[1];
      local_78 = 0;
      local_74 = lbl_803E1208;
      local_70 = lbl_803E11F0;
      local_6c = lbl_803E11F0;
      local_68 = lbl_803E11F0;
      FUN_80017754(afStack_64,&local_7c);
      if ((*param_3 & 0x10000) == 0) {
        FUN_80017778((double)(float)param_3[0xa1],(double)lbl_803E11F0,
                     -(double)(float)param_3[0xa0],afStack_64,&local_84,&fStack_80,&local_88);
      }
      else {
        FUN_80017778((double)(float)param_3[0xa1],(double)(float)param_3[0xa2],
                     -(double)(float)param_3[0xa0],afStack_64,&local_84,(float *)(param_2 + 0x14),
                     &local_88);
      }
      *(float *)(param_2 + 0x12) = local_84;
      *(float *)(param_2 + 0x16) = local_88;
    }
    FUN_80017a88((double)(float)((double)*(float *)(param_2 + 0x12) * param_1),
                 (double)(float)((double)*(float *)(param_2 + 0x14) * param_1),
                 (double)(float)((double)*(float *)(param_2 + 0x16) * param_1),(int)param_2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d8240
 * EN v1.0 Address: 0x800D8240
 * EN v1.0 Size: 396b
 * EN v1.1 Address: 0x800D86A0
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8240(ushort *param_1,int param_2)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  double dVar4;
  
  *(undefined4 *)(param_2 + 0x29c) = *(undefined4 *)(param_2 + 0x298);
  dVar4 = FUN_80293900((double)(*(float *)(param_2 + 0x290) * *(float *)(param_2 + 0x290) +
                               *(float *)(param_2 + 0x28c) * *(float *)(param_2 + 0x28c)));
  *(float *)(param_2 + 0x298) = (float)dVar4;
  if (lbl_803E11F8 < *(float *)(param_2 + 0x298)) {
    *(float *)(param_2 + 0x298) = lbl_803E11F8;
  }
  *(float *)(param_2 + 0x298) = *(float *)(param_2 + 0x298) / lbl_803E11F8;
  iVar1 = FUN_80017730();
  DAT_803de0cc = (short)iVar1 - *(short *)(param_2 + 0x330);
  uVar2 = (int)DAT_803de0cc - (uint)*param_1;
  if (0x8000 < (int)uVar2) {
    uVar2 = uVar2 - 0xffff;
  }
  if ((int)uVar2 < -0x8000) {
    uVar2 = uVar2 + 0xffff;
  }
  *(short *)(param_2 + 0x336) =
       (short)(int)((f32)(s32)(uVar2) /
                   lbl_803E1210);
  if ((int)uVar2 < 0) {
    *(short *)(param_2 + 0x334) = -*(short *)(param_2 + 0x336);
  }
  else {
    *(undefined2 *)(param_2 + 0x334) = *(undefined2 *)(param_2 + 0x336);
  }
  if (lbl_803E1214 <= *(float *)(param_2 + 0x298)) {
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
 * Function: FUN_800d83cc
 * EN v1.0 Address: 0x800D83CC
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x800D8830
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d83cc(int param_1,undefined4 param_2,undefined4 param_3,int param_4,int param_5)
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
 * Function: FUN_800d84e0
 * EN v1.0 Address: 0x800D84E0
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x800D8938
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d84e0(undefined4 param_1,undefined4 param_2,int param_3,int param_4,undefined4 param_5,
                 int param_6)
{
  int *piVar1;
  
  piVar1 = (int *)FUN_80006b14(param_3 + 0x58U & 0xffff);
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
  FUN_80006b0c((undefined *)piVar1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d85f4
 * EN v1.0 Address: 0x800D85F4
 * EN v1.0 Size: 772b
 * EN v1.1 Address: 0x800D8A44
 * EN v1.1 Size: 460b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d85f4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
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
    if ((*(float *)(param_10 + 0x280) <= lbl_803E11F0) ||
       (*(short *)(param_9 + 0xa0) == DAT_803de0bc)) {
      if ((*(float *)(param_10 + 0x280) < lbl_803E11F0) &&
         (*(short *)(param_9 + 0xa0) != DAT_803de0b8)) {
        ObjAnim_SetCurrentMove((int)param_9,DAT_803de0b8,*(float *)(param_9 + 0x98),0);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else {
      ObjAnim_SetCurrentMove((int)param_9,DAT_803de0bc,*(float *)(param_9 + 0x98),0);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    dVar4 = FUN_80293900((double)(*(float *)(param_10 + 0x280) * *(float *)(param_10 + 0x280) +
                                 *(float *)(param_10 + 0x284) * *(float *)(param_10 + 0x284)));
    iVar1 = ObjAnim_SampleRootCurvePhase((float)dVar4,(ObjAnimComponent *)param_9,local_38);
    if (iVar1 != 0) {
      *(float *)(param_10 + 0x2a0) = local_38[0];
    }
    dVar3 = (double)lbl_803E11F0;
    if (dVar3 != dVar4) {
      dVar3 = (double)(float)((double)*(float *)(param_10 + 0x284) / dVar4);
    }
    local_38[0] = (float)dVar3;
    uVar2 = (uint)(lbl_803E1220 * (float)dVar3);
    local_30 = (longlong)(int)uVar2;
    if ((int)uVar2 < 0) {
      uVar2 = -uVar2;
    }
    uStack_24 = uVar2 ^ 0x80000000;
    local_28 = 0x43300000;
    if (lbl_803E1220 < (f32)(s32)uStack_24) {
      uVar2 = 0x4000;
    }
    dVar4 = (double)*(float *)(param_10 + 0x284);
    if (dVar4 <= (double)lbl_803E11F0) {
      Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent *)param_9,param_11,(short)uVar2);
    }
    else {
      Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent *)param_9,param_12,(short)uVar2);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d88f8
 * EN v1.0 Address: 0x800D88F8
 * EN v1.0 Size: 532b
 * EN v1.1 Address: 0x800D8C10
 * EN v1.1 Size: 560b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d88f8(double param_1,double param_2,int param_3,int param_4)
{
  float fVar1;
  double dVar2;
  double dVar3;
  
  *(byte *)(param_4 + 0x34c) = *(byte *)(param_4 + 0x34c) | 1;
  if (DAT_803de0b4 == '\0') {
    dVar2 = (double)FUN_80293f90();
    dVar2 = (double)(float)(param_2 * (double)(float)((double)*(float *)(param_4 + 0x298) * -dVar2))
    ;
    dVar3 = (double)FUN_80294964();
    dVar3 = (double)(float)(param_2 * (double)(float)((double)*(float *)(param_4 + 0x298) * -dVar3))
    ;
    if ((double)*(float *)(param_4 + 0x298) < (double)lbl_803E122C) {
      dVar3 = (double)lbl_803E11F0;
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
  fVar1 = lbl_803E11F0;
  if (*(float *)(param_4 + 0x294) < lbl_803E1230) {
    *(float *)(param_4 + 0x294) = lbl_803E11F0;
    *(float *)(param_3 + 0x24) = fVar1;
    *(float *)(param_3 + 0x2c) = fVar1;
  }
  dVar2 = (double)FUN_80293f90();
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
 * Function: FUN_800d8b0c
 * EN v1.0 Address: 0x800D8B0C
 * EN v1.0 Size: 740b
 * EN v1.1 Address: 0x800D8E40
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8b0c(double param_1,int param_2,uint *param_3)
{
  int iVar1;
  
  if (param_3[0xcf] == 0xffffffff) {
    param_3[0xaf] = (uint)lbl_803E11F0;
  }
  else {
    iVar1 = (**(code **)(*DAT_803dd71c + 0x1c))();
    if (iVar1 == 0) {
      param_3[0xaf] = (uint)lbl_803E11F0;
    }
    else {
      FUN_800d7e08((double)*(float *)(iVar1 + 8),(double)*(float *)(iVar1 + 0x10),param_1,param_2,
                   param_3);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d8df0
 * EN v1.0 Address: 0x800D8DF0
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800D8EE8
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8df0(int param_1,int param_2,undefined4 param_3)
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
 * Function: FUN_800d8e54
 * EN v1.0 Address: 0x800D8E54
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x800D8F48
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8e54(uint param_1,int param_2,int param_3,int param_4,int param_5)
{
  if ((*(uint *)(param_2 + 0x314) & 1 << param_3) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & ~(1 << param_3);
    FUN_80006824(param_1,(ushort)*(undefined4 *)(param_5 + param_4 * 4));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800d8e9c
 * EN v1.0 Address: 0x800D8E9C
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x800D8F94
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800d8e9c(uint param_1,int param_2,int param_3,int param_4,int param_5)
{
  if ((*(uint *)(param_2 + 0x314) & 1 << param_3) != 0) {
    *(uint *)(param_2 + 0x314) = *(uint *)(param_2 + 0x314) & ~(1 << param_3);
    FUN_80006824(param_1,(ushort)*(undefined4 *)(param_5 + param_4 * 4));
  }
  return;
}


/* Trivial 4b 0-arg blr leaves. */
void Checkpoint_release(void) {}
void Dummy04_func14_nop(void) {}
void Dummy04_func26_nop(void) {}
void Dummy04_func25_nop(void) {}
void Dummy04_func23_nop(void) {}
void Dummy04_func20_nop(void) {}
void Dummy04_func1F_nop(void) {}
void Dummy04_func1E_nop(void) {}
void Dummy04_func1C_nop(void) {}
void Dummy04_func1B_nop(void) {}
void Dummy04_func1A_nop(void) {}
void Dummy04_func19_nop(void) {}
void Dummy04_func18_nop(void) {}
void Dummy04_func17_nop(void) {}
void Dummy04_func16_nop(void) {}
void Dummy04_onSetupPlayer(void) {}
void Dummy04_func15_nop(void) {}
void Dummy04_func13_nop(void) {}
void Dummy04_func12_nop(void) {}
void Dummy04_func10_nop(void) {}
void Dummy04_func0E_nop(void) {}
void Dummy04_func0C_nop(void) {}
void Dummy04_onSelectSave(void) {}
void Dummy04_func08_nop(void) {}
void Dummy04_func07_nop(void) {}
void Dummy04_func04_nop(void) {}
void Dummy04_release(void) {}
void Dummy04_initialise(void) {}
void dll_0F_func19_nop(void) {}

/* 8b "li r3, N; blr" returners. */
int Dummy04_func24_ret_0(void) { return 0x0; }
int Dummy04_func22_ret_127(void) { return 0x7f; }
int Dummy04_func21_ret_0(void) { return 0x0; }
int Dummy04_func1D_ret_0(void) { return 0x0; }
int Dummy04_func11_ret_0(void) { return 0x0; }
int Dummy04_func0F_ret_0(void) { return 0x0; }
int Dummy04_func0D_ret_0(void) { return 0x0; }
int Dummy04_func0B_ret_0(void) { return 0x0; }
int Dummy04_func0A_ret_0(void) { return 0x0; }
int Dummy04_func05_ret_0(void) { return 0x0; }

/* sda21 accessors. */
extern u8 lbl_803DD42D;
u8 screenTransition_func07(void) { return lbl_803DD42D; }

/* Pattern wrappers. */
extern u32 lbl_803DD410;
void Checkpoint_reset(void) { lbl_803DD410 = 0x0; }

/* 12b 3-insn patterns. */
extern u32 lbl_803DD43C;
extern u32 lbl_803DD438;
void player_setAnimIds(int unused1, int unused2, u32 a, u32 b) { lbl_803DD43C = a; lbl_803DD438 = b; }

/* misc 8b leaves */
extern f32 lbl_803DD420;
f32 screenTransition_getAlpha(void) { return lbl_803DD420; }

/* Pattern wrappers. */
int Dummy04_func03_ret_m1(void) { return -0x1; }

/* sda21 writers. */
extern u8 lbl_803DD42F;
#pragma peephole off
void setScreenTransitionPause(u32 pause) { lbl_803DD42F = (u8)pause; }
#pragma peephole reset

/* fcmp-eq-to-bool. */
extern f32 lbl_803E0558;
u32 isScreenTransitionActive(void) { return lbl_803E0558 == lbl_803DD420; }

/* multi-store leaf (single float broadcast). */
#pragma scheduling off
#pragma peephole off
extern f32 lbl_803E0570;
void player_clearXZvel(int *obj, int *state) {
    f32 z = lbl_803E0570;
    *(f32*)((char*)obj + 0x24) = z;
    *(f32*)((char*)obj + 0x2c) = z;
    *(f32*)((char*)state + 0x294) = z;
    *(f32*)((char*)state + 0x280) = z;
    *(f32*)((char*)state + 0x284) = z;
}
#pragma peephole reset
#pragma scheduling reset

/* Checkpoint table initialiser. */
extern u32 lbl_8039CA98[];
extern void *lbl_803DD41C;
extern void *lbl_803DD418;
extern void Sfx_PlayFromObject(int* obj, int sfxId);
extern int* gRomCurveInterface;
extern f32 lbl_803E0588;
extern f32 lbl_803E0564;
extern f32 lbl_803E0560;
extern f32 lbl_803E055C;
extern f32 lbl_803DD424;
extern f32 lbl_803DD428;
extern u8 lbl_803DD42C;
extern u8 lbl_803DD42E;
extern void player_followCurve(int* obj, int* state, f32 a, f32 b, f32 t, int p5);
extern f32 lbl_803E05B4;
extern f32 lbl_803E05B8;
extern int* Resource_Acquire(int id, int kind);
extern void Resource_Release(int* res);

#pragma scheduling off
#pragma peephole off
void player_playSoundFn0F(int* obj, int* state, int bit, int idx, int* sfxTable)
{
    register int flags;
    register int mask;
    mask = 1 << bit;
    flags = *(int*)((char*)state + 788);
    if ((flags & mask) != 0) {
        *(int*)((char*)state + 788) = flags & ~mask;
        Sfx_PlayFromObject(obj, (u16)sfxTable[idx]);
    }
}

void player_playSoundFn10(int* obj, int* state, int bit, int idx, int* sfxTable)
{
    register int flags;
    register int mask;
    mask = 1 << bit;
    flags = *(int*)((char*)state + 788);
    if ((flags & mask) != 0) {
        *(int*)((char*)state + 788) = flags & ~mask;
        Sfx_PlayFromObject(obj, (u16)sfxTable[idx]);
    }
}

void player_render2(int* obj, int* state, f32 f1, f32 f2)
{
    f32 cur = *(f32*)((char*)state + 680);
    f32 new_ = f2 * f1 + cur;
    if (new_ > lbl_803E0588) {
        new_ = lbl_803E0588;
    }
    {
        f32 delta = new_ - cur;
        if (delta > lbl_803E0570) {
            *(s16*)obj = *(s16*)obj + (s32)(*(f32*)((char*)state + 768) * delta);
        }
    }
    *(f32*)((char*)state + 680) = new_;
}

void player_modelMtxFn(f32* mtx, int* state, f32 f1, f32 f2)
{
    f32 cur = *(f32*)((char*)state + 684);
    f32 new_ = f2 * f1 + cur;
    if (new_ > lbl_803E0588) {
        new_ = lbl_803E0588;
    }
    {
        f32 delta = new_ - cur;
        if (delta <= lbl_803E0570) return;
        *(f32*)((char*)mtx + 12) = *(f32*)((char*)state + 756) * delta + *(f32*)((char*)mtx + 12);
        *(f32*)((char*)mtx + 16) = *(f32*)((char*)state + 760) * delta + *(f32*)((char*)mtx + 16);
        *(f32*)((char*)mtx + 20) = *(f32*)((char*)state + 764) * delta + *(f32*)((char*)mtx + 20);
    }
    *(f32*)((char*)state + 684) = new_;
}

void player_findCurve(int* obj, int* state, int p3)
{
    *(int*)((char*)state + 0x33c) = ((int(*)(f32, f32, f32, int*, int, int))
        ((void**)*gRomCurveInterface)[5])(
            *(f32*)((char*)obj + 0xc),
            *(f32*)((char*)obj + 0x10),
            *(f32*)((char*)obj + 0x14),
            &p3, 1,
            *(s8*)((char*)state + 0x344));
}

void screenTransitionFn_800d7b04(int duration, int type)
{
    lbl_803DD420 = lbl_803E0558;
    lbl_803DD424 = lbl_803E0564 / (f32)duration;
    lbl_803DD428 = lbl_803E0560;
    lbl_803DD42C = (u8)type;
    lbl_803DD42E = 5;
}

void screenTransition_fadeFrom(int duration, int type, f32 from)
{
    lbl_803DD420 = lbl_803E0558 * from;
    lbl_803DD424 = -(lbl_803E055C * from) / (f32)duration;
    lbl_803DD428 = lbl_803E0560;
    lbl_803DD42C = (u8)type;
    lbl_803DD42E = 1;
}

#pragma opt_common_subs off
void screenTransition_screenFade(int duration, int type)
{
    if (lbl_803DD424 >= lbl_803E0560 || lbl_803E0560 == lbl_803DD420) {
        lbl_803DD420 = lbl_803E0558;
    }
    lbl_803DD424 = lbl_803E0564 / (f32)duration;
    lbl_803DD428 = lbl_803E0560;
    lbl_803DD42C = (u8)type;
    lbl_803DD42E = 1;
}
#pragma opt_common_subs reset

#pragma opt_common_subs off
void screenTransition_Do(int duration, int type)
{
    if (lbl_803DD424 <= lbl_803E0560 || lbl_803E0558 == lbl_803DD420) {
        lbl_803DD420 = lbl_803E0560;
    }
    lbl_803DD424 = lbl_803E055C / (f32)duration;
    lbl_803DD428 = lbl_803E0560;
    lbl_803DD42C = (u8)type;
    lbl_803DD42E = 0;
}
#pragma opt_common_subs reset

void dll_0F_func0B(int* obj, int* state, f32 f1, f32 f2, f32 f3)
{
    if (*(f32*)((char*)state + 664) > lbl_803E05B4) {
        f32 q = (f2 * f1) / f3;
        *(s16*)obj = (s32)((f32)*(s16*)obj + lbl_803E05B8 * q);
    }
}

void player_updateCurve(int* obj, int* state, f32 t)
{
    int idx = *(int*)((char*)state + 828);
    if (idx == -1) {
        *(f32*)((char*)state + 700) = lbl_803E0570;
    } else {
        int* curve = ((int*(*)(int))((void**)*gRomCurveInterface)[7])(idx);
        if (curve == NULL) {
            *(f32*)((char*)state + 700) = lbl_803E0570;
        } else {
            player_followCurve(obj, state, *(f32*)((char*)curve + 8), *(f32*)((char*)curve + 16), t, 1);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f32 sqrtf(f32 x);
extern f32 lbl_803E0574;
extern f32 lbl_803E0578;
extern f32 lbl_803E057C;
extern f32 lbl_803E0580;
extern f32 lbl_803E0584;

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void player_followCurve(int* obj, int* state, f32 cx, f32 cz, f32 t, int p5)
{
    f32 dx, dz, dist, max;

    *(u32*)state &= ~0x100000;
    dx = *(f32*)((char*)obj + 0xc) - cx;
    dz = *(f32*)((char*)obj + 0x14) - cz;
    dist = sqrtf(dx * dx + dz * dz);
    *(f32*)((char*)state + 0x2bc) = dist;
    max = lbl_803E0578;
    if (*(f32*)((char*)state + 0x2bc) < lbl_803E0580) {
        max = lbl_803E0584 * *(f32*)((char*)state + 0x2bc);
        *(f32*)((char*)state + 0x294) = *(f32*)((char*)state + 0x294) * lbl_803E0574;
    }
    if (dist > max) {
        f32 q = dist / max;
        dx = dx / q;
        dz = dz / q;
    }
    *(f32*)((char*)state + 0x290) = dx;
    *(f32*)((char*)state + 0x28c) = -dz;
    *(f32*)((char*)state + 0x290) = *(f32*)((char*)state + 0x290) * t;
    *(f32*)((char*)state + 0x28c) = *(f32*)((char*)state + 0x28c) * t;
    if (*(f32*)((char*)state + 0x290) > lbl_803E0578) {
        *(f32*)((char*)state + 0x290) = lbl_803E0578;
    }
    if (*(f32*)((char*)state + 0x290) < lbl_803E057C) {
        *(f32*)((char*)state + 0x290) = lbl_803E057C;
    }
    if (*(f32*)((char*)state + 0x28c) > lbl_803E0578) {
        *(f32*)((char*)state + 0x28c) = lbl_803E0578;
    }
    if (*(f32*)((char*)state + 0x28c) < lbl_803E057C) {
        *(f32*)((char*)state + 0x28c) = lbl_803E057C;
    }
}
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

extern f32 sin(f32 x);
extern f32 fn_80293E80(f32 x);
extern u8 lbl_803DD434;
extern f32 lbl_803E05A4;
extern f32 lbl_803E05A8;
extern f32 lbl_803E05AC;
extern f32 lbl_803E05B0;
extern f32 lbl_803E0570;

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void dll_0F_func13(s16* obj, int* state, int angle, f32 t, f32 scale)
{
    f32 ang, vx, vz, q, w, dist, c, s;

    *(s8*)((char*)state + 0x34c) |= 1;
    if ((s8)lbl_803DD434 == 0) {
        ang = (lbl_803E05A4 * (f32)angle) / lbl_803E05A8;
        vx = scale * (*(f32*)((char*)state + 0x298) * -fn_80293E80(ang));
        vz = scale * (*(f32*)((char*)state + 0x298) * -sin(ang));
        if (*(f32*)((char*)state + 0x298) < lbl_803E05AC) {
            vx = lbl_803E0570;
            vz = vx;
        }
        *(f32*)((char*)obj + 0x24) = *(f32*)((char*)obj + 0x24)
            + (t * (vx - *(f32*)((char*)obj + 0x24))) / *(f32*)((char*)state + 0x2b8);
        *(f32*)((char*)obj + 0x2c) = *(f32*)((char*)obj + 0x2c)
            + (t * (vz - *(f32*)((char*)obj + 0x2c))) / *(f32*)((char*)state + 0x2b8);
    } else {
        *(s8*)((char*)state + 0x34c) &= ~1;
    }
    q = *(f32*)((char*)obj + 0x24) * *(f32*)((char*)obj + 0x24);
    w = *(f32*)((char*)obj + 0x2c) * *(f32*)((char*)obj + 0x2c);
    dist = sqrtf(q + w);
    *(f32*)((char*)state + 0x294) = dist;
    if (*(f32*)((char*)state + 0x294) < lbl_803E05B0) {
        f32 z = lbl_803E0570;
        *(f32*)((char*)state + 0x294) = z;
        *(f32*)((char*)obj + 0x24) = z;
        *(f32*)((char*)obj + 0x2c) = z;
    }
    c = fn_80293E80((lbl_803E05A4 * (f32)*obj) / lbl_803E05A8);
    s = sin((lbl_803E05A4 * (f32)*obj) / lbl_803E05A8);
    *(f32*)((char*)state + 0x284) = *(f32*)((char*)obj + 0x24) * s - *(f32*)((char*)obj + 0x2c) * c;
    *(f32*)((char*)state + 0x280) = -*(f32*)((char*)obj + 0x2c) * s - *(f32*)((char*)obj + 0x24) * c;
}
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void Checkpoint_initialise(void) {
    lbl_803DD410 = 0;
    lbl_803DD41C = lbl_8039CA98;
    lbl_803DD418 = (void*)((u8*)lbl_8039CA98 + 0x28);
}
#pragma peephole reset
#pragma scheduling reset

/* Checkpoint_Add: sorted insertion of (entry->_14 as key, entry as pointer) into lbl_8039C458 table. */
typedef struct CheckpointSlot {
    u32 key;
    void *entry;
} CheckpointSlot;
extern CheckpointSlot lbl_8039C458[];
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void Checkpoint_Add(int *entry) {
    int i = 0;
    CheckpointSlot *p = lbl_8039C458;
    int count = lbl_803DD410;
    while (i < count && (u32)entry[5] > p[i].key) {
        i++;
    }
    {
        CheckpointSlot *end = &lbl_8039C458[count];
        int remaining = count - i;
        while (remaining > 0) {
            end->entry = (end - 1)->entry;
            end->key   = (end - 1)->key;
            end--;
            remaining--;
        }
    }
    lbl_803DD410 = count + 1;
    lbl_8039C458[i].entry = entry;
    lbl_8039C458[i].key   = entry[5];
}
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

extern int *gPartfxInterface;

#pragma scheduling off
#pragma peephole off
void player_updateParticles(int *p1, int p2, int p3, int count, int mode)
{
    while (count != 0 && p1 != NULL) {
        if (mode == 0) {
            (*(void (*)(int *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 8)))(p1, p3, 0, 2, -1, 0);
        } else if (mode == 1) {
            (*(void (*)(int *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 8)))(p1, p3, 0, 2, -1, 0);
        } else if (mode == 2) {
            (*(void (*)(int *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 8)))(p1, p3, 0, 4, -1, 0);
        }
        count--;
    }
}

#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void player_doProjGfx(int *p1, int p2, int p3, int count, int p5, int mode)
{
    int *res = Resource_Acquire((u16)(p3 + 0x58), 1);
    while (count != 0) {
        if (mode == 0) {
            (*(void (*)(int *, int, int, int, int, int))(*(int *)(*(int *)res + 4)))(p1, 0, 0, 1, -1, 0);
        } else if (mode == 1) {
            (*(void (*)(int *, int, int, int, int, int))(*(int *)(*(int *)res + 4)))(p1, 0, 0, 2, -1, 0);
        } else if (mode == 2) {
            (*(void (*)(int *, int, int, int, int, int))(*(int *)(*(int *)res + 4)))(p1, 0, 0, 4, -1, 0);
        }
        count--;
    }
    Resource_Release(res);
}
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void Checkpoint_remove(int *obj) {
    int count;
    int i = 0;
    CheckpointSlot *p = lbl_8039C458;
    CheckpointSlot *e;

    count = lbl_803DD410;

    while (i < count && (u32)obj[5] != p[i].key) {
        i++;
    }
    if (i >= count) return;
    count = lbl_803DD410 - 1;
    lbl_803DD410 = count;
    e = &lbl_8039C458[i];
    while (i < count) {
        e->entry = (e + 1)->entry;
        e->key   = (e + 1)->key;
        e++;
        i++;
    }
}
#pragma opt_common_subs reset
extern int getAngle(f32 a, f32 b);
extern f32 lbl_803E0584;
extern f32 timeDelta;
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void player_rotateTowardEnemy(int *obj, int *ctx, int spd) {
    int *enemy;
    f32 dx;
    f32 dz;
    int diff;
    enemy = (int *)ctx[0x2d0 / 4];
    if (enemy != 0) {
        if (enemy[0x30 / 4] == obj[0x30 / 4]) {
            dx = *(f32 *)((char *)enemy + 0xc) - *(f32 *)((char *)obj + 0xc);
            dz = *(f32 *)((char *)enemy + 0x14) - *(f32 *)((char *)obj + 0x14);
        } else {
            dx = *(f32 *)((char *)obj + 0x18) - *(f32 *)((char *)enemy + 0x18);
            dz = *(f32 *)((char *)obj + 0x20) - *(f32 *)((char *)enemy + 0x20);
        }
        diff = (u16)getAngle(-dx, -dz) - (u16)*(s16 *)((char *)obj + 0);
        if (diff > 0x8000) {
            diff -= 0xffff;
        }
        if (diff < -0x8000) {
            diff += 0xffff;
        }
        *(s16 *)((char *)obj + 0) =
            (s16)(*(s16 *)((char *)obj + 0) +
                  (int)((f32)diff * timeDelta / (lbl_803E0584 * (f32)spd)));
    }
}
#pragma opt_common_subs reset
extern f32 lbl_803E058C;
extern void setMatrixFromObjectPos(f32 *mtx, void *desc);
extern void Matrix_TransformPoint(f32 *mtx, f32 x, f32 y, f32 z, f32 *ox, f32 *oy, f32 *oz);
extern void objMove(int *obj, f32 vx, f32 vy, f32 vz);
struct PartDesc {
    s16 ang[3];
    f32 sc[4];
};
#pragma scheduling off
#pragma peephole off
void player_applyVelocityStep(int *p, int *ctx, f32 t) {
    int flags;
    int b;
    struct PartDesc desc;
    f32 mtx[12];
    f32 outX;
    f32 outY;
    f32 outZ;
    flags = ctx[0];
    if ((flags & 0x2000000) != 0) {
        return;
    }
    if ((flags & 0x200000) == 0) {
        *(f32 *)((char *)p + 0x28) = *(f32 *)((char *)p + 0x28) * lbl_803E058C;
        *(f32 *)((char *)p + 0x28) =
            -(*(f32 *)((char *)ctx + 0x2a4) * t) + *(f32 *)((char *)p + 0x28);
    }
    b = (s8)*(u8 *)((char *)ctx + 0x34c);
    if ((b & 1) == 0 || (b & 4) != 0) {
        desc.ang[0] = *(s16 *)((char *)p + 0);
        desc.ang[1] = *(s16 *)((char *)p + 2);
        desc.ang[2] = 0;
        desc.sc[0] = lbl_803E0588;
        desc.sc[1] = lbl_803E0570;
        desc.sc[2] = lbl_803E0570;
        desc.sc[3] = lbl_803E0570;
        setMatrixFromObjectPos(mtx, &desc);
        if ((ctx[0] & 0x10000) != 0) {
            Matrix_TransformPoint(mtx, *(f32 *)((char *)ctx + 0x284), *(f32 *)((char *)ctx + 0x288),
                                  -*(f32 *)((char *)ctx + 0x280), &outX, (f32 *)((char *)p + 0x28),
                                  &outZ);
        } else {
            Matrix_TransformPoint(mtx, *(f32 *)((char *)ctx + 0x284), lbl_803E0570,
                                  -*(f32 *)((char *)ctx + 0x280), &outX, &outY, &outZ);
        }
        *(f32 *)((char *)p + 0x24) = outX;
        *(f32 *)((char *)p + 0x2c) = outZ;
    }
    objMove(p, *(f32 *)((char *)p + 0x24) * t, *(f32 *)((char *)p + 0x28) * t,
            *(f32 *)((char *)p + 0x2c) * t);
}
extern float sqrtf(float x);
extern f32 lbl_803E0578;
extern f32 lbl_803E0590;
extern f32 lbl_803E0594;
extern s16 lbl_803DD44C;
#pragma scheduling off
#pragma peephole off
void fn_800D8414(int *obj, int *ctx) {
    int diff;
    *(f32 *)((char *)ctx + 0x29c) = *(f32 *)((char *)ctx + 0x298);
    *(f32 *)((char *)ctx + 0x298) =
        sqrtf(*(f32 *)((char *)ctx + 0x290) * *(f32 *)((char *)ctx + 0x290) +
              *(f32 *)((char *)ctx + 0x28c) * *(f32 *)((char *)ctx + 0x28c));
    if (*(f32 *)((char *)ctx + 0x298) > lbl_803E0578) {
        *(f32 *)((char *)ctx + 0x298) = lbl_803E0578;
    }
    *(f32 *)((char *)ctx + 0x298) = *(f32 *)((char *)ctx + 0x298) / lbl_803E0578;
    lbl_803DD44C = (s16)getAngle(*(f32 *)((char *)ctx + 0x290), -*(f32 *)((char *)ctx + 0x28c));
    lbl_803DD44C = (s16)(lbl_803DD44C - *(s16 *)((char *)ctx + 0x330));
    diff = lbl_803DD44C - (u16)*(s16 *)((char *)obj + 0);
    if (diff > 0x8000) {
        diff -= 0xffff;
    }
    if (diff < -0x8000) {
        diff += 0xffff;
    }
    *(s16 *)((char *)ctx + 0x336) = (s16)(int)((f32)diff / lbl_803E0590);
    if (diff < 0) {
        *(s16 *)((char *)ctx + 0x334) = -*(s16 *)((char *)ctx + 0x336);
    } else {
        *(s16 *)((char *)ctx + 0x334) = *(s16 *)((char *)ctx + 0x336);
    }
    diff += 0x10000;
    if (*(f32 *)((char *)ctx + 0x298) < lbl_803E0594) {
        *(u8 *)((char *)ctx + 0x34b) = 0;
    } else {
        diff -= 0x6000;
        if (diff < 0) {
            diff += 0xffff;
        }
        if (diff > 0xffff) {
            diff -= 0xffff;
        }
        *(u8 *)((char *)ctx + 0x34b) = (u8)(4 - diff / 0x4000);
    }
}
extern f32 lbl_803E0574;
extern f32 lbl_803E057C;
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void player_getExtraSize(int *a, int *ctx, f32 px, f32 pz, f32 lo, f32 hi, f32 spd) {
    f32 dx;
    f32 dz;
    f32 mag;
    dx = *(f32 *)((char *)a + 0xc) - px;
    dz = *(f32 *)((char *)a + 0x14) - pz;
    mag = sqrtf(dx * dx + dz * dz);
    *(f32 *)((char *)ctx + 0x2bc) = mag;
    if (lbl_803E0570 != mag) {
        dx = dx / mag;
        dz = dz / mag;
    }
    if (*(f32 *)((char *)ctx + 0x2bc) > lo + hi) {
        *(f32 *)((char *)ctx + 0x290) = dx * spd;
        *(f32 *)((char *)ctx + 0x28c) = -dz * spd;
    } else {
        *(f32 *)((char *)ctx + 0x294) = *(f32 *)((char *)ctx + 0x294) * lbl_803E0574;
        *(f32 *)((char *)ctx + 0x290) = lbl_803E0570;
        *(f32 *)((char *)ctx + 0x28c) = lbl_803E0570;
    }
    if (*(f32 *)((char *)ctx + 0x290) > lbl_803E0578) {
        *(f32 *)((char *)ctx + 0x290) = lbl_803E0578;
    }
    if (*(f32 *)((char *)ctx + 0x290) < lbl_803E057C) {
        *(f32 *)((char *)ctx + 0x290) = lbl_803E057C;
    }
    if (*(f32 *)((char *)ctx + 0x28c) > lbl_803E0578) {
        *(f32 *)((char *)ctx + 0x28c) = lbl_803E0578;
    }
    if (*(f32 *)((char *)ctx + 0x28c) < lbl_803E057C) {
        *(f32 *)((char *)ctx + 0x28c) = lbl_803E057C;
    }
}
#pragma opt_common_subs reset
extern u8 lbl_803DD434;
extern f32 lbl_803E05A0;
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void player_animFn16(int *obj, int *ctx, int moveA, int moveB) {
    f32 mag;
    f32 tmp;
    f32 q1, q2;
    f64 ratio;
    int idx;
    if ((s8)lbl_803DD434 != 0) {
        if (*(f32 *)((char *)ctx + 0x280) > lbl_803E0570 && *(s16 *)((char *)obj + 0xa0) != (int)lbl_803DD43C) {
            ObjAnim_SetCurrentMove((int)obj, lbl_803DD43C, *(f32 *)((char *)obj + 0x98), 0);
            *(u8 *)((char *)ctx + 0x346) = 0;
        } else if (*(f32 *)((char *)ctx + 0x280) < lbl_803E0570 && *(s16 *)((char *)obj + 0xa0) != (int)lbl_803DD438) {
            ObjAnim_SetCurrentMove((int)obj, lbl_803DD438, *(f32 *)((char *)obj + 0x98), 0);
            *(u8 *)((char *)ctx + 0x346) = 0;
        }
        q1 = *(f32 *)((char *)ctx + 0x280) * *(f32 *)((char *)ctx + 0x280);
        q2 = *(f32 *)((char *)ctx + 0x284) * *(f32 *)((char *)ctx + 0x284);
        mag = sqrtf(q1 + q2);
        if (ObjAnim_SampleRootCurvePhase(mag, (ObjAnimComponent *)obj, &tmp) != 0) {
            *(f32 *)((char *)ctx + 0x2a0) = tmp;
        }
        ratio = lbl_803E0570;
        if (ratio != mag) {
            ratio = *(f32 *)((char *)ctx + 0x284) / mag;
        }
        tmp = ratio;
        idx = (int)(lbl_803E05A0 * (f32)ratio);
        if (idx < 0) {
            idx = -idx;
        }
        if ((f32)idx > lbl_803E05A0) {
            idx = 0x4000;
        }
        if (*(f32 *)((char *)ctx + 0x284) > lbl_803E0570) {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent *)obj, moveB, idx);
        } else {
            Object_ObjAnimSetSecondaryBlendMove((ObjAnimComponent *)obj, moveA, idx);
        }
    }
}
#pragma opt_common_subs reset
typedef struct {
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} HudColor;
extern u8 lbl_803DC950;
extern f32 lbl_803E0568;
extern void *gScreenTransitionInterface;
extern void GXGetScissor(int *x, int *y, int *w, int *h);
extern void GXSetScissor(int x, int y, int w, int h);
extern void hudDrawRect(int x, int y, int w, int h, HudColor col);
extern void setHudOpacity(int op);
extern void screenRectFn_800d7568(int p1, int p2, int p3, u8 r, u8 g, u8 b);
#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
void screenTransition_do2(int p1, int p2, int p3) {
    int sx;
    int sy;
    int sw;
    int sh;
    HudColor col;
    if (lbl_803DD42E != 0) {
        lbl_803DD42E = lbl_803DD42E - 1;
        return;
    }
    if (lbl_803DD42F == 0 && lbl_803DD428 >= lbl_803E0568) {
        (*(code *)(*(int *)gScreenTransitionInterface + 0xc))(0x1e, lbl_803DD42C);
        lbl_803DD428 = lbl_803E0560;
    }
    lbl_803DD420 = lbl_803DD424 * timeDelta + lbl_803DD420;
    if (lbl_803DD420 < lbl_803E0560) {
        lbl_803DD420 = lbl_803E0560;
        lbl_803DD42D = 1;
        if (lbl_803DD42C == 5) {
            setHudOpacity(0xff);
        }
        return;
    }
    if (lbl_803DD420 > lbl_803E0558) {
        lbl_803DD420 = lbl_803E0558;
        lbl_803DD42D = 1;
        if (lbl_803DD42F == 0) {
            lbl_803DD428 = lbl_803DD428 + timeDelta;
        }
        if (lbl_803DD42C != 5) {
            setHudOpacity(0xff);
        }
    } else {
        lbl_803DD42D = 0;
    }
    if (lbl_803DC950 != 0) {
        return;
    }
    switch (lbl_803DD42C) {
    case 1:
        GXGetScissor(&sx, &sy, &sw, &sh);
        GXSetScissor(0, 0, 0x280, 0x1e0);
        col.b = 0;
        col.g = 0;
        col.r = 0;
        col.a = (u8)(int)lbl_803DD420;
        hudDrawRect(sx, sy, sw, sh, col);
        GXSetScissor(sx, sy, sw, sh);
        break;
    case 2:
        GXGetScissor(&sx, &sy, &sw, &sh);
        GXSetScissor(0, 0, 0x280, 0x1e0);
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = (u8)(int)lbl_803DD420;
        hudDrawRect(sx, sy, sw, sh, col);
        GXSetScissor(sx, sy, sw, sh);
        break;
    case 3:
        screenRectFn_800d7568(p1, p2, p3, 0xff, 0xff, 0xff);
        break;
    case 4:
        GXGetScissor(&sx, &sy, &sw, &sh);
        GXSetScissor(0, 0, 0x280, 0x1e0);
        col.r = 0xff;
        col.g = 0;
        col.b = 0;
        col.a = (u8)(int)lbl_803DD420;
        hudDrawRect(sx, sy, sw, sh, col);
        GXSetScissor(sx, sy, sw, sh);
        break;
    }
}
#pragma opt_common_subs reset
#pragma scheduling reset
#pragma peephole reset

extern f32 lbl_803E0540;
extern f32 lbl_803E0544;
extern f32 lbl_803E0548;
extern void Camera_GetCurrentViewport(int *x1, int *y1, int *x2, int *y2);

#pragma scheduling off
#pragma peephole off
void screenRectFn_800d7568(int p1, int p2, int p3, u8 r, u8 g, u8 b)
{
    int vx;
    int vy;
    int vr;
    int vb;
    int sx;
    int sy;
    int sw;
    int sh;
    HudColor col;
    uint uVar1, uVar3, uVar5, uVar7, uVar8, uVar9, uVar10, uVar11, uVar12, H;
    u8 step, a8;
    int iVar6;
    f32 conv;

    GXGetScissor(&sx, &sy, &sw, &sh);
    Camera_GetCurrentViewport(&vx, &vy, &vr, &vb);
    uVar5 = (vr - vx) & 0xffff;
    H = (vb - vy) & 0xffff;
    if (lbl_803DD420 > lbl_803E0540) {
        uVar12 = 0xff;
        uVar11 = (int)(lbl_803DD420 - lbl_803E0540);
    } else {
        uVar12 = (int)(lbl_803E0544 * lbl_803DD420);
        uVar11 = 0;
    }
    uVar1 = (uVar5 >> 1) & 0xffff;
    uVar11 = uVar11 & 0xffff;
    conv = (f32)(int)(uVar11 * uVar1);
    uVar7 = (uint)(int)(conv * lbl_803E0548) & 0xffff;
    if (uVar7 == uVar1) {
        int sh2;
        int sw2;
        int sy2;
        int sx2;
        HudColor col2;
        GXGetScissor(&sx2, &sy2, &sw2, &sh2);
        GXSetScissor(0, 0, 0x280, 0x1e0);
        col2.r = r;
        col2.g = b;
        col2.b = g;
        col2.a = (int)lbl_803DD420;
        hudDrawRect(sx2, sy2, sw2, sh2, col2);
        GXSetScissor(sx2, sy2, sw2, sh2);
    } else {
        uVar10 = (uVar1 - uVar7) & 0xffff;
        uVar8 = (uVar1 + uVar7) & 0xffff;
        uVar7 = ((uVar1 - 1) - uVar7) & 0xffff;
        GXSetScissor(vx, vy, vr - vx, vb - vy);
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = uVar12;
        hudDrawRect(vx + uVar7 + 1, vy, vx + uVar8, vb, col);
        step = (int)uVar10 / ((int)uVar1 / 6);
        if (step == 0) {
            step = 1;
        }
        a8 = uVar12;
        for (uVar9 = 0; uVar3 = uVar9 & 0xffff, (int)uVar3 < (int)(uVar10 - step); uVar9 += step) {
            col.r = 0xff;
            col.g = 0xff;
            col.b = 0xff;
            col.a = ((int)(a8 * (uVar1 - uVar3)) / (int)uVar1) & 0xff;
            iVar6 = vx + (uVar8 & 0xffff);
            hudDrawRect(iVar6, vy, step + iVar6, vb, col);
            iVar6 = vx + (uVar7 & 0xffff);
            hudDrawRect((iVar6 - step) + 1, vy, iVar6 + 1, vb, col);
            uVar8 += step;
            uVar7 -= step;
        }
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = ((int)(a8 * (uVar1 - uVar3)) / (int)uVar1) & 0xff;
        hudDrawRect(vx + (uVar8 & 0xffff), vy, vr, vb, col);
        hudDrawRect(vx, vy, vx + (uVar7 & 0xffff) + 1, vb, col);
        uVar7 = (H >> 1) & 0xffff;
        conv = (f32)(int)(uVar11 * uVar7);
        uVar11 = (uint)(int)(conv * lbl_803E0548) & 0xffff;
        uVar1 = (uVar7 - uVar11) & 0xffff;
        uVar10 = (uVar7 + uVar11) & 0xffff;
        uVar11 = ((uVar7 - 1) - uVar11) & 0xffff;
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = uVar12;
        hudDrawRect(vx, vy + uVar11 + 1, vr, vy + uVar10, col);
        step = (int)uVar1 / (int)(uVar7 >> 3);
        if (step == 0) {
            step = 1;
        }
        for (uVar12 = 0; uVar8 = uVar12 & 0xffff, (int)uVar8 < (int)(uVar1 - step); uVar12 += step) {
            col.r = 0xff;
            col.g = 0xff;
            col.b = 0xff;
            col.a = ((int)(a8 * (uVar7 - uVar8)) / (int)uVar7) & 0xff;
            iVar6 = vy + (uVar10 & 0xffff);
            hudDrawRect(vx, iVar6, vr, step + iVar6, col);
            iVar6 = vy + (uVar11 & 0xffff);
            hudDrawRect(vx, (iVar6 - step) + 1, vr, iVar6 + 1, col);
            uVar10 += step;
            uVar11 -= step;
        }
        col.r = 0xff;
        col.g = 0xff;
        col.b = 0xff;
        col.a = ((int)(a8 * (uVar7 - uVar8)) / (int)uVar7) & 0xff;
        hudDrawRect(vx, vy + (uVar10 & 0xffff), vr, vb, col);
        hudDrawRect(vx, vy, vr, vy + (uVar11 & 0xffff) + 1, col);
        GXSetScissor(sx, sy, sw, sh);
    }
}
#pragma peephole reset
#pragma scheduling reset

extern f64 lbl_803E0520;
extern f32 lbl_803E051C;
extern f32 lbl_803E0528;
extern f32 lbl_803E052C;
extern f32 lbl_803E0530;
extern f32 lbl_803E0534;
extern f32 lbl_803E0538;

#pragma scheduling off
#pragma peephole off
void Checkpoint_func06(int* obj, int* state, int filter)
{
    int stack[64];
    char visited[200];
    int cur;
    int slot;
    int k, count, i, j;
    char* cp;
    char* p;
    char* n;
    char* e;
    f32 cos1, sin1, cos2, sin2;
    f32 dist1, dist2, nx, nz, offs1, dz;
    f32 offs2, distA, distB, dx, dy, len, q, t0, sum, frac, b1, width;
    f32 px, py, pz, outX, outY;
    f32 ddx, ddy, ddz;

    count = 0;
    for (i = 0; i < (int)lbl_803DD410; i++) {
        visited[i] = 0;
    }
    cp = (char*)Checkpoint_find(*(int*)((char*)state + 0x10), &cur);
    if (cp != NULL) {
        stack[count++] = cur;
    } else {
        for (i = 0; i < (int)lbl_803DD410; i++) {
            e = (char*)lbl_8039C458[i].entry;
            if (visited[i] == 0 && (filter == -1 || *(s8*)(e + 0x28) == filter)) {
                ddx = *(f32*)(e + 8) - *(f32*)((char*)obj + 0xc);
                ddy = *(f32*)(e + 0xc) - *(f32*)((char*)obj + 0x10);
                ddz = *(f32*)(e + 0x10) - *(f32*)((char*)obj + 0x14);
                if (ddz * ddz + (ddx * ddx + ddy * ddy) < lbl_803E051C) {
                    stack[count++] = i;
                    for (j = i; j < (int)lbl_803DD410; j++) {
                        if (filter == *(s8*)((char*)lbl_8039C458[j].entry + 0x28)) {
                            visited[j] = 1;
                        }
                    }
                }
            }
        }
    }
    for (i = 0; i < (int)lbl_803DD410; i++) {
        visited[i] = 0;
    }
    for (;;) {
        if (count > 0) {
            count--;
            cur = stack[count];
            cp = (char*)lbl_8039C458[cur].entry;
        } else {
            *(int*)((char*)state + 0x10) = -1;
            return;
        }
        if (cp == NULL) {
            return;
        }
        p = cp;
        for (k = 0; k < 2; k++) {
            n = (char*)Checkpoint_find(*(int*)(p + 0x20), &slot);
            if (n != NULL) {
                cos1 = fn_80293E80((lbl_803E04D8 * (f32)(*(u8*)(cp + 0x29) << 8)) / lbl_803E04DC);
                sin1 = sin((lbl_803E04D8 * (f32)(*(u8*)(cp + 0x29) << 8)) / lbl_803E04DC);
                offs1 = -(*(f32*)(cp + 8) * cos1 + *(f32*)(cp + 0x10) * sin1);
                cos2 = fn_80293E80((lbl_803E04D8 * (f32)(*(u8*)(n + 0x29) << 8)) / lbl_803E04DC);
                sin2 = sin((lbl_803E04D8 * (f32)(*(u8*)(n + 0x29) << 8)) / lbl_803E04DC);
                offs2 = -(*(f32*)(n + 8) * cos2 + *(f32*)(n + 0x10) * sin2);
                dist1 = offs1 + (cos1 * *(f32*)((char*)obj + 0xc) + sin1 * *(f32*)((char*)obj + 0x14));
                dist2 = offs2 + (cos2 * *(f32*)((char*)obj + 0xc) + sin2 * *(f32*)((char*)obj + 0x14));
                distA = offs1 + (cos1 * *(f32*)(n + 8) + sin1 * *(f32*)(n + 0x10));
                distB = offs2 + (cos2 * *(f32*)(cp + 8) + sin2 * *(f32*)(cp + 0x10));
                if (((distA <= lbl_803E04E8 && dist1 <= lbl_803E04E8) || (distA > lbl_803E04E8 && dist1 > lbl_803E04E8)) &&
                    ((distB <= lbl_803E04E8 && dist2 <= lbl_803E04E8) || (distB > lbl_803E04E8 && dist2 > lbl_803E04E8))) {
                    dx = *(f32*)(cp + 8) - *(f32*)(n + 8);
                    dy = *(f32*)(cp + 0xc) - *(f32*)(n + 0xc);
                    dz = *(f32*)(cp + 0x10) - *(f32*)(n + 0x10);
                    len = sqrtf(dz * dz + (dx * dx + dy * dy));
                    if (len > lbl_803E0520) {
                        q = lbl_803E0504 / len;
                        nx = dx * q;
                        nz = dz * q;
                    }
                    q = cos1 * nx + sin1 * nz;
                    t0 = -dist1 / q;
                    sum = t0 + dist2 / (cos2 * nx + sin2 * nz);
                    if (sum > lbl_803E0528 || sum < lbl_803E052C) {
                        frac = t0 / sum;
                    } else {
                        frac = lbl_803E04E8;
                    }
                    if (frac < lbl_803E04E8) {
                        frac = lbl_803E04E8;
                    }
                    if (frac >= lbl_803E0518) {
                        frac = lbl_803E0518;
                    }
                    b1 = (f32)*(u8*)(cp + 0x2a);
                    width = frac * ((f32)*(u8*)(n + 0x2a) - b1) + b1;
                    px = -(dx * frac - *(f32*)(cp + 8));
                    py = -(dy * frac - *(f32*)(cp + 0xc));
                    pz = -(dz * frac - *(f32*)(cp + 0x10));
                    outY = (*(f32*)((char*)obj + 0x10) - py) / width;
                    outX = (-(px * nz - pz * nx) + (*(f32*)((char*)obj + 0xc) * nz - *(f32*)((char*)obj + 0x14) * nx)) / width;
                    if (outX < lbl_803E0530 || outX > lbl_803E0534 || outY < lbl_803E0538 || outY > lbl_803E0534) {
                    } else {
                        *(int*)((char*)state + 0x10) = *(int*)(cp + 0x14);
                        *(int*)((char*)state + 0x14) = *(int*)(cp + 0x14);
                        *(f32*)((char*)state + 0) = outX;
                        *(f32*)((char*)state + 4) = outY;
                        *(f32*)((char*)state + 8) = frac;
                        *(s16*)((char*)state + 0x20) = *(s8*)(cp + 0x28);
                        return;
                    }
                }
            }
            p += 4;
        }
        if (visited[cur] == 0) {
            p = cp + 4;
            for (k = 1; k >= 0; k--) {
                n = (char*)Checkpoint_find(*(int*)(p + 0x18), &slot);
                if (n != NULL && visited[slot] == 0 && count < 0x3c) {
                    stack[count++] = slot;
                }
                n = (char*)Checkpoint_find(*(int*)(p + 0x20), &slot);
                if (n != NULL && visited[slot] == 0 && count < 0x3c) {
                    stack[count++] = slot;
                }
                p -= 4;
            }
            visited[cur] = 1;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset
