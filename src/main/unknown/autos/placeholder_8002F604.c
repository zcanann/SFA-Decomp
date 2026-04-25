#include "ghidra_import.h"
#include "main/objanim_internal.h"
#include "main/unknown/autos/placeholder_8002F604.h"

extern undefined4 FUN_8001786c();
extern undefined4 FUN_80017abc();
extern undefined4 FUN_8003582c();
extern undefined4 FUN_800723a0();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028688c();

extern f64 DOUBLE_803df568;
extern f64 DOUBLE_803df580;
extern f32 FLOAT_803df560;
extern f32 FLOAT_803df570;
extern f32 FLOAT_803df574;
extern f32 FLOAT_803df578;
extern f32 FLOAT_803df588;
extern f32 FLOAT_803df58c;

/*
 * These helpers sit directly next to src/main/objanim.c and operate on the
 * same object-animation state. Keep the shared field names aligned so meaning
 * can propagate across both files instead of drifting back to raw offsets.
 */

/*
 * --INFO--
 *
 * Function: ObjAnim_SampleRootCurvePhase
 * EN v1.0 Address: 0x8002F5D4
 * EN v1.0 Size: 1140b
 * EN v1.1 Address: 0x8002F6CC
 * EN v1.1 Size: 1140b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjAnim_SampleRootCurvePhase(double param_1,int param_2,float *param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  short sVar6;
  float fVar7;
  float fVar8;
  bool bVar9;
  uint uVar10;
  uint uVar11;
  int *piVar12;
  int iVar13;
  float *pfVar14;
  float *pfVar15;
  float *pfVar16;
  int iVar17;
  int iVar18;
  double in_f6;
  double in_f7;
  double in_f8;
  undefined8 local_20;

  piVar12 = *(int **)(*(int *)(param_2 + 0x7c) + *(char *)(param_2 + 0xad) * 4);
  iVar17 = *piVar12;
  if (*(short *)(iVar17 + 0xec) != 0) {
    iVar18 = piVar12[0xb];
    fVar5 = *(float *)(param_2 + 8);
    pfVar15 = (float *)0x0;
    if (*(ushort *)(iVar18 + 0x5a) != 0) {
      in_f7 = (double)((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar18 + 0x5a)) -
                              DOUBLE_803df568) / FLOAT_803df574);
      in_f8 = (double)(float)((double)FLOAT_803df560 - in_f7);
      if ((*(ushort *)(iVar17 + 2) & 0x40) == 0) {
        iVar13 = *(int *)(*(int *)(iVar17 + 100) + (uint)*(ushort *)(iVar18 + 0x48) * 4);
      }
      else {
        iVar13 = *(int *)(iVar18 + (uint)*(ushort *)(iVar18 + 0x48) * 4 + 0x24) + 0x80;
      }
      if (*(short *)(iVar13 + 4) != 0) {
        pfVar16 = (float *)(iVar13 + *(short *)(iVar13 + 4));
        in_f6 = (double)(*pfVar16 * fVar5);
        pfVar15 = (float *)((int)pfVar16 + 6);
        if (((*(short *)pfVar15 == 0) && (pfVar15 = pfVar16 + 2, *(short *)pfVar15 == 0)) &&
           (pfVar15 = (float *)((int)pfVar16 + 10), *(short *)pfVar15 == 0)) {
          pfVar15 = (float *)0x0;
        }
        if (pfVar15 != (float *)0x0) {
          pfVar15 = (float *)((int)pfVar15 + 2);
        }
      }
    }
    if ((*(ushort *)(iVar17 + 2) & 0x40) == 0) {
      iVar17 = *(int *)(*(int *)(iVar17 + 100) + (uint)*(ushort *)(iVar18 + 0x44) * 4);
    }
    else {
      iVar17 = *(int *)(iVar18 + (uint)*(ushort *)(iVar18 + 0x44) * 4 + 0x1c) + 0x80;
    }
    if (*(short *)(iVar17 + 4) != 0) {
      pfVar16 = (float *)(iVar17 + *(short *)(iVar17 + 4));
      fVar7 = *pfVar16 * fVar5;
      uVar10 = (int)*(short *)(pfVar16 + 1) - 1;
      pfVar14 = (float *)((int)pfVar16 + 6);
      if ((*(short *)pfVar14 == 0) && (pfVar14 = pfVar16 + 2, *(short *)pfVar14 == 0)) {
        pfVar14 = (float *)((int)pfVar16 + 10);
      }
      if (*(short *)pfVar14 != 0) {
        sVar6 = *(short *)((int)pfVar14 + uVar10 * 2 + 2);
        if (sVar6 < 0) {
          fVar7 = -fVar7;
        }
        if (sVar6 != 0) {
          fVar4 = (float)((double)CONCAT44(0x43300000,uVar10 ^ 0x80000000) - DOUBLE_803df580);
          fVar8 = FLOAT_803df560 / fVar4;
          fVar4 = fVar4 * *(float *)(param_2 + 0x98);
          uVar11 = (uint)fVar4;
          fVar4 = fVar4 - (float)((double)CONCAT44(0x43300000,uVar11 ^ 0x80000000) - DOUBLE_803df580
                                 );
          if (pfVar15 == (float *)0x0) {
            fVar1 = fVar7 * (float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)((int)pfVar14 + uVar11 * 2 + 2)
                                                     ^ 0x80000000) - DOUBLE_803df580);
            fVar2 = fVar7 * (float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)((int)pfVar14 + uVar11 * 2 + 4)
                                                     ^ 0x80000000) - DOUBLE_803df580);
          }
          else {
            if (*(short *)((int)pfVar15 + uVar10 * 2) < 0) {
              in_f6 = -in_f6;
            }
            iVar17 = uVar11 * 2;
            local_20 = (double)CONCAT44(0x43300000,
                                        (int)*(short *)((int)pfVar15 + iVar17) ^ 0x80000000);
            fVar1 = (float)(in_f6 * (double)(float)(in_f7 * (double)(float)(local_20 -
                                                                           DOUBLE_803df580)) +
                           (double)(fVar7 * (float)(in_f8 * (double)(float)((double)CONCAT44(
                                                  0x43300000,
                                                  (int)*(short *)((int)pfVar14 + iVar17 + 2) ^
                                                  0x80000000) - DOUBLE_803df580))));
            fVar2 = (float)(in_f6 * (double)(float)(in_f7 * (double)(float)((double)CONCAT44(
                                                  0x43300000,
                                                  (int)*(short *)((int)pfVar15 + iVar17 + 2) ^
                                                  0x80000000) - DOUBLE_803df580)) +
                           (double)(fVar7 * (float)(in_f8 * (double)(float)((double)CONCAT44(
                                                  0x43300000,
                                                  (int)*(short *)((int)pfVar14 + iVar17 + 4) ^
                                                  0x80000000) - DOUBLE_803df580))));
          }
          fVar5 = (float)(param_1 * (double)(fVar5 / *(float *)(*(int *)(param_2 + 0x50) + 4))) +
                  fVar4 * (fVar2 - fVar1) + fVar1;
          fVar4 = -(fVar8 * fVar4 - fVar8);
          bVar9 = false;
          do {
            if (fVar2 <= fVar5) {
              uVar11 = uVar11 + 1;
              if ((int)uVar10 <= (int)uVar11) {
                uVar11 = 0;
              }
              if (pfVar15 == (float *)0x0) {
                fVar3 = fVar7 * ((float)((double)CONCAT44(0x43300000,
                                                          (int)*(short *)((int)pfVar14 +
                                                                         uVar11 * 2 + 4) ^
                                                          0x80000000) - DOUBLE_803df580) -
                                (float)((double)CONCAT44(0x43300000,
                                                         (int)*(short *)((int)pfVar14 +
                                                                        uVar11 * 2 + 2) ^ 0x80000000
                                                        ) - DOUBLE_803df580));
              }
              else {
                iVar17 = uVar11 * 2;
                local_20 = (double)CONCAT44(0x43300000,
                                            (int)((short *)((int)pfVar15 + iVar17))[1] ^ 0x80000000)
                ;
                fVar3 = (float)((double)(fVar7 * ((float)((double)CONCAT44(0x43300000,
                                                                           (int)*(short *)((int)
                                                  pfVar14 + iVar17 + 4) ^ 0x80000000) -
                                                  DOUBLE_803df580) -
                                                 (float)((double)CONCAT44(0x43300000,
                                                                          (int)*(short *)((int)
                                                  pfVar14 + iVar17 + 2) ^ 0x80000000) -
                                                  DOUBLE_803df580))) * in_f8 +
                               (double)(float)((double)(float)(in_f6 * (double)((float)(local_20 -
                                                  DOUBLE_803df580) -
                                                  (float)((double)CONCAT44(0x43300000,
                                                                           (int)*(short *)((int)
                                                  pfVar15 + iVar17) ^ 0x80000000) - DOUBLE_803df580)
                                                  )) * in_f7));
              }
              fVar4 = fVar4 + fVar8;
              fVar1 = fVar2;
              fVar2 = fVar2 + fVar3;
            }
            else {
              fVar4 = fVar4 - (fVar8 * (fVar2 - fVar5)) / (fVar2 - fVar1);
              bVar9 = true;
            }
          } while (!bVar9);
          if (param_3 != (float *)0x0) {
            *param_3 = fVar4;
          }
          return 1;
        }
        return 0;
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: ObjAnim_AdvanceCurrentMove
 * EN v1.0 Address: 0x8002FA48
 * EN v1.0 Size: 2236b
 * EN v1.1 Address: 0x8002FB40
 * EN v1.1 Size: 2236b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjAnim_AdvanceCurrentMove(double param_1,double param_2)
{
  double dVar1;
  char cVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  float fVar10;
  float fVar11;
  float fVar12;
  float fVar13;
  float fVar14;
  uint uVar15;
  uint uVar16;
  undefined uVar17;
  undefined4 uVar18;
  int iVar19;
  float *pfVar20;
  int iVar21;
  int *piVar22;
  int iVar23;
  int iVar24;
  int iVar25;
  int iVar26;
  float *pfVar27;
  short *psVar28;
  byte bVar29;
  int iVar30;
  double dVar31;
  undefined8 uVar32;
  undefined8 local_48;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_20;

  uVar32 = FUN_80286840();
  iVar19 = (int)((ulonglong)uVar32 >> 0x20);
  pfVar20 = (float *)uVar32;
  dVar31 = (double)FLOAT_803df58c;
  uVar18 = 0;
  if ((dVar31 <= param_1) && (dVar31 = param_1, (double)FLOAT_803df560 < param_1)) {
    dVar31 = (double)FLOAT_803df560;
  }
  piVar22 = *(int **)(*(int *)(iVar19 + 0x7c) + *(char *)(iVar19 + 0xad) * 4);
  if ((*(short *)(*piVar22 + 0xec) != 0) && (iVar24 = piVar22[0xb], iVar24 != 0)) {
    *(float *)(iVar24 + 0xc) = (float)(dVar31 * (double)*(float *)(iVar24 + 0x14));
    if (*(short *)(iVar24 + 0x58) != 0) {
      if ((*(byte *)(iVar24 + 99) & 8) != 0) {
        *(undefined4 *)(iVar24 + 0x10) = *(undefined4 *)(iVar24 + 0xc);
      }
      *(float *)(iVar24 + 8) =
           (float)((double)*(float *)(iVar24 + 0x10) * param_2 + (double)*(float *)(iVar24 + 8));
      fVar4 = FLOAT_803df570;
      fVar3 = *(float *)(iVar24 + 0x18);
      if (*(char *)(iVar24 + 0x61) == '\0') {
        fVar4 = *(float *)(iVar24 + 8);
        fVar5 = FLOAT_803df570;
        if ((FLOAT_803df570 <= fVar4) && (fVar5 = fVar4, fVar3 < fVar4)) {
          fVar5 = fVar3;
        }
        *(float *)(iVar24 + 8) = fVar5;
      }
      else {
        if (*(float *)(iVar24 + 8) < FLOAT_803df570) {
          while (*(float *)(iVar24 + 8) < fVar4) {
            *(float *)(iVar24 + 8) = *(float *)(iVar24 + 8) + fVar3;
          }
        }
        if (fVar3 <= *(float *)(iVar24 + 8)) {
          while (fVar3 <= *(float *)(iVar24 + 8)) {
            *(float *)(iVar24 + 8) = *(float *)(iVar24 + 8) - fVar3;
          }
        }
      }
      if ((*(byte *)(iVar24 + 99) & 2) == 0) {
        uVar15 = (uint)-(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                 (uint)*(ushort *)(iVar24 + 0x5e)) -
                                               DOUBLE_803df568) * param_2 -
                               (double)(float)((double)CONCAT44(0x43300000,
                                                                *(ushort *)(iVar24 + 0x58) ^
                                                                0x80000000) - DOUBLE_803df580));
        fVar3 = FLOAT_803df570;
        if ((-1 < (int)uVar15) &&
           (uVar15 = uVar15 ^ 0x80000000, fVar3 = FLOAT_803df574,
           (float)((double)CONCAT44(0x43300000,uVar15) - DOUBLE_803df580) <= FLOAT_803df574)) {
          local_38 = (double)CONCAT44(0x43300000,uVar15);
          fVar3 = (float)(local_38 - DOUBLE_803df580);
        }
        *(short *)(iVar24 + 0x58) = (short)(int)fVar3;
      }
      if (*(short *)(iVar24 + 0x58) == 0) {
        *(undefined2 *)(iVar24 + 0x5c) = 0;
      }
    }
    fVar4 = *(float *)(iVar19 + 0x98);
    fVar3 = (float)(dVar31 * param_2);
    *(float *)(iVar19 + 0x98) = fVar4 + fVar3;
    fVar6 = FLOAT_803df570;
    fVar5 = FLOAT_803df560;
    if (*(float *)(iVar19 + 0x98) < FLOAT_803df560) {
      if (*(float *)(iVar19 + 0x98) < FLOAT_803df570) {
        if (*(char *)(iVar24 + 0x60) == '\0') {
          *(float *)(iVar19 + 0x98) = FLOAT_803df570;
        }
        else {
          while (*(float *)(iVar19 + 0x98) < fVar6) {
            *(float *)(iVar19 + 0x98) = *(float *)(iVar19 + 0x98) + fVar5;
          }
        }
        uVar18 = 1;
      }
    }
    else if (*(char *)(iVar24 + 0x60) == '\0') {
      *(float *)(iVar19 + 0x98) = FLOAT_803df560;
      uVar18 = 1;
    }
    else {
      while (fVar5 <= *(float *)(iVar19 + 0x98)) {
        *(float *)(iVar19 + 0x98) = *(float *)(iVar19 + 0x98) - fVar5;
      }
      uVar18 = 1;
    }
    if (pfVar20 != (float *)0x0) {
      *(undefined *)((int)pfVar20 + 0x12) = 0;
      fVar5 = FLOAT_803df570;
      pfVar20[2] = FLOAT_803df570;
      pfVar20[1] = fVar5;
      *pfVar20 = fVar5;
      if (*(int *)(iVar19 + 0x60) != 0) {
        *(undefined *)((int)pfVar20 + 0x1b) = 0;
        iVar23 = **(int **)(iVar19 + 0x60) >> 1;
        if (iVar23 != 0) {
          iVar30 = (int)(FLOAT_803df578 * fVar4);
          iVar26 = (int)(FLOAT_803df578 * *(float *)(iVar19 + 0x98));
          bVar29 = iVar26 < iVar30;
          if (fVar3 < FLOAT_803df570) {
            bVar29 = bVar29 | 2;
          }
          iVar25 = 0;
          iVar21 = 0;
          while ((iVar25 < iVar23 && (*(char *)((int)pfVar20 + 0x1b) < '\b'))) {
            uVar16 = (uint)*(short *)(*(int *)(*(int *)(iVar19 + 0x60) + 4) + iVar21);
            uVar15 = uVar16 & 0x1ff;
            uVar16 = uVar16 >> 9 & 0x7f;
            if (uVar16 != 0x7f) {
              uVar17 = (undefined)uVar16;
              if (((bVar29 == 0) && (iVar30 <= (int)uVar15)) && ((int)uVar15 < iVar26)) {
                cVar2 = *(char *)((int)pfVar20 + 0x1b);
                *(char *)((int)pfVar20 + 0x1b) = cVar2 + '\x01';
                *(undefined *)((int)pfVar20 + cVar2 + 0x13) = uVar17;
              }
              if ((bVar29 == 1) && ((iVar30 <= (int)uVar15 || ((int)uVar15 < iVar26)))) {
                cVar2 = *(char *)((int)pfVar20 + 0x1b);
                *(char *)((int)pfVar20 + 0x1b) = cVar2 + '\x01';
                *(undefined *)((int)pfVar20 + cVar2 + 0x13) = uVar17;
              }
              if (((bVar29 == 3) && (iVar26 < (int)uVar15)) && ((int)uVar15 <= iVar30)) {
                cVar2 = *(char *)((int)pfVar20 + 0x1b);
                *(char *)((int)pfVar20 + 0x1b) = cVar2 + '\x01';
                *(undefined *)((int)pfVar20 + cVar2 + 0x13) = uVar17;
              }
              if ((bVar29 == 2) && ((iVar26 < (int)uVar15 || ((int)uVar15 <= iVar30)))) {
                cVar2 = *(char *)((int)pfVar20 + 0x1b);
                *(char *)((int)pfVar20 + 0x1b) = cVar2 + '\x01';
                *(undefined *)((int)pfVar20 + cVar2 + 0x13) = uVar17;
              }
            }
            iVar21 = iVar21 + 2;
            iVar25 = iVar25 + 1;
          }
        }
      }
      if ((*(ushort *)(*piVar22 + 2) & 0x40) == 0) {
        iVar23 = *(int *)(*(int *)(*piVar22 + 100) + (uint)*(ushort *)(iVar24 + 0x44) * 4);
      }
      else {
        iVar23 = *(int *)(iVar24 + (uint)*(ushort *)(iVar24 + 0x44) * 4 + 0x1c) + 0x80;
      }
      if (*(short *)(iVar23 + 4) == 0) {
        *(undefined *)((int)pfVar20 + 0x12) = 0;
      }
      else {
        *(undefined *)((int)pfVar20 + 0x12) = 1;
        pfVar27 = (float *)(iVar23 + *(short *)(iVar23 + 4));
        fVar5 = *pfVar27;
        fVar6 = *(float *)(iVar19 + 8);
        iVar23 = (int)*(short *)(pfVar27 + 1);
        psVar28 = (short *)((int)pfVar27 + 6);
        local_30 = (double)CONCAT44(0x43300000,iVar23 - 1U ^ 0x80000000);
        fVar7 = (float)(local_30 - DOUBLE_803df580) * fVar4;
        uVar15 = (uint)fVar7;
        dVar31 = (double)CONCAT44(0x43300000,uVar15 ^ 0x80000000) - DOUBLE_803df580;
        fVar8 = (float)(local_30 - DOUBLE_803df580) * *(float *)(iVar19 + 0x98);
        uVar16 = (uint)fVar8;
        dVar1 = (double)CONCAT44(0x43300000,uVar16 ^ 0x80000000) - DOUBLE_803df580;
        iVar30 = 0;
        fVar11 = FLOAT_803df570;
        fVar13 = FLOAT_803df560;
        if (*(ushort *)(iVar24 + 0x5a) != 0) {
          local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar24 + 0x5a));
          fVar11 = (float)(local_30 - DOUBLE_803df568) / FLOAT_803df574;
          if ((*(ushort *)(*piVar22 + 2) & 0x40) == 0) {
            iVar24 = *(int *)(*(int *)(*piVar22 + 100) + (uint)*(ushort *)(iVar24 + 0x48) * 4);
          }
          else {
            iVar24 = *(int *)(iVar24 + (uint)*(ushort *)(iVar24 + 0x48) * 4 + 0x24) + 0x80;
          }
          iVar30 = iVar24 + *(short *)(iVar24 + 4) + 6;
          fVar13 = FLOAT_803df560 - fVar11;
        }
        iVar26 = 0;
        iVar24 = (iVar23 - 1U) * 2;
        pfVar27 = pfVar20;
        do {
          if (*psVar28 == 0) {
            psVar28 = psVar28 + 1;
            if (iVar30 != 0) {
              iVar30 = iVar30 + 2;
            }
            if (iVar26 < 3) {
              *pfVar20 = FLOAT_803df570;
            }
            else {
              *(undefined2 *)((int)pfVar27 + 6) = 0;
            }
          }
          else {
            if (iVar30 != 0) {
              iVar30 = iVar30 + 2;
            }
            local_30 = (double)CONCAT44(0x43300000,(int)psVar28[uVar15 + 1] ^ 0x80000000);
            fVar9 = fVar13 * (float)(local_30 - DOUBLE_803df580);
            if (iVar30 != 0) {
              local_38 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(uVar15 * 2 + iVar30) ^ 0x80000000);
              fVar9 = fVar11 * (float)(local_38 - DOUBLE_803df580) + fVar9;
            }
            fVar10 = fVar13 * (float)((double)CONCAT44(0x43300000,
                                                       (int)(psVar28 + uVar15 + 1)[1] ^ 0x80000000)
                                     - DOUBLE_803df580);
            if (iVar30 != 0) {
              local_48 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(uVar15 * 2 + iVar30 + 2) ^ 0x80000000);
              fVar10 = fVar11 * (float)(local_48 - DOUBLE_803df580) + fVar10;
            }
            fVar12 = fVar13 * (float)((double)CONCAT44(0x43300000,
                                                       (int)psVar28[uVar16 + 1] ^ 0x80000000) -
                                     DOUBLE_803df580);
            if (iVar30 != 0) {
              fVar12 = fVar11 * (float)((double)CONCAT44(0x43300000,
                                                         (int)*(short *)(uVar16 * 2 + iVar30) ^
                                                         0x80000000) - DOUBLE_803df580) + fVar12;
            }
            fVar14 = fVar13 * (float)((double)CONCAT44(0x43300000,
                                                       (int)(psVar28 + uVar16 + 1)[1] ^ 0x80000000)
                                     - DOUBLE_803df580);
            if (iVar30 != 0) {
              local_20 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(uVar16 * 2 + iVar30 + 2) ^ 0x80000000);
              fVar14 = fVar11 * (float)(local_20 - DOUBLE_803df580) + fVar14;
            }
            fVar12 = (fVar8 - (float)dVar1) * (fVar14 - fVar12) + fVar12;
            if (fVar3 <= FLOAT_803df570) {
              if (fVar4 < *(float *)(iVar19 + 0x98)) {
                local_20 = (double)CONCAT44(0x43300000,(int)psVar28[iVar23] ^ 0x80000000);
                fVar12 = -(fVar13 * (float)(local_20 - DOUBLE_803df580) - fVar12);
                if (iVar30 != 0) {
                  local_20 = (double)CONCAT44(0x43300000,
                                              (int)*(short *)(iVar24 + iVar30) ^ 0x80000000);
                  fVar12 = fVar11 * (float)(local_20 - DOUBLE_803df580) + fVar12;
                }
              }
            }
            else if (*(float *)(iVar19 + 0x98) < fVar4) {
              local_20 = (double)CONCAT44(0x43300000,(int)psVar28[iVar23] ^ 0x80000000);
              fVar12 = fVar13 * (float)(local_20 - DOUBLE_803df580) + fVar12;
              if (iVar30 != 0) {
                local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar24 + iVar30) ^ 0x80000000
                                           );
                fVar12 = fVar11 * (float)(local_20 - DOUBLE_803df580) + fVar12;
              }
            }
            fVar12 = fVar12 - ((fVar7 - (float)dVar31) * (fVar10 - fVar9) + fVar9);
            if (iVar26 < 3) {
              *pfVar20 = fVar12 * fVar5 * fVar6;
            }
            else {
              *(short *)((int)pfVar27 + 6) = (short)(int)fVar12;
            }
            psVar28 = psVar28 + iVar23 + 1;
            if (iVar30 != 0) {
              iVar30 = iVar30 + iVar23 * 2;
            }
          }
          pfVar20 = pfVar20 + 1;
          pfVar27 = (float *)((int)pfVar27 + 2);
          iVar26 = iVar26 + 1;
        } while (iVar26 < 6);
      }
    }
  }
  FUN_8028688c();
  return uVar18;
}

/*
 * --INFO--
 *
 * Function: ObjAnim_SetMoveProgress
 * EN v1.0 Address: 0x80030304
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x800303FC
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 ObjAnim_SetMoveProgress(double param_1,int param_2)
{
  double dVar1;

  dVar1 = param_1;
  if ((double)FLOAT_803df588 < dVar1) {
    dVar1 = (double)FLOAT_803df588;
  }
  if (dVar1 < (double)FLOAT_803df570) {
    dVar1 = (double)FLOAT_803df570;
  }
  *(float *)(param_2 + 0x98) = (float)dVar1;
  return 0;
}

/*
 * --INFO--
 *
 * Function: ObjAnim_SetCurrentMove
 * EN v1.0 Address: 0x80030334
 * EN v1.0 Size: 852b
 * EN v1.1 Address: 0x8003042C
 * EN v1.1 Size: 852b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void ObjAnim_SetCurrentMove(double param_1,double param_2,double param_3,undefined8 param_4,
                            undefined8 param_5,undefined8 param_6,undefined8 param_7,
                            undefined8 param_8,undefined4 param_9,undefined4 param_10,
                            uint param_11,undefined4 param_12,undefined4 param_13,
                            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  uint uVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  undefined8 uVar10;

  uVar10 = FUN_80286840();
  iVar5 = (int)((ulonglong)uVar10 >> 0x20);
  uVar2 = (uint)uVar10;
  dVar8 = param_1;
  if ((double)FLOAT_803df560 < dVar8) {
    dVar8 = (double)FLOAT_803df560;
  }
  if (dVar8 < (double)FLOAT_803df570) {
    dVar8 = (double)FLOAT_803df570;
  }
  *(float *)(iVar5 + 0x98) = (float)dVar8;
  piVar3 = *(int **)(*(int *)(iVar5 + 0x7c) + *(char *)(iVar5 + 0xad) * 4);
  if ((piVar3 != (int *)0x0) && (iVar7 = *piVar3, *(short *)(iVar7 + 0xec) != 0)) {
    iVar6 = piVar3[0xb];
    *(char *)(iVar6 + 99) = (char)param_11;
    *(undefined2 *)(iVar6 + 0x46) = *(undefined2 *)(iVar6 + 0x44);
    *(undefined4 *)(iVar6 + 8) = *(undefined4 *)(iVar6 + 4);
    *(undefined4 *)(iVar6 + 0x18) = *(undefined4 *)(iVar6 + 0x14);
    *(undefined4 *)(iVar6 + 0x10) = *(undefined4 *)(iVar6 + 0xc);
    *(undefined4 *)(iVar6 + 0x38) = *(undefined4 *)(iVar6 + 0x34);
    *(undefined *)(iVar6 + 0x61) = *(undefined *)(iVar6 + 0x60);
    *(undefined2 *)(iVar6 + 0x4a) = *(undefined2 *)(iVar6 + 0x48);
    *(undefined4 *)(iVar6 + 0x40) = *(undefined4 *)(iVar6 + 0x3c);
    *(undefined2 *)(iVar6 + 0x5c) = *(undefined2 *)(iVar6 + 0x5a);
    *(undefined2 *)(iVar6 + 0x5a) = 0;
    *(undefined2 *)(iVar6 + 100) = 0xffff;
    iVar4 = *(int *)(iVar5 + 0x54);
    dVar9 = param_1;
    if ((iVar4 != 0) && (*(int *)(iVar4 + 8) != 0)) {
      param_14 = 0;
      dVar9 = (double)FUN_8003582c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,
                                   param_8,iVar5,piVar3,(int)*(short *)(iVar5 + 0x46),iVar4,uVar2,0,
                                   param_15,param_16);
    }
    if (*(uint **)(iVar5 + 0x60) != (uint *)0x0) {
      dVar9 = (double)FUN_80017abc(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                   iVar5,(int)*(short *)(iVar5 + 0x46),*(uint **)(iVar5 + 0x60),
                                   uVar2,0,param_14,param_15,param_16);
    }
    sVar1 = *(short *)(iVar5 + 0xa0);
    *(short *)(iVar5 + 0xa0) = (short)uVar10;
    iVar5 = (int)*(short *)(iVar7 + ((int)uVar2 >> 8) * 2 + 0x70) + (uVar2 & 0xff);
    if ((int)(uint)*(ushort *)(iVar7 + 0xec) <= iVar5) {
      iVar5 = *(ushort *)(iVar7 + 0xec) - 1;
    }
    if (iVar5 < 0) {
      iVar5 = 0;
    }
    if ((*(ushort *)(iVar7 + 2) & 0x40) == 0) {
      *(short *)(iVar6 + 0x44) = (short)iVar5;
      iVar5 = *(int *)(*(int *)(iVar7 + 100) + (uint)*(ushort *)(iVar6 + 0x44) * 4);
    }
    else {
      if (uVar2 != (uint)(u16)sVar1) {
        *(char *)(iVar6 + 0x62) = '\x01' - *(char *)(iVar6 + 0x62);
        *(short *)(iVar6 + 0x44) = (short)*(char *)(iVar6 + 0x62);
        if (*(short *)(*(int *)(iVar7 + 0x6c) + iVar5 * 2) == -1) {
          dVar9 = (double)FUN_800723a0();
          iVar5 = 0;
        }
        FUN_8001786c(dVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     (int)*(short *)(*(int *)(iVar7 + 0x6c) + iVar5 * 2),(int)(short)iVar5,
                     *(undefined4 *)(iVar6 + (uint)*(ushort *)(iVar6 + 0x44) * 4 + 0x1c),iVar7);
      }
      iVar5 = *(int *)(iVar6 + (uint)*(ushort *)(iVar6 + 0x44) * 4 + 0x1c) + 0x80;
    }
    *(int *)(iVar6 + 0x34) = iVar5 + 6;
    *(byte *)(iVar6 + 0x60) = *(byte *)(iVar5 + 1) & 0xf0;
    *(float *)(iVar6 + 0x14) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(iVar6 + 0x34) + 1)) -
                DOUBLE_803df568);
    if (*(char *)(iVar6 + 0x60) == '\0') {
      *(float *)(iVar6 + 0x14) = *(float *)(iVar6 + 0x14) - FLOAT_803df560;
    }
    uVar2 = *(u8 *)(iVar5 + 1) & 0xf;
    if ((uVar2 == 0) || ((param_11 & 0x10) != 0)) {
      *(undefined2 *)(iVar6 + 0x58) = 0;
    }
    else {
      *(undefined4 *)(iVar6 + 0x10) = *(undefined4 *)(iVar6 + 0xc);
      *(short *)(iVar6 + 0x5e) =
           (short)(int)(FLOAT_803df574 /
                       (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803df580));
      *(undefined2 *)(iVar6 + 0x58) = 0x4000;
    }
    *(float *)(iVar6 + 0xc) = FLOAT_803df570;
    *(float *)(iVar6 + 4) = (float)(dVar8 * (double)*(float *)(iVar6 + 0x14));
  }
  FUN_8028688c();
}
