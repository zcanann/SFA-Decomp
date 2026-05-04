#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/dll/curves.h"
#include <string.h>

extern undefined4 FUN_80003494();
extern undefined4 FUN_800068f4();
extern undefined4 FUN_800068f8();
extern uint GameBit_Get(int eventId);
extern double FUN_80017714();
extern int FUN_80017730();
extern undefined4 FUN_8001774c();
extern undefined4 FUN_80017754();
extern uint FUN_80017760();
extern undefined4 FUN_80017778();
extern undefined4 FUN_80017b00();
extern ushort ObjHits_IsObjectEnabled();
extern undefined4 ObjHits_AddContactObject();
extern undefined4 FUN_80061fc8();
extern int FUN_800620e8();
extern int FUN_800632f4();
extern undefined FUN_80063a68();
extern undefined4 FUN_80063a74();
extern undefined4 FUN_800723a0();
extern undefined4 FUN_80247eb8();
extern double FUN_80247f54();
extern undefined8 FUN_8028680c();
extern undefined8 FUN_80286810();
extern undefined8 FUN_80286828();
extern undefined8 FUN_8028682c();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern longlong FUN_8028683c();
extern undefined4 FUN_80286858();
extern undefined4 FUN_8028685c();
extern undefined4 FUN_80286874();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint countLeadingZeros();

extern int DAT_803a2448;
extern undefined4 DAT_803a3898;
extern undefined4 gGameplayRegisteredDebugOptions;
extern undefined4 gGameplayEnabledDebugOptions;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803de0e8;
extern undefined4 DAT_803de0ec;
extern undefined4 DAT_803de0f0;
extern undefined4 DAT_803de0f8;
extern undefined4 DAT_803de0fc;
extern f64 DOUBLE_803e12a8;
extern f64 DOUBLE_803e12f0;
extern f64 DOUBLE_803e1318;
extern f32 lbl_803E1290;
extern f32 lbl_803E12B0;
extern f32 lbl_803E12B4;
extern f32 lbl_803E12B8;
extern f32 lbl_803E12C4;
extern f32 lbl_803E12D8;
extern f32 lbl_803E12DC;
extern f32 lbl_803E12E4;
extern f32 lbl_803E12E8;
extern f32 lbl_803E12EC;
extern f32 lbl_803E12F8;
extern f32 lbl_803E12FC;
extern f32 lbl_803E1300;
extern f32 lbl_803E1304;
extern f32 lbl_803E1308;
extern f32 lbl_803E130C;
extern f32 lbl_803E1320;
extern f32 lbl_803E1324;
extern f32 lbl_803E1328;
extern f32 lbl_803E132C;
extern f32 lbl_803E1330;
extern f32 lbl_803E1334;
extern f32 lbl_803E1338;
extern f32 lbl_803E133C;
extern f32 lbl_803E1340;
extern char lbl_803116BC[];

#define ROMCURVE_MAX_CURVES 0x514
#define ROMCURVE_ID_OFFSET 0x14

/*
 * --INFO--
 *
 * Function: FUN_800e1b24
 * EN v1.0 Address: 0x800E1B24
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800E1DA8
 * EN v1.1 Size: 1048b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_800e1b24(double param_1,double param_2,double param_3,uint *param_4,float *param_5,
            float *param_6,float *param_7)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800e1b2c
 * EN v1.0 Address: 0x800E1B2C
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x800E21C0
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_800e1b2c(double param_1,undefined8 param_2,double param_3,int param_4,int param_5)
{
  float fVar1;
  float fVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  
  dVar3 = (double)*(float *)(param_4 + 8);
  dVar5 = (double)*(float *)(param_4 + 0x10);
  dVar4 = (double)*(float *)(param_5 + 8);
  dVar6 = (double)*(float *)(param_5 + 0x10);
  fVar2 = (float)(dVar4 * dVar5 - (double)(float)(dVar3 * dVar6));
  fVar1 = fVar2 + (float)(param_1 * (double)(float)(dVar6 - dVar5) +
                         (double)(float)(param_3 * (double)(float)(dVar3 - dVar4)));
  if (((fVar1 <= lbl_803E12B8) && (lbl_803E12B8 <= fVar2)) ||
     ((lbl_803E12B8 <= fVar1 && (fVar2 < lbl_803E12B8)))) {
    fVar2 = (float)(-param_3 * dVar3 + (double)(float)(param_1 * dVar5));
    fVar1 = (float)(-param_3 * dVar4 + (double)(float)(param_1 * dVar6));
    if (((fVar2 <= lbl_803E12B8) && (lbl_803E12B8 <= fVar1)) ||
       ((lbl_803E12B8 <= fVar2 && (fVar1 < lbl_803E12B8)))) {
      return 1;
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800e1c00
 * EN v1.0 Address: 0x800E1C00
 * EN v1.0 Size: 748b
 * EN v1.1 Address: 0x800E2278
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e1c00(undefined8 param_1,double param_2,double param_3)
{
  float fVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  float *pfVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  int iVar11;
  uint uVar12;
  double extraout_f1;
  double dVar13;
  double dVar14;
  longlong lVar15;
  
  lVar15 = FUN_8028683c();
  uVar4 = (uint)((ulonglong)lVar15 >> 0x20);
  pfVar5 = (float *)lVar15;
  if (lVar15 < 0) {
    iVar9 = 0;
  }
  else {
    iVar7 = DAT_803de0f0 + -1;
    iVar11 = 0;
    while (iVar11 <= iVar7) {
      iVar8 = iVar7 + iVar11 >> 1;
      iVar9 = (&DAT_803a2448)[iVar8];
      if (*(uint *)(iVar9 + 0x14) < uVar4) {
        iVar11 = iVar8 + 1;
      }
      else {
        if (*(uint *)(iVar9 + 0x14) <= uVar4) goto LAB_800e2324;
        iVar7 = iVar8 + -1;
      }
    }
    iVar9 = 0;
  }
LAB_800e2324:
  *pfVar5 = lbl_803E12DC;
  uVar10 = uVar4;
  dVar14 = extraout_f1;
  do {
    uVar12 = 0xffffffff;
    iVar7 = 0;
    iVar11 = iVar9;
    while ((iVar7 < 4 && (uVar12 == 0xffffffff))) {
      if (((int)*(char *)(iVar9 + 0x1b) & 1 << iVar7) == 0) {
        uVar12 = *(uint *)(iVar11 + 0x1c);
      }
      iVar11 = iVar11 + 4;
      iVar7 = iVar7 + 1;
    }
    iVar11 = iVar9;
    if (uVar12 != 0xffffffff) {
      if ((int)uVar12 < 0) {
        iVar11 = 0;
      }
      else {
        iVar8 = DAT_803de0f0 + -1;
        iVar7 = 0;
        while (iVar7 <= iVar8) {
          iVar6 = iVar8 + iVar7 >> 1;
          iVar11 = (&DAT_803a2448)[iVar6];
          if (*(uint *)(iVar11 + 0x14) < uVar12) {
            iVar7 = iVar6 + 1;
          }
          else {
            if (*(uint *)(iVar11 + 0x14) <= uVar12) goto LAB_800e23ec;
            iVar8 = iVar6 + -1;
          }
        }
        iVar11 = 0;
      }
LAB_800e23ec:
      iVar7 = FUN_800e1b2c(dVar14,param_2,param_3,iVar9,iVar11);
      uVar10 = uVar12;
      if ((iVar7 != 0) &&
         (fVar1 = (float)((double)*(float *)(iVar9 + 8) - dVar14),
         fVar2 = (float)((double)*(float *)(iVar9 + 0xc) - param_2),
         fVar3 = (float)((double)*(float *)(iVar9 + 0x10) - param_3),
         dVar13 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2)),
         dVar13 < (double)*pfVar5)) {
        *pfVar5 = (float)dVar13;
      }
    }
    if ((uVar10 == uVar4) || (iVar9 = iVar11, uVar12 == 0xffffffff)) {
      FUN_80286888();
      return;
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: curves_distanceToNearestOfType16
 * EN v1.0 Address: 0x800E1EEC
 * EN v1.0 Size: 420b
 * EN v1.1 Address: 0x800E2498
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int curves_distanceToNearestOfType16(double param_1,double param_2,double param_3,int param_4)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  int local_78;
  undefined4 uStack_74;
  undefined8 local_70;
  
  piVar4 = (int *)FUN_80017b00(&uStack_74,&local_78);
  dVar9 = (double)lbl_803E12B0;
  dVar10 = (double)lbl_803E12B8;
  for (iVar7 = 0; iVar7 < local_78; iVar7 = iVar7 + 1) {
    iVar5 = *piVar4;
    if ((((*(short *)(iVar5 + 0x44) == 0x2c) && (*(char *)(iVar5 + 0xac) != param_4)) &&
        (iVar6 = *(int *)(iVar5 + 0x4c), iVar6 != 0)) &&
       ((*(char *)(iVar6 + 0x19) == '\x16' &&
        ((fVar1 = (float)((double)*(float *)(iVar5 + 0x18) - param_1),
         fVar2 = (float)((double)*(float *)(iVar5 + 0x1c) - param_2),
         fVar3 = (float)((double)*(float *)(iVar5 + 0x20) - param_3),
         dVar8 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2)),
         (double)lbl_803E12B0 == dVar9 || (dVar8 < dVar10)))))) {
      local_70 = (double)CONCAT44(0x43300000,*(undefined4 *)(iVar6 + 0x14));
      dVar9 = (double)(float)(local_70 - DOUBLE_803e12a8);
      dVar10 = dVar8;
    }
    piVar4 = piVar4 + 1;
  }
  return (int)dVar9;
}

/*
 * --INFO--
 *
 * Function: FUN_800e2090
 * EN v1.0 Address: 0x800E2090
 * EN v1.0 Size: 1280b
 * EN v1.1 Address: 0x800E260C
 * EN v1.1 Size: 1416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e2090(undefined4 param_1,undefined4 param_2,uint param_3,int *param_4)
{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  float *pfVar7;
  uint uVar8;
  char *pcVar9;
  undefined *puVar10;
  undefined4 *puVar11;
  int iVar12;
  undefined4 *puVar13;
  float *pfVar14;
  int iVar15;
  int iVar16;
  int iVar17;
  undefined4 *puVar18;
  float *pfVar19;
  int iVar20;
  int iVar21;
  undefined4 *puVar22;
  float *pfVar23;
  int iVar24;
  int iVar25;
  uint uVar26;
  double in_f31;
  double dVar27;
  double in_ps31_1;
  undefined8 uVar28;
  char local_6e4 [4];
  int local_6e0;
  int local_6dc;
  float local_6d8 [4];
  undefined4 local_6c8 [4];
  float local_6b8 [40];
  int local_618 [40];
  char local_578 [48];
  undefined local_548 [1344];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar28 = FUN_8028680c();
  iVar5 = RomCurve_getById((uint)((ulonglong)uVar28 >> 0x20),&local_6e0);
  if (iVar5 != 0) {
    iVar16 = 0;
    iVar17 = 0;
    pfVar14 = local_6d8;
    puVar18 = local_6c8;
    pfVar19 = pfVar14;
    iVar20 = iVar5;
    do {
      if (-1 < *(int *)(iVar20 + 0x1c)) {
        pcVar9 = local_578;
        iVar25 = 0x1b;
        iVar12 = 0;
        do {
          iVar24 = iVar12;
          *pcVar9 = '\0';
          pcVar9[1] = '\0';
          pcVar9[2] = '\0';
          pcVar9[3] = '\0';
          pcVar9[4] = '\0';
          pcVar9[5] = '\0';
          pcVar9[6] = '\0';
          pcVar9[7] = '\0';
          pcVar9[8] = '\0';
          pcVar9[9] = '\0';
          pcVar9[10] = '\0';
          pcVar9[0xb] = '\0';
          pcVar9[0xc] = '\0';
          pcVar9[0xd] = '\0';
          pcVar9[0xe] = '\0';
          pcVar9[0xf] = '\0';
          pcVar9[0x10] = '\0';
          pcVar9[0x11] = '\0';
          pcVar9[0x12] = '\0';
          pcVar9[0x13] = '\0';
          pcVar9[0x14] = '\0';
          pcVar9[0x15] = '\0';
          pcVar9[0x16] = '\0';
          pcVar9[0x17] = '\0';
          pcVar9[0x18] = '\0';
          pcVar9[0x19] = '\0';
          pcVar9[0x1a] = '\0';
          pcVar9[0x1b] = '\0';
          pcVar9[0x1c] = '\0';
          pcVar9[0x1d] = '\0';
          pcVar9[0x1e] = '\0';
          pcVar9[0x1f] = '\0';
          pcVar9[0x20] = '\0';
          pcVar9[0x21] = '\0';
          pcVar9[0x22] = '\0';
          pcVar9[0x23] = '\0';
          pcVar9[0x24] = '\0';
          pcVar9[0x25] = '\0';
          pcVar9[0x26] = '\0';
          pcVar9[0x27] = '\0';
          pcVar9[0x28] = '\0';
          pcVar9[0x29] = '\0';
          pcVar9[0x2a] = '\0';
          pcVar9[0x2b] = '\0';
          pcVar9[0x2c] = '\0';
          pcVar9[0x2d] = '\0';
          pcVar9[0x2e] = '\0';
          pcVar9[0x2f] = '\0';
          pcVar9 = pcVar9 + 0x30;
          iVar12 = iVar24 + 0x30;
          iVar25 = iVar25 + -1;
        } while (iVar25 != 0);
        puVar10 = local_548 + iVar24;
        iVar25 = 0x514 - iVar12;
        if (iVar12 < 0x514) {
          do {
            *puVar10 = 0;
            puVar10 = puVar10 + 1;
            iVar25 = iVar25 + -1;
          } while (iVar25 != 0);
        }
        local_578[local_6e0] = '\x01';
        iVar12 = RomCurve_getById(*(uint *)(iVar20 + 0x1c),&local_6dc);
        if (iVar12 != 0) {
          fVar1 = *(float *)(iVar12 + 0x10) - *(float *)(iVar5 + 0x10);
          fVar2 = *(float *)(iVar12 + 8) - *(float *)(iVar5 + 8);
          fVar3 = *(float *)(iVar12 + 0xc) - *(float *)(iVar5 + 0xc);
          local_6b8[0] = fVar1 * fVar1 + fVar2 * fVar2 + fVar3 * fVar3;
          iVar12 = 1;
          local_618[0] = local_6dc;
          local_578[local_6dc] = '\x01';
          bVar4 = false;
          puVar22 = puVar18;
          pfVar23 = pfVar19;
          do {
            if (iVar12 < 1) {
              bVar4 = true;
            }
            else {
              iVar12 = iVar12 + -1;
              local_6dc = local_618[iVar12];
              iVar25 = (&DAT_803a2448)[local_618[iVar12]];
              dVar27 = (double)local_6b8[iVar12];
              if ((((int)*(char *)(iVar25 + 0x19) == (int)uVar28) || ((int)uVar28 == -1)) &&
                 ((*(byte *)(iVar25 + 0x31) == param_3 ||
                  ((*(byte *)(iVar25 + 0x32) == param_3 || (*(byte *)(iVar25 + 0x33) == param_3)))))
                 ) {
                bVar4 = true;
                *pfVar23 = local_6b8[iVar12];
                if (iVar16 < 4) {
                  *puVar22 = *(undefined4 *)(iVar25 + 0x14);
                  pfVar19 = pfVar19 + 1;
                  puVar18 = puVar18 + 1;
                  pfVar23 = pfVar23 + 1;
                  puVar22 = puVar22 + 1;
                  local_6e4[iVar16] = (char)iVar17;
                  iVar16 = iVar16 + 1;
                }
              }
              else {
                iVar15 = 0;
                iVar24 = iVar12 * 4;
                iVar21 = iVar25;
                do {
                  if ((((-1 < (int)*(uint *)(iVar21 + 0x1c)) &&
                       (iVar6 = RomCurve_getById(*(uint *)(iVar21 + 0x1c),&local_6dc), iVar6 != 0)) &&
                      (local_578[local_6dc] == '\0')) && (iVar12 < 0x28)) {
                    fVar1 = *(float *)(iVar25 + 0x10) - *(float *)(iVar6 + 0x10);
                    fVar2 = *(float *)(iVar25 + 8) - *(float *)(iVar6 + 8);
                    fVar3 = *(float *)(iVar25 + 0xc) - *(float *)(iVar6 + 0xc);
                    fVar1 = fVar1 * fVar1 +
                            (float)(dVar27 + (double)(fVar2 * fVar2)) + fVar3 * fVar3;
                    iVar6 = 0;
                    for (pfVar7 = local_6b8; (iVar6 < iVar12 && (fVar1 < *pfVar7));
                        pfVar7 = pfVar7 + 1) {
                      iVar6 = iVar6 + 1;
                    }
                    puVar11 = (undefined4 *)((int)local_618 + iVar24);
                    puVar13 = (undefined4 *)((int)local_6b8 + iVar24);
                    uVar8 = iVar12 - iVar6;
                    if (iVar6 < iVar12) {
                      uVar26 = uVar8 >> 3;
                      if (uVar26 != 0) {
                        do {
                          *puVar11 = puVar11[-1];
                          *puVar13 = puVar13[-1];
                          puVar11[-1] = puVar11[-2];
                          puVar13[-1] = puVar13[-2];
                          puVar11[-2] = puVar11[-3];
                          puVar13[-2] = puVar13[-3];
                          puVar11[-3] = puVar11[-4];
                          puVar13[-3] = puVar13[-4];
                          puVar11[-4] = puVar11[-5];
                          puVar13[-4] = puVar13[-5];
                          puVar11[-5] = puVar11[-6];
                          puVar13[-5] = puVar13[-6];
                          puVar11[-6] = puVar11[-7];
                          puVar13[-6] = puVar13[-7];
                          puVar11[-7] = puVar11[-8];
                          puVar13[-7] = puVar13[-8];
                          puVar11 = puVar11 + -8;
                          puVar13 = puVar13 + -8;
                          uVar26 = uVar26 - 1;
                        } while (uVar26 != 0);
                        uVar8 = uVar8 & 7;
                        if (uVar8 == 0) goto LAB_800e2a50;
                      }
                      do {
                        *puVar11 = puVar11[-1];
                        *puVar13 = puVar13[-1];
                        puVar11 = puVar11 + -1;
                        puVar13 = puVar13 + -1;
                        uVar8 = uVar8 - 1;
                      } while (uVar8 != 0);
                    }
LAB_800e2a50:
                    iVar12 = iVar12 + 1;
                    iVar24 = iVar24 + 4;
                    local_6b8[iVar6] = fVar1;
                    local_618[iVar6] = local_6dc;
                    local_578[local_6dc] = '\x01';
                  }
                  iVar21 = iVar21 + 4;
                  iVar15 = iVar15 + 1;
                } while (iVar15 < 4);
              }
            }
          } while (!bVar4);
        }
      }
      iVar20 = iVar20 + 4;
      iVar17 = iVar17 + 1;
    } while (iVar17 < 4);
    if (0 < iVar16) {
      iVar5 = 0;
      iVar20 = 0;
      if (0 < iVar16) {
        do {
          if (*pfVar14 < local_6d8[iVar5]) {
            iVar5 = iVar20;
          }
          pfVar14 = pfVar14 + 1;
          iVar20 = iVar20 + 1;
          iVar16 = iVar16 + -1;
        } while (iVar16 != 0);
      }
      if (param_4 != (int *)0x0) {
        *param_4 = (int)local_6e4[iVar5];
      }
    }
  }
  FUN_80286858();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e2590
 * EN v1.0 Address: 0x800E2590
 * EN v1.0 Size: 1528b
 * EN v1.1 Address: 0x800E2B94
 * EN v1.1 Size: 1612b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e2590(undefined4 param_1,undefined4 param_2,int param_3,int *param_4)
{
  float fVar1;
  float fVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  int iVar6;
  float *pfVar7;
  char *pcVar8;
  undefined *puVar9;
  undefined4 *puVar10;
  uint uVar11;
  uint uVar12;
  int iVar13;
  undefined4 *puVar14;
  int iVar15;
  int *piVar16;
  int iVar17;
  int iVar18;
  float *pfVar19;
  float *pfVar20;
  int iVar21;
  int iVar22;
  float *pfVar23;
  int iVar24;
  int iVar25;
  uint uVar26;
  double in_f31;
  double dVar27;
  double in_ps31_1;
  undefined8 uVar28;
  int local_6d8;
  int local_6d4;
  float local_6d0 [4];
  int local_6c0 [4];
  float local_6b0 [40];
  int local_610 [40];
  char local_570 [48];
  undefined local_540 [1336];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar28 = FUN_80286810();
  iVar15 = (int)((ulonglong)uVar28 >> 0x20);
  if ((iVar15 != 0) && (iVar5 = RomCurve_getById(*(uint *)(iVar15 + 0x14),&local_6d8), iVar5 != 0)) {
    iVar5 = 0;
    iVar18 = 0;
    pfVar19 = local_6d0;
    pfVar20 = pfVar19;
    iVar21 = iVar15;
    do {
      if (-1 < *(int *)(iVar21 + 0x1c)) {
        pcVar8 = local_570;
        iVar25 = 0x1b;
        iVar13 = 0;
        do {
          iVar24 = iVar13;
          *pcVar8 = '\0';
          pcVar8[1] = '\0';
          pcVar8[2] = '\0';
          pcVar8[3] = '\0';
          pcVar8[4] = '\0';
          pcVar8[5] = '\0';
          pcVar8[6] = '\0';
          pcVar8[7] = '\0';
          pcVar8[8] = '\0';
          pcVar8[9] = '\0';
          pcVar8[10] = '\0';
          pcVar8[0xb] = '\0';
          pcVar8[0xc] = '\0';
          pcVar8[0xd] = '\0';
          pcVar8[0xe] = '\0';
          pcVar8[0xf] = '\0';
          pcVar8[0x10] = '\0';
          pcVar8[0x11] = '\0';
          pcVar8[0x12] = '\0';
          pcVar8[0x13] = '\0';
          pcVar8[0x14] = '\0';
          pcVar8[0x15] = '\0';
          pcVar8[0x16] = '\0';
          pcVar8[0x17] = '\0';
          pcVar8[0x18] = '\0';
          pcVar8[0x19] = '\0';
          pcVar8[0x1a] = '\0';
          pcVar8[0x1b] = '\0';
          pcVar8[0x1c] = '\0';
          pcVar8[0x1d] = '\0';
          pcVar8[0x1e] = '\0';
          pcVar8[0x1f] = '\0';
          pcVar8[0x20] = '\0';
          pcVar8[0x21] = '\0';
          pcVar8[0x22] = '\0';
          pcVar8[0x23] = '\0';
          pcVar8[0x24] = '\0';
          pcVar8[0x25] = '\0';
          pcVar8[0x26] = '\0';
          pcVar8[0x27] = '\0';
          pcVar8[0x28] = '\0';
          pcVar8[0x29] = '\0';
          pcVar8[0x2a] = '\0';
          pcVar8[0x2b] = '\0';
          pcVar8[0x2c] = '\0';
          pcVar8[0x2d] = '\0';
          pcVar8[0x2e] = '\0';
          pcVar8[0x2f] = '\0';
          pcVar8 = pcVar8 + 0x30;
          iVar13 = iVar24 + 0x30;
          iVar25 = iVar25 + -1;
        } while (iVar25 != 0);
        puVar9 = local_540 + iVar24;
        iVar25 = 0x514 - iVar13;
        if (iVar13 < 0x514) {
          do {
            *puVar9 = 0;
            puVar9 = puVar9 + 1;
            iVar25 = iVar25 + -1;
          } while (iVar25 != 0);
        }
        local_570[local_6d8] = '\x01';
        iVar13 = RomCurve_getById(*(uint *)(iVar21 + 0x1c),&local_6d4);
        if (iVar13 != 0) {
          fVar1 = *(float *)(iVar13 + 0x10) - *(float *)(iVar15 + 0x10);
          fVar2 = *(float *)(iVar13 + 8) - *(float *)(iVar15 + 8);
          fVar3 = *(float *)(iVar13 + 0xc) - *(float *)(iVar15 + 0xc);
          local_6b0[0] = fVar1 * fVar1 + fVar2 * fVar2 + fVar3 * fVar3;
          iVar13 = 1;
          local_610[0] = local_6d4;
          local_570[local_6d4] = '\x01';
          bVar4 = false;
          pfVar23 = pfVar20;
          do {
            if (iVar13 < 1) {
              bVar4 = true;
            }
            else {
              iVar13 = iVar13 + -1;
              local_6d4 = local_610[iVar13];
              iVar25 = (&DAT_803a2448)[local_610[iVar13]];
              dVar27 = (double)local_6b0[iVar13];
              if (((int)*(char *)(iVar25 + 0x19) == (int)uVar28) &&
                 ((param_3 == -1 || (param_3 == *(char *)(iVar25 + 0x18))))) {
                bVar4 = true;
                *pfVar23 = local_6b0[iVar13];
                pfVar20 = pfVar20 + 1;
                pfVar23 = pfVar23 + 1;
                local_6b0[iVar5 + -4] = *(float *)(iVar21 + 0x1c);
                iVar5 = iVar5 + 1;
              }
              else {
                iVar17 = 0;
                iVar24 = iVar13 * 4;
                iVar22 = iVar25;
                do {
                  if ((((-1 < (int)*(uint *)(iVar22 + 0x1c)) &&
                       (iVar6 = RomCurve_getById(*(uint *)(iVar22 + 0x1c),&local_6d4), iVar6 != 0)) &&
                      (local_570[local_6d4] == '\0')) && (iVar13 < 0x28)) {
                    fVar1 = *(float *)(iVar25 + 0x10) - *(float *)(iVar6 + 0x10);
                    fVar2 = *(float *)(iVar25 + 8) - *(float *)(iVar6 + 8);
                    fVar3 = *(float *)(iVar25 + 0xc) - *(float *)(iVar6 + 0xc);
                    fVar1 = fVar1 * fVar1 +
                            (float)(dVar27 + (double)(fVar2 * fVar2)) + fVar3 * fVar3;
                    iVar6 = 0;
                    for (pfVar7 = local_6b0; (iVar6 < iVar13 && (fVar1 < *pfVar7));
                        pfVar7 = pfVar7 + 1) {
                      iVar6 = iVar6 + 1;
                    }
                    puVar10 = (undefined4 *)((int)local_610 + iVar24);
                    puVar14 = (undefined4 *)((int)local_6b0 + iVar24);
                    uVar11 = iVar13 - iVar6;
                    if (iVar6 < iVar13) {
                      uVar26 = uVar11 >> 3;
                      if (uVar26 != 0) {
                        do {
                          *puVar10 = puVar10[-1];
                          *puVar14 = puVar14[-1];
                          puVar10[-1] = puVar10[-2];
                          puVar14[-1] = puVar14[-2];
                          puVar10[-2] = puVar10[-3];
                          puVar14[-2] = puVar14[-3];
                          puVar10[-3] = puVar10[-4];
                          puVar14[-3] = puVar14[-4];
                          puVar10[-4] = puVar10[-5];
                          puVar14[-4] = puVar14[-5];
                          puVar10[-5] = puVar10[-6];
                          puVar14[-5] = puVar14[-6];
                          puVar10[-6] = puVar10[-7];
                          puVar14[-6] = puVar14[-7];
                          puVar10[-7] = puVar10[-8];
                          puVar14[-7] = puVar14[-8];
                          puVar10 = puVar10 + -8;
                          puVar14 = puVar14 + -8;
                          uVar26 = uVar26 - 1;
                        } while (uVar26 != 0);
                        uVar11 = uVar11 & 7;
                        if (uVar11 == 0) goto LAB_800e2fbc;
                      }
                      do {
                        *puVar10 = puVar10[-1];
                        *puVar14 = puVar14[-1];
                        puVar10 = puVar10 + -1;
                        puVar14 = puVar14 + -1;
                        uVar11 = uVar11 - 1;
                      } while (uVar11 != 0);
                    }
LAB_800e2fbc:
                    iVar13 = iVar13 + 1;
                    iVar24 = iVar24 + 4;
                    local_6b0[iVar6] = fVar1;
                    local_610[iVar6] = local_6d4;
                    local_570[local_6d4] = '\x01';
                  }
                  iVar22 = iVar22 + 4;
                  iVar17 = iVar17 + 1;
                } while (iVar17 < 4);
              }
            }
          } while (!bVar4);
        }
      }
      iVar21 = iVar21 + 4;
      iVar18 = iVar18 + 1;
    } while (iVar18 < 4);
    if (iVar5 != 0) {
      if (iVar5 == 1) {
        *param_4 = *(int *)(iVar15 + 0x14);
      }
      else if (1 < iVar5) {
        iVar21 = 0;
        for (iVar18 = 0; iVar18 < iVar5; iVar18 = iVar18 + 1) {
          piVar16 = (int *)((int)local_6c0 + iVar21);
          if (*param_4 == *piVar16) {
            puVar10 = (undefined4 *)((int)local_6d0 + iVar21);
            uVar11 = (iVar5 + -1) - iVar18;
            if (iVar18 < iVar5 + -1) {
              uVar26 = uVar11 >> 3;
              uVar12 = uVar11;
              if (uVar26 == 0) goto LAB_800e3130;
              do {
                *piVar16 = piVar16[1];
                *puVar10 = puVar10[1];
                piVar16[1] = piVar16[2];
                puVar10[1] = puVar10[2];
                piVar16[2] = piVar16[3];
                puVar10[2] = puVar10[3];
                piVar16[3] = piVar16[4];
                puVar10[3] = puVar10[4];
                piVar16[4] = piVar16[5];
                puVar10[4] = puVar10[5];
                piVar16[5] = piVar16[6];
                puVar10[5] = puVar10[6];
                piVar16[6] = piVar16[7];
                puVar10[6] = puVar10[7];
                piVar16[7] = piVar16[8];
                puVar10[7] = puVar10[8];
                piVar16 = piVar16 + 8;
                puVar10 = puVar10 + 8;
                iVar21 = iVar21 + 0x20;
                uVar26 = uVar26 - 1;
              } while (uVar26 != 0);
              for (uVar12 = uVar11 & 7; uVar12 != 0; uVar12 = uVar12 - 1) {
LAB_800e3130:
                *piVar16 = piVar16[1];
                *puVar10 = puVar10[1];
                piVar16 = piVar16 + 1;
                puVar10 = puVar10 + 1;
                iVar21 = iVar21 + 4;
              }
              iVar18 = iVar18 + uVar11;
            }
            iVar5 = iVar5 + -1;
          }
          iVar21 = iVar21 + 4;
        }
        *param_4 = *(int *)(iVar15 + 0x14);
        iVar15 = 0;
        iVar21 = 0;
        if (0 < iVar5) {
          do {
            if (*pfVar19 < local_6d0[iVar15]) {
              iVar15 = iVar21;
            }
            pfVar19 = pfVar19 + 1;
            iVar21 = iVar21 + 1;
            iVar5 = iVar5 + -1;
          } while (iVar5 != 0);
        }
      }
    }
  }
  FUN_8028685c();
  return;
}

/*
 * --INFO--
 *
 * Function: RomCurve_getRandomLinkedOfTypes
 * EN v1.0 Address: 0x800E2B88
 * EN v1.0 Size: 588b
 * EN v1.1 Address: 0x800E31E0
 * EN v1.1 Size: 980b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int RomCurve_getRandomLinkedOfTypes(int param_1,int param_2,int param_3,int *param_4)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  uint uVar11;
  int local_28 [7];
  
  if (param_1 == 0) {
    local_28[0] = -1;
  }
  else {
    iVar2 = 0;
    iVar10 = 4;
    iVar7 = param_1;
    do {
      uVar9 = *(uint *)(iVar7 + 0x1c);
      if (-1 < (int)uVar9) {
        if ((int)uVar9 < 0) {
          iVar8 = 0;
        }
        else {
          iVar3 = 0;
          iVar6 = DAT_803de0f0 + -1;
          while (iVar3 <= iVar6) {
            iVar4 = iVar6 + iVar3 >> 1;
            iVar8 = (&DAT_803a2448)[iVar4];
            if (*(uint *)(iVar8 + 0x14) < uVar9) {
              iVar3 = iVar4 + 1;
            }
            else {
              if (*(uint *)(iVar8 + 0x14) <= uVar9) goto LAB_800e3290;
              iVar6 = iVar4 + -1;
            }
          }
          iVar8 = 0;
        }
LAB_800e3290:
        for (iVar6 = 0; iVar6 < param_3; iVar6 = iVar6 + 1) {
          iVar3 = iVar2;
          if ((int)*(char *)(iVar8 + 0x19) == *(int *)(param_2 + iVar6 * 4)) {
            iVar3 = iVar2 + 1;
            local_28[iVar2] = *(int *)(iVar7 + 0x1c);
            iVar6 = param_3;
          }
          iVar2 = iVar3;
        }
      }
      iVar7 = iVar7 + 4;
      iVar10 = iVar10 + -1;
    } while (iVar10 != 0);
    if (iVar2 == 0) {
      local_28[0] = -1;
    }
    else if (iVar2 == 1) {
      *param_4 = *(int *)(param_1 + 0x14);
    }
    else if (iVar2 < 2) {
      local_28[0] = -1;
    }
    else {
      iVar7 = 0;
      for (iVar10 = 0; iVar10 < iVar2; iVar10 = iVar10 + 1) {
        piVar5 = (int *)((int)local_28 + iVar7);
        if (*param_4 == *piVar5) {
          uVar9 = (iVar2 + -1) - iVar10;
          if (iVar10 < iVar2 + -1) {
            uVar11 = uVar9 >> 3;
            uVar1 = uVar9;
            if (uVar11 == 0) goto LAB_800e33ac;
            do {
              *piVar5 = piVar5[1];
              piVar5[1] = piVar5[2];
              piVar5[2] = piVar5[3];
              piVar5[3] = piVar5[4];
              piVar5[4] = piVar5[5];
              piVar5[5] = piVar5[6];
              piVar5[6] = piVar5[7];
              piVar5[7] = piVar5[8];
              piVar5 = piVar5 + 8;
              iVar7 = iVar7 + 0x20;
              uVar11 = uVar11 - 1;
            } while (uVar11 != 0);
            for (uVar1 = uVar9 & 7; uVar1 != 0; uVar1 = uVar1 - 1) {
LAB_800e33ac:
              *piVar5 = piVar5[1];
              piVar5 = piVar5 + 1;
              iVar7 = iVar7 + 4;
            }
            iVar10 = iVar10 + uVar9;
          }
          iVar2 = iVar2 + -1;
        }
        iVar7 = iVar7 + 4;
      }
      *param_4 = *(int *)(param_1 + 0x14);
      uVar9 = FUN_80017760(0,iVar2 - 1);
      local_28[0] = local_28[uVar9];
    }
  }
  return local_28[0];
}

/*
 * --INFO--
 *
 * Function: curves_distXZ
 * EN v1.0 Address: 0x800E2DD4
 * EN v1.0 Size: 172b
 * EN v1.1 Address: 0x800E35B4
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
double curves_distXZ(double param_1,double param_2,uint param_3)
{
  float fVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  double dVar7;

  if ((int)param_3 < 0) {
    iVar6 = 0;
  }
  else {
    iVar5 = DAT_803de0f0 + -1;
    iVar4 = 0;
    while (iVar4 <= iVar5) {
      iVar3 = iVar5 + iVar4 >> 1;
      iVar6 = (&DAT_803a2448)[iVar3];
      if (*(uint *)(iVar6 + 0x14) < param_3) {
        iVar4 = iVar3 + 1;
      }
      else {
        if (*(uint *)(iVar6 + 0x14) <= param_3) goto LAB_800e3628;
        iVar5 = iVar3 + -1;
      }
    }
    iVar6 = 0;
  }
LAB_800e3628:
  if (iVar6 == 0) {
    dVar7 = (double)lbl_803E12B0;
  }
  else {
    fVar1 = (float)((double)*(float *)(iVar6 + 8) - param_1);
    fVar2 = (float)((double)*(float *)(iVar6 + 0x10) - param_2);
    dVar7 = FUN_80293900((double)(fVar1 * fVar1 + fVar2 * fVar2));
  }
  return dVar7;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: RomCurve_distanceToObject
 * EN v1.0 Address: 0x800E2E80
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x800E3664
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
double RomCurve_distanceToObject(int param_1,uint param_2)
{
  float fVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  double dVar8;

  if ((int)param_2 < 0) {
    iVar7 = 0;
  }
  else {
    iVar6 = DAT_803de0f0 + -1;
    iVar5 = 0;
    while (iVar5 <= iVar6) {
      iVar4 = iVar6 + iVar5 >> 1;
      iVar7 = (&DAT_803a2448)[iVar4];
      if (*(uint *)(iVar7 + 0x14) < param_2) {
        iVar5 = iVar4 + 1;
      }
      else {
        if (*(uint *)(iVar7 + 0x14) <= param_2) goto LAB_800e36d8;
        iVar6 = iVar4 + -1;
      }
    }
    iVar7 = 0;
  }
LAB_800e36d8:
  if ((iVar7 == 0) || (param_1 == 0)) {
    dVar8 = (double)lbl_803E12B0;
  }
  else {
    fVar1 = *(float *)(iVar7 + 8) - *(float *)(param_1 + 0xc);
    fVar2 = *(float *)(iVar7 + 0xc) - *(float *)(param_1 + 0x10);
    fVar3 = *(float *)(iVar7 + 0x10) - *(float *)(param_1 + 0x14);
    dVar8 = FUN_80293900((double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2));
  }
  return dVar8;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: curves_find
 * EN v1.0 Address: 0x800E2F44
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x800E3734
 * EN v1.1 Size: 584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void curves_find(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 *param_6,undefined4 *param_7,undefined4 *param_8)
{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int *piVar10;
  int iVar11;
  double dVar12;
  double extraout_f1;
  double dVar13;
  double dVar14;
  double in_f28;
  double dVar15;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar16;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar17;
  float local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  float local_80;
  float local_7c;
  float local_78;
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
  uVar17 = FUN_80286828();
  fVar1 = lbl_803E12B8;
  *param_8 = lbl_803E12B8;
  *param_7 = fVar1;
  *param_6 = fVar1;
  dVar16 = (double)lbl_803E12C4;
  iVar8 = 0;
  piVar10 = &DAT_803a2448;
  dVar15 = extraout_f1;
  do {
    if (DAT_803de0f0 <= iVar8) {
      FUN_80286874();
      return;
    }
    iVar9 = *piVar10;
    if (((int)*(char *)(iVar9 + 0x18) == (int)uVar17) &&
       ((int)*(char *)(iVar9 + 0x19) == (int)((ulonglong)uVar17 >> 0x20))) {
      local_98 = *(float *)(iVar9 + 8);
      local_94 = *(undefined4 *)(iVar9 + 0xc);
      local_90 = *(undefined4 *)(iVar9 + 0x10);
      iVar7 = 0;
      iVar11 = iVar9;
      do {
        if (((int)*(char *)(iVar9 + 0x1b) & 1 << iVar7) == 0) {
          uVar5 = *(uint *)(iVar11 + 0x1c);
          if ((int)uVar5 < 0) {
            iVar6 = 0;
          }
          else {
            iVar4 = DAT_803de0f0 + -1;
            iVar3 = 0;
            while (iVar3 <= iVar4) {
              iVar2 = iVar4 + iVar3 >> 1;
              iVar6 = (&DAT_803a2448)[iVar2];
              if (*(uint *)(iVar6 + 0x14) < uVar5) {
                iVar3 = iVar2 + 1;
              }
              else {
                if (*(uint *)(iVar6 + 0x14) <= uVar5) goto LAB_800e3878;
                iVar4 = iVar2 + -1;
              }
            }
            iVar6 = 0;
          }
LAB_800e3878:
          if (iVar6 != 0) {
            local_8c = *(undefined4 *)(iVar6 + 8);
            local_88 = *(undefined4 *)(iVar6 + 0xc);
            local_84 = *(undefined4 *)(iVar6 + 0x10);
            dVar13 = RomCurve_distanceToSegment(dVar15,param_2,param_3,&local_98);
            dVar14 = dVar16;
            if (dVar16 < (double)lbl_803E12B8) {
              dVar14 = -dVar16;
            }
            dVar12 = dVar13;
            if (dVar13 < (double)lbl_803E12B8) {
              dVar12 = -dVar13;
            }
            if (dVar12 < dVar14) {
              DAT_803de0e8 = iVar6;
              DAT_803de0ec = iVar9;
              *param_6 = local_80;
              *param_7 = local_7c;
              *param_8 = local_78;
              dVar16 = dVar13;
            }
          }
        }
        iVar11 = iVar11 + 4;
        iVar7 = iVar7 + 1;
      } while (iVar7 < 4);
    }
    piVar10 = piVar10 + 1;
    iVar8 = iVar8 + 1;
  } while( true );
}

/*
 * --INFO--
 *
 * Function: RomCurve_getById
 * EN v1.0 Address: 0x800E315C
 * EN v1.0 Size: 128b
 * EN v1.1 Address: 0x800E397C
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 RomCurve_getById(uint curveId,int *outIndex)
{
  int high;
  int low;
  int mid;
  int curve;

  *outIndex = -1;
  if ((int)curveId < 0) {
    return 0;
  }
  high = DAT_803de0f0 + -1;
  low = 0;
  while (low <= high) {
    mid = high + low >> 1;
    curve = (&DAT_803a2448)[mid];
    if (curveId > *(uint *)(curve + 0x14)) {
      low = mid + 1;
    }
    else if (curveId < *(uint *)(curve + 0x14)) {
      high = mid + -1;
    }
    else {
      *outIndex = mid;
      return curve;
    }
  }
  *outIndex = -1;
  return 0;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800e31dc
 * EN v1.0 Address: 0x800E31DC
 * EN v1.0 Size: 2296b
 * EN v1.1 Address: 0x800E3A00
 * EN v1.1 Size: 2996b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e31dc(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5)
{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  double dVar11;
  undefined8 uVar12;
  uint local_a8 [4];
  uint local_98 [4];
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  
  uVar12 = FUN_8028682c();
  iVar3 = (int)((ulonglong)uVar12 >> 0x20);
  iVar2 = (int)uVar12;
  bVar1 = false;
  if ((*(int *)(iVar3 + 0x1c) == -1) || ((*(byte *)(iVar3 + 0x1b) & 1) != 0)) {
    if ((*(int *)(iVar3 + 0x20) == -1) || ((*(byte *)(iVar3 + 0x1b) & 2) != 0)) {
      if ((*(int *)(iVar3 + 0x24) == -1) || ((*(byte *)(iVar3 + 0x1b) & 4) != 0)) {
        if ((*(int *)(iVar3 + 0x28) == -1) || ((*(byte *)(iVar3 + 0x1b) & 8) != 0)) {
          bVar1 = true;
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
    }
    else {
      bVar1 = false;
    }
  }
  iVar10 = 0;
  iVar9 = 0;
  iVar8 = 0;
  if (bVar1) {
    while (iVar8 = iVar3, iVar8 != 0) {
      bVar1 = false;
      if ((*(int *)(iVar8 + 0x1c) == -1) || ((*(byte *)(iVar8 + 0x1b) & 1) == 0)) {
        if ((*(int *)(iVar8 + 0x20) == -1) || ((*(byte *)(iVar8 + 0x1b) & 2) == 0)) {
          if ((*(int *)(iVar8 + 0x24) == -1) || ((*(byte *)(iVar8 + 0x1b) & 4) == 0)) {
            if ((*(int *)(iVar8 + 0x28) == -1) || ((*(byte *)(iVar8 + 0x1b) & 8) == 0)) {
              bVar1 = true;
            }
            else {
              bVar1 = false;
            }
          }
          else {
            bVar1 = false;
          }
        }
        else {
          bVar1 = false;
        }
      }
      if (bVar1) break;
      iVar3 = 0;
      uVar5 = *(uint *)(iVar8 + 0x1c);
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar8 + 0x1b) & 1) != 0)) && (uVar5 != 0)) {
        iVar3 = 1;
        local_a8[0] = uVar5;
      }
      uVar5 = *(uint *)(iVar8 + 0x20);
      iVar4 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar8 + 0x1b) & 2) != 0)) && (uVar5 != 0)) {
        iVar4 = iVar3 + 1;
        local_a8[iVar3] = uVar5;
      }
      uVar5 = *(uint *)(iVar8 + 0x24);
      iVar3 = iVar4;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar8 + 0x1b) & 4) != 0)) && (uVar5 != 0)) {
        iVar3 = iVar4 + 1;
        local_a8[iVar4] = uVar5;
      }
      uVar5 = *(uint *)(iVar8 + 0x28);
      iVar4 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar8 + 0x1b) & 8) != 0)) && (uVar5 != 0)) {
        iVar4 = iVar3 + 1;
        local_a8[iVar3] = uVar5;
      }
      if (iVar4 == 0) {
        uVar5 = 0xffffffff;
      }
      else {
        uVar5 = FUN_80017760(0,iVar4 - 1);
        uVar5 = local_a8[uVar5];
      }
      if ((int)uVar5 < 0) {
        iVar3 = 0;
      }
      else {
        iVar7 = DAT_803de0f0 + -1;
        iVar4 = 0;
        while (iVar4 <= iVar7) {
          iVar6 = iVar7 + iVar4 >> 1;
          iVar3 = (&DAT_803a2448)[iVar6];
          if (*(uint *)(iVar3 + 0x14) < uVar5) {
            iVar4 = iVar6 + 1;
          }
          else {
            if (*(uint *)(iVar3 + 0x14) <= uVar5) goto LAB_800e41e4;
            iVar7 = iVar6 + -1;
          }
        }
        iVar3 = 0;
      }
LAB_800e41e4:
      if (iVar3 != 0) {
        if (param_5 != 0) {
          *(undefined *)(param_5 + (iVar10 >> 2)) = *(undefined *)(iVar8 + 0x19);
        }
        *(undefined4 *)(iVar2 + iVar9) = *(undefined4 *)(iVar8 + 8);
        *(undefined4 *)(param_3 + iVar9) = *(undefined4 *)(iVar8 + 0xc);
        iVar4 = iVar9 + 4;
        *(undefined4 *)(param_4 + iVar9) = *(undefined4 *)(iVar8 + 0x10);
        *(undefined4 *)(iVar2 + iVar4) = *(undefined4 *)(iVar3 + 8);
        *(undefined4 *)(param_3 + iVar4) = *(undefined4 *)(iVar3 + 0xc);
        *(undefined4 *)(param_4 + iVar4) = *(undefined4 *)(iVar3 + 0x10);
        uStack_2c = (int)*(char *)(iVar8 + 0x2c) << 8 ^ 0x80000000;
        local_30 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_34 = (uint)*(byte *)(iVar8 + 0x2e);
        local_38 = 0x43300000;
        *(float *)(iVar2 + iVar9 + 8) =
             lbl_803E1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_3c = (int)*(char *)(iVar8 + 0x2d) << 8 ^ 0x80000000;
        local_40 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_44 = (uint)*(byte *)(iVar8 + 0x2e);
        local_48 = 0x43300000;
        *(float *)(param_3 + iVar9 + 8) =
             lbl_803E1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_44) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_4c = (int)*(char *)(iVar8 + 0x2c) << 8 ^ 0x80000000;
        local_50 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        uStack_54 = (uint)*(byte *)(iVar8 + 0x2e);
        local_58 = 0x43300000;
        iVar8 = iVar10 + 3;
        *(float *)(param_4 + (iVar10 + 2) * 4) =
             lbl_803E1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_5c = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_60 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_64 = (uint)*(byte *)(iVar3 + 0x2e);
        local_68 = 0x43300000;
        *(float *)(iVar2 + iVar9 + 0xc) =
             lbl_803E1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_6c = (int)*(char *)(iVar3 + 0x2d) << 8 ^ 0x80000000;
        local_70 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_74 = (uint)*(byte *)(iVar3 + 0x2e);
        local_78 = 0x43300000;
        *(float *)(param_3 + iVar9 + 0xc) =
             lbl_803E1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_7c = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_80 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        uStack_84 = (uint)*(byte *)(iVar3 + 0x2e);
        local_88 = 0x43300000;
        iVar10 = iVar10 + 4;
        iVar9 = iVar9 + 0x10;
        *(float *)(param_4 + iVar8 * 4) =
             lbl_803E1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_84) - DOUBLE_803e12a8) *
                    dVar11);
      }
    }
  }
  else {
    while (iVar9 = iVar3, iVar9 != 0) {
      bVar1 = false;
      if ((*(int *)(iVar9 + 0x1c) == -1) || ((*(byte *)(iVar9 + 0x1b) & 1) != 0)) {
        if ((*(int *)(iVar9 + 0x20) == -1) || ((*(byte *)(iVar9 + 0x1b) & 2) != 0)) {
          if ((*(int *)(iVar9 + 0x24) == -1) || ((*(byte *)(iVar9 + 0x1b) & 4) != 0)) {
            if ((*(int *)(iVar9 + 0x28) == -1) || ((*(byte *)(iVar9 + 0x1b) & 8) != 0)) {
              bVar1 = true;
            }
            else {
              bVar1 = false;
            }
          }
          else {
            bVar1 = false;
          }
        }
        else {
          bVar1 = false;
        }
      }
      if (bVar1) break;
      iVar3 = 0;
      uVar5 = *(uint *)(iVar9 + 0x1c);
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 1) == 0)) && (uVar5 != 0)) {
        iVar3 = 1;
        local_98[0] = uVar5;
      }
      uVar5 = *(uint *)(iVar9 + 0x20);
      iVar4 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 2) == 0)) && (uVar5 != 0)) {
        iVar4 = iVar3 + 1;
        local_98[iVar3] = uVar5;
      }
      uVar5 = *(uint *)(iVar9 + 0x24);
      iVar3 = iVar4;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 4) == 0)) && (uVar5 != 0)) {
        iVar3 = iVar4 + 1;
        local_98[iVar4] = uVar5;
      }
      uVar5 = *(uint *)(iVar9 + 0x28);
      iVar4 = iVar3;
      if (((-1 < (int)uVar5) && ((*(byte *)(iVar9 + 0x1b) & 8) == 0)) && (uVar5 != 0)) {
        iVar4 = iVar3 + 1;
        local_98[iVar3] = uVar5;
      }
      if (iVar4 == 0) {
        uVar5 = 0xffffffff;
      }
      else {
        uVar5 = FUN_80017760(0,iVar4 - 1);
        uVar5 = local_98[uVar5];
      }
      if ((int)uVar5 < 0) {
        iVar3 = 0;
      }
      else {
        iVar7 = DAT_803de0f0 + -1;
        iVar4 = 0;
        while (iVar4 <= iVar7) {
          iVar6 = iVar7 + iVar4 >> 1;
          iVar3 = (&DAT_803a2448)[iVar6];
          if (*(uint *)(iVar3 + 0x14) < uVar5) {
            iVar4 = iVar6 + 1;
          }
          else {
            if (*(uint *)(iVar3 + 0x14) <= uVar5) goto LAB_800e3ca0;
            iVar7 = iVar6 + -1;
          }
        }
        iVar3 = 0;
      }
LAB_800e3ca0:
      if (iVar3 != 0) {
        if (param_5 != 0) {
          *(undefined *)(param_5 + (iVar10 >> 2)) = *(undefined *)(iVar9 + 0x19);
        }
        *(undefined4 *)(iVar2 + iVar8) = *(undefined4 *)(iVar9 + 8);
        *(undefined4 *)(param_3 + iVar8) = *(undefined4 *)(iVar9 + 0xc);
        iVar4 = iVar8 + 4;
        *(undefined4 *)(param_4 + iVar8) = *(undefined4 *)(iVar9 + 0x10);
        *(undefined4 *)(iVar2 + iVar4) = *(undefined4 *)(iVar3 + 8);
        *(undefined4 *)(param_3 + iVar4) = *(undefined4 *)(iVar3 + 0xc);
        *(undefined4 *)(param_4 + iVar4) = *(undefined4 *)(iVar3 + 0x10);
        uStack_84 = (int)*(char *)(iVar9 + 0x2c) << 8 ^ 0x80000000;
        local_88 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_7c = (uint)*(byte *)(iVar9 + 0x2e);
        local_80 = 0x43300000;
        *(float *)(iVar2 + iVar8 + 8) =
             lbl_803E1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_74 = (int)*(char *)(iVar9 + 0x2d) << 8 ^ 0x80000000;
        local_78 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_6c = (uint)*(byte *)(iVar9 + 0x2e);
        local_70 = 0x43300000;
        *(float *)(param_3 + iVar8 + 8) =
             lbl_803E1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_64 = (int)*(char *)(iVar9 + 0x2c) << 8 ^ 0x80000000;
        local_68 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        uStack_5c = (uint)*(byte *)(iVar9 + 0x2e);
        local_60 = 0x43300000;
        iVar9 = iVar10 + 3;
        *(float *)(param_4 + (iVar10 + 2) * 4) =
             lbl_803E1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_5c) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_54 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_58 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_4c = (uint)*(byte *)(iVar3 + 0x2e);
        local_50 = 0x43300000;
        *(float *)(iVar2 + iVar8 + 0xc) =
             lbl_803E1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_44 = (int)*(char *)(iVar3 + 0x2d) << 8 ^ 0x80000000;
        local_48 = 0x43300000;
        dVar11 = (double)FUN_80293f90();
        uStack_3c = (uint)*(byte *)(iVar3 + 0x2e);
        local_40 = 0x43300000;
        *(float *)(param_3 + iVar8 + 0xc) =
             lbl_803E1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e12a8) *
                    dVar11);
        uStack_34 = (int)*(char *)(iVar3 + 0x2c) << 8 ^ 0x80000000;
        local_38 = 0x43300000;
        dVar11 = (double)FUN_80294964();
        uStack_2c = (uint)*(byte *)(iVar3 + 0x2e);
        local_30 = 0x43300000;
        iVar10 = iVar10 + 4;
        iVar8 = iVar8 + 0x10;
        *(float *)(param_4 + iVar9 * 4) =
             lbl_803E1290 *
             (float)((double)(float)((double)CONCAT44(0x43300000,uStack_2c) - DOUBLE_803e12a8) *
                    dVar11);
      }
    }
  }
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e3ad4
 * EN v1.0 Address: 0x800E3AD4
 * EN v1.0 Size: 536b
 * EN v1.1 Address: 0x800E45B4
 * EN v1.1 Size: 672b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_800e3ad4(int param_1)
{
  bool bVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  uint local_18 [4];
  
  iVar6 = 1;
  do {
    if (param_1 == 0) {
      return iVar6;
    }
    bVar1 = false;
    if ((*(int *)(param_1 + 0x1c) == -1) || ((*(byte *)(param_1 + 0x1b) & 1) != 0)) {
      if ((*(int *)(param_1 + 0x20) == -1) || ((*(byte *)(param_1 + 0x1b) & 2) != 0)) {
        if ((*(int *)(param_1 + 0x24) == -1) || ((*(byte *)(param_1 + 0x1b) & 4) != 0)) {
          if ((*(int *)(param_1 + 0x28) == -1) || ((*(byte *)(param_1 + 0x1b) & 8) != 0)) {
            bVar1 = true;
          }
          else {
            bVar1 = false;
          }
        }
        else {
          bVar1 = false;
        }
      }
      else {
        bVar1 = false;
      }
    }
    if (bVar1) {
      return iVar6;
    }
    iVar2 = 0;
    uVar4 = *(uint *)(param_1 + 0x1c);
    if (((-1 < (int)uVar4) && ((*(byte *)(param_1 + 0x1b) & 1) == 0)) && (uVar4 != 0)) {
      iVar2 = 1;
      local_18[0] = uVar4;
    }
    uVar4 = *(uint *)(param_1 + 0x20);
    iVar3 = iVar2;
    if (((-1 < (int)uVar4) && ((*(byte *)(param_1 + 0x1b) & 2) == 0)) && (uVar4 != 0)) {
      iVar3 = iVar2 + 1;
      local_18[iVar2] = uVar4;
    }
    uVar4 = *(uint *)(param_1 + 0x24);
    iVar2 = iVar3;
    if (((-1 < (int)uVar4) && ((*(byte *)(param_1 + 0x1b) & 4) == 0)) && (uVar4 != 0)) {
      iVar2 = iVar3 + 1;
      local_18[iVar3] = uVar4;
    }
    uVar4 = *(uint *)(param_1 + 0x28);
    iVar3 = iVar2;
    if (((-1 < (int)uVar4) && ((*(byte *)(param_1 + 0x1b) & 8) == 0)) && (uVar4 != 0)) {
      iVar3 = iVar2 + 1;
      local_18[iVar2] = uVar4;
    }
    if (iVar3 == 0) {
      uVar4 = 0xffffffff;
    }
    else {
      uVar4 = FUN_80017760(0,iVar3 - 1);
      uVar4 = local_18[uVar4];
    }
    if ((int)uVar4 < 0) {
      param_1 = 0;
    }
    else {
      iVar3 = DAT_803de0f0 + -1;
      iVar2 = 0;
      while (iVar2 <= iVar3) {
        iVar5 = iVar3 + iVar2 >> 1;
        param_1 = (&DAT_803a2448)[iVar5];
        if (*(uint *)(param_1 + 0x14) < uVar4) {
          iVar2 = iVar5 + 1;
        }
        else {
          if (*(uint *)(param_1 + 0x14) <= uVar4) goto LAB_800e4758;
          iVar3 = iVar5 + -1;
        }
      }
      param_1 = 0;
    }
LAB_800e4758:
    if (param_1 != 0) {
      iVar6 = iVar6 + 1;
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_800e3cec
 * EN v1.0 Address: 0x800E3CEC
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x800E4854
 * EN v1.1 Size: 500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e3cec(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)
{
  uint *puVar1;
  float *pfVar2;
  int *piVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  float *pfVar9;
  float *pfVar10;
  int *piVar11;
  uint uVar12;
  int iVar13;
  undefined8 uVar14;
  int local_28 [10];
  
  uVar14 = FUN_8028683c();
  pfVar2 = (float *)uVar14;
  iVar4 = 0;
  piVar3 = local_28;
  iVar13 = 4;
  pfVar9 = param_4;
  pfVar10 = param_3;
  piVar11 = piVar3;
  do {
    puVar1 = (uint *)((ulonglong)uVar14 >> 0x20);
    uVar12 = *puVar1;
    if ((int)uVar12 < 0) {
      iVar8 = 0;
    }
    else {
      iVar7 = DAT_803de0f0 + -1;
      iVar5 = 0;
      while (iVar5 <= iVar7) {
        iVar6 = iVar7 + iVar5 >> 1;
        iVar8 = (&DAT_803a2448)[iVar6];
        if (*(uint *)(iVar8 + 0x14) < uVar12) {
          iVar5 = iVar6 + 1;
        }
        else {
          if (*(uint *)(iVar8 + 0x14) <= uVar12) goto LAB_800e48f4;
          iVar7 = iVar6 + -1;
        }
      }
      iVar8 = 0;
    }
LAB_800e48f4:
    *piVar11 = iVar8;
    iVar5 = *piVar11;
    if (iVar5 != 0) {
      *(undefined4 *)uVar14 = *(undefined4 *)(iVar5 + 8);
      *pfVar10 = *(float *)(iVar5 + 0xc);
      *pfVar9 = *(float *)(iVar5 + 0x10);
      iVar4 = iVar4 + 1;
    }
    piVar11 = piVar11 + 1;
    uVar14 = CONCAT44(puVar1 + 1,(undefined4 *)uVar14 + 1);
    pfVar10 = pfVar10 + 1;
    pfVar9 = pfVar9 + 1;
    iVar13 = iVar13 + -1;
    if (iVar13 == 0) {
      if (((1 < iVar4) && (local_28[1] != 0)) && (local_28[2] != 0)) {
        iVar4 = 0;
        iVar13 = 4;
        do {
          if (*piVar3 == 0) {
            if (iVar4 == 0) {
              *pfVar2 = *(float *)(local_28[1] + 8) +
                        (*(float *)(local_28[1] + 8) - *(float *)(local_28[2] + 8));
              *param_3 = *(float *)(local_28[1] + 0xc) +
                         (*(float *)(local_28[1] + 0xc) - *(float *)(local_28[2] + 0xc));
              *param_4 = *(float *)(local_28[1] + 0x10) +
                         (*(float *)(local_28[1] + 0x10) - *(float *)(local_28[2] + 0x10));
            }
            else if (iVar4 == 3) {
              *pfVar2 = *(float *)(local_28[2] + 8) +
                        (*(float *)(local_28[2] + 8) - *(float *)(local_28[1] + 8));
              *param_3 = *(float *)(local_28[2] + 0xc) +
                         (*(float *)(local_28[2] + 0xc) - *(float *)(local_28[1] + 0xc));
              *param_4 = *(float *)(local_28[2] + 0x10) +
                         (*(float *)(local_28[2] + 0x10) - *(float *)(local_28[1] + 0x10));
            }
          }
          piVar3 = piVar3 + 1;
          pfVar2 = pfVar2 + 1;
          param_3 = param_3 + 1;
          param_4 = param_4 + 1;
          iVar4 = iVar4 + 1;
          iVar13 = iVar13 + -1;
        } while (iVar13 != 0);
      }
      FUN_80286888();
      return;
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: RomCurve_getAdjacentWindow
 * EN v1.0 Address: 0x800E3ED8
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x800E4A48
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void RomCurve_getAdjacentWindow(int param_1,int *param_2)
{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  
  *param_2 = -1;
  param_2[1] = -1;
  param_2[2] = -1;
  param_2[3] = -1;
  if (param_1 == 0) {
    return;
  }
  param_2[1] = *(int *)(param_1 + 0x14);
  iVar3 = *(int *)(param_1 + 0x1c);
  if (iVar3 != -1) {
    bVar1 = (*(byte *)(param_1 + 0x1b) & 1) == 0;
    if (bVar1) {
      if (bVar1) {
        param_2[2] = iVar3;
      }
    }
    else {
      *param_2 = iVar3;
    }
  }
  iVar3 = *(int *)(param_1 + 0x20);
  if (iVar3 != -1) {
    bVar1 = (*(byte *)(param_1 + 0x1b) & 2) == 0;
    if (bVar1) {
      if (bVar1) {
        param_2[2] = iVar3;
      }
    }
    else {
      *param_2 = iVar3;
    }
  }
  iVar3 = *(int *)(param_1 + 0x24);
  if (iVar3 != -1) {
    bVar1 = (*(byte *)(param_1 + 0x1b) & 4) == 0;
    if (bVar1) {
      if (bVar1) {
        param_2[2] = iVar3;
      }
    }
    else {
      *param_2 = iVar3;
    }
  }
  iVar3 = *(int *)(param_1 + 0x28);
  if (iVar3 != -1) {
    bVar1 = (*(byte *)(param_1 + 0x1b) & 8) == 0;
    if (bVar1) {
      if (bVar1) {
        param_2[2] = iVar3;
      }
    }
    else {
      *param_2 = iVar3;
    }
  }
  uVar5 = param_2[2];
  if ((int)uVar5 < 0) {
    return;
  }
  if ((int)uVar5 < 0) {
    iVar6 = 0;
  }
  else {
    iVar4 = DAT_803de0f0 + -1;
    iVar3 = 0;
    while (iVar3 <= iVar4) {
      iVar2 = iVar4 + iVar3 >> 1;
      iVar6 = (&DAT_803a2448)[iVar2];
      if (*(uint *)(iVar6 + 0x14) < uVar5) {
        iVar3 = iVar2 + 1;
      }
      else {
        if (*(uint *)(iVar6 + 0x14) <= uVar5) goto LAB_800e4bc4;
        iVar4 = iVar2 + -1;
      }
    }
    iVar6 = 0;
  }
LAB_800e4bc4:
  if (iVar6 == 0) {
    return;
  }
  if ((*(int *)(iVar6 + 0x1c) != -1) && ((*(byte *)(iVar6 + 0x1b) & 1) == 0)) {
    param_2[3] = *(int *)(iVar6 + 0x1c);
  }
  if ((*(int *)(iVar6 + 0x20) != -1) && ((*(byte *)(iVar6 + 0x1b) & 2) == 0)) {
    param_2[3] = *(int *)(iVar6 + 0x20);
  }
  if ((*(int *)(iVar6 + 0x24) != -1) && ((*(byte *)(iVar6 + 0x1b) & 4) == 0)) {
    param_2[3] = *(int *)(iVar6 + 0x24);
  }
  if (*(int *)(iVar6 + 0x28) == -1) {
    return;
  }
  if ((*(byte *)(iVar6 + 0x1b) & 8) != 0) {
    return;
  }
  param_2[3] = *(int *)(iVar6 + 0x28);
  return;
}

/*
 * --INFO--
 *
 * Function: RomCurve_getNearestAdjacentLink
 * EN v1.0 Address: 0x800E409C
 * EN v1.0 Size: 456b
 * EN v1.1 Address: 0x800E4C84
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int RomCurve_getNearestAdjacentLink(double param_1,double param_2,double param_3,int param_4,
                                    int param_5)
{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  float local_78 [2];
  int local_70 [2];
  float local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  float local_50;
  float local_4c;
  float local_48;
  
  local_70[1] = -1;
  local_70[0] = -1;
  local_78[1] = lbl_803E12B8;
  local_78[0] = lbl_803E12B8;
  local_68 = *(float *)(param_4 + 8);
  local_64 = *(undefined4 *)(param_4 + 0xc);
  local_60 = *(undefined4 *)(param_4 + 0x10);
  iVar7 = 0;
  do {
    uVar6 = *(uint *)(param_4 + 0x1c);
    if (-1 < (int)uVar6) {
      if ((int)uVar6 < 0) {
        iVar5 = 0;
      }
      else {
        iVar4 = DAT_803de0f0 + -1;
        iVar3 = 0;
        while (iVar3 <= iVar4) {
          iVar2 = iVar4 + iVar3 >> 1;
          iVar5 = (&DAT_803a2448)[iVar2];
          if (*(uint *)(iVar5 + 0x14) < uVar6) {
            iVar3 = iVar2 + 1;
          }
          else {
            if (*(uint *)(iVar5 + 0x14) <= uVar6) goto LAB_800e4d74;
            iVar4 = iVar2 + -1;
          }
        }
        iVar5 = 0;
      }
LAB_800e4d74:
      if (iVar5 != 0) {
        local_5c = *(undefined4 *)(iVar5 + 8);
        local_58 = *(undefined4 *)(iVar5 + 0xc);
        local_54 = *(undefined4 *)(iVar5 + 0x10);
        RomCurve_distanceToSegment(param_1,param_2,param_3,&local_68);
        fVar1 = (float)((double)local_48 - param_3) * (float)((double)local_48 - param_3) +
                (float)((double)local_50 - param_1) * (float)((double)local_50 - param_1) +
                (float)((double)local_4c - param_2) * (float)((double)local_4c - param_2);
        uVar6 = countLeadingZeros(param_5 - uVar6);
        uVar6 = uVar6 >> 5;
        if (local_78[uVar6] < fVar1) {
          local_78[uVar6] = fVar1;
          local_70[uVar6] = *(int *)(param_4 + 0x1c);
        }
      }
    }
    param_4 = param_4 + 4;
    iVar7 = iVar7 + 1;
    if (3 < iVar7) {
      if ((local_70[0] == -1) && (local_70[0] = local_70[1], local_70[1] == -1)) {
        local_70[0] = -1;
      }
      return local_70[0];
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: RomCurve_distanceToSegment
 * EN v1.0 Address: 0x800E4264
 * EN v1.0 Size: 452b
 * EN v1.1 Address: 0x800E4E68
 * EN v1.1 Size: 324b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double RomCurve_distanceToSegment(double param_1,double param_2,double param_3,float *param_4)
{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  
  dVar5 = (double)param_4[3];
  dVar4 = (double)*param_4;
  dVar8 = (double)(float)(dVar5 - dVar4);
  dVar6 = (double)param_4[4];
  dVar3 = (double)param_4[1];
  dVar9 = (double)(float)(dVar6 - dVar3);
  dVar7 = (double)param_4[5];
  dVar2 = (double)param_4[2];
  dVar10 = (double)(float)(dVar7 - dVar2);
  dVar1 = (double)lbl_803E12B8;
  if (((dVar1 != dVar8) || (dVar1 != dVar9)) || (dVar1 != dVar10)) {
    dVar1 = (double)((float)(dVar10 * (double)(float)(param_3 - dVar2) +
                            (double)(float)(dVar8 * (double)(float)(param_1 - dVar4) +
                                           (double)(float)(dVar9 * (double)(float)(param_2 - dVar3))
                                           )) /
                    (float)(dVar10 * dVar10 +
                           (double)(float)(dVar8 * dVar8 + (double)(float)(dVar9 * dVar9))));
  }
  if ((double)lbl_803E12B8 <= dVar1) {
    if (dVar1 <= (double)lbl_803E12B4) {
      dVar5 = (double)(float)(dVar1 * dVar8 + dVar4);
      dVar6 = (double)(float)(dVar1 * dVar9 + dVar3);
      dVar7 = (double)(float)(dVar1 * dVar10 + dVar2);
      dVar1 = (double)((float)(dVar7 - param_3) * (float)(dVar7 - param_3) +
                      (float)(dVar5 - param_1) * (float)(dVar5 - param_1) +
                      (float)(dVar6 - param_2) * (float)(dVar6 - param_2));
    }
    else {
      dVar1 = -(double)((float)(dVar7 - param_3) * (float)(dVar7 - param_3) +
                       (float)(dVar5 - param_1) * (float)(dVar5 - param_1) +
                       (float)(dVar6 - param_2) * (float)(dVar6 - param_2));
    }
  }
  else {
    dVar1 = -(double)((float)(dVar2 - param_3) * (float)(dVar2 - param_3) +
                     (float)(dVar4 - param_1) * (float)(dVar4 - param_1) +
                     (float)(dVar3 - param_2) * (float)(dVar3 - param_2));
    dVar5 = dVar4;
    dVar6 = dVar3;
    dVar7 = dVar2;
  }
  param_4[6] = (float)dVar5;
  param_4[7] = (float)dVar6;
  param_4[8] = (float)dVar7;
  return dVar1;
}

/*
 * --INFO--
 *
 * Function: RomCurve_getRandomBlockedLink
 * EN v1.0 Address: 0x800E4428
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x800E4FAC
 * EN v1.1 Size: 472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int RomCurve_getRandomBlockedLink(int param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int local_18 [6];

  iVar4 = 0;
  iVar2 = *(int *)(param_1 + 0x1c);
  if (((-1 < iVar2) && ((*(byte *)(param_1 + 0x1b) & 1) != 0)) && (iVar2 != param_2)) {
    iVar4 = 1;
    local_18[0] = iVar2;
  }
  iVar3 = *(int *)(param_1 + 0x20);
  iVar2 = iVar4;
  if (((-1 < iVar3) && ((*(byte *)(param_1 + 0x1b) & 2) != 0)) && (iVar3 != param_2)) {
    iVar2 = iVar4 + 1;
    local_18[iVar4] = iVar3;
  }
  iVar3 = *(int *)(param_1 + 0x24);
  iVar4 = iVar2;
  if (((-1 < iVar3) && ((*(byte *)(param_1 + 0x1b) & 4) != 0)) && (iVar3 != param_2)) {
    iVar4 = iVar2 + 1;
    local_18[iVar2] = iVar3;
  }
  iVar3 = *(int *)(param_1 + 0x28);
  iVar2 = iVar4;
  if (((-1 < iVar3) && ((*(byte *)(param_1 + 0x1b) & 8) != 0)) && (iVar3 != param_2)) {
    iVar2 = iVar4 + 1;
    local_18[iVar4] = iVar3;
  }
  if (iVar2 == 0) {
    iVar2 = -1;
  }
  else {
    uVar1 = FUN_80017760(0,iVar2 - 1);
    iVar2 = local_18[uVar1];
  }
  return iVar2;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: RomCurve_getRandomUnblockedLink
 * EN v1.0 Address: 0x800E4528
 * EN v1.0 Size: 256b
 * EN v1.1 Address: 0x800E5184
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int RomCurve_getRandomUnblockedLink(int param_1,int param_2)
{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int local_18 [6];

  iVar4 = 0;
  iVar2 = *(int *)(param_1 + 0x1c);
  if (((-1 < iVar2) && ((*(byte *)(param_1 + 0x1b) & 1) == 0)) && (iVar2 != param_2)) {
    iVar4 = 1;
    local_18[0] = iVar2;
  }
  iVar3 = *(int *)(param_1 + 0x20);
  iVar2 = iVar4;
  if (((-1 < iVar3) && ((*(byte *)(param_1 + 0x1b) & 2) == 0)) && (iVar3 != param_2)) {
    iVar2 = iVar4 + 1;
    local_18[iVar4] = iVar3;
  }
  iVar3 = *(int *)(param_1 + 0x24);
  iVar4 = iVar2;
  if (((-1 < iVar3) && ((*(byte *)(param_1 + 0x1b) & 4) == 0)) && (iVar3 != param_2)) {
    iVar4 = iVar2 + 1;
    local_18[iVar2] = iVar3;
  }
  iVar3 = *(int *)(param_1 + 0x28);
  iVar2 = iVar4;
  if (((-1 < iVar3) && ((*(byte *)(param_1 + 0x1b) & 8) == 0)) && (iVar3 != param_2)) {
    iVar2 = iVar4 + 1;
    local_18[iVar4] = iVar3;
  }
  if (iVar2 == 0) {
    iVar2 = -1;
  }
  else {
    uVar1 = FUN_80017760(0,iVar2 - 1);
    iVar2 = local_18[uVar1];
  }
  return iVar2;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800e4628
 * EN v1.0 Address: 0x800E4628
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x800E5330
 * EN v1.1 Size: 572b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e4628(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,int param_6)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int *piVar5;
  double extraout_f1;
  double dVar6;
  double in_f30;
  double in_f31;
  double dVar7;
  double dVar8;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar9;
  float local_58;
  float local_54;
  float local_50;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar9 = FUN_80286834();
  iVar1 = (int)uVar9;
  dVar7 = (double)lbl_803E12E4;
  local_58 = (float)extraout_f1;
  local_54 = (float)param_2;
  local_50 = (float)param_3;
  piVar5 = &DAT_803a2448;
  dVar8 = dVar7;
  for (iVar4 = 0; iVar4 < DAT_803de0f0; iVar4 = iVar4 + 1) {
    iVar3 = *piVar5;
    iVar2 = 0;
    do {
      if ((iVar1 < 1) ||
         ((int)*(char *)(iVar3 + 0x19) == *(int *)((int)((ulonglong)uVar9 >> 0x20) + iVar2 * 4))) {
        dVar6 = FUN_80017714(&local_58,(float *)(iVar3 + 8));
        if (dVar6 < dVar8) {
          dVar8 = dVar6;
        }
        iVar2 = iVar1;
        if ((*(char *)(iVar3 + 0x18) == param_6) && (dVar6 < dVar7)) {
          dVar7 = dVar6;
        }
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 < iVar1);
    piVar5 = piVar5 + 1;
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: curves_addCurveDef
 * EN v1.0 Address: 0x800E4724
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800E556C
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void curves_addCurveDef(int curve)
{
  int count;
  int insertIndex;
  int *slot;
  int remaining;

  count = DAT_803de0f0;
  if (count == ROMCURVE_MAX_CURVES) {
    OSReport(lbl_803116BC);
    return;
  }

  insertIndex = 0;
  slot = &DAT_803a2448;
  while ((insertIndex < count) &&
         (*(uint *)(curve + ROMCURVE_ID_OFFSET) > *(uint *)(*slot + ROMCURVE_ID_OFFSET))) {
    slot = slot + 1;
    insertIndex = insertIndex + 1;
  }

  slot = &DAT_803a2448 + count;
  remaining = count - insertIndex;
  while (remaining > 0) {
    *slot = slot[-1];
    slot = slot + -1;
    remaining = remaining + -1;
  }

  DAT_803de0f0 = DAT_803de0f0 + 1;
  (&DAT_803a2448)[insertIndex] = curve;
}

/*
 * --INFO--
 *
 * Function: curves_countRandomPoints
 * EN v1.0 Address: 0x800E4728
 * EN v1.0 Size: 664b
 * EN v1.1 Address: 0x800E56B8
 * EN v1.1 Size: 624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void curves_countRandomPoints(void)
{
  bool bVar1;
  int iVar2;
  int iVar3;
  float *pfVar4;
  uint *puVar5;
  undefined4 *puVar6;
  uint uVar7;
  int iVar8;
  float *pfVar9;
  uint *puVar10;
  double dVar11;
  double in_f28;
  double dVar12;
  double in_f29;
  double dVar13;
  double in_f30;
  double dVar14;
  double in_f31;
  double dVar15;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar16;
  undefined4 *local_98;
  float local_94 [5];
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
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
  uVar16 = FUN_8028683c();
  iVar2 = (int)((ulonglong)uVar16 >> 0x20);
  puVar5 = (uint *)uVar16;
  if ((int)(uint)*(byte *)(puVar5 + 0x97) >> 4 == 4) {
    dVar12 = (double)lbl_803E12E8;
    uVar7 = 0;
    pfVar9 = local_94;
    puVar10 = puVar5;
    dVar13 = dVar12;
    dVar14 = dVar12;
    dVar15 = dVar12;
    for (iVar8 = 0; dVar11 = DOUBLE_803e12f0, iVar8 < (int)(uint)*(byte *)(puVar5 + 0x97) >> 4;
        iVar8 = iVar8 + 1) {
      *pfVar9 = (float)puVar10[3];
      iVar3 = FUN_800632f4((double)(float)puVar10[2],(double)*(float *)(iVar2 + 0x1c),
                           (double)(float)puVar10[4],iVar2,&local_98,-1,0);
      bVar1 = false;
      if ((iVar3 != 0) && (puVar6 = local_98, 0 < iVar3)) {
        do {
          if (!bVar1) {
            pfVar4 = (float *)*puVar6;
            dVar11 = (double)*pfVar4;
            if ((dVar11 < (double)(lbl_803E12EC + *(float *)(iVar2 + 0x1c))) &&
               (*(char *)(pfVar4 + 5) != '\x0e')) {
              *pfVar9 = *pfVar4;
              dVar15 = (double)(float)(dVar15 + (double)pfVar4[1]);
              dVar14 = (double)(float)(dVar14 + (double)pfVar4[2]);
              dVar13 = (double)(float)(dVar13 + (double)pfVar4[3]);
              dVar12 = (double)(float)(dVar12 + dVar11);
              uVar7 = uVar7 + 1;
              bVar1 = true;
            }
          }
          iVar3 = iVar3 + -1;
          puVar6 = puVar6 + 1;
        } while (iVar3 != 0);
      }
      puVar10[3] = (uint)*pfVar9;
      puVar10 = puVar10 + 3;
      pfVar9 = pfVar9 + 1;
    }
    if (uVar7 == 0) {
      *(undefined *)((int)puVar5 + 0x261) = 0;
    }
    else {
      uStack_7c = uVar7 ^ 0x80000000;
      local_80 = 0x43300000;
      *(float *)(iVar2 + 0x1c) =
           (float)(dVar12 / (double)(float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e12f0
                                           ));
      local_78 = 0x43300000;
      puVar5[0x68] = (uint)(float)(dVar15 / (double)(float)((double)CONCAT44(0x43300000,uStack_7c) -
                                                           dVar11));
      local_70 = 0x43300000;
      puVar5[0x69] = (uint)(float)(dVar14 / (double)(float)((double)CONCAT44(0x43300000,uStack_7c) -
                                                           dVar11));
      local_68 = 0x43300000;
      puVar5[0x6a] = (uint)(float)(dVar13 / (double)(float)((double)CONCAT44(0x43300000,uStack_7c) -
                                                           dVar11));
      *(undefined *)((int)puVar5 + 0x261) = 1;
      uStack_74 = uStack_7c;
      uStack_6c = uStack_7c;
      uStack_64 = uStack_7c;
    }
    FUN_80017730();
    iVar8 = FUN_80017730();
    *(short *)(iVar2 + 2) = -(short)iVar8;
    if ((*puVar5 & 0x400) != 0) {
      iVar8 = FUN_80017730();
      *(short *)(iVar2 + 4) = (short)iVar8;
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e49c0
 * EN v1.0 Address: 0x800E49C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800E5928
 * EN v1.1 Size: 600b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e49c0(int param_1,uint *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800e49c4
 * EN v1.0 Address: 0x800E49C4
 * EN v1.0 Size: 672b
 * EN v1.1 Address: 0x800E5B80
 * EN v1.1 Size: 960b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e49c4(void)
{
  float fVar1;
  float fVar2;
  int iVar3;
  short *psVar4;
  uint *puVar5;
  int iVar6;
  uint *puVar7;
  uint *puVar8;
  short sVar9;
  float *pfVar10;
  float *pfVar11;
  float *pfVar12;
  undefined8 uVar13;
  float local_b8 [4];
  float local_a8 [4];
  float local_98 [4];
  short local_88;
  short local_86;
  short local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float afStack_70 [16];
  undefined4 local_30;
  int iStack_2c;
  
  uVar13 = FUN_80286834();
  psVar4 = (short *)((ulonglong)uVar13 >> 0x20);
  puVar7 = (uint *)uVar13;
  puVar7[0x68] = puVar7[0x1a];
  puVar7[0x69] = puVar7[0x1b];
  puVar7[0x6a] = puVar7[0x1c];
  fVar2 = lbl_803E12E8;
  iVar3 = (int)(uint)*(byte *)(puVar7 + 0x97) >> 4;
  if ((iVar3 == 2) || (iVar3 == 4)) {
    *(float *)(psVar4 + 0xc) = lbl_803E12E8;
    *(float *)(psVar4 + 0xe) = fVar2;
    *(float *)(psVar4 + 0x10) = fVar2;
    puVar5 = puVar7;
    puVar8 = puVar7;
    for (sVar9 = 0; fVar2 = lbl_803E130C, (int)sVar9 < iVar3 * 3; sVar9 = sVar9 + 3) {
      *(float *)(psVar4 + 0xc) = *(float *)(psVar4 + 0xc) + (float)puVar5[2];
      *(float *)(psVar4 + 0xe) = *(float *)(psVar4 + 0xe) + (float)puVar8[3];
      *(float *)(psVar4 + 0x10) = *(float *)(psVar4 + 0x10) + (float)puVar8[4];
      puVar5 = puVar5 + 3;
      puVar8 = puVar8 + 3;
    }
    local_30 = 0x43300000;
    fVar1 = lbl_803E130C / (float)((double)CONCAT44(0x43300000,iVar3) - DOUBLE_803e1318);
    *(float *)(psVar4 + 0xc) = *(float *)(psVar4 + 0xc) * fVar1;
    *(float *)(psVar4 + 0xe) = *(float *)(psVar4 + 0xe) * fVar1;
    *(float *)(psVar4 + 0x10) = *(float *)(psVar4 + 0x10) * fVar1;
    iStack_2c = iVar3;
    if ((*puVar7 & 0x8600) != 0) {
      local_88 = -*psVar4;
      local_86 = -psVar4[1];
      local_84 = -psVar4[2];
      local_80 = fVar2;
      local_7c = -*(float *)(psVar4 + 0xc);
      local_78 = -*(float *)(psVar4 + 0xe);
      local_74 = -*(float *)(psVar4 + 0x10);
      FUN_8001774c(afStack_70,(int)&local_88);
      pfVar12 = local_b8;
      pfVar10 = local_a8;
      pfVar11 = local_98;
      puVar5 = puVar7;
      for (sVar9 = 0; sVar9 < iVar3; sVar9 = sVar9 + 1) {
        FUN_80017778((double)(float)puVar5[2],(double)(float)puVar5[3],(double)(float)puVar5[4],
                     afStack_70,pfVar11,pfVar10,pfVar12);
        puVar5 = puVar5 + 3;
        pfVar12 = pfVar12 + 1;
        pfVar10 = pfVar10 + 1;
        pfVar11 = pfVar11 + 1;
      }
      if ((*puVar7 & 0x8000) != 0) {
        iVar6 = FUN_80017730();
        *psVar4 = *psVar4 + ((short)((short)iVar6 + -0x8000) >> 2);
      }
      if ((*puVar7 & 0x200) != 0) {
        iVar6 = FUN_80017730();
        *(short *)(puVar7 + 0x66) = -(short)iVar6;
      }
      if ((iVar3 == 4) && ((*puVar7 & 0x400) != 0)) {
        iVar3 = FUN_80017730();
        *(short *)((int)puVar7 + 0x19a) = (short)iVar3;
      }
    }
  }
  else {
    *(uint *)(psVar4 + 0xc) = puVar7[2];
    *(uint *)(psVar4 + 0xe) = puVar7[3];
    *(uint *)(psVar4 + 0x10) = puVar7[4];
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e4c64
 * EN v1.0 Address: 0x800E4C64
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x800E5F40
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e4c64(short *param_1,int param_2)
{
  float fVar1;
  short sVar2;
  int iVar3;
  float local_78;
  float local_74;
  float local_70;
  short local_6c [4];
  float local_64;
  float local_60;
  float local_5c;
  float local_58;
  float afStack_54 [20];
  
  if ((*(byte *)(param_2 + 0x260) & 0x10) == 0) {
    *(short *)(param_2 + 0x198) =
         *(short *)(param_2 + 0x198) -
         (short)((int)((int)*(short *)(param_2 + 0x198) * (uint)DAT_803dc070) >> 3);
    *(short *)(param_2 + 0x19a) =
         *(short *)(param_2 + 0x19a) -
         (short)((int)((int)*(short *)(param_2 + 0x19a) * (uint)DAT_803dc070) >> 3);
    fVar1 = lbl_803E12E8;
    *(float *)(param_2 + 0x1a0) = lbl_803E12E8;
    *(float *)(param_2 + 0x1a4) = lbl_803E130C;
    *(float *)(param_2 + 0x1a8) = fVar1;
  }
  else {
    local_6c[0] = -*param_1;
    if (*(short **)(param_1 + 0x18) != (short *)0x0) {
      local_6c[0] = local_6c[0] - **(short **)(param_1 + 0x18);
    }
    local_6c[1] = 0;
    local_6c[2] = 0;
    local_64 = lbl_803E130C;
    local_60 = lbl_803E12E8;
    local_5c = lbl_803E12E8;
    local_58 = lbl_803E12E8;
    FUN_8001774c(afStack_54,(int)local_6c);
    FUN_80017778((double)*(float *)(param_2 + 0x1a0),(double)*(float *)(param_2 + 0x1a4),
                 (double)*(float *)(param_2 + 0x1a8),afStack_54,&local_70,&local_74,&local_78);
    iVar3 = FUN_80017730();
    sVar2 = 0x4000 - (short)iVar3;
    *(short *)(param_2 + 0x19c) = sVar2;
    *(short *)(param_2 + 0x198) =
         *(short *)(param_2 + 0x198) +
         (short)((int)((uint)DAT_803dc070 * ((int)sVar2 - (int)*(short *)(param_2 + 0x198))) >> 3);
    iVar3 = FUN_80017730();
    sVar2 = -(0x4000 - (short)iVar3);
    *(short *)(param_2 + 0x19e) = sVar2;
    *(short *)(param_2 + 0x19a) =
         *(short *)(param_2 + 0x19a) +
         (short)((int)((uint)DAT_803dc070 * ((int)sVar2 - (int)*(short *)(param_2 + 0x19a))) >> 3);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e4db4
 * EN v1.0 Address: 0x800E4DB4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800E60BC
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e4db4(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800e4db8
 * EN v1.0 Address: 0x800E4DB8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800E61A0
 * EN v1.1 Size: 624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e4db8(int param_1,int param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800e4dbc
 * EN v1.0 Address: 0x800E4DBC
 * EN v1.0 Size: 912b
 * EN v1.1 Address: 0x800E6410
 * EN v1.1 Size: 872b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e4dbc(void)
{
  float fVar1;
  ushort *puVar2;
  uint uVar3;
  uint *puVar4;
  uint *puVar5;
  float *pfVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  undefined8 uVar11;
  float fStack_90;
  float fStack_8c;
  ushort local_88;
  ushort local_86;
  ushort local_84;
  float local_80;
  int local_7c;
  int local_78;
  int local_74;
  float afStack_70 [16];
  undefined4 local_30;
  uint uStack_2c;
  
  uVar11 = FUN_80286838();
  puVar2 = (ushort *)((ulonglong)uVar11 >> 0x20);
  puVar4 = (uint *)uVar11;
  uVar9 = *(byte *)(puVar4 + 0x97) & 0xf;
  *(undefined *)((int)puVar4 + 0x25e) = 0;
  puVar5 = puVar4;
  for (iVar7 = 0; fVar1 = lbl_803E12E8, iVar7 < (int)uVar9; iVar7 = iVar7 + 1) {
    if ((*puVar4 & 0x200000) == 0) {
      pfVar6 = (float *)0x4;
    }
    else {
      pfVar6 = (float *)0x2;
    }
    iVar8 = FUN_800620e8(puVar5 + 0x45,puVar5 + 0x39,pfVar6,(int *)(puVar4 + 0x51),(int *)puVar2,
                         (uint)*(byte *)((int)puVar4 + 0x25d),0xffffffff,0,*(byte *)(puVar4 + 0x99))
    ;
    *(byte *)((int)puVar4 + 0x25e) = *(byte *)((int)puVar4 + 0x25e) | (byte)(iVar8 << iVar7);
    if ((*puVar4 & 0x2000000) != 0) {
      if ((*puVar4 & 0x200000) == 0) {
        pfVar6 = (float *)0x4;
      }
      else {
        pfVar6 = (float *)0x2;
      }
      FUN_800620e8(puVar5 + 0x45,puVar5 + 0x39,pfVar6,(int *)(puVar4 + 0x51),(int *)puVar2,
                   (uint)*(byte *)((int)puVar4 + 0x263),0xffffffff,0,*(byte *)(puVar4 + 0x99));
    }
    puVar5 = puVar5 + 3;
  }
  if (uVar9 < 2) {
    if ((*puVar4 & 0x100000) == 0) {
      *(uint *)(puVar2 + 6) = puVar4[0x39];
      *(uint *)(puVar2 + 10) = puVar4[0x3b];
    }
    goto LAB_800e6690;
  }
  if ((*puVar4 & 0x100000) != 0) goto LAB_800e6690;
  *(float *)(puVar2 + 6) = lbl_803E12E8;
  *(float *)(puVar2 + 10) = fVar1;
  uVar3 = (uVar9 * 3 + 2) / 3;
  if (uVar9 * 3 != 0) {
    uVar10 = uVar3 >> 2;
    puVar5 = puVar4;
    if (uVar10 != 0) {
      do {
        *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) + (float)puVar5[0x39];
        *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) + (float)puVar5[0x3b];
        *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) + (float)puVar5[0x3c];
        *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) + (float)puVar5[0x3e];
        *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) + (float)puVar5[0x3f];
        *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) + (float)puVar5[0x41];
        *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) + (float)puVar5[0x42];
        *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) + (float)puVar5[0x44];
        puVar5 = puVar5 + 0xc;
        uVar10 = uVar10 - 1;
      } while (uVar10 != 0);
      uVar3 = uVar3 & 3;
      if (uVar3 == 0) goto LAB_800e6630;
    }
    do {
      *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) + (float)puVar5[0x39];
      *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) + (float)puVar5[0x3b];
      uVar3 = uVar3 - 1;
      puVar5 = puVar5 + 3;
    } while (uVar3 != 0);
  }
LAB_800e6630:
  local_30 = 0x43300000;
  fVar1 = lbl_803E130C / (float)((double)CONCAT44(0x43300000,uVar9) - DOUBLE_803e1318);
  *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) * fVar1;
  *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) * fVar1;
  uStack_2c = uVar9;
LAB_800e6690:
  local_88 = *puVar2;
  if ((*puVar4 & 0x20) == 0) {
    local_86 = puVar2[1];
    local_84 = puVar2[2];
  }
  else {
    local_86 = 0;
    local_84 = 0;
  }
  local_80 = lbl_803E130C;
  local_7c = *(int *)(puVar2 + 6);
  local_78 = *(int *)(puVar2 + 8);
  local_74 = *(int *)(puVar2 + 10);
  FUN_80017754(afStack_70,&local_88);
  iVar7 = 0;
  puVar5 = puVar4;
  for (iVar8 = 0; iVar8 < (int)(uVar9 * 3); iVar8 = iVar8 + 3) {
    puVar5[0x45] = puVar5[0x39];
    puVar5[0x47] = puVar5[0x3b];
    pfVar6 = (float *)(puVar4[0x37] + iVar7);
    FUN_80017778((double)*pfVar6,(double)pfVar6[1],(double)pfVar6[2],afStack_70,&fStack_8c,
                 (float *)(puVar4 + iVar8 + 0x46),&fStack_90);
    puVar5 = puVar5 + 3;
    iVar7 = iVar7 + 0xc;
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e514c
 * EN v1.0 Address: 0x800E514C
 * EN v1.0 Size: 732b
 * EN v1.1 Address: 0x800E6778
 * EN v1.1 Size: 696b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e514c(void)
{
  uint uVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  ushort *puVar5;
  int iVar6;
  ushort uVar8;
  uint *puVar7;
  uint *puVar9;
  float *pfVar10;
  uint *puVar11;
  int iVar12;
  int iVar13;
  undefined8 uVar14;
  ushort local_78;
  ushort local_76;
  ushort local_74;
  float local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  float afStack_60 [24];
  
  uVar14 = FUN_8028683c();
  puVar5 = (ushort *)((ulonglong)uVar14 >> 0x20);
  puVar9 = (uint *)uVar14;
  if ((*puVar9 & 0x4000000) != 0) {
    iVar6 = *(int *)(puVar5 + 0x18);
    if (iVar6 == 0) {
      *(undefined4 *)(puVar5 + 0xc) = *(undefined4 *)(puVar5 + 6);
      *(undefined4 *)(puVar5 + 0xe) = *(undefined4 *)(puVar5 + 8);
      *(undefined4 *)(puVar5 + 0x10) = *(undefined4 *)(puVar5 + 10);
    }
    else if ((*(int *)(iVar6 + 0x58) == 0) || (uVar8 = ObjHits_IsObjectEnabled(iVar6), uVar8 == 0)) {
      FUN_800068f8((double)*(float *)(puVar5 + 6),(double)*(float *)(puVar5 + 8),
                   (double)*(float *)(puVar5 + 10),(float *)(puVar5 + 0xc),(float *)(puVar5 + 0xe),
                   (float *)(puVar5 + 0x10),*(int *)(puVar5 + 0x18));
    }
    else {
      FUN_80017778((double)*(float *)(puVar5 + 6),(double)*(float *)(puVar5 + 8),
                   (double)*(float *)(puVar5 + 10),
                   (float *)(*(int *)(*(int *)(puVar5 + 0x18) + 0x58) +
                            (*(byte *)(*(int *)(*(int *)(puVar5 + 0x18) + 0x58) + 0x10c) + 2) * 0x40
                            ),(float *)(puVar5 + 0xc),(float *)(puVar5 + 0xe),
                   (float *)(puVar5 + 0x10));
    }
    if ((*puVar9 & 0x2000) != 0) {
      local_78 = *puVar5;
      if ((*puVar9 & 0x20) == 0) {
        local_76 = puVar5[1];
        local_74 = puVar5[2];
      }
      else {
        local_76 = 0;
        local_74 = 0;
      }
      local_70 = lbl_803E130C;
      local_6c = *(undefined4 *)(puVar5 + 0xc);
      local_68 = *(undefined4 *)(puVar5 + 0xe);
      local_64 = *(undefined4 *)(puVar5 + 0x10);
      FUN_80017754(afStack_60,&local_78);
      iVar13 = 0;
      iVar6 = 0;
      puVar7 = puVar9;
      for (iVar12 = 0; fVar2 = lbl_803E1338, iVar12 < (int)(uint)*(byte *)(puVar9 + 0x97) >> 4;
          iVar12 = iVar12 + 1) {
        pfVar10 = (float *)(puVar9[1] + iVar6);
        FUN_80017778((double)*pfVar10,(double)pfVar10[1],(double)pfVar10[2],afStack_60,
                     (float *)(puVar7 + 2),(float *)(puVar9 + iVar13 + 3),
                     (float *)(puVar9 + iVar13 + 4));
        *(undefined *)((int)puVar9 + iVar12 + 0xb8) = 0xff;
        puVar7 = puVar7 + 3;
        iVar6 = iVar6 + 0xc;
        iVar13 = iVar13 + 3;
      }
      puVar7 = puVar9;
      puVar11 = puVar9;
      for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(puVar9 + 0x97) >> 4; iVar6 = iVar6 + 1) {
        puVar7[0xe] = puVar7[2];
        puVar7[0xf] = (uint)(fVar2 + (float)puVar7[3] + (float)puVar11[0x2a]);
        puVar7[0x10] = puVar7[4];
        puVar7 = puVar7 + 3;
        puVar11 = puVar11 + 1;
      }
    }
    if (puVar5[0x22] == 1) {
      uVar1 = *(uint *)(puVar5 + 0xc);
      puVar9[8] = uVar1;
      puVar9[0x14] = uVar1;
      fVar2 = lbl_803E133C + *(float *)(puVar5 + 0xe);
      puVar9[9] = (uint)fVar2;
      puVar9[0x15] = (uint)fVar2;
      uVar1 = *(uint *)(puVar5 + 0x10);
      puVar9[10] = uVar1;
      puVar9[0x16] = uVar1;
    }
    *(undefined *)(puVar9 + 0x98) = 0;
    *(undefined *)((int)puVar9 + 0x25f) = 0;
    fVar3 = lbl_803E1324;
    puVar9[0x6f] = (uint)lbl_803E1324;
    puVar9[0x6e] = (uint)fVar3;
    fVar4 = lbl_803E1328;
    puVar9[0x6c] = (uint)lbl_803E1328;
    fVar2 = lbl_803E12E8;
    puVar9[0x6d] = (uint)lbl_803E12E8;
    puVar9[0x6b] = (uint)fVar2;
    puVar9[0x36] = 0;
    puVar7 = puVar9;
    for (iVar6 = 0; iVar6 < (int)(uint)*(byte *)(puVar9 + 0x97) >> 4; iVar6 = iVar6 + 1) {
      puVar7[0x80] = (uint)fVar3;
      puVar7[0x7c] = (uint)fVar3;
      puVar7[0x74] = (uint)fVar4;
      puVar7 = puVar7 + 1;
    }
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e5428
 * EN v1.0 Address: 0x800E5428
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x800E6A30
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e5428(void)
{
  float fVar1;
  ushort *puVar2;
  uint uVar3;
  uint *puVar4;
  uint *puVar5;
  float *pfVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  ushort local_78;
  ushort local_76;
  ushort local_74;
  float local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  float afStack_60 [24];
  
  uVar10 = FUN_8028683c();
  puVar2 = (ushort *)((ulonglong)uVar10 >> 0x20);
  puVar5 = (uint *)uVar10;
  uVar3 = *puVar5;
  if (((uVar3 & 0x4000000) != 0) && ((uVar3 & 8) != 0)) {
    local_78 = *puVar2;
    if ((uVar3 & 0x20) == 0) {
      local_76 = puVar2[1];
      local_74 = puVar2[2];
    }
    else {
      local_76 = 0;
      local_74 = 0;
    }
    local_70 = lbl_803E130C;
    local_6c = *(undefined4 *)(puVar2 + 6);
    local_68 = *(undefined4 *)(puVar2 + 8);
    local_64 = *(undefined4 *)(puVar2 + 10);
    FUN_80017754(afStack_60,&local_78);
    iVar9 = 0;
    iVar7 = 0;
    puVar4 = puVar5;
    for (iVar8 = 0; fVar1 = lbl_803E130C, iVar8 < (int)(*(byte *)(puVar5 + 0x97) & 0xf);
        iVar8 = iVar8 + 1) {
      pfVar6 = (float *)(puVar5[0x37] + iVar7);
      FUN_80017778((double)*pfVar6,(double)pfVar6[1],(double)pfVar6[2],afStack_60,
                   (float *)(puVar4 + 0x39),(float *)(puVar5 + iVar9 + 0x3a),
                   (float *)(puVar5 + iVar9 + 0x3b));
      puVar4 = puVar4 + 3;
      iVar7 = iVar7 + 0xc;
      iVar9 = iVar9 + 3;
    }
    puVar4 = puVar5;
    for (iVar7 = 0; iVar7 < (int)(*(byte *)(puVar5 + 0x97) & 0xf); iVar7 = iVar7 + 1) {
      puVar4[0x45] = puVar4[0x39];
      puVar4[0x46] = (uint)(fVar1 + (float)puVar4[0x3a]);
      puVar4[0x47] = puVar4[0x3b];
      puVar4 = puVar4 + 3;
    }
    FUN_80061fc8((int)puVar2);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e5570
 * EN v1.0 Address: 0x800E5570
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x800E6BA0
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e5570(void)
{
  float fVar1;
  ushort *puVar2;
  uint uVar3;
  uint *puVar4;
  float *pfVar5;
  uint *puVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  undefined8 uVar10;
  ushort local_78;
  ushort local_76;
  ushort local_74;
  float local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  float afStack_60 [24];
  
  uVar10 = FUN_8028683c();
  puVar2 = (ushort *)((ulonglong)uVar10 >> 0x20);
  puVar4 = (uint *)uVar10;
  FUN_800e514c();
  uVar3 = *puVar4;
  if (((uVar3 & 0x4000000) != 0) && ((uVar3 & 8) != 0)) {
    local_78 = *puVar2;
    if ((uVar3 & 0x20) == 0) {
      local_76 = puVar2[1];
      local_74 = puVar2[2];
    }
    else {
      local_76 = 0;
      local_74 = 0;
    }
    local_70 = lbl_803E130C;
    local_6c = *(undefined4 *)(puVar2 + 6);
    local_68 = *(undefined4 *)(puVar2 + 8);
    local_64 = *(undefined4 *)(puVar2 + 10);
    FUN_80017754(afStack_60,&local_78);
    iVar9 = 0;
    iVar7 = 0;
    puVar6 = puVar4;
    for (iVar8 = 0; fVar1 = lbl_803E130C, iVar8 < (int)(*(byte *)(puVar4 + 0x97) & 0xf);
        iVar8 = iVar8 + 1) {
      pfVar5 = (float *)(puVar4[0x37] + iVar7);
      FUN_80017778((double)*pfVar5,(double)pfVar5[1],(double)pfVar5[2],afStack_60,
                   (float *)(puVar6 + 0x39),(float *)(puVar4 + iVar9 + 0x3a),
                   (float *)(puVar4 + iVar9 + 0x3b));
      puVar6 = puVar6 + 3;
      iVar7 = iVar7 + 0xc;
      iVar9 = iVar9 + 3;
    }
    puVar6 = puVar4;
    for (iVar7 = 0; iVar7 < (int)(*(byte *)(puVar4 + 0x97) & 0xf); iVar7 = iVar7 + 1) {
      puVar6[0x45] = puVar6[0x39];
      puVar6[0x46] = (uint)(fVar1 + (float)puVar6[0x3a]);
      puVar6[0x47] = puVar6[0x3b];
      puVar6 = puVar6 + 3;
    }
    FUN_80061fc8((int)puVar2);
  }
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e56bc
 * EN v1.0 Address: 0x800E56BC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800E6D14
 * EN v1.1 Size: 168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_800e56bc(undefined8 param_1,double param_2,double param_3,double param_4,int param_5)
{
    return 0.0;
}

/*
 * --INFO--
 *
 * Function: curves_getCurves
 * EN v1.0 Address: 0x800E56C4
 * EN v1.0 Size: 500b
 * EN v1.1 Address: 0x800E6DBC
 * EN v1.1 Size: 428b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 *
curves_getCurves(undefined8 param_1,double param_2,int param_3,undefined4 *param_4,int param_5)
{
  int iVar1;
  undefined4 *puVar2;
  uint uVar3;
  uint uVar4;
  int *local_18 [5];
  
  if (param_3 != DAT_803de0fc) {
    if (param_5 == 0) {
      iVar1 = -2;
    }
    else {
      iVar1 = 1;
    }
    DAT_803de0fc = param_3;
    DAT_803de0f8 = FUN_800632f4(param_1,(double)*(float *)(param_3 + 0x1c),param_2,param_3,local_18,
                                iVar1,0);
    if (0x23 < (int)DAT_803de0f8) {
      DAT_803de0f8 = 0x23;
    }
    uVar3 = DAT_803de0f8;
    puVar2 = &DAT_803a3898;
    if (0 < (int)DAT_803de0f8) {
      uVar4 = DAT_803de0f8 >> 1;
      if (uVar4 != 0) {
        do {
          *puVar2 = *(undefined4 *)*local_18[0];
          puVar2[1] = *(undefined4 *)(*local_18[0] + 4);
          puVar2[2] = *(undefined4 *)(*local_18[0] + 8);
          puVar2[3] = *(undefined4 *)(*local_18[0] + 0xc);
          puVar2[4] = *(undefined4 *)(*local_18[0] + 0x10);
          *(undefined *)(puVar2 + 5) = *(undefined *)(*local_18[0] + 0x14);
          puVar2[6] = *(undefined4 *)local_18[0][1];
          puVar2[7] = *(undefined4 *)(local_18[0][1] + 4);
          puVar2[8] = *(undefined4 *)(local_18[0][1] + 8);
          puVar2[9] = *(undefined4 *)(local_18[0][1] + 0xc);
          puVar2[10] = *(undefined4 *)(local_18[0][1] + 0x10);
          *(undefined *)(puVar2 + 0xb) = *(undefined *)(local_18[0][1] + 0x14);
          local_18[0] = local_18[0] + 2;
          puVar2 = puVar2 + 0xc;
          uVar4 = uVar4 - 1;
        } while (uVar4 != 0);
        uVar3 = uVar3 & 1;
        if (uVar3 == 0) goto LAB_800e6f44;
      }
      do {
        *puVar2 = *(undefined4 *)*local_18[0];
        puVar2[1] = *(undefined4 *)(*local_18[0] + 4);
        puVar2[2] = *(undefined4 *)(*local_18[0] + 8);
        puVar2[3] = *(undefined4 *)(*local_18[0] + 0xc);
        puVar2[4] = *(undefined4 *)(*local_18[0] + 0x10);
        *(undefined *)(puVar2 + 5) = *(undefined *)(*local_18[0] + 0x14);
        local_18[0] = local_18[0] + 1;
        puVar2 = puVar2 + 6;
        uVar3 = uVar3 - 1;
      } while (uVar3 != 0);
    }
  }
LAB_800e6f44:
  *param_4 = DAT_803de0f8;
  return &DAT_803a3898;
}

/*
 * --INFO--
 *
 * Function: FUN_800e58b8
 * EN v1.0 Address: 0x800E58B8
 * EN v1.0 Size: 2184b
 * EN v1.1 Address: 0x800E6F68
 * EN v1.1 Size: 2472b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e58b8(void)
{
  byte bVar1;
  float fVar2;
  float fVar3;
  ushort *puVar4;
  ushort uVar6;
  undefined uVar7;
  uint uVar5;
  uint *puVar8;
  float *pfVar9;
  uint *puVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  double extraout_f1;
  double in_f31;
  double dVar14;
  double in_ps31_1;
  undefined8 uVar15;
  ushort local_1e8;
  ushort local_1e6;
  ushort local_1e4;
  float local_1e0;
  undefined4 local_1dc;
  undefined4 local_1d8;
  undefined4 local_1d4;
  ushort local_1d0;
  ushort local_1ce;
  ushort local_1cc;
  float local_1c8;
  undefined4 local_1c4;
  undefined4 local_1c0;
  undefined4 local_1bc;
  ushort local_1b8;
  ushort local_1b6;
  ushort local_1b4;
  float local_1b0;
  undefined4 local_1ac;
  undefined4 local_1a8;
  undefined4 local_1a4;
  ushort local_1a0;
  ushort local_19e;
  ushort local_19c;
  float local_198;
  undefined4 local_194;
  undefined4 local_190;
  undefined4 local_18c;
  ushort local_188;
  ushort local_186;
  ushort local_184;
  float local_180;
  undefined4 local_17c;
  undefined4 local_178;
  undefined4 local_174;
  float afStack_170 [16];
  float afStack_130 [16];
  float afStack_f0 [16];
  float afStack_b0 [16];
  float afStack_70 [26];
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar15 = FUN_8028683c();
  fVar3 = lbl_803E130C;
  puVar4 = (ushort *)((ulonglong)uVar15 >> 0x20);
  puVar8 = (uint *)uVar15;
  if ((*puVar8 & 0x4000000) == 0) goto LAB_800e78f0;
  dVar14 = (double)(float)((double)lbl_803E130C / extraout_f1);
  puVar8[0x36] = 0;
  fVar2 = lbl_803E12E8;
  if (*(char *)((int)puVar8 + 0x25b) == '\x01') {
    DAT_803de0fc = 0;
    DAT_803de0f8 = 0;
    puVar8[0x68] = (uint)lbl_803E12E8;
    puVar8[0x69] = (uint)fVar3;
    puVar8[0x6a] = (uint)fVar2;
    if (((*puVar8 & 8) != 0) && ((*(byte *)(puVar8 + 0x97) & 0xf) != 0)) {
      local_188 = *puVar4;
      if ((*puVar8 & 0x20) == 0) {
        local_186 = puVar4[1];
        local_184 = puVar4[2];
      }
      else {
        local_186 = 0;
        local_184 = 0;
      }
      local_180 = lbl_803E130C;
      local_17c = *(undefined4 *)(puVar4 + 6);
      local_178 = *(undefined4 *)(puVar4 + 8);
      local_174 = *(undefined4 *)(puVar4 + 10);
      FUN_80017754(afStack_70,&local_188);
      iVar13 = 0;
      iVar11 = 0;
      puVar10 = puVar8;
      for (iVar12 = 0; iVar12 < (int)(*(byte *)(puVar8 + 0x97) & 0xf); iVar12 = iVar12 + 1) {
        pfVar9 = (float *)(puVar8[0x37] + iVar11);
        FUN_80017778((double)*pfVar9,(double)pfVar9[1],(double)pfVar9[2],afStack_70,
                     (float *)(puVar10 + 0x39),(float *)(puVar8 + iVar13 + 0x3a),
                     (float *)(puVar8 + iVar13 + 0x3b));
        puVar10 = puVar10 + 3;
        iVar11 = iVar11 + 0xc;
        iVar13 = iVar13 + 3;
      }
      FUN_800e4dbc();
      iVar11 = *(int *)(puVar4 + 0x18);
      if (iVar11 == 0) {
        *(undefined4 *)(puVar4 + 0xc) = *(undefined4 *)(puVar4 + 6);
        *(undefined4 *)(puVar4 + 0xe) = *(undefined4 *)(puVar4 + 8);
        *(undefined4 *)(puVar4 + 0x10) = *(undefined4 *)(puVar4 + 10);
      }
      else if ((*(int *)(iVar11 + 0x58) == 0) || (uVar6 = ObjHits_IsObjectEnabled(iVar11), uVar6 == 0)) {
        FUN_800068f8((double)*(float *)(puVar4 + 6),(double)*(float *)(puVar4 + 8),
                     (double)*(float *)(puVar4 + 10),(float *)(puVar4 + 0xc),(float *)(puVar4 + 0xe)
                     ,(float *)(puVar4 + 0x10),*(int *)(puVar4 + 0x18));
      }
      else {
        FUN_80017778((double)*(float *)(puVar4 + 6),(double)*(float *)(puVar4 + 8),
                     (double)*(float *)(puVar4 + 10),
                     (float *)(*(int *)(*(int *)(puVar4 + 0x18) + 0x58) +
                              (*(byte *)(*(int *)(*(int *)(puVar4 + 0x18) + 0x58) + 0x10c) + 2) *
                              0x40),(float *)(puVar4 + 0xc),(float *)(puVar4 + 0xe),
                     (float *)(puVar4 + 0x10));
      }
    }
    if (((*puVar8 & 0x2000) != 0) && ((*(byte *)(puVar8 + 0x97) & 0xf0) != 0)) {
      local_1a0 = *puVar4;
      if ((*puVar8 & 0x20) == 0) {
        local_19e = puVar4[1];
        local_19c = puVar4[2];
      }
      else {
        local_19e = 0;
        local_19c = 0;
      }
      local_198 = lbl_803E130C;
      local_194 = *(undefined4 *)(puVar4 + 0xc);
      local_190 = *(undefined4 *)(puVar4 + 0xe);
      local_18c = *(undefined4 *)(puVar4 + 0x10);
      FUN_80017754(afStack_b0,&local_1a0);
      iVar12 = 0;
      iVar11 = 0;
      puVar10 = puVar8;
      for (iVar13 = 0; iVar13 < (int)(uint)*(byte *)(puVar8 + 0x97) >> 4; iVar13 = iVar13 + 1) {
        pfVar9 = (float *)(puVar8[1] + iVar11);
        FUN_80017778((double)*pfVar9,(double)pfVar9[1],(double)pfVar9[2],afStack_b0,
                     (float *)(puVar10 + 2),(float *)(puVar8 + iVar12 + 3),
                     (float *)(puVar8 + iVar12 + 4));
        *(undefined *)((int)puVar8 + iVar13 + 0xb8) = 0xff;
        puVar10 = puVar10 + 3;
        iVar11 = iVar11 + 0xc;
        iVar12 = iVar12 + 3;
      }
      if ((*puVar8 & 2) != 0) {
        uVar7 = FUN_80063a68();
        *(undefined *)(puVar8 + 0x98) = uVar7;
        *(char *)((int)puVar8 + 0x261) = (char)*(undefined2 *)(puVar8 + 0x35);
        *(undefined *)((int)puVar8 + 0x25f) = 0;
      }
      bVar1 = *(byte *)((int)puVar8 + 0x262);
      if (bVar1 == 3) {
          curves_countRandomPoints();
      }
      else if (bVar1 < 3) {
        if (bVar1 == 1) {
          FUN_800e49c0((int)puVar4,puVar8);
        }
        else {
LAB_800e7350:
          FUN_800e49c4();
        }
      }
      else {
        if (4 < bVar1) goto LAB_800e7350;
        puVar8[0x68] = puVar8[0x1a];
        puVar8[0x69] = puVar8[0x1b];
        puVar8[0x6a] = puVar8[0x1c];
        if (((*(byte *)(puVar8 + 0x98) & 1) != 0) && (*(char *)(puVar8 + 0x2e) == '!')) {
          *(uint *)(puVar4 + 0xc) = puVar8[2];
          *(uint *)(puVar4 + 0xe) = puVar8[3];
          *(uint *)(puVar4 + 0x10) = puVar8[4];
        }
      }
      if ((*puVar8 & 0x100) != 0) {
        FUN_800e4db4((int)puVar4,(int)puVar8);
      }
      if ((*puVar8 & 0x80) != 0) {
        FUN_800e4c64((short *)puVar4,(int)puVar8);
      }
      if ((*puVar8 & 1) != 0) {
        FUN_800e4db8((int)puVar4,(int)puVar8);
      }
      FUN_80003494((uint)(puVar8 + 0xe),(uint)(puVar8 + 2),
                   ((int)(uint)*(byte *)(puVar8 + 0x97) >> 4) * 0xc);
    }
    if ((*puVar8 & 0x800) != 0) {
      if (0x3400 < (short)puVar4[1]) {
        puVar4[1] = 0x3400;
      }
      if ((short)puVar4[1] < -0x3400) {
        puVar4[1] = 0xcc00;
      }
    }
    if ((*puVar8 & 0x1000) != 0) {
      if (0x3400 < (short)puVar4[2]) {
        puVar4[2] = 0x3400;
      }
      if ((short)puVar4[2] < -0x3400) {
        puVar4[2] = 0xcc00;
      }
    }
    if ((*puVar8 & 0x40000) == 0) {
      iVar11 = *(int *)(puVar4 + 0x2a);
      if ((iVar11 == 0) || ((*(ushort *)(iVar11 + 0x60) & 1) == 0)) {
        *(float *)(puVar4 + 0x14) =
             (float)(dVar14 * (double)(*(float *)(puVar4 + 0xe) - *(float *)(puVar4 + 0x48)));
      }
      else {
        *(float *)(puVar4 + 0x14) =
             (float)(dVar14 * (double)(*(float *)(puVar4 + 0xe) - *(float *)(iVar11 + 0x20)));
        if (*(float *)(*(int *)(puVar4 + 0x2a) + 0x20) < *(float *)(puVar4 + 0xe)) {
          *(float *)(puVar4 + 0x14) = lbl_803E12E8;
        }
      }
    }
  }
  else if (*(char *)((int)puVar8 + 0x25b) == '\x02') {
    FUN_800e514c();
    uVar5 = *puVar8;
    if (((uVar5 & 0x4000000) != 0) && ((uVar5 & 8) != 0)) {
      local_1d0 = *puVar4;
      if ((uVar5 & 0x20) == 0) {
        local_1ce = puVar4[1];
        local_1cc = puVar4[2];
      }
      else {
        local_1ce = 0;
        local_1cc = 0;
      }
      local_1c8 = lbl_803E130C;
      local_1c4 = *(undefined4 *)(puVar4 + 6);
      local_1c0 = *(undefined4 *)(puVar4 + 8);
      local_1bc = *(undefined4 *)(puVar4 + 10);
      FUN_80017754(afStack_130,&local_1d0);
      iVar12 = 0;
      iVar11 = 0;
      puVar10 = puVar8;
      for (iVar13 = 0; fVar3 = lbl_803E130C, iVar13 < (int)(*(byte *)(puVar8 + 0x97) & 0xf);
          iVar13 = iVar13 + 1) {
        pfVar9 = (float *)(puVar8[0x37] + iVar11);
        FUN_80017778((double)*pfVar9,(double)pfVar9[1],(double)pfVar9[2],afStack_130,
                     (float *)(puVar10 + 0x39),(float *)(puVar8 + iVar12 + 0x3a),
                     (float *)(puVar8 + iVar12 + 0x3b));
        puVar10 = puVar10 + 3;
        iVar11 = iVar11 + 0xc;
        iVar12 = iVar12 + 3;
      }
      puVar10 = puVar8;
      for (iVar11 = 0; iVar11 < (int)(*(byte *)(puVar8 + 0x97) & 0xf); iVar11 = iVar11 + 1) {
        puVar10[0x45] = puVar10[0x39];
        puVar10[0x46] = (uint)(fVar3 + (float)puVar10[0x3a]);
        puVar10[0x47] = puVar10[0x3b];
        puVar10 = puVar10 + 3;
      }
      FUN_80061fc8((int)puVar4);
    }
    if ((*puVar8 & 0x2000) != 0) {
      local_1b8 = *puVar4;
      if ((*puVar8 & 0x20) == 0) {
        local_1b6 = puVar4[1];
        local_1b4 = puVar4[2];
      }
      else {
        local_1b6 = 0;
        local_1b4 = 0;
      }
      local_1b0 = lbl_803E130C;
      local_1ac = *(undefined4 *)(puVar4 + 0xc);
      local_1a8 = *(undefined4 *)(puVar4 + 0xe);
      local_1a4 = *(undefined4 *)(puVar4 + 0x10);
      FUN_80017754(afStack_f0,&local_1b8);
      iVar12 = 0;
      iVar11 = 0;
      puVar10 = puVar8;
      for (iVar13 = 0; iVar13 < (int)(uint)*(byte *)(puVar8 + 0x97) >> 4; iVar13 = iVar13 + 1) {
        pfVar9 = (float *)(puVar8[1] + iVar11);
        FUN_80017778((double)*pfVar9,(double)pfVar9[1],(double)pfVar9[2],afStack_f0,
                     (float *)(puVar10 + 2),(float *)(puVar8 + iVar12 + 3),
                     (float *)(puVar8 + iVar12 + 4));
        *(undefined *)((int)puVar8 + iVar13 + 0xb8) = 0xff;
        puVar10 = puVar10 + 3;
        iVar11 = iVar11 + 0xc;
        iVar12 = iVar12 + 3;
      }
      FUN_80003494((uint)(puVar8 + 0xe),(uint)(puVar8 + 2),
                   ((int)(uint)*(byte *)(puVar8 + 0x97) >> 4) * 0xc);
      if ((*puVar8 & 1) != 0) {
        FUN_800e4db8((int)puVar4,(int)puVar8);
      }
    }
  }
  else {
    FUN_800e514c();
    uVar5 = *puVar8;
    if (((uVar5 & 0x4000000) != 0) && ((uVar5 & 8) != 0)) {
      local_1e8 = *puVar4;
      if ((uVar5 & 0x20) == 0) {
        local_1e6 = puVar4[1];
        local_1e4 = puVar4[2];
      }
      else {
        local_1e6 = 0;
        local_1e4 = 0;
      }
      local_1e0 = lbl_803E130C;
      local_1dc = *(undefined4 *)(puVar4 + 6);
      local_1d8 = *(undefined4 *)(puVar4 + 8);
      local_1d4 = *(undefined4 *)(puVar4 + 10);
      FUN_80017754(afStack_170,&local_1e8);
      iVar12 = 0;
      iVar11 = 0;
      puVar10 = puVar8;
      for (iVar13 = 0; fVar3 = lbl_803E130C, iVar13 < (int)(*(byte *)(puVar8 + 0x97) & 0xf);
          iVar13 = iVar13 + 1) {
        pfVar9 = (float *)(puVar8[0x37] + iVar11);
        FUN_80017778((double)*pfVar9,(double)pfVar9[1],(double)pfVar9[2],afStack_170,
                     (float *)(puVar10 + 0x39),(float *)(puVar8 + iVar12 + 0x3a),
                     (float *)(puVar8 + iVar12 + 0x3b));
        puVar10 = puVar10 + 3;
        iVar11 = iVar11 + 0xc;
        iVar12 = iVar12 + 3;
      }
      puVar10 = puVar8;
      for (iVar11 = 0; iVar11 < (int)(*(byte *)(puVar8 + 0x97) & 0xf); iVar11 = iVar11 + 1) {
        puVar10[0x45] = puVar10[0x39];
        puVar10[0x46] = (uint)(fVar3 + (float)puVar10[0x3a]);
        puVar10[0x47] = puVar10[0x3b];
        puVar10 = puVar10 + 3;
      }
      FUN_80061fc8((int)puVar4);
    }
  }
  iVar11 = *(int *)(puVar4 + 0x18);
  if (iVar11 == 0) {
    *(undefined4 *)(puVar4 + 6) = *(undefined4 *)(puVar4 + 0xc);
    *(undefined4 *)(puVar4 + 8) = *(undefined4 *)(puVar4 + 0xe);
    *(undefined4 *)(puVar4 + 10) = *(undefined4 *)(puVar4 + 0x10);
  }
  else if ((*(int *)(iVar11 + 0x58) == 0) || (uVar6 = ObjHits_IsObjectEnabled(iVar11), uVar6 == 0)) {
    FUN_800068f4((double)*(float *)(puVar4 + 0xc),(double)*(float *)(puVar4 + 0xe),
                 (double)*(float *)(puVar4 + 0x10),(float *)(puVar4 + 6),(float *)(puVar4 + 8),
                 (float *)(puVar4 + 10),*(int *)(puVar4 + 0x18));
  }
  else {
    FUN_80017778((double)*(float *)(puVar4 + 0xc),(double)*(float *)(puVar4 + 0xe),
                 (double)*(float *)(puVar4 + 0x10),
                 (float *)(*(int *)(*(int *)(puVar4 + 0x18) + 0x58) +
                          (uint)*(byte *)(*(int *)(*(int *)(puVar4 + 0x18) + 0x58) + 0x10c) * 0x40),
                 (float *)(puVar4 + 6),(float *)(puVar4 + 8),(float *)(puVar4 + 10));
  }
LAB_800e78f0:
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e6140
 * EN v1.0 Address: 0x800E6140
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x800E7910
 * EN v1.1 Size: 144b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e6140(undefined4 param_1,uint *param_2)
{
  uint uVar1;
  uint uVar2;
  
  uVar2 = *param_2;
  if ((((uVar2 & 0x4000000) != 0) && ((uVar2 & 0x2000) != 0)) &&
     ((*(char *)((int)param_2 + 0x25b) == '\x01' || (*(char *)((int)param_2 + 0x25b) == '\x02')))) {
    uVar1 = (uint)((uVar2 & 4) != 0);
    if ((uVar2 & 0x1000000) != 0) {
      uVar1 = uVar1 | 0x20;
    }
    FUN_80063a74(param_1,param_2 + 0x90,uVar1,'\x01');
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e61a4
 * EN v1.0 Address: 0x800E61A4
 * EN v1.0 Size: 1060b
 * EN v1.1 Address: 0x800E79A0
 * EN v1.1 Size: 1384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e61a4(void)
{
  uint uVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  float fVar9;
  uint *puVar10;
  int iVar11;
  ushort *puVar12;
  int iVar13;
  ushort uVar14;
  uint *puVar15;
  float *pfVar16;
  int iVar17;
  float *pfVar18;
  float *pfVar19;
  float *pfVar20;
  uint *puVar21;
  int iVar22;
  float *pfVar23;
  double dVar24;
  double in_f31;
  double dVar25;
  double in_ps31_1;
  undefined8 uVar26;
  float local_118 [4];
  ushort local_108;
  ushort local_106;
  ushort local_104;
  float local_100;
  undefined4 local_fc;
  undefined4 local_f8;
  undefined4 local_f4;
  float local_f0 [12];
  float afStack_c0 [16];
  longlong local_80;
  longlong local_78;
  undefined4 local_70;
  uint uStack_6c;
  longlong local_68;
  undefined4 local_60;
  uint uStack_5c;
  longlong local_58;
  longlong local_50;
  longlong local_48;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar26 = FUN_80286830();
  puVar12 = (ushort *)((ulonglong)uVar26 >> 0x20);
  puVar15 = (uint *)uVar26;
  if (((*(char *)((int)puVar15 + 0x25b) != '\0') && ((*puVar15 & 0x4000000) != 0)) &&
     ((*puVar15 & 0x2000) != 0)) {
    iVar13 = *(int *)(puVar12 + 0x18);
    if (iVar13 == 0) {
      *(undefined4 *)(puVar12 + 0xc) = *(undefined4 *)(puVar12 + 6);
      *(undefined4 *)(puVar12 + 0xe) = *(undefined4 *)(puVar12 + 8);
      *(undefined4 *)(puVar12 + 0x10) = *(undefined4 *)(puVar12 + 10);
    }
    else if ((*(int *)(iVar13 + 0x58) == 0) || (uVar14 = ObjHits_IsObjectEnabled(iVar13), uVar14 == 0)) {
      FUN_800068f8((double)*(float *)(puVar12 + 6),(double)*(float *)(puVar12 + 8),
                   (double)*(float *)(puVar12 + 10),(float *)(puVar12 + 0xc),
                   (float *)(puVar12 + 0xe),(float *)(puVar12 + 0x10),*(int *)(puVar12 + 0x18));
    }
    else {
      FUN_80017778((double)*(float *)(puVar12 + 6),(double)*(float *)(puVar12 + 8),
                   (double)*(float *)(puVar12 + 10),
                   (float *)(*(int *)(*(int *)(puVar12 + 0x18) + 0x58) +
                            (*(byte *)(*(int *)(*(int *)(puVar12 + 0x18) + 0x58) + 0x10c) + 2) *
                            0x40),(float *)(puVar12 + 0xc),(float *)(puVar12 + 0xe),
                   (float *)(puVar12 + 0x10));
    }
    local_108 = *puVar12;
    if ((*puVar15 & 0x20) == 0) {
      local_106 = puVar12[1];
      local_104 = puVar12[2];
    }
    else {
      local_106 = 0;
      local_104 = 0;
    }
    local_100 = lbl_803E130C;
    local_fc = *(undefined4 *)(puVar12 + 0xc);
    local_f8 = *(undefined4 *)(puVar12 + 0xe);
    local_f4 = *(undefined4 *)(puVar12 + 0x10);
    FUN_80017754(afStack_c0,&local_108);
    iVar13 = 0;
    pfVar18 = local_f0;
    iVar22 = 0;
    pfVar19 = local_118;
    dVar25 = (double)lbl_803E1340;
    pfVar20 = pfVar19;
    puVar21 = puVar15;
    pfVar23 = pfVar18;
    for (iVar17 = 0; iVar11 = (int)(uint)*(byte *)(puVar15 + 0x97) >> 4, puVar10 = puVar15,
        fVar3 = lbl_803E1324, fVar4 = lbl_803E1324, fVar5 = lbl_803E1324,
        fVar6 = lbl_803E1328, fVar7 = lbl_803E1328, fVar8 = lbl_803E1328, iVar17 < iVar11;
        iVar17 = iVar17 + 1) {
      pfVar16 = (float *)(puVar15[1] + iVar22);
      FUN_80017778((double)*pfVar16,(double)pfVar16[1],(double)pfVar16[2],afStack_c0,pfVar23,
                   local_f0 + iVar13 + 1,local_f0 + iVar13 + 2);
      *pfVar20 = (float)puVar21[0x2a];
      dVar24 = FUN_80293900((double)(float)((double)(float)(dVar25 * (double)*pfVar20) *
                                           (double)*pfVar20));
      *pfVar20 = (float)dVar24;
      pfVar23 = pfVar23 + 3;
      iVar22 = iVar22 + 0xc;
      iVar13 = iVar13 + 3;
      puVar21 = puVar21 + 1;
      pfVar20 = pfVar20 + 1;
    }
    for (; iVar11 != 0; iVar11 = iVar11 + -1) {
      fVar2 = *pfVar19;
      fVar9 = *pfVar18 + fVar2;
      if (fVar3 < fVar9) {
        fVar3 = fVar9;
      }
      fVar9 = *pfVar18 - fVar2;
      if (fVar9 < fVar6) {
        fVar6 = fVar9;
      }
      fVar9 = pfVar18[1] + fVar2;
      if (fVar5 < fVar9) {
        fVar5 = fVar9;
      }
      fVar9 = pfVar18[1] - fVar2;
      if (fVar9 < fVar8) {
        fVar8 = fVar9;
      }
      fVar9 = pfVar18[2] + fVar2;
      if (fVar4 < fVar9) {
        fVar4 = fVar9;
      }
      fVar9 = pfVar18[2] - fVar2;
      if (fVar9 < fVar7) {
        fVar7 = fVar9;
      }
      fVar9 = (float)puVar10[0xe] + fVar2;
      if (fVar3 < fVar9) {
        fVar3 = fVar9;
      }
      fVar9 = (float)puVar10[0xe] - fVar2;
      if (fVar9 < fVar6) {
        fVar6 = fVar9;
      }
      fVar9 = (float)puVar10[0xf] + fVar2;
      if (fVar5 < fVar9) {
        fVar5 = fVar9;
      }
      fVar9 = (float)puVar10[0xf] - fVar2;
      if (fVar9 < fVar8) {
        fVar8 = fVar9;
      }
      fVar9 = (float)puVar10[0x10] + fVar2;
      if (fVar4 < fVar9) {
        fVar4 = fVar9;
      }
      fVar2 = (float)puVar10[0x10] - fVar2;
      if (fVar2 < fVar7) {
        fVar7 = fVar2;
      }
      pfVar18 = pfVar18 + 3;
      pfVar19 = pfVar19 + 1;
      puVar10 = puVar10 + 3;
    }
    local_80 = (longlong)(int)fVar6;
    puVar15[0x90] = (int)fVar6;
    local_78 = (longlong)(int)fVar3;
    puVar15[0x93] = (int)fVar3;
    dVar25 = DOUBLE_803e1318;
    uStack_6c = (uint)*(byte *)(puVar15 + 0x96);
    local_70 = 0x43300000;
    uVar1 = (uint)(fVar8 - (float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e1318));
    local_68 = (longlong)(int)uVar1;
    puVar15[0x91] = uVar1;
    uStack_5c = (uint)*(byte *)(puVar15 + 0x96);
    local_60 = 0x43300000;
    uVar1 = (uint)(fVar5 + (float)((double)CONCAT44(0x43300000,uStack_5c) - dVar25));
    local_58 = (longlong)(int)uVar1;
    puVar15[0x94] = uVar1;
    local_50 = (longlong)(int)fVar7;
    puVar15[0x92] = (int)fVar7;
    local_48 = (longlong)(int)fVar4;
    puVar15[0x95] = (int)fVar4;
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800e65c8
 * EN v1.0 Address: 0x800E65C8
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x800E7F08
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800e65c8(uint *param_1,byte param_2,uint param_3,uint param_4,undefined param_5,
                 undefined param_6)
{
  *(byte *)(param_1 + 0x97) = *(byte *)(param_1 + 0x97) & 0xf0;
  *(byte *)(param_1 + 0x97) = *(byte *)(param_1 + 0x97) | param_2 & 0xf;
  *(undefined *)((int)param_1 + 0x25d) = param_5;
  *(undefined *)((int)param_1 + 0x263) = param_6;
  param_1[0x37] = param_3;
  param_1[0x38] = param_4;
  *param_1 = *param_1 | 0x2000008;
  *(undefined *)(param_1 + 0x99) = 10;
  return;
}

/*
 * --INFO--
 *
 * Function: curves_clear
 * EN v1.0 Address: 0x800E6610
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x800E7FA4
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void curves_clear(uint *param_1,int param_2,uint param_3,int param_4)
{
  uint *curve;
  int flagsByte;
  uint flags;
  int subtype;

  curve = param_1;
  flagsByte = param_2;
  flags = param_3;
  subtype = param_4;
  memset(curve,0,0x268);
  *(s8 *)((int)curve + 0x25b) = (s8)subtype;
  *curve = flags | 0x4000000;
  *(u8 *)((int)curve + 0x262) = (u8)flagsByte;
  *(u8 *)(curve + 0x96) = 5;
  return;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: FUN_800e6680
 * EN v1.0 Address: 0x800E6680
 * EN v1.0 Size: 180b
 * EN v1.1 Address: 0x800E8024
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_800e6680(char param_1,uint param_2)
{
  uint uVar1;
  
  if (param_1 == '\0') {
    uVar1 = GameBit_Get(param_2);
  }
  else {
    uVar1 = GameBit_Get(0xbfd);
    if ((((uVar1 == 0) && (uVar1 = GameBit_Get(0xff), uVar1 == 0)) &&
        (uVar1 = GameBit_Get(0xba8), uVar1 == 0)) &&
       (((uVar1 = GameBit_Get(0xc85), uVar1 == 0 && (uVar1 = GameBit_Get(0xc6e), uVar1 == 0)) &&
        (uVar1 = GameBit_Get(0x174), uVar1 == 0)))) {
      uVar1 = 0;
    }
    else {
      uVar1 = 1;
    }
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: gameplay_setDebugOptionEnabled
 * EN v1.0 Address: 0x800E6734
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x800E80C4
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern u8 lbl_803A31C4[];
#pragma scheduling off
#pragma peephole off
void gameplay_setDebugOptionEnabled(uint param_1,u8 param_2)
{
  uint uVar1;
  u8* base = lbl_803A31C4;

  uVar1 = 1 << (param_1 & 0xff);
  if ((*(u32*)(base + 0x10) & uVar1) == 0) {
    return;
  }
  if (param_2 != 0) {
    *(u32*)(base + 0x14) = *(u32*)(base + 0x14) | uVar1;
    return;
  }
  *(u32*)(base + 0x14) = *(u32*)(base + 0x14) & ~uVar1;
  return;
}
#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */
void fn_800E542C(void) {}
void fn_800E5430(void) {}
void fn_800E7D98(void) {}
void fn_800E7D9C(void) {}

/* Pattern wrappers. */
extern u32 lbl_803DD478;
void fn_800E5420(void) { lbl_803DD478 = 0x0; }

/* *p1 = lbl1; *p2 = lbl2; (u32) */
extern u32 lbl_803DD474;
extern u32 lbl_803DD470;
void fn_800E36E4(u32 *p1, u32 *p2) { *p1 = lbl_803DD474; *p2 = lbl_803DD470; }
