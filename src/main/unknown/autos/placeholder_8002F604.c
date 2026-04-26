#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/objanim_internal.h"
#include "main/unknown/autos/placeholder_8002F604.h"

extern void fn_80024E7C(int animId,int moveIndex,undefined4 cache,ObjAnimDef *animDef);
extern void fn_8002C6C8(int objAnim,int objType,uint *eventTable,u32 moveId,int param_5);
extern void fn_80035774(int objAnim,int *bank,int objType,int hitState,u32 moveId,int param_6);

extern char gObjAnimSetBlendMoveMissingAnimWarning[];
extern f64 lbl_803DE8E8;
extern f64 lbl_803DE900;
extern f32 lbl_803DE8E0;
extern f32 lbl_803DE8F0;
extern f32 lbl_803DE8F4;
extern f32 lbl_803DE8F8;
extern f32 lbl_803DE908;
extern f32 lbl_803DE90C;

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
#pragma scheduling off
undefined4 ObjAnim_SampleRootCurvePhase(double distance,int objAnimArg,float *phaseOut)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
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

  objAnim = (ObjAnimComponent *)objAnimArg;
  bank = ObjAnim_GetActiveBank(objAnim);
  piVar12 = (int *)bank;
  animDef = bank->animDef;
  iVar17 = (int)animDef;
  if (animDef->moveCount != 0) {
    state = bank->secondaryState;
    iVar18 = (int)state;
    fVar5 = *(float *)(objAnimArg + 8);
    pfVar15 = (float *)0x0;
    if (*(ushort *)(iVar18 + 0x5a) != 0) {
      in_f7 = (double)((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar18 + 0x5a)) -
                              lbl_803DE8E8) / lbl_803DE8F4);
      in_f8 = (double)(float)((double)lbl_803DE8E0 - in_f7);
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
          fVar4 = (float)((double)CONCAT44(0x43300000,uVar10 ^ 0x80000000) - lbl_803DE900);
          fVar8 = lbl_803DE8E0 / fVar4;
          fVar4 = fVar4 * *(float *)(objAnimArg + 0x98);
          uVar11 = (uint)fVar4;
          fVar4 = fVar4 - (float)((double)CONCAT44(0x43300000,uVar11 ^ 0x80000000) - lbl_803DE900
                                 );
          if (pfVar15 == (float *)0x0) {
            fVar1 = fVar7 * (float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)((int)pfVar14 + uVar11 * 2 + 2)
                                                     ^ 0x80000000) - lbl_803DE900);
            fVar2 = fVar7 * (float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)((int)pfVar14 + uVar11 * 2 + 4)
                                                     ^ 0x80000000) - lbl_803DE900);
          }
          else {
            if (*(short *)((int)pfVar15 + uVar10 * 2) < 0) {
              in_f6 = -in_f6;
            }
            iVar17 = uVar11 * 2;
            local_20 = (double)CONCAT44(0x43300000,
                                        (int)*(short *)((int)pfVar15 + iVar17) ^ 0x80000000);
            fVar1 = (float)(in_f6 * (double)(float)(in_f7 * (double)(float)(local_20 -
                                                                           lbl_803DE900)) +
                           (double)(fVar7 * (float)(in_f8 * (double)(float)((double)CONCAT44(
                                                  0x43300000,
                                                  (int)*(short *)((int)pfVar14 + iVar17 + 2) ^
                                                  0x80000000) - lbl_803DE900))));
            fVar2 = (float)(in_f6 * (double)(float)(in_f7 * (double)(float)((double)CONCAT44(
                                                  0x43300000,
                                                  (int)*(short *)((int)pfVar15 + iVar17 + 2) ^
                                                  0x80000000) - lbl_803DE900)) +
                           (double)(fVar7 * (float)(in_f8 * (double)(float)((double)CONCAT44(
                                                  0x43300000,
                                                  (int)*(short *)((int)pfVar14 + iVar17 + 4) ^
                                                  0x80000000) - lbl_803DE900))));
          }
          fVar5 = (float)(distance * (double)(fVar5 / *(float *)(*(int *)(objAnimArg + 0x50) + 4))) +
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
                                                          0x80000000) - lbl_803DE900) -
                                (float)((double)CONCAT44(0x43300000,
                                                         (int)*(short *)((int)pfVar14 +
                                                                        uVar11 * 2 + 2) ^ 0x80000000
                                                        ) - lbl_803DE900));
              }
              else {
                iVar17 = uVar11 * 2;
                local_20 = (double)CONCAT44(0x43300000,
                                            (int)((short *)((int)pfVar15 + iVar17))[1] ^ 0x80000000)
                ;
                fVar3 = (float)((double)(fVar7 * ((float)((double)CONCAT44(0x43300000,
                                                                           (int)*(short *)((int)
                                                  pfVar14 + iVar17 + 4) ^ 0x80000000) -
                                                  lbl_803DE900) -
                                                 (float)((double)CONCAT44(0x43300000,
                                                                          (int)*(short *)((int)
                                                  pfVar14 + iVar17 + 2) ^ 0x80000000) -
                                                  lbl_803DE900))) * in_f8 +
                               (double)(float)((double)(float)(in_f6 * (double)((float)(local_20 -
                                                  lbl_803DE900) -
                                                  (float)((double)CONCAT44(0x43300000,
                                                                           (int)*(short *)((int)
                                                  pfVar15 + iVar17) ^ 0x80000000) - lbl_803DE900)
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
          if (phaseOut != (float *)0x0) {
            *phaseOut = fVar4;
          }
          return 1;
        }
        return 0;
      }
    }
  }
  return 0;
}
#pragma scheduling reset

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
#pragma scheduling off
undefined4 ObjAnim_AdvanceCurrentMove(double moveStepScale,double deltaTime,int objAnimArg,
                                      ObjAnimEventList *events)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
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
  undefined8 local_48;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_20;
  float *pfVar20;

  pfVar20 = (float *)events;
  dVar31 = (double)lbl_803DE90C;
  uVar18 = 0;
  if ((dVar31 <= moveStepScale) &&
     (dVar31 = moveStepScale, (double)lbl_803DE8E0 < moveStepScale)) {
    dVar31 = (double)lbl_803DE8E0;
  }
  objAnim = (ObjAnimComponent *)objAnimArg;
  bank = ObjAnim_GetActiveBank(objAnim);
  piVar22 = (int *)bank;
  animDef = bank->animDef;
  if ((animDef->moveCount != 0) &&
     (state = bank->secondaryState, iVar24 = (int)state, iVar24 != 0)) {
    *(float *)(iVar24 + 0xc) = (float)(dVar31 * (double)*(float *)(iVar24 + 0x14));
    if (*(short *)(iVar24 + 0x58) != 0) {
      if ((*(byte *)(iVar24 + 99) & 8) != 0) {
        *(undefined4 *)(iVar24 + 0x10) = *(undefined4 *)(iVar24 + 0xc);
      }
      *(float *)(iVar24 + 8) =
           (float)((double)*(float *)(iVar24 + 0x10) * deltaTime + (double)*(float *)(iVar24 + 8));
      fVar4 = lbl_803DE8F0;
      fVar3 = *(float *)(iVar24 + 0x18);
      if (*(char *)(iVar24 + 0x61) == '\0') {
        fVar4 = *(float *)(iVar24 + 8);
        fVar5 = lbl_803DE8F0;
        if ((lbl_803DE8F0 <= fVar4) && (fVar5 = fVar4, fVar3 < fVar4)) {
          fVar5 = fVar3;
        }
        *(float *)(iVar24 + 8) = fVar5;
      }
      else {
        if (*(float *)(iVar24 + 8) < lbl_803DE8F0) {
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
                                               lbl_803DE8E8) * deltaTime -
                               (double)(float)((double)CONCAT44(0x43300000,
                                                                *(ushort *)(iVar24 + 0x58) ^
                                                                0x80000000) - lbl_803DE900));
        fVar3 = lbl_803DE8F0;
        if ((-1 < (int)uVar15) &&
           (uVar15 = uVar15 ^ 0x80000000, fVar3 = lbl_803DE8F4,
           (float)((double)CONCAT44(0x43300000,uVar15) - lbl_803DE900) <= lbl_803DE8F4)) {
          local_38 = (double)CONCAT44(0x43300000,uVar15);
          fVar3 = (float)(local_38 - lbl_803DE900);
        }
        *(short *)(iVar24 + 0x58) = (short)(int)fVar3;
      }
      if (*(short *)(iVar24 + 0x58) == 0) {
        *(undefined2 *)(iVar24 + 0x5c) = 0;
      }
    }
    fVar4 = *(float *)(objAnimArg + 0x98);
    fVar3 = (float)(dVar31 * deltaTime);
    *(float *)(objAnimArg + 0x98) = fVar4 + fVar3;
    fVar6 = lbl_803DE8F0;
    fVar5 = lbl_803DE8E0;
    if (*(float *)(objAnimArg + 0x98) < lbl_803DE8E0) {
      if (*(float *)(objAnimArg + 0x98) < lbl_803DE8F0) {
        if (*(char *)(iVar24 + 0x60) == '\0') {
          *(float *)(objAnimArg + 0x98) = lbl_803DE8F0;
        }
        else {
          while (*(float *)(objAnimArg + 0x98) < fVar6) {
            *(float *)(objAnimArg + 0x98) = *(float *)(objAnimArg + 0x98) + fVar5;
          }
        }
        uVar18 = 1;
      }
    }
    else if (*(char *)(iVar24 + 0x60) == '\0') {
      *(float *)(objAnimArg + 0x98) = lbl_803DE8E0;
      uVar18 = 1;
    }
    else {
      while (fVar5 <= *(float *)(objAnimArg + 0x98)) {
        *(float *)(objAnimArg + 0x98) = *(float *)(objAnimArg + 0x98) - fVar5;
      }
      uVar18 = 1;
    }
    if (pfVar20 != (float *)0x0) {
      *(undefined *)((int)pfVar20 + 0x12) = 0;
      fVar5 = lbl_803DE8F0;
      pfVar20[2] = lbl_803DE8F0;
      pfVar20[1] = fVar5;
      *pfVar20 = fVar5;
      if (*(int *)(objAnimArg + 0x60) != 0) {
        *(undefined *)((int)pfVar20 + 0x1b) = 0;
        iVar23 = **(int **)(objAnimArg + 0x60) >> 1;
        if (iVar23 != 0) {
          iVar30 = (int)(lbl_803DE8F8 * fVar4);
          iVar26 = (int)(lbl_803DE8F8 * *(float *)(objAnimArg + 0x98));
          bVar29 = iVar26 < iVar30;
          if (fVar3 < lbl_803DE8F0) {
            bVar29 = bVar29 | 2;
          }
          iVar25 = 0;
          iVar21 = 0;
          while ((iVar25 < iVar23 && (*(char *)((int)pfVar20 + 0x1b) < '\b'))) {
            uVar16 = (uint)*(short *)(*(int *)(*(int *)(objAnimArg + 0x60) + 4) + iVar21);
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
        fVar6 = *(float *)(objAnimArg + 8);
        iVar23 = (int)*(short *)(pfVar27 + 1);
        psVar28 = (short *)((int)pfVar27 + 6);
        local_30 = (double)CONCAT44(0x43300000,iVar23 - 1U ^ 0x80000000);
        fVar7 = (float)(local_30 - lbl_803DE900) * fVar4;
        uVar15 = (uint)fVar7;
        dVar31 = (double)CONCAT44(0x43300000,uVar15 ^ 0x80000000) - lbl_803DE900;
        fVar8 = (float)(local_30 - lbl_803DE900) * *(float *)(objAnimArg + 0x98);
        uVar16 = (uint)fVar8;
        dVar1 = (double)CONCAT44(0x43300000,uVar16 ^ 0x80000000) - lbl_803DE900;
        iVar30 = 0;
        fVar11 = lbl_803DE8F0;
        fVar13 = lbl_803DE8E0;
        if (*(ushort *)(iVar24 + 0x5a) != 0) {
          local_30 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar24 + 0x5a));
          fVar11 = (float)(local_30 - lbl_803DE8E8) / lbl_803DE8F4;
          if ((*(ushort *)(*piVar22 + 2) & 0x40) == 0) {
            iVar24 = *(int *)(*(int *)(*piVar22 + 100) + (uint)*(ushort *)(iVar24 + 0x48) * 4);
          }
          else {
            iVar24 = *(int *)(iVar24 + (uint)*(ushort *)(iVar24 + 0x48) * 4 + 0x24) + 0x80;
          }
          iVar30 = iVar24 + *(short *)(iVar24 + 4) + 6;
          fVar13 = lbl_803DE8E0 - fVar11;
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
              *pfVar20 = lbl_803DE8F0;
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
            fVar9 = fVar13 * (float)(local_30 - lbl_803DE900);
            if (iVar30 != 0) {
              local_38 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(uVar15 * 2 + iVar30) ^ 0x80000000);
              fVar9 = fVar11 * (float)(local_38 - lbl_803DE900) + fVar9;
            }
            fVar10 = fVar13 * (float)((double)CONCAT44(0x43300000,
                                                       (int)(psVar28 + uVar15 + 1)[1] ^ 0x80000000)
                                     - lbl_803DE900);
            if (iVar30 != 0) {
              local_48 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(uVar15 * 2 + iVar30 + 2) ^ 0x80000000);
              fVar10 = fVar11 * (float)(local_48 - lbl_803DE900) + fVar10;
            }
            fVar12 = fVar13 * (float)((double)CONCAT44(0x43300000,
                                                       (int)psVar28[uVar16 + 1] ^ 0x80000000) -
                                     lbl_803DE900);
            if (iVar30 != 0) {
              fVar12 = fVar11 * (float)((double)CONCAT44(0x43300000,
                                                         (int)*(short *)(uVar16 * 2 + iVar30) ^
                                                         0x80000000) - lbl_803DE900) + fVar12;
            }
            fVar14 = fVar13 * (float)((double)CONCAT44(0x43300000,
                                                       (int)(psVar28 + uVar16 + 1)[1] ^ 0x80000000)
                                     - lbl_803DE900);
            if (iVar30 != 0) {
              local_20 = (double)CONCAT44(0x43300000,
                                          (int)*(short *)(uVar16 * 2 + iVar30 + 2) ^ 0x80000000);
              fVar14 = fVar11 * (float)(local_20 - lbl_803DE900) + fVar14;
            }
            fVar12 = (fVar8 - (float)dVar1) * (fVar14 - fVar12) + fVar12;
            if (fVar3 <= lbl_803DE8F0) {
              if (fVar4 < *(float *)(objAnimArg + 0x98)) {
                local_20 = (double)CONCAT44(0x43300000,(int)psVar28[iVar23] ^ 0x80000000);
                fVar12 = -(fVar13 * (float)(local_20 - lbl_803DE900) - fVar12);
                if (iVar30 != 0) {
                  local_20 = (double)CONCAT44(0x43300000,
                                              (int)*(short *)(iVar24 + iVar30) ^ 0x80000000);
                  fVar12 = fVar11 * (float)(local_20 - lbl_803DE900) + fVar12;
                }
              }
            }
            else if (*(float *)(objAnimArg + 0x98) < fVar4) {
              local_20 = (double)CONCAT44(0x43300000,(int)psVar28[iVar23] ^ 0x80000000);
              fVar12 = fVar13 * (float)(local_20 - lbl_803DE900) + fVar12;
              if (iVar30 != 0) {
                local_20 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar24 + iVar30) ^ 0x80000000
                                           );
                fVar12 = fVar11 * (float)(local_20 - lbl_803DE900) + fVar12;
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
  return uVar18;
}
#pragma scheduling reset

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
undefined4 ObjAnim_SetMoveProgress(f32 param_1,int param_2)
{
  if (param_1 > lbl_803DE908) {
    param_1 = lbl_803DE908;
  }
  else if (param_1 < lbl_803DE8F0) {
    param_1 = lbl_803DE8F0;
  }
  *(float *)(param_2 + 0x98) = param_1;
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
undefined4 ObjAnim_SetCurrentMove(double moveProgress,int objAnimArg,int moveId,u32 flags)
{
  ObjAnimComponent *objAnim;
  ObjAnimBank *bank;
  ObjAnimDef *animDef;
  ObjAnimState *state;
  s16 previousMove;
  u8 moveChanged;
  int frameStep;
  int moveIndex;
  int moveData;
  f32 clampedProgress;
  int hitState;

  objAnim = (ObjAnimComponent *)objAnimArg;
  clampedProgress = (float)moveProgress;
  if (lbl_803DE8E0 < clampedProgress) {
    clampedProgress = lbl_803DE8E0;
  }
  else if (clampedProgress < lbl_803DE8F0) {
    clampedProgress = lbl_803DE8F0;
  }
  objAnim->currentMoveProgress = clampedProgress;
  bank = ObjAnim_GetActiveBank(objAnim);
  if (bank == (ObjAnimBank *)0x0) {
    return 0;
  }
  animDef = bank->animDef;
  if (animDef->moveCount == 0) {
    return 0;
  }
  state = bank->secondaryState;
  state->flags = (s8)flags;
  state->prevMoveCacheSlot = state->moveCacheSlot;
  state->progress = state->speed;
  state->prevSegmentLength = state->segmentLength;
  state->savedStep = state->step;
  state->prevFrameData = state->frameData;
  state->prevFrameType = state->frameType;
  state->prevBlendCacheSlot = state->blendCacheSlot;
  state->prevFrameCmd = state->frameCmd;
  state->prevEventState = state->eventState;
  state->eventState = 0;
  state->lastBlendMoveIndex = -1;
  hitState = (int)objAnim->hitReactState;
  if ((hitState != 0) && (*(int *)(hitState + 8) != 0)) {
    fn_80035774(objAnimArg,(int *)bank,(int)objAnim->objType,hitState,moveId,0);
  }
  if (objAnim->eventTable != (ObjAnimEventTable *)0x0) {
    fn_8002C6C8(objAnimArg,(int)objAnim->objType,(uint *)objAnim->eventTable,moveId,0);
  }
  previousMove = objAnim->currentMove;
  moveChanged = previousMove != moveId;
  objAnim->currentMove = (s16)moveId;
  moveIndex = animDef->moveBaseTable[(s32)moveId >> 8] + (moveId & 0xff);
  if (moveIndex >= animDef->moveCount) {
    moveIndex = animDef->moveCount - 1;
  }
  if (moveIndex < 0) {
    moveIndex = 0;
  }
  if ((animDef->flags & 0x40) != 0) {
    if (moveChanged != 0) {
      state->blendToggle = '\x01' - state->blendToggle;
      state->moveCacheSlot = (u16)state->blendToggle;
      if (animDef->blendMoveIds[moveIndex] == -1) {
        OSReport(gObjAnimSetBlendMoveMissingAnimWarning,animDef->modNo);
        moveIndex = 0;
      }
      fn_80024E7C((int)animDef->blendMoveIds[moveIndex],(int)(s16)moveIndex,
                  (undefined4)state->moveCache[state->moveCacheSlot],animDef);
    }
    moveData = (int)state->moveCache[state->moveCacheSlot] + 0x80;
  }
  else {
    state->moveCacheSlot = (u16)moveIndex;
    moveData = (int)animDef->moveData[state->moveCacheSlot];
  }
  state->frameData = (u8 *)(moveData + 6);
  state->frameType = *(s8 *)(moveData + 1) & 0xf0;
  state->segmentLength =
       ObjAnim_U32AsDouble((uint)state->frameData[1]) - lbl_803DE8E8;
  if (state->frameType == 0) {
    state->segmentLength = state->segmentLength - lbl_803DE8E0;
  }
  frameStep = *(s8 *)(moveData + 1) & 0xf;
  if ((frameStep != 0) && ((flags & 0x10) == 0)) {
    state->savedStep = state->step;
    state->eventStep =
         (short)(int)(lbl_803DE8F4 /
                      (float)(ObjAnim_U32AsDouble(frameStep ^ 0x80000000) - lbl_803DE900));
    state->eventCountdown = 0x4000;
  }
  else {
    state->eventCountdown = 0;
  }
  state->step = lbl_803DE8F0;
  state->speed = clampedProgress * state->segmentLength;
  return 0;
}
