#include "ghidra_import.h"
#include "main/dll/animobjD2.h"

extern bool FUN_800067f0();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068cc();
extern undefined4 FUN_800068d0();
extern double FUN_80017708();
extern undefined4 FUN_80017710();
extern undefined4 FUN_80017760();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ae4();
extern uint FUN_80017ae8();
extern void* ObjGroup_GetObjects();
extern undefined4 ObjLink_AttachChild();
extern undefined4 FUN_80039468();
extern int FUN_801365c4();
extern undefined4 FUN_80139a4c();
extern char FUN_8013b368();
extern int FUN_8013f100();
extern undefined4 FUN_80146fa0();
extern undefined4 FUN_801778d0();
extern undefined8 FUN_80286838();
extern undefined4 FUN_80286884();
extern int FUN_80294c54();

extern f64 DOUBLE_803e30f0;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e306c;
extern f32 FLOAT_803e3088;
extern f32 FLOAT_803e30a0;
extern f32 FLOAT_803e30a4;
extern f32 FLOAT_803e30a8;
extern f32 FLOAT_803e30cc;
extern f32 FLOAT_803e30d0;
extern f32 FLOAT_803e30d4;
extern f32 FLOAT_803e3118;
extern f32 FLOAT_803e3138;
extern f32 FLOAT_803e3164;
extern f32 FLOAT_803e316c;
extern f32 FLOAT_803e3170;
extern f32 FLOAT_803e3174;
extern f32 FLOAT_803e3178;

/*
 * --INFO--
 *
 * Function: FUN_8013e0d0
 * EN v1.0 Address: 0x8013E0D0
 * EN v1.0 Size: 4332b
 * EN v1.1 Address: 0x8013E458
 * EN v1.1 Size: 3508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013e0d0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,undefined4 param_12,
                 undefined4 param_13,uint param_14,undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  uint uVar2;
  char cVar8;
  uint uVar3;
  undefined2 *puVar4;
  undefined4 uVar5;
  bool bVar9;
  int iVar6;
  int *piVar7;
  undefined4 *puVar10;
  byte bVar11;
  byte bVar12;
  int iVar13;
  undefined4 *puVar14;
  int iVar15;
  double extraout_f1;
  double extraout_f1_00;
  double dVar16;
  double dVar17;
  double dVar18;
  double in_f28;
  double dVar19;
  double in_f29;
  double in_f30;
  double in_f31;
  double dVar20;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar21;
  char local_78 [4];
  int local_74 [15];
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
  uVar21 = FUN_80286838();
  uVar2 = (uint)((ulonglong)uVar21 >> 0x20);
  puVar10 = (undefined4 *)uVar21;
  bVar11 = (byte)param_13;
  iVar15 = 0;
  dVar19 = (double)FLOAT_803e306c;
  bVar12 = *(byte *)((int)puVar10 + 10);
  if (bVar12 == 3) {
    if ((*(short *)(uVar2 + 0xa0) == 0x34) &&
       (dVar19 = (double)*(float *)(uVar2 + 0x98), (double)FLOAT_803e3178 < dVar19)) {
      uVar3 = FUN_80017ae8();
      if ((uVar3 & 0xff) != 0) {
        puVar10[0x15] = puVar10[0x15] | 0x800;
        iVar15 = 0;
        puVar14 = puVar10;
        do {
          puVar4 = FUN_80017aa4(0x24,0x4f0);
          *(undefined *)(puVar4 + 2) = 2;
          *(undefined *)((int)puVar4 + 5) = 1;
          puVar4[0xd] = (short)iVar15;
          uVar5 = FUN_80017ae4(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar4
                               ,5,*(undefined *)(uVar2 + 0xac),0xffffffff,*(uint **)(uVar2 + 0x30),
                               param_14,param_15,param_16);
          puVar14[0x1c0] = uVar5;
          puVar14 = puVar14 + 1;
          iVar15 = iVar15 + 1;
          dVar19 = extraout_f1_00;
        } while (iVar15 < 7);
        FUN_80006824(uVar2,0x3db);
        FUN_800068d0(uVar2,0x3dc);
      }
      *(char *)*puVar10 = *(char *)*puVar10 + -2;
      *(undefined *)((int)puVar10 + 10) = 4;
    }
  }
  else if (bVar12 < 3) {
    if (bVar12 == 1) {
      iVar15 = puVar10[0x1ca];
      FUN_80146fa0();
      cVar8 = FUN_8013b368((double)FLOAT_803e3164,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,uVar2,puVar10,iVar15,param_12,bVar11,param_14,param_15,param_16);
      iVar15 = FUN_801365c4();
      puVar10[9] = iVar15;
      if (iVar15 == 0) {
        *(undefined *)(puVar10 + 2) = 1;
        bVar9 = false;
        *(undefined *)((int)puVar10 + 10) = 0;
        fVar1 = FLOAT_803e306c;
        puVar10[0x1c7] = FLOAT_803e306c;
        puVar10[0x1c8] = fVar1;
        puVar10[0x15] = puVar10[0x15] & 0xffffffef;
        puVar10[0x15] = puVar10[0x15] & 0xfffeffff;
        puVar10[0x15] = puVar10[0x15] & 0xfffdffff;
        puVar10[0x15] = puVar10[0x15] & 0xfffbffff;
        *(undefined *)((int)puVar10 + 0xd) = 0xff;
      }
      else {
        if (puVar10[10] != puVar10[9] + 0x18) {
          puVar10[10] = puVar10[9] + 0x18;
          puVar10[0x15] = puVar10[0x15] & 0xfffffbff;
          *(undefined2 *)((int)puVar10 + 0xd2) = 0;
        }
        bVar9 = true;
      }
      if (bVar9) {
        dVar19 = extraout_f1;
        if (puVar10[0x1ca] == 0) {
          iVar15 = FUN_8013f100(uVar2,(int)puVar10);
          puVar10[0x1c8] = iVar15;
          if (iVar15 != 0) {
            puVar10[9] = puVar10[0x1c8];
            puVar10[0x1c9] = 0;
            *(undefined *)((int)puVar10 + 10) = 5;
            goto LAB_8013f1d4;
          }
        }
        if (cVar8 == '\x02') {
          *(undefined *)(puVar10 + 2) = 1;
          *(undefined *)((int)puVar10 + 10) = 0;
          fVar1 = FLOAT_803e306c;
          puVar10[0x1c7] = FLOAT_803e306c;
          puVar10[0x1c8] = fVar1;
          puVar10[0x15] = puVar10[0x15] & 0xffffffef;
          puVar10[0x15] = puVar10[0x15] & 0xfffeffff;
          puVar10[0x15] = puVar10[0x15] & 0xfffdffff;
          puVar10[0x15] = puVar10[0x15] & 0xfffbffff;
          *(undefined *)((int)puVar10 + 0xd) = 0xff;
        }
        else {
          if (cVar8 == '\0') {
            dVar19 = (double)FLOAT_803e30cc;
            FUN_80139a4c(dVar19,uVar2,0x33,0);
          }
          if (puVar10[0x1ca] != 0) {
            if (1 < *(byte *)*puVar10) {
              *(undefined *)((int)puVar10 + 10) = 2;
              goto LAB_8013f1d4;
            }
            puVar10[0x1ca] = 0;
            uVar3 = FUN_80017ae8();
            if ((uVar3 & 0xff) != 0) {
              puVar10[0x15] = puVar10[0x15] | 4;
              *(undefined *)(puVar10 + 2) = 1;
              *(undefined *)((int)puVar10 + 10) = 0;
              fVar1 = FLOAT_803e306c;
              puVar10[0x1c7] = FLOAT_803e306c;
              puVar10[0x1c8] = fVar1;
              puVar10[0x15] = puVar10[0x15] & 0xffffffef;
              puVar10[0x15] = puVar10[0x15] & 0xfffeffff;
              puVar10[0x15] = puVar10[0x15] & 0xfffdffff;
              puVar10[0x15] = puVar10[0x15] & 0xfffbffff;
              *(undefined *)((int)puVar10 + 0xd) = 0xff;
              if (puVar10[0x1ee] == 0) {
                puVar4 = FUN_80017aa4(0x20,0x17b);
                local_78[0] = -1;
                local_78[1] = -1;
                local_78[2] = -1;
                if (puVar10[0x1ea] != 0) {
                  local_78[*(byte *)(puVar10 + 0x1ef) >> 6] = '\x01';
                }
                if (puVar10[0x1ec] != 0) {
                  local_78[*(byte *)(puVar10 + 0x1ef) >> 4 & 3] = '\x01';
                }
                if (puVar10[0x1ee] != 0) {
                  local_78[*(byte *)(puVar10 + 0x1ef) >> 2 & 3] = '\x01';
                }
                if (local_78[0] == -1) {
                  uVar3 = 0;
                }
                else if (local_78[1] == -1) {
                  uVar3 = 1;
                }
                else if (local_78[2] == -1) {
                  uVar3 = 2;
                }
                else if (local_78[3] == -1) {
                  uVar3 = 3;
                }
                else {
                  uVar3 = 0xffffffff;
                }
                *(byte *)(puVar10 + 0x1ef) =
                     (byte)((uVar3 & 0xff) << 2) & 0xc | *(byte *)(puVar10 + 0x1ef) & 0xf3;
                uVar5 = FUN_80017ae4(dVar19,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                                     puVar4,4,0xff,0xffffffff,*(uint **)(uVar2 + 0x30),param_14,
                                     param_15,param_16);
                puVar10[0x1ee] = uVar5;
                ObjLink_AttachChild(uVar2,puVar10[0x1ee],*(byte *)(puVar10 + 0x1ef) >> 2 & 3);
                fVar1 = FLOAT_803e306c;
                puVar10[0x1f0] = FLOAT_803e306c;
                puVar10[0x1f1] = fVar1;
                puVar10[0x1f2] = fVar1;
              }
            }
          }
          dVar19 = FUN_80017708((float *)(uVar2 + 0x18),(float *)(puVar10[9] + 0x18));
          if (dVar19 <= (double)FLOAT_803e3170) {
            puVar10[0x1c7] = (float)puVar10[0x1c7] - FLOAT_803dc074;
            if ((float)puVar10[0x1c7] < FLOAT_803e306c) {
              local_74[2] = FUN_80017760(200,600);
              local_74[2] = local_74[2] ^ 0x80000000;
              local_74[1] = 0x43300000;
              puVar10[0x1c7] =
                   (float)((double)CONCAT44(0x43300000,local_74[2]) - DOUBLE_803e30f0) *
                   FLOAT_803e3138;
              iVar15 = *(int *)(uVar2 + 0xb8);
              if ((((*(byte *)(iVar15 + 0x58) >> 6 & 1) == 0) &&
                  ((0x2f < *(short *)(uVar2 + 0xa0) || (*(short *)(uVar2 + 0xa0) < 0x29)))) &&
                 (bVar9 = FUN_800067f0(uVar2,0x10), !bVar9)) {
                FUN_80039468(uVar2,iVar15 + 0x3a8,0x29b,0x1000,0xffffffff,0);
              }
            }
          }
          else {
            *(undefined *)((int)puVar10 + 10) = 0;
          }
        }
      }
    }
    else if (bVar12 == 0) {
      FUN_80146fa0();
      cVar8 = FUN_8013b368((double)FLOAT_803e3164,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,uVar2,puVar10,param_11,param_12,bVar11,param_14,param_15,param_16
                          );
      iVar15 = FUN_801365c4();
      puVar10[9] = iVar15;
      if (iVar15 == 0) {
        *(undefined *)(puVar10 + 2) = 1;
        bVar9 = false;
        *(undefined *)((int)puVar10 + 10) = 0;
        fVar1 = FLOAT_803e306c;
        puVar10[0x1c7] = FLOAT_803e306c;
        puVar10[0x1c8] = fVar1;
        puVar10[0x15] = puVar10[0x15] & 0xffffffef;
        puVar10[0x15] = puVar10[0x15] & 0xfffeffff;
        puVar10[0x15] = puVar10[0x15] & 0xfffdffff;
        puVar10[0x15] = puVar10[0x15] & 0xfffbffff;
        *(undefined *)((int)puVar10 + 0xd) = 0xff;
      }
      else {
        if (puVar10[10] != puVar10[9] + 0x18) {
          puVar10[10] = puVar10[9] + 0x18;
          puVar10[0x15] = puVar10[0x15] & 0xfffffbff;
          *(undefined2 *)((int)puVar10 + 0xd2) = 0;
        }
        bVar9 = true;
      }
      if (bVar9) {
        if (puVar10[0x1ca] == 0) {
          iVar15 = FUN_8013f100(uVar2,(int)puVar10);
          puVar10[0x1c8] = iVar15;
          if (iVar15 != 0) {
            puVar10[9] = puVar10[0x1c8];
            puVar10[0x1c9] = 0;
            *(undefined *)((int)puVar10 + 10) = 5;
            goto LAB_8013f1d4;
          }
        }
        if (cVar8 == '\x02') {
          *(undefined *)(puVar10 + 2) = 1;
          *(undefined *)((int)puVar10 + 10) = 0;
          fVar1 = FLOAT_803e306c;
          puVar10[0x1c7] = FLOAT_803e306c;
          puVar10[0x1c8] = fVar1;
          puVar10[0x15] = puVar10[0x15] & 0xffffffef;
          puVar10[0x15] = puVar10[0x15] & 0xfffeffff;
          puVar10[0x15] = puVar10[0x15] & 0xfffdffff;
          puVar10[0x15] = puVar10[0x15] & 0xfffbffff;
          *(undefined *)((int)puVar10 + 0xd) = 0xff;
        }
        else {
          dVar19 = FUN_80017708((float *)(uVar2 + 0x18),(float *)(puVar10[9] + 0x18));
          if (dVar19 < (double)FLOAT_803e316c) {
            bVar9 = true;
            *(undefined *)((int)puVar10 + 10) = 1;
            fVar1 = FLOAT_803e306c;
            puVar10[0x1c7] = FLOAT_803e306c;
            if (fVar1 == (float)puVar10[0xab]) {
              bVar9 = false;
            }
            else if ((FLOAT_803e30a0 != (float)puVar10[0xac]) &&
                    ((float)puVar10[0xad] - (float)puVar10[0xac] <= FLOAT_803e30a4)) {
              bVar9 = false;
            }
            if (bVar9) {
              FUN_80139a4c((double)FLOAT_803e30cc,uVar2,8,0);
              puVar10[0x1e7] = FLOAT_803e30d0;
              puVar10[0x20e] = FLOAT_803e306c;
              FUN_80146fa0();
            }
            else {
              FUN_80139a4c((double)FLOAT_803e30d4,uVar2,0,0);
              FUN_80146fa0();
            }
          }
        }
      }
    }
    else {
      FUN_80146fa0();
      cVar8 = FUN_8013b368((double)FLOAT_803e3174,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,uVar2,puVar10,param_11,param_12,bVar11,param_14,param_15,param_16
                          );
      iVar15 = FUN_801365c4();
      puVar10[9] = iVar15;
      if (iVar15 == 0) {
        *(undefined *)(puVar10 + 2) = 1;
        bVar9 = false;
        *(undefined *)((int)puVar10 + 10) = 0;
        fVar1 = FLOAT_803e306c;
        puVar10[0x1c7] = FLOAT_803e306c;
        puVar10[0x1c8] = fVar1;
        puVar10[0x15] = puVar10[0x15] & 0xffffffef;
        puVar10[0x15] = puVar10[0x15] & 0xfffeffff;
        puVar10[0x15] = puVar10[0x15] & 0xfffdffff;
        puVar10[0x15] = puVar10[0x15] & 0xfffbffff;
        *(undefined *)((int)puVar10 + 0xd) = 0xff;
      }
      else {
        if (puVar10[10] != puVar10[9] + 0x18) {
          puVar10[10] = puVar10[9] + 0x18;
          puVar10[0x15] = puVar10[0x15] & 0xfffffbff;
          *(undefined2 *)((int)puVar10 + 0xd2) = 0;
        }
        bVar9 = true;
      }
      if ((bVar9) && (cVar8 != '\x01')) {
        FUN_80139a4c((double)FLOAT_803e30d4,uVar2,0x34,0x4000000);
        puVar10[0x15] = puVar10[0x15] | 0x10;
        *(undefined *)((int)puVar10 + 10) = 3;
        puVar10[0x1ca] = 0;
      }
    }
  }
  else if (bVar12 == 5) {
    iVar6 = FUN_801365c4();
    if ((iVar6 == 0) || (*(short *)(iVar6 + 0x46) != 0x6a3)) {
      iVar6 = FUN_80294c54(puVar10[1]);
    }
    bVar12 = (byte)param_13;
    if ((iVar6 == puVar10[0x1c8]) && (puVar10[0x1ca] == 0)) {
      piVar7 = ObjGroup_GetObjects(0x4b,local_74);
      dVar20 = (double)FLOAT_803e3088;
      for (iVar13 = 0; bVar12 = (byte)param_13, iVar13 < local_74[0]; iVar13 = iVar13 + 1) {
        dVar16 = (double)FUN_80017710((float *)(*piVar7 + 0x18),(float *)(iVar6 + 0x18));
        dVar17 = (double)FUN_80017710((float *)(*piVar7 + 0x18),(float *)(puVar10[1] + 0x18));
        dVar18 = (double)FUN_80017710((float *)(iVar6 + 0x18),(float *)(puVar10[1] + 0x18));
        param_2 = (double)(float)(dVar16 + dVar17);
        if ((double)(float)(dVar20 * dVar18) < param_2) {
          dVar16 = (double)FUN_80017710((float *)(*piVar7 + 0x18),(float *)(uVar2 + 0x18));
          if (dVar19 < (double)(float)(dVar17 - dVar16)) {
            iVar15 = *piVar7;
            dVar19 = (double)(float)(dVar17 - dVar16);
          }
        }
        piVar7 = piVar7 + 1;
      }
      if ((puVar10[0x1c9] != 0) && ((*(ushort *)(puVar10[0x1c9] + 0xb0) & 0x40) != 0)) {
        puVar10[0x1c9] = 0;
        if (puVar10[10] != puVar10[1] + 0x18) {
          puVar10[10] = puVar10[1] + 0x18;
          puVar10[0x15] = puVar10[0x15] & 0xfffffbff;
          *(undefined2 *)((int)puVar10 + 0xd2) = 0;
        }
      }
      if (iVar15 != 0) {
        if ((((puVar10[0x1c9] == 0) &&
             (iVar6 = *(int *)(uVar2 + 0xb8), (*(byte *)(iVar6 + 0x58) >> 6 & 1) == 0)) &&
            ((0x2f < *(short *)(uVar2 + 0xa0) || (*(short *)(uVar2 + 0xa0) < 0x29)))) &&
           (bVar9 = FUN_800067f0(uVar2,0x10), !bVar9)) {
          param_11 = 0x35b;
          param_12 = 0x500;
          bVar12 = 0xff;
          param_14 = 0;
          FUN_80039468(uVar2,iVar6 + 0x3a8,0x35b,0x500,0xffffffff,0);
        }
        if ((puVar10[0x1c9] == 0) || (puVar10[0x1c9] != iVar15)) {
          puVar10[0x1c9] = iVar15;
          if (puVar10[10] != puVar10[0x1c9] + 0x18) {
            puVar10[10] = puVar10[0x1c9] + 0x18;
            puVar10[0x15] = puVar10[0x15] & 0xfffffbff;
            *(undefined2 *)((int)puVar10 + 0xd2) = 0;
          }
        }
      }
    }
    else {
      if (puVar10[10] != puVar10[9] + 0x18) {
        puVar10[10] = puVar10[9] + 0x18;
        puVar10[0x15] = puVar10[0x15] & 0xfffffbff;
        *(undefined2 *)((int)puVar10 + 0xd2) = 0;
      }
      *(undefined *)((int)puVar10 + 10) = 0;
    }
    if (puVar10[0x1c9] == 0) {
      cVar8 = FUN_8013b368((double)FLOAT_803e30a8,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,uVar2,puVar10,param_11,param_12,bVar12,param_14,param_15,param_16
                          );
    }
    else {
      cVar8 = FUN_8013b368((double)FLOAT_803e3118,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,uVar2,puVar10,param_11,param_12,bVar12,param_14,param_15,param_16
                          );
    }
    if (cVar8 != '\x01') {
      if (FLOAT_803e306c == (float)puVar10[0xab]) {
        bVar9 = false;
      }
      else if (FLOAT_803e30a0 == (float)puVar10[0xac]) {
        bVar9 = true;
      }
      else if ((float)puVar10[0xad] - (float)puVar10[0xac] <= FLOAT_803e30a4) {
        bVar9 = false;
      }
      else {
        bVar9 = true;
      }
      if (bVar9) {
        FUN_80139a4c((double)FLOAT_803e30cc,uVar2,8,0);
        puVar10[0x1e7] = FLOAT_803e30d0;
        puVar10[0x20e] = FLOAT_803e306c;
        FUN_80146fa0();
      }
      else {
        FUN_80139a4c((double)FLOAT_803e30d4,uVar2,0,0);
        FUN_80146fa0();
      }
    }
  }
  else if (bVar12 < 5) {
    FUN_80146fa0();
    if ((puVar10[0x15] & 0x8000000) != 0) {
      puVar10[0x15] = puVar10[0x15] & 0xfffff7ff;
      puVar10[0x15] = puVar10[0x15] | 0x1000;
      iVar15 = 0;
      puVar14 = puVar10;
      do {
        FUN_801778d0(puVar14[0x1c0]);
        puVar14 = puVar14 + 1;
        iVar15 = iVar15 + 1;
      } while (iVar15 < 7);
      FUN_800068cc();
      iVar15 = *(int *)(uVar2 + 0xb8);
      if (((*(byte *)(iVar15 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(uVar2 + 0xa0) || (*(short *)(uVar2 + 0xa0) < 0x29)) &&
          (bVar9 = FUN_800067f0(uVar2,0x10), !bVar9)))) {
        FUN_80039468(uVar2,iVar15 + 0x3a8,0x29d,0,0xffffffff,0);
      }
      puVar10[0x15] = puVar10[0x15] & 0xffffffef;
      *(undefined *)((int)puVar10 + 10) = 0;
    }
  }
LAB_8013f1d4:
  FUN_80286884();
  return;
}
