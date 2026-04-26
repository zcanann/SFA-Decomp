#include "ghidra_import.h"
#include "main/dll/sidekickToy.h"

extern undefined4 ABS();
extern undefined8 FUN_80003494();
extern double FUN_80017714();
extern uint FUN_80017730();
extern undefined4 FUN_80017754();
extern undefined4 FUN_80017778();
extern undefined8 FUN_800178a0();
extern undefined4 FUN_80017a88();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern int FUN_8002f6ac();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern undefined4 ObjHits_DisableObject();
extern int FUN_80037008();
extern void* FUN_80037134();
extern undefined8 FUN_8003b06c();
extern undefined8 FUN_8003b280();
extern ushort FUN_800632f4();
extern undefined4 FUN_80146fa4();
extern undefined4 FUN_80147218();
extern undefined4 FUN_801476cc();
extern char FUN_80147884();
extern undefined4 FUN_80147a70();
extern undefined4 FUN_80147d2c();
extern undefined4 FUN_8014ff20();
extern undefined4 FUN_8014ff24();
extern undefined4 FUN_80150624();
extern undefined4 FUN_801511e8();
extern undefined4 FUN_80151b1c();
extern undefined4 FUN_801523f8();
extern undefined4 FUN_80152cf0();
extern undefined4 FUN_80152fb4();
extern undefined4 FUN_801534d8();
extern undefined4 FUN_80153738();
extern undefined4 FUN_80153e5c();
extern undefined4 FUN_801544a4();
extern undefined4 FUN_80154290();
extern undefined4 FUN_80154724();
extern undefined4 FUN_80154870();
extern undefined4 FUN_80154b88();
extern undefined4 FUN_80155b6c();
extern undefined4 FUN_80155cac();
extern undefined4 FUN_80155e00();
extern undefined4 FUN_8015666c();
extern undefined4 FUN_80156978();
extern undefined4 FUN_80156eb8();
extern undefined4 FUN_80157220();
extern undefined4 FUN_801579f4();
extern undefined4 FUN_80157004();
extern undefined4 FUN_801571c4();
extern undefined4 FUN_8015750c();
extern undefined4 FUN_80157b68();
extern undefined4 FUN_80158c58();
extern undefined4 FUN_80158c5c();
extern undefined4 FUN_80159520();
extern undefined4 FUN_80159cdc();
extern undefined4 FUN_80159ce0();
extern undefined4 FUN_8015ad60();
extern undefined4 FUN_8015b10c();
extern undefined4 FUN_8015b2d0();
extern undefined4 FUN_8015b34c();
extern undefined4 FUN_80247944();
extern undefined4 FUN_80247cd8();
extern undefined4 FUN_80247ef8();
extern double FUN_80247f54();
extern undefined4 FUN_80247f90();
extern undefined4 FUN_80247fb0();
extern ulonglong FUN_8028682c();
extern undefined4 FUN_8028683c();
extern undefined4 FUN_80286878();
extern undefined4 FUN_80286888();
extern undefined4 FUN_80292754();
extern undefined4 FUN_80293130();
extern double FUN_80293900();
extern byte FUN_80294c20();

extern undefined4 DAT_8031e840;
extern undefined4 DAT_8031e860;
extern undefined4 DAT_803dc8c0;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd71c;
extern f64 DOUBLE_803e3218;
extern f64 DOUBLE_803e3278;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc078;
extern f32 FLOAT_803e31fc;
extern f32 FLOAT_803e3200;
extern f32 FLOAT_803e3204;
extern f32 FLOAT_803e3208;
extern f32 FLOAT_803e320c;
extern f32 FLOAT_803e3210;
extern f32 FLOAT_803e322c;
extern f32 FLOAT_803e3234;
extern f32 FLOAT_803e3258;
extern f32 FLOAT_803e325c;
extern f32 FLOAT_803e3260;
extern f32 FLOAT_803e3264;
extern f32 FLOAT_803e3268;
extern f32 FLOAT_803e326c;
extern f32 FLOAT_803e3270;
extern f32 FLOAT_803e3280;

/*
 * --INFO--
 *
 * Function: FUN_8014a9f0
 * EN v1.0 Address: 0x8014A9F0
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x8014ACCC
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014a9f0(int param_1,int param_2,float *param_3,float *param_4)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  ushort uVar7;
  ushort uVar8;
  float *pfVar9;
  int local_18 [2];
  
  fVar2 = FLOAT_803e3258;
  *param_3 = FLOAT_803e3258;
  *param_4 = fVar2;
  uVar7 = FUN_800632f4((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                       (double)*(float *)(param_1 + 0x14),param_1,local_18,0,0);
  *param_3 = *(float *)(param_1 + 0x10);
  *param_4 = *(float *)(param_1 + 0x10);
  fVar2 = FLOAT_803e325c;
  *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) & 0xefffffff;
  fVar6 = FLOAT_803e31fc;
  *(float *)(param_2 + 0x1b8) = FLOAT_803e31fc;
  *(byte *)(param_2 + 0x264) = *(byte *)(param_2 + 0x264) & 0xef;
  fVar4 = fVar2;
  for (uVar8 = 0; uVar8 < uVar7; uVar8 = uVar8 + 1) {
    pfVar9 = *(float **)(local_18[0] + (uint)uVar8 * 4);
    fVar1 = *pfVar9;
    fVar5 = fVar1 - *(float *)(param_1 + 0x10);
    fVar3 = fVar5;
    if (fVar5 < fVar6) {
      fVar3 = -fVar5;
    }
    if (*(char *)(pfVar9 + 5) == '\x0e') {
      if (fVar3 < fVar4) {
        *(float *)(param_2 + 0x1b8) = fVar5;
        *(byte *)(param_2 + 0x264) = *(byte *)(param_2 + 0x264) | 0x10;
        *param_4 = **(float **)(local_18[0] + (uint)uVar8 * 4);
        fVar4 = fVar3;
        if (FLOAT_803e3234 < *(float *)(param_2 + 0x1b8)) {
          *(uint *)(param_2 + 0x2dc) = *(uint *)(param_2 + 0x2dc) | 0x10100000;
        }
      }
    }
    else if (fVar3 < fVar2) {
      *param_3 = fVar1;
      *(byte *)(param_2 + 0x264) = *(byte *)(param_2 + 0x264) | 0x10;
      fVar2 = fVar3;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ab58
 * EN v1.0 Address: 0x8014AB58
 * EN v1.0 Size: 5468b
 * EN v1.1 Address: 0x8014AE50
 * EN v1.1 Size: 3744b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ab58(undefined8 param_1,double param_2,double param_3,double param_4,double param_5,
                 double param_6,double param_7,undefined8 param_8,ushort *param_9,int *param_10,
                 undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
                 undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  float fVar2;
  ushort uVar3;
  float fVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  float *pfVar8;
  undefined8 uVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  float fStack_d8;
  float local_d4;
  ushort local_d0;
  ushort local_ce;
  ushort local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  short local_aa;
  char local_a5 [8];
  char local_9d;
  float afStack_9c [17];
  longlong local_58;
  
  FUN_80003494((uint)(param_10 + 0xb1),(uint)(param_10 + 0xae),0xc);
  piVar7 = (int *)0xc;
  uVar9 = FUN_80003494((uint)(param_10 + 0xae),(uint)(param_9 + 0x12),0xc);
  if ((param_10[0xb9] & 0x400U) != 0) {
    uVar9 = FUN_8003b280((int)param_9,(int)(param_10 + 0x9b));
  }
  if ((param_10[0xa7] != 0) && ((param_10[0xb9] & 0x800U) != 0)) {
    piVar7 = param_10 + 0x9b;
    param_12 = 0x19;
    uVar9 = FUN_8003b06c((short *)param_9,param_10[0xa7],(int)piVar7,0x19);
  }
  *(undefined *)(param_10 + 0xbc) = *(undefined *)((int)param_10 + 0x2ef);
  uVar5 = param_10[0xb7];
  if ((uVar5 & 0x800) != 0) {
    FUN_80147218(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                 (int)param_10,piVar7,param_12,param_13,param_14,param_15,param_16);
    goto LAB_8014b804;
  }
  if ((uVar5 & 0x1000) != 0) {
    FUN_80146fa4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                 (int)param_10,piVar7,param_12,param_13,param_14,param_15,param_16);
    goto LAB_8014b804;
  }
  if ((uVar5 & 0x20000000) == 0) {
    if ((uVar5 & 0x100) != 0) {
      *(undefined *)((int)param_10 + 0x2ef) = 2;
      if (((param_10[0xb7] & 0x100U) != 0) && ((param_10[0xb8] & 0x100U) == 0)) {
        param_2 = (double)(float)param_10[199];
        if ((double)FLOAT_803e31fc == param_2) {
          param_10[0xc2] = (int)FLOAT_803e3208;
        }
        else {
          param_10[0xc2] = (int)(FLOAT_803e3200 / (float)((double)FLOAT_803e3204 * param_2));
        }
        *(undefined *)((int)param_10 + 0x323) = 1;
        FUN_800305f8((double)FLOAT_803e31fc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,(uint)*(byte *)((int)param_10 + 0x322),0x10,param_12,param_13,param_14,
                     param_15,param_16);
        if (*(int *)(param_9 + 0x2a) != 0) {
          *(undefined *)(*(int *)(param_9 + 0x2a) + 0x70) = 0;
        }
      }
      if ((param_10[0xb7] & 0x40000000U) == 0) {
        local_58 = (longlong)(int)(FLOAT_803e3210 * *(float *)(param_9 + 0x4c));
        *(char *)(param_9 + 0x1b) = (char)(int)(FLOAT_803e3210 * *(float *)(param_9 + 0x4c));
        param_9[3] = param_9[3] & 0xbfff;
      }
      else {
        param_10[0xc2] = (int)FLOAT_803e320c;
        *(undefined *)((int)param_10 + 0x323) = 0;
        FUN_800305f8((double)FLOAT_803e31fc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,0,0,param_12,param_13,param_14,param_15,param_16);
        if (*(int *)(param_9 + 0x2a) != 0) {
          *(undefined *)(*(int *)(param_9 + 0x2a) + 0x70) = 0;
        }
        param_10[0xb7] = param_10[0xb7] & 0xfffffeff;
        *(undefined *)(param_9 + 0x1b) = 0xff;
      }
      goto LAB_8014b804;
    }
    *(undefined *)((int)param_10 + 0x2ef) = 5;
    uVar3 = param_9[0x23];
    if (uVar3 == 0x4d7) {
      FUN_80157220(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_10,
                   piVar7,param_12,param_13,param_14,param_15,param_16);
      goto LAB_8014b804;
    }
    if ((short)uVar3 < 0x4d7) {
      if (uVar3 == 0x281) {
LAB_8014b6e8:
        FUN_801523f8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                     (int)param_10);
        goto LAB_8014b804;
      }
      if ((short)uVar3 < 0x281) {
        if (uVar3 == 0x13a) {
LAB_8014b6d8:
          FUN_80150624(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x13a) {
          if (uVar3 == 0xd8) goto LAB_8014b6e8;
          if (((short)uVar3 < 0xd8) && (uVar3 == 0x11)) goto LAB_8014b6d8;
        }
        else {
          if (uVar3 == 0x25d) {
            FUN_80155b6c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int *)param_9,(int)param_10);
            goto LAB_8014b804;
          }
          if (((short)uVar3 < 0x25d) && (uVar3 == 0x251)) {
            FUN_80154870(param_9,param_10);
            goto LAB_8014b804;
          }
        }
      }
      else {
        if (uVar3 == 0x427) {
          FUN_8014ff20();
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x427) {
          if (uVar3 == 0x3fe) {
LAB_8014b718:
            FUN_801534d8(param_9,param_10);
            goto LAB_8014b804;
          }
          if (((short)uVar3 < 0x3fe) && (uVar3 == 0x369)) {
            FUN_80154290(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (short *)param_9,param_10);
            goto LAB_8014b804;
          }
        }
        else {
          if (uVar3 == 0x458) {
            FUN_80157004(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9
                         ,(int)param_10);
            goto LAB_8014b804;
          }
          if ((short)uVar3 < 0x458) {
            if (0x456 < (short)uVar3) {
              FUN_8015666c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (int)param_9,(int)param_10);
              goto LAB_8014b804;
            }
          }
          else if (uVar3 == 0x4ac) {
            FUN_801571c4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         (int)param_10);
            goto LAB_8014b804;
          }
        }
      }
    }
    else {
      if (uVar3 == 0x7a6) goto LAB_8014b6d8;
      if ((short)uVar3 < 0x7a6) {
        if (uVar3 == 0x613) {
          FUN_80152cf0(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x613) {
          if ((short)uVar3 < 0x5ba) {
            if (uVar3 == 0x58b) {
              FUN_80153e5c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (short *)param_9,(int)param_10);
              goto LAB_8014b804;
            }
            if ((0x58a < (short)uVar3) && (0x5b6 < (short)uVar3)) goto LAB_8014b6d8;
          }
          else if (uVar3 == 0x5e1) goto LAB_8014b6d8;
        }
        else if ((short)uVar3 < 0x6a2) {
          if (uVar3 == 0x642) {
            FUN_80152fb4(param_9,(int)param_10);
            goto LAB_8014b804;
          }
        }
        else if ((short)uVar3 < 0x6a6) {
          FUN_80158c58(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          goto LAB_8014b804;
        }
      }
      else {
        if (uVar3 == 0x842) {
LAB_8014b7a8:
          FUN_8015b10c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                       (int)param_10);
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x842) {
          if (uVar3 != 0x7c7) {
            if ((short)uVar3 < 0x7c7) {
              if (0x7c5 < (short)uVar3) goto LAB_8014b718;
            }
            else if ((short)uVar3 < 0x7c9) {
              FUN_80159cdc(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_10);
              goto LAB_8014b804;
            }
          }
        }
        else {
          if (uVar3 == 0x851) {
            FUN_8015b34c((short *)param_9,(int)param_10);
            goto LAB_8014b804;
          }
          if (((short)uVar3 < 0x851) && (uVar3 == 0x84b)) goto LAB_8014b7a8;
        }
      }
    }
    FUN_8014ff20();
    goto LAB_8014b804;
  }
  if ((uVar5 & 0x400) == 0) {
    *(undefined *)((int)param_10 + 0x2ef) = 4;
    uVar3 = param_9[0x23];
    if (uVar3 == 0x4d7) {
      FUN_80156eb8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                   (int)param_10,piVar7,param_12,param_13,param_14,param_15,param_16);
      goto LAB_8014b804;
    }
    if ((short)uVar3 < 0x4d7) {
      if (uVar3 == 0x281) {
LAB_8014b338:
        FUN_801523f8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                     (int)param_10);
        goto LAB_8014b804;
      }
      if ((short)uVar3 < 0x281) {
        if (uVar3 == 0x13a) {
LAB_8014b328:
          FUN_801511e8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x13a) {
          if (uVar3 == 0xd8) goto LAB_8014b338;
          if (((short)uVar3 < 0xd8) && (uVar3 == 0x11)) goto LAB_8014b328;
        }
        else {
          if (uVar3 == 0x25d) {
            FUN_80155cac(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (int *)param_9,(int)param_10);
            goto LAB_8014b804;
          }
          if (((short)uVar3 < 0x25d) && (uVar3 == 0x251)) {
            FUN_80154b88(param_9,param_10);
            goto LAB_8014b804;
          }
        }
      }
      else {
        if (uVar3 == 0x427) {
          FUN_8014ff20();
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x427) {
          if (uVar3 == 0x3fe) {
LAB_8014b368:
            FUN_80153738(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_10);
            goto LAB_8014b804;
          }
          if (((short)uVar3 < 0x3fe) && (uVar3 == 0x369)) {
            FUN_80154724(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         (short *)param_9,(int)param_10);
            goto LAB_8014b804;
          }
        }
        else {
          if (uVar3 == 0x458) {
            FUN_801579f4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9
                         ,(int)param_10);
            goto LAB_8014b804;
          }
          if ((short)uVar3 < 0x458) {
            if (0x456 < (short)uVar3) {
              FUN_80156978(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (uint)param_9,(int)param_10);
              goto LAB_8014b804;
            }
          }
          else if (uVar3 == 0x4ac) {
            FUN_8015750c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
            goto LAB_8014b804;
          }
        }
      }
    }
    else {
      if (uVar3 == 0x7a6) goto LAB_8014b328;
      if ((short)uVar3 < 0x7a6) {
        if (uVar3 == 0x613) {
          FUN_80152cf0(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x613) {
          if ((short)uVar3 < 0x5ba) {
            if (uVar3 == 0x58b) {
              FUN_801544a4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           (uint)param_9,(int)param_10);
              goto LAB_8014b804;
            }
            if ((0x58a < (short)uVar3) && (0x5b6 < (short)uVar3)) goto LAB_8014b328;
          }
          else if (uVar3 == 0x5e1) goto LAB_8014b328;
        }
        else if ((short)uVar3 < 0x6a2) {
          if (uVar3 == 0x642) {
            FUN_80152fb4(param_9,(int)param_10);
            goto LAB_8014b804;
          }
        }
        else if ((short)uVar3 < 0x6a6) {
          FUN_80158c5c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
          goto LAB_8014b804;
        }
      }
      else {
        if (uVar3 == 0x842) {
LAB_8014b3f8:
          FUN_8015ad60(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (short *)param_9,(int)param_10);
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x842) {
          if (uVar3 != 0x7c7) {
            if ((short)uVar3 < 0x7c7) {
              if (0x7c5 < (short)uVar3) goto LAB_8014b368;
            }
            else if ((short)uVar3 < 0x7c9) {
              FUN_80159ce0((short *)param_9,param_10);
              goto LAB_8014b804;
            }
          }
        }
        else {
          if (uVar3 == 0x851) {
            FUN_8015b2d0((short *)param_9,(int)param_10);
            goto LAB_8014b804;
          }
          if (((short)uVar3 < 0x851) && (uVar3 == 0x84b)) goto LAB_8014b3f8;
        }
      }
    }
    FUN_8014ff20();
    goto LAB_8014b804;
  }
  *(undefined *)((int)param_10 + 0x2ef) = 3;
  uVar3 = param_9[0x23];
  if (uVar3 == 0x4d7) {
    FUN_80156eb8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,(int)param_10
                 ,piVar7,param_12,param_13,param_14,param_15,param_16);
    goto LAB_8014b804;
  }
  if ((short)uVar3 < 0x4d7) {
    if (uVar3 == 0x281) {
LAB_8014b0b4:
      FUN_801523f8(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                   (int)param_10);
      goto LAB_8014b804;
    }
    if ((short)uVar3 < 0x281) {
      if (uVar3 == 0x13a) {
LAB_8014b0a4:
        FUN_80151b1c(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        goto LAB_8014b804;
      }
      if ((short)uVar3 < 0x13a) {
        if (uVar3 == 0xd8) goto LAB_8014b0b4;
        if (((short)uVar3 < 0xd8) && (uVar3 == 0x11)) goto LAB_8014b0a4;
      }
      else {
        if (uVar3 == 0x25d) {
          FUN_80155e00(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int *)param_9,
                       (int)param_10);
          goto LAB_8014b804;
        }
        if (((short)uVar3 < 0x25d) && (uVar3 == 0x251)) {
          FUN_80154b88(param_9,param_10);
          goto LAB_8014b804;
        }
      }
    }
    else {
      if (uVar3 == 0x427) {
        FUN_8014ff24((short *)param_9,param_10);
        goto LAB_8014b804;
      }
      if ((short)uVar3 < 0x427) {
        if (uVar3 == 0x3fe) {
LAB_8014b0e4:
          FUN_80153738(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       param_10);
          goto LAB_8014b804;
        }
        if (((short)uVar3 < 0x3fe) && (uVar3 == 0x369)) {
          FUN_80154724(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                       (short *)param_9,(int)param_10);
          goto LAB_8014b804;
        }
      }
      else {
        if (uVar3 == 0x458) {
          FUN_801579f4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                       (int)param_10);
          goto LAB_8014b804;
        }
        if ((short)uVar3 < 0x458) {
          if (0x456 < (short)uVar3) {
            FUN_80156978(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9
                         ,(int)param_10);
            goto LAB_8014b804;
          }
        }
        else if (uVar3 == 0x4ac) {
          FUN_80157b68(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                       (int)param_10);
          goto LAB_8014b804;
        }
      }
    }
  }
  else {
    if (uVar3 == 0x7a6) goto LAB_8014b0a4;
    if ((short)uVar3 < 0x7a6) {
      if (uVar3 == 0x613) {
        FUN_80152cf0(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        goto LAB_8014b804;
      }
      if ((short)uVar3 < 0x613) {
        if ((short)uVar3 < 0x5ba) {
          if (uVar3 == 0x58b) {
            FUN_801544a4(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9
                         ,(int)param_10);
            goto LAB_8014b804;
          }
          if ((0x58a < (short)uVar3) && (0x5b6 < (short)uVar3)) goto LAB_8014b0a4;
        }
        else if (uVar3 == 0x5e1) goto LAB_8014b0a4;
      }
      else if ((short)uVar3 < 0x6a2) {
        if (uVar3 == 0x642) {
          FUN_80152fb4(param_9,(int)param_10);
          goto LAB_8014b804;
        }
      }
      else if ((short)uVar3 < 0x6a6) {
        FUN_80159520(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
        goto LAB_8014b804;
      }
    }
    else {
      if (uVar3 == 0x842) {
LAB_8014b174:
        FUN_8015ad60(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(short *)param_9,
                     (int)param_10);
        goto LAB_8014b804;
      }
      if ((short)uVar3 < 0x842) {
        if (uVar3 != 0x7c7) {
          if ((short)uVar3 < 0x7c7) {
            if (0x7c5 < (short)uVar3) goto LAB_8014b0e4;
          }
          else if ((short)uVar3 < 0x7c9) {
            FUN_80159cdc(uVar9,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_10);
            goto LAB_8014b804;
          }
        }
      }
      else {
        if (uVar3 == 0x851) {
          FUN_8015b2d0((short *)param_9,(int)param_10);
          goto LAB_8014b804;
        }
        if (((short)uVar3 < 0x851) && (uVar3 == 0x84b)) goto LAB_8014b174;
      }
    }
  }
  FUN_8014ff24((short *)param_9,param_10);
LAB_8014b804:
  if (*(char *)((int)param_10 + 0x2ef) == *(char *)(param_10 + 0xbc)) {
    param_10[0xb7] = param_10[0xb7] & 0x7fffffff;
  }
  else {
    param_10[0xb7] = param_10[0xb7] | 0x80000000;
  }
  local_9d = '\0';
  iVar6 = FUN_8002fc3c((double)(float)param_10[0xc2],(double)FLOAT_803dc074);
  if (iVar6 == 0) {
    param_10[0xb7] = param_10[0xb7] & 0xbfffffff;
  }
  else {
    param_10[0xb7] = param_10[0xb7] | 0x40000000;
  }
  *(undefined2 *)(param_10 + 0xbe) = 0;
  pfVar8 = &local_b8;
  for (iVar6 = 0; iVar6 < local_9d; iVar6 = iVar6 + 1) {
    *(ushort *)(param_10 + 0xbe) =
         *(ushort *)(param_10 + 0xbe) | (ushort)(1 << (int)*(char *)((int)pfVar8 + 0x13));
    pfVar8 = (float *)((int)pfVar8 + 1);
  }
  dVar13 = (double)FLOAT_803e31fc;
  if (((((param_10[0xb9] & 0x20U) != 0) && ((param_10[0xb9] & 0x400000U) == 0)) &&
      ((param_10[0xb7] & 0x1800U) == 0)) && ((*(byte *)((int)param_10 + 0x323) & 4) == 0)) {
    dVar13 = -(double)((float)param_10[0xc0] * FLOAT_803dc074 - *(float *)(param_9 + 0x14));
  }
  fVar2 = *(float *)(param_9 + 0x12);
  fVar4 = FLOAT_803e3260;
  if ((FLOAT_803e3260 <= fVar2) && (fVar4 = fVar2, FLOAT_803e3264 < fVar2)) {
    fVar4 = FLOAT_803e3264;
  }
  *(float *)(param_9 + 0x12) = fVar4;
  fVar2 = *(float *)(param_9 + 0x14);
  fVar4 = FLOAT_803e3260;
  if ((FLOAT_803e3260 <= fVar2) && (fVar4 = fVar2, FLOAT_803e3264 < fVar2)) {
    fVar4 = FLOAT_803e3264;
  }
  *(float *)(param_9 + 0x14) = fVar4;
  fVar2 = *(float *)(param_9 + 0x16);
  fVar4 = FLOAT_803e3260;
  if ((FLOAT_803e3260 <= fVar2) && (fVar4 = fVar2, FLOAT_803e3264 < fVar2)) {
    fVar4 = FLOAT_803e3264;
  }
  *(float *)(param_9 + 0x16) = fVar4;
  iVar6 = 0;
  uVar5 = param_10[0xb9];
  if (((uVar5 & 0x80) == 0) || (*(char *)((int)param_10 + 0x323) == '\0')) {
    if ((uVar5 & 0x100) == 0) {
      if ((uVar5 & 0x10) != 0) {
        iVar6 = 3;
      }
    }
    else {
      iVar6 = 2;
    }
  }
  else {
    iVar6 = 1;
  }
  if (((uVar5 & 0x200) != 0) && ((param_10[0xb7] & 0x4010U) != 0)) {
    iVar6 = 3;
  }
  if (iVar6 == 1) {
    dVar12 = (double)FLOAT_803e31fc;
    bVar1 = *(byte *)((int)param_10 + 0x323);
    dVar11 = dVar12;
    if ((bVar1 & 2) != 0) {
      dVar11 = (double)(local_b8 * FLOAT_803dc078);
    }
    dVar10 = dVar12;
    if ((bVar1 & 4) != 0) {
      dVar10 = (double)(local_b4 * FLOAT_803dc078);
    }
    if ((bVar1 & 1) != 0) {
      dVar12 = (double)(-local_b0 * FLOAT_803dc078);
    }
    if ((bVar1 & 8) != 0) {
      *param_9 = *param_9 + local_aa;
    }
    local_d0 = *param_9;
    local_ce = param_9[1];
    local_cc = param_9[2];
    local_c8 = FLOAT_803e3200;
    local_c4 = FLOAT_803e31fc;
    local_c0 = FLOAT_803e31fc;
    local_bc = FLOAT_803e31fc;
    FUN_80017754(afStack_9c,&local_d0);
    if ((*(byte *)((int)param_10 + 0x323) & 4) == 0) {
      FUN_80017778(dVar11,(double)FLOAT_803e31fc,-dVar12,afStack_9c,(float *)(param_9 + 0x12),
                   &fStack_d8,(float *)(param_9 + 0x16));
    }
    else {
      FUN_80017778(dVar11,dVar10,-dVar12,afStack_9c,(float *)(param_9 + 0x12),
                   (float *)(param_9 + 0x14),(float *)(param_9 + 0x16));
    }
  }
  else if (iVar6 == 2) {
    dVar11 = FUN_80293900((double)(*(float *)(param_9 + 0x12) * *(float *)(param_9 + 0x12) +
                                  *(float *)(param_9 + 0x16) * *(float *)(param_9 + 0x16)));
    iVar6 = FUN_8002f6ac(dVar11,(int)param_9,&local_d4);
    if (iVar6 != 0) {
      param_10[0xc2] = (int)local_d4;
    }
  }
  else if ((iVar6 == 3) && ((*(byte *)((int)param_10 + 0x2f1) & 0x80) == 0)) {
    dVar11 = (double)FUN_80293130((double)(float)param_10[0xc1],(double)FLOAT_803dc074);
    *(float *)(param_9 + 0x12) = (float)((double)*(float *)(param_9 + 0x12) * dVar11);
    dVar11 = (double)FUN_80293130((double)(float)param_10[0xc1],(double)FLOAT_803dc074);
    *(float *)(param_9 + 0x14) = (float)((double)*(float *)(param_9 + 0x14) * dVar11);
    dVar11 = (double)FUN_80293130((double)(float)param_10[0xc1],(double)FLOAT_803dc074);
    *(float *)(param_9 + 0x16) = (float)((double)*(float *)(param_9 + 0x16) * dVar11);
  }
  FUN_80147d2c((int)param_9,(int)param_10);
  if (((param_10[0xb9] & 0x400000U) == 0) && ((param_10[0xb7] & 0x8100000U) == 0)) {
    if ((param_10[0xb9] & 0x20U) == 0) {
      if ((*(byte *)((int)param_10 + 0x2f1) & 0x80) == 0) {
        FUN_80017a88((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
                     (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074),
                     (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
      }
    }
    else if ((*(byte *)((int)param_10 + 0x2f1) & 0x80) == 0) {
      FUN_80017a88((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
                   (double)(-(FLOAT_803e3268 *
                              (float)param_10[0xc0] * FLOAT_803dc074 * FLOAT_803dc074 -
                             (*(float *)(param_9 + 0x14) * FLOAT_803dc074 + *(float *)(param_9 + 8))
                             ) - *(float *)(param_9 + 8)),
                   (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
      *(float *)(param_9 + 0x14) = (float)dVar13;
    }
  }
  else if ((*(byte *)((int)param_10 + 0x2f1) & 0x80) == 0) {
    FUN_80017a88((double)(*(float *)(param_9 + 0x12) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x14) * FLOAT_803dc074),
                 (double)(*(float *)(param_9 + 0x16) * FLOAT_803dc074),(int)param_9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014c0b4
 * EN v1.0 Address: 0x8014C0B4
 * EN v1.0 Size: 1140b
 * EN v1.1 Address: 0x8014BCF0
 * EN v1.1 Size: 1056b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014c0b4(double param_1,double param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  char cVar5;
  byte bVar6;
  double extraout_f1;
  double extraout_f1_00;
  double dVar7;
  
  iVar1 = FUN_80017a98();
  iVar2 = FUN_80017a90();
  if (((*(int *)(param_10 + 0x29c) == 0) || ((*(uint *)(param_10 + 0x2e4) & 0x10000) != 0)) ||
     ((*(int *)(param_10 + 0x29c) == iVar1 && ((*(ushort *)(iVar1 + 0xb0) & 0x1000) != 0)))) {
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xff7ff9ff;
    if (((*(uint *)(param_10 + 0x2e4) & 0x10000) != 0) ||
       ((*(int *)(param_10 + 0x29c) == iVar1 && ((*(ushort *)(iVar1 + 0xb0) & 0x1000) != 0)))) {
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xdfffffff;
    }
  }
  else {
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xff7fffff;
    iVar3 = (**(code **)(*DAT_803dd6d0 + 0x3c))();
    if (iVar3 == param_9) {
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x800200;
    }
    uVar4 = (uint)*(ushort *)(param_10 + 0x2a4);
    if (uVar4 < ((int)*(float *)(param_10 + 0x2ac) & 0xffffU)) {
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x400;
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xfffffdff;
      param_1 = extraout_f1;
    }
    else {
      param_1 = (double)*(float *)(param_10 + 0x2a8);
      if (uVar4 < ((int)*(float *)(param_10 + 0x2a8) & 0xffffU)) {
        *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x200;
        *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xfffffbff;
      }
      else if (((int)((double)FLOAT_803e326c * param_1) & 0xffffU) < uVar4) {
        *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xdffff9ff;
      }
    }
  }
  *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xf890fff7;
  if ((iVar2 != 0) &&
     (cVar5 = (**(code **)(**(int **)(iVar2 + 0x68) + 0x40))(iVar2), param_1 = extraout_f1_00,
     cVar5 != '\0')) {
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x200000;
  }
  if (((*(int *)(param_10 + 0x29c) == iVar1) && (bVar6 = FUN_80294c20(iVar1), bVar6 != 0)) &&
     (*(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 8,
     (*(uint *)(param_10 + 0x2e4) & 0x2000) != 0)) {
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xff7ff9ff;
  }
  if ((*(uint *)(param_10 + 0x2dc) & 0x20000600) != 0) {
    if ((*(uint *)(param_10 + 0x2e4) & 0x1000) == 0) {
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x1000000;
    }
    else {
      cVar5 = FUN_80147884(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           param_10,(float *)(param_9 + 0x18),
                           (float *)(*(int *)(param_10 + 0x29c) + 0x18));
      if (cVar5 != '\0') {
        *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x1000000;
      }
      if ((*(uint *)(param_10 + 0x2dc) & 0x1000000) == 0) {
        *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) & 0xdfffffff;
      }
    }
    if ((*(ushort *)(param_10 + 0x2a0) < 2) || (5 < *(ushort *)(param_10 + 0x2a0))) {
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x400000;
    }
    else if ((*(uint *)(param_10 + 0x2dc) & 0x1000000) != 0) {
      *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x2000000;
    }
    if ((*(uint *)(param_10 + 0x2e4) & 0x4000) == 0) {
      iVar1 = *(int *)(param_10 + 0x29c);
      param_2 = (double)(*(float *)(iVar1 + 0x2c) * *(float *)(iVar1 + 0x2c));
      dVar7 = FUN_80293900((double)(float)(param_2 +
                                          (double)(*(float *)(iVar1 + 0x24) *
                                                   *(float *)(iVar1 + 0x24) +
                                                  *(float *)(iVar1 + 0x28) *
                                                  *(float *)(iVar1 + 0x28))));
      if ((double)FLOAT_803e3268 < dVar7) {
        *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x4000000;
      }
    }
    uVar4 = *(uint *)(param_10 + 0x2dc);
    if ((((uVar4 & 0x600) != 0) && ((uVar4 & 0x6800000) != 0)) && ((uVar4 & 0x1000000) != 0)) {
      *(uint *)(param_10 + 0x2dc) = uVar4 | 0x20000000;
    }
    if ((*(uint *)(param_10 + 0x2dc) & 0x20000000) != 0) {
      if ((*(uint *)(param_10 + 0x2e4) & 0x40) == 0) {
        *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0xf0000;
      }
      else {
        FUN_80147a70((double)*(float *)(param_10 + 0x2ac),param_2,param_3,param_4,param_5,param_6,
                     param_7,param_8);
      }
    }
  }
  if (*(short *)(param_10 + 0x2b0) == 0) {
    *(uint *)(param_10 + 0x2dc) = *(uint *)(param_10 + 0x2dc) | 0x800;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014c528
 * EN v1.0 Address: 0x8014C528
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x8014C110
 * EN v1.1 Size: 388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014c528(ushort *param_1,int param_2)
{
  ushort uVar1;
  int iVar2;
  uint uVar3;
  double dVar4;
  float local_28;
  float local_24;
  float local_20;
  
  iVar2 = *(int *)(param_2 + 0x29c);
  if (iVar2 != 0) {
    if ((*(uint *)(param_2 + 0x2e4) & 0x8000) == 0) {
      local_28 = *(float *)(param_1 + 0xc) - *(float *)(iVar2 + 0x18);
      local_24 = *(float *)(param_1 + 0xe) - *(float *)(iVar2 + 0x1c);
      local_20 = *(float *)(param_1 + 0x10) - *(float *)(iVar2 + 0x20);
    }
    else {
      local_28 = *(float *)(param_1 + 0xc) - *(float *)(iVar2 + 0x18);
      local_24 = FLOAT_803e31fc;
      local_20 = *(float *)(param_1 + 0x10) - *(float *)(iVar2 + 0x20);
    }
    uVar3 = FUN_80017730();
    if (*(short **)(param_1 + 0x18) == (short *)0x0) {
      uVar1 = *param_1;
    }
    else {
      uVar1 = *param_1 + **(short **)(param_1 + 0x18);
    }
    uVar3 = (uVar3 & 0xffff) - (uint)uVar1;
    if (0x8000 < (int)uVar3) {
      uVar3 = uVar3 - 0xffff;
    }
    if ((int)uVar3 < -0x8000) {
      uVar3 = uVar3 + 0xffff;
    }
    *(short *)(param_2 + 0x2a2) = (short)uVar3;
    *(short *)(param_2 + 0x2a0) = (short)((uVar3 & 0xffff) >> 0xd);
    dVar4 = FUN_80293900((double)(local_20 * local_20 + local_28 * local_28 + local_24 * local_24));
    *(short *)(param_2 + 0x2a4) = (short)(int)dVar4;
    *(short *)(param_2 + 0x2a6) =
         (short)(int)(*(float *)(*(int *)(param_2 + 0x29c) + 0x1c) - *(float *)(param_1 + 0xe));
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014c690
 * EN v1.0 Address: 0x8014C690
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8014C294
 * EN v1.1 Size: 584b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014c690(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8014c694
 * EN v1.0 Address: 0x8014C694
 * EN v1.0 Size: 248b
 * EN v1.1 Address: 0x8014C4DC
 * EN v1.1 Size: 184b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014c694(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  char cVar1;
  int *piVar2;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  if (((piVar2[0xb7] & 0x2000U) == 0) ||
     (cVar1 = FUN_80147884(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                           piVar2,(float *)(param_9 + 0x18),(float *)(*piVar2 + 0x68)),
     cVar1 == '\0')) {
    cVar1 = (**(code **)(*DAT_803dd71c + 0x8c))
                      ((double)FLOAT_803e3270,*piVar2,param_9,&DAT_803dc8c0,0xffffffff);
    if (cVar1 == '\0') {
      piVar2[0xb7] = piVar2[0xb7] | 0x2000;
    }
    else {
      piVar2[0xb7] = piVar2[0xb7] & 0xffffdfff;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014c78c
 * EN v1.0 Address: 0x8014C78C
 * EN v1.0 Size: 772b
 * EN v1.1 Address: 0x8014C594
 * EN v1.1 Size: 956b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014c78c(undefined4 param_1,undefined4 param_2,int param_3,int *param_4)
{
  ushort uVar1;
  ushort *puVar2;
  uint uVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double extraout_f1;
  double dVar9;
  ulonglong uVar10;
  float local_48;
  int local_44;
  float local_40;
  float local_3c;
  float local_38;
  longlong local_30;
  
  uVar10 = FUN_8028682c();
  puVar2 = (ushort *)(uVar10 >> 0x20);
  local_48 = (float)extraout_f1;
  iVar8 = *(int *)(puVar2 + 0x5c);
  local_44 = 0;
  iVar7 = 0;
  if ((uVar10 & 1) == 0) {
    local_48 = (float)extraout_f1 * (float)extraout_f1;
    puVar4 = FUN_80037134(3,&local_44);
    if (local_44 != 0) {
      for (iVar6 = 0; iVar6 < local_44; iVar6 = iVar6 + 1) {
        dVar9 = FUN_80017714((float *)(puVar2 + 0xc),(float *)(puVar4[iVar6] + 0x18));
        if ((dVar9 < (double)local_48) && ((ushort *)puVar4[iVar6] != puVar2)) {
          *param_4 = (int)puVar4[iVar6];
          dVar9 = FUN_80293900(dVar9);
          local_30 = (longlong)(int)dVar9;
          *(short *)(param_4 + 1) = (short)(int)dVar9;
          if ((uVar10 & 2) != 0) {
            if ((*(uint *)(iVar8 + 0x2e4) & 0x8000) == 0) {
              iVar5 = *param_4;
              local_40 = *(float *)(puVar2 + 0xc) - *(float *)(iVar5 + 0x18);
              local_3c = *(float *)(puVar2 + 0xe) - *(float *)(iVar5 + 0x1c);
              local_38 = *(float *)(puVar2 + 0x10) - *(float *)(iVar5 + 0x20);
            }
            else {
              local_40 = *(float *)(puVar2 + 0xc) - *(float *)(*param_4 + 0x18);
              local_3c = FLOAT_803e31fc;
              local_38 = *(float *)(puVar2 + 0x10) - *(float *)(*param_4 + 0x20);
            }
            uVar3 = FUN_80017730();
            if (*(short **)(puVar2 + 0x18) == (short *)0x0) {
              uVar1 = *puVar2;
            }
            else {
              uVar1 = *puVar2 + **(short **)(puVar2 + 0x18);
            }
            uVar3 = (uVar3 & 0xffff) - (uint)uVar1;
            if (0x8000 < (int)uVar3) {
              uVar3 = uVar3 - 0xffff;
            }
            if ((int)uVar3 < -0x8000) {
              uVar3 = uVar3 + 0xffff;
            }
            iVar5 = (short)((uVar3 & 0xffff) >> 0xd) * 4;
            *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) & ~*(uint *)(&DAT_8031e840 + iVar5);
            if ((uVar10 & 4) != 0) {
              *(uint *)(*(int *)(*param_4 + 0xb8) + 0x2dc) =
                   *(uint *)(*(int *)(*param_4 + 0xb8) + 0x2dc) & ~*(uint *)(&DAT_8031e860 + iVar5);
            }
          }
          param_4 = param_4 + 2;
          iVar7 = iVar7 + 1;
          if (param_3 <= iVar7) {
            iVar6 = local_44;
          }
        }
      }
    }
  }
  else {
    iVar7 = FUN_80037008(3,puVar2,&local_48);
    *param_4 = iVar7;
    if (iVar7 != 0) {
      local_30 = (longlong)(int)local_48;
      *(short *)(param_4 + 1) = (short)(int)local_48;
      if ((uVar10 & 2) != 0) {
        if ((*(uint *)(iVar8 + 0x2e4) & 0x8000) == 0) {
          iVar7 = *param_4;
          local_40 = *(float *)(puVar2 + 0xc) - *(float *)(iVar7 + 0x18);
          local_3c = *(float *)(puVar2 + 0xe) - *(float *)(iVar7 + 0x1c);
          local_38 = *(float *)(puVar2 + 0x10) - *(float *)(iVar7 + 0x20);
        }
        else {
          local_40 = *(float *)(puVar2 + 0xc) - *(float *)(*param_4 + 0x18);
          local_3c = FLOAT_803e31fc;
          local_38 = *(float *)(puVar2 + 0x10) - *(float *)(*param_4 + 0x20);
        }
        uVar3 = FUN_80017730();
        if (*(short **)(puVar2 + 0x18) == (short *)0x0) {
          uVar1 = *puVar2;
        }
        else {
          uVar1 = *puVar2 + **(short **)(puVar2 + 0x18);
        }
        uVar3 = (uVar3 & 0xffff) - (uint)uVar1;
        if (0x8000 < (int)uVar3) {
          uVar3 = uVar3 - 0xffff;
        }
        if ((int)uVar3 < -0x8000) {
          uVar3 = uVar3 + 0xffff;
        }
        iVar7 = (short)((uVar3 & 0xffff) >> 0xd) * 4;
        *(uint *)(iVar8 + 0x2dc) = *(uint *)(iVar8 + 0x2dc) & ~*(uint *)(&DAT_8031e840 + iVar7);
        if ((uVar10 & 4) != 0) {
          *(uint *)(*(int *)(*param_4 + 0xb8) + 0x2dc) =
               *(uint *)(*(int *)(*param_4 + 0xb8) + 0x2dc) & ~*(uint *)(&DAT_8031e860 + iVar7);
        }
      }
    }
  }
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ca90
 * EN v1.0 Address: 0x8014CA90
 * EN v1.0 Size: 100b
 * EN v1.1 Address: 0x8014C950
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_8014ca90(int param_1)
{
  float fVar1;
  uint uVar2;
  
  if (param_1 == 0) {
    uVar2 = 0;
  }
  else if (*(int *)(param_1 + 0xb8) == 0) {
    uVar2 = 0;
  }
  else {
    fVar1 = *(float *)(*(int *)(param_1 + 0xb8) + 0x2d8);
    if (fVar1 == FLOAT_803e31fc) {
      uVar2 = 0;
    }
    else {
      uVar2 = (int)(fVar1 / FLOAT_803e322c) + 1U & 0xff;
    }
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_8014caf4
 * EN v1.0 Address: 0x8014CAF4
 * EN v1.0 Size: 200b
 * EN v1.1 Address: 0x8014C9B8
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014caf4(int param_1,uint *param_2,float *param_3,float *param_4)
{
  float fVar1;
  double dVar2;
  int iVar3;
  
  dVar2 = DOUBLE_803e3278;
  fVar1 = FLOAT_803e31fc;
  if ((param_1 == 0) || (iVar3 = *(int *)(param_1 + 0xb8), iVar3 == 0)) {
    *param_3 = FLOAT_803e31fc;
    *param_4 = fVar1;
    *param_2 = 0;
  }
  else {
    *param_3 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar3 + 0x2f3)) - DOUBLE_803e3278
                      ) / FLOAT_803e3210;
    *param_4 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar3 + 0x2f4)) - dVar2);
    *param_2 = (uint)*(byte *)(iVar3 + 0x2f2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014cbbc
 * EN v1.0 Address: 0x8014CBBC
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x8014CA38
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014cbbc(int param_1)
{
  *(undefined2 *)(*(int *)(param_1 + 0xb8) + 0x2b0) = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014cbcc
 * EN v1.0 Address: 0x8014CBCC
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x8014CA48
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_8014cbcc(int param_1)
{
  int iVar1;
  double dVar2;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (iVar1 == 0) {
    dVar2 = (double)FLOAT_803e31fc;
  }
  else if ((*(ushort *)(iVar1 + 0x2b2) == 0) || (*(ushort *)(iVar1 + 0x2b0) == 0)) {
    dVar2 = (double)FLOAT_803e31fc;
  }
  else {
    dVar2 = (double)((float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar1 + 0x2b0)) -
                            DOUBLE_803e3278) /
                    (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar1 + 0x2b2)) -
                           DOUBLE_803e3278));
  }
  return dVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_8014cc7c
 * EN v1.0 Address: 0x8014CC7C
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x8014CAB4
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014cc7c(int param_1)
{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80017a98();
  *(undefined4 *)(iVar2 + 0x29c) = uVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ccac
 * EN v1.0 Address: 0x8014CCAC
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8014CAE4
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ccac(int param_1,undefined4 param_2)
{
  *(undefined4 *)(*(int *)(param_1 + 0xb8) + 0x29c) = param_2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014ccb8
 * EN v1.0 Address: 0x8014CCB8
 * EN v1.0 Size: 756b
 * EN v1.1 Address: 0x8014CAF0
 * EN v1.1 Size: 680b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8014ccb8(double param_1,double param_2,double param_3,int param_4,int param_5,
                 float *param_6,char param_7)
{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  float afStack_c8 [3];
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float afStack_a4 [13];
  undefined4 local_70;
  uint uStack_6c;
  
  dVar2 = FUN_80247f54((float *)(param_5 + 0x2b8));
  if (dVar2 <= (double)FLOAT_803e31fc) {
    local_b0 = FLOAT_803e31fc;
    local_ac = FLOAT_803e31fc;
    local_a8 = FLOAT_803e31fc;
  }
  else {
    local_a8 = (float)((double)FLOAT_803e3200 / dVar2);
    local_b0 = *(float *)(param_5 + 0x2b8) * local_a8;
    local_ac = *(float *)(param_5 + 700) * local_a8;
    local_a8 = *(float *)(param_5 + 0x2c0) * local_a8;
    FUN_80247ef8(&local_b0,&local_b0);
  }
  dVar3 = FUN_80247f54(param_6);
  if (dVar3 <= (double)FLOAT_803e31fc) {
    local_bc = FLOAT_803e31fc;
    local_b8 = FLOAT_803e31fc;
    local_b4 = FLOAT_803e31fc;
  }
  else {
    local_b4 = (float)((double)FLOAT_803e3200 / dVar3);
    local_bc = *param_6 * local_b4;
    local_b8 = param_6[1] * local_b4;
    local_b4 = param_6[2] * local_b4;
  }
  FUN_80247fb0(&local_b0,&local_bc,afStack_c8);
  dVar4 = FUN_80247f54(afStack_c8);
  if ((double)FLOAT_803e31fc < dVar4) {
    FUN_80247f90(&local_b0,&local_bc);
    dVar4 = (double)FUN_80292754();
    uStack_6c = ((uint)(byte)((param_3 < dVar4) << 2) << 0x1c) >> 0x1e ^ 0x80000000;
    local_70 = 0x43300000;
    if (ABS((double)(float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e3218)) !=
        (double)FLOAT_803e31fc) {
      fVar1 = FLOAT_803e3258;
      if ((double)FLOAT_803e31fc < dVar4) {
        fVar1 = FLOAT_803e3200;
      }
      FUN_80247944((double)(float)(param_3 * (double)fVar1),afStack_a4,afStack_c8);
      FUN_80247cd8(afStack_a4,&local_b0,&local_bc);
    }
  }
  dVar4 = (double)(float)(dVar3 * (double)FLOAT_803e3280);
  dVar3 = (double)(float)(dVar2 + param_2);
  if ((dVar4 <= dVar3) && (dVar3 = dVar4, dVar4 < (double)(float)(dVar2 - param_2))) {
    dVar3 = (double)(float)(dVar2 - param_2);
  }
  if (param_1 < dVar3) {
    dVar3 = param_1;
  }
  *(float *)(param_4 + 0x24) = (float)((double)local_bc * dVar3);
  *(float *)(param_4 + 0x28) = (float)((double)local_b8 * dVar3);
  *(float *)(param_4 + 0x2c) = (float)((double)local_b4 * dVar3);
  if ((param_7 != '\0') && (*(float *)(param_4 + 0x28) < FLOAT_803e31fc)) {
    fVar1 = FLOAT_803e3264 + *(float *)(*(int *)(param_5 + 0x29c) + 0x10);
    if (*(float *)(param_4 + 0x10) < fVar1) {
      *(float *)(param_4 + 0x28) =
           *(float *)(param_4 + 0x28) *
           (FLOAT_803e3200 - (fVar1 - *(float *)(param_4 + 0x10)) / FLOAT_803e3264);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8014cfac
 * EN v1.0 Address: 0x8014CFAC
 * EN v1.0 Size: 760b
 * EN v1.1 Address: 0x8014CD98
 * EN v1.1 Size: 564b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_8014cfac(double param_1,double param_2,double param_3,double param_4,double param_5,
                   double param_6,double param_7,int param_8)
{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  
  dVar2 = (double)(float)(param_1 - (double)*(float *)(param_8 + 0x18));
  dVar4 = (double)(float)(param_2 - (double)*(float *)(param_8 + 0x1c));
  dVar3 = (double)(float)(param_3 - (double)*(float *)(param_8 + 0x20));
  dVar1 = FUN_80293900((double)(float)(dVar3 * dVar3 +
                                      (double)(float)(dVar2 * dVar2 + (double)(float)(dVar4 * dVar4)
                                                     )));
  if (dVar1 <= param_4) {
    if ((double)FLOAT_803e31fc < dVar1) {
      *(float *)(param_8 + 0x24) =
           FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar2 / param_4)) +
           *(float *)(param_8 + 0x24);
      *(float *)(param_8 + 0x28) =
           FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar4 / param_4)) +
           *(float *)(param_8 + 0x28);
      *(float *)(param_8 + 0x2c) =
           FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar3 / param_4)) +
           *(float *)(param_8 + 0x2c);
    }
  }
  else {
    *(float *)(param_8 + 0x24) =
         FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar2 / dVar1)) +
         *(float *)(param_8 + 0x24);
    *(float *)(param_8 + 0x28) =
         FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar4 / dVar1)) +
         *(float *)(param_8 + 0x28);
    *(float *)(param_8 + 0x2c) =
         FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar3 / dVar1)) +
         *(float *)(param_8 + 0x2c);
  }
  dVar1 = -param_6;
  if (dVar1 <= (double)*(float *)(param_8 + 0x24)) {
    if (param_6 < (double)*(float *)(param_8 + 0x24)) {
      *(float *)(param_8 + 0x24) = (float)param_6;
    }
  }
  else {
    *(float *)(param_8 + 0x24) = (float)dVar1;
  }
  if (dVar1 <= (double)*(float *)(param_8 + 0x28)) {
    if (param_6 < (double)*(float *)(param_8 + 0x28)) {
      *(float *)(param_8 + 0x28) = (float)param_6;
    }
  }
  else {
    *(float *)(param_8 + 0x28) = (float)dVar1;
  }
  if (dVar1 <= (double)*(float *)(param_8 + 0x2c)) {
    if (param_6 < (double)*(float *)(param_8 + 0x2c)) {
      *(float *)(param_8 + 0x2c) = (float)param_6;
    }
  }
  else {
    *(float *)(param_8 + 0x2c) = (float)dVar1;
  }
  if ((double)FLOAT_803e31fc != param_7) {
    dVar1 = (double)FUN_80293130(param_7,(double)FLOAT_803dc074);
    *(float *)(param_8 + 0x24) = (float)((double)*(float *)(param_8 + 0x24) * dVar1);
    dVar1 = (double)FUN_80293130(param_7,(double)FLOAT_803dc074);
    *(float *)(param_8 + 0x28) = (float)((double)*(float *)(param_8 + 0x28) * dVar1);
    dVar1 = (double)FUN_80293130(param_7,(double)FLOAT_803dc074);
    *(float *)(param_8 + 0x2c) = (float)((double)*(float *)(param_8 + 0x2c) * dVar1);
  }
  return dVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_8014d2a4
 * EN v1.0 Address: 0x8014D2A4
 * EN v1.0 Size: 592b
 * EN v1.1 Address: 0x8014CFCC
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_8014d2a4(double param_1,double param_2,double param_3,double param_4,double param_5,
                   double param_6,double param_7,int param_8)
{
  double dVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  
  dVar2 = (double)(float)(param_1 - (double)*(float *)(param_8 + 0x18));
  dVar4 = (double)(float)(param_2 - (double)*(float *)(param_8 + 0x1c));
  dVar3 = (double)(float)(param_3 - (double)*(float *)(param_8 + 0x20));
  dVar1 = FUN_80293900((double)(float)(dVar2 * dVar2 + (double)(float)(dVar3 * dVar3)));
  if (dVar1 <= param_4) {
    if ((double)FLOAT_803e31fc < dVar1) {
      *(float *)(param_8 + 0x24) =
           FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar2 / param_4)) +
           *(float *)(param_8 + 0x24);
      *(float *)(param_8 + 0x2c) =
           FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar3 / param_4)) +
           *(float *)(param_8 + 0x2c);
    }
  }
  else {
    *(float *)(param_8 + 0x24) =
         FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar2 / dVar1)) +
         *(float *)(param_8 + 0x24);
    *(float *)(param_8 + 0x2c) =
         FLOAT_803dc074 * (float)(param_5 * (double)(float)(dVar3 / dVar1)) +
         *(float *)(param_8 + 0x2c);
  }
  dVar1 = -param_6;
  if (dVar1 <= (double)*(float *)(param_8 + 0x24)) {
    if (param_6 < (double)*(float *)(param_8 + 0x24)) {
      *(float *)(param_8 + 0x24) = (float)param_6;
    }
  }
  else {
    *(float *)(param_8 + 0x24) = (float)dVar1;
  }
  if (dVar1 <= (double)*(float *)(param_8 + 0x2c)) {
    if (param_6 < (double)*(float *)(param_8 + 0x2c)) {
      *(float *)(param_8 + 0x2c) = (float)param_6;
    }
  }
  else {
    *(float *)(param_8 + 0x2c) = (float)dVar1;
  }
  if ((double)FLOAT_803e31fc != param_7) {
    dVar1 = (double)FUN_80293130(param_7,(double)FLOAT_803dc074);
    *(float *)(param_8 + 0x24) = (float)((double)*(float *)(param_8 + 0x24) * dVar1);
    dVar1 = (double)FUN_80293130(param_7,(double)FLOAT_803dc074);
    *(float *)(param_8 + 0x2c) = (float)((double)*(float *)(param_8 + 0x2c) * dVar1);
  }
  return dVar4;
}
