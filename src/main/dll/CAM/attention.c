#include "ghidra_import.h"
#include "main/dll/CAM/attention.h"

extern undefined4 FUN_8000e054();
extern double FUN_80010de0();
extern undefined FUN_80064248();
extern int FUN_80065fcc();
extern undefined4 FUN_80067ad4();
extern undefined4 FUN_8006933c();
extern void trackDolphin_buildSweptBounds(uint *boundsOut,float *startPoints,float *endPoints,
                                          float *radii,int pointCount);
extern ulonglong FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_803dc070;
extern undefined4* gCamcontrolModeSettings;
extern f64 DOUBLE_803e2318;
extern f32 FLOAT_803e2308;
extern f32 FLOAT_803e2324;
extern f32 FLOAT_803e232c;
extern f32 FLOAT_803e2334;
extern f32 FLOAT_803e2350;
extern f32 FLOAT_803e2354;

/*
 * --INFO--
 *
 * Function: camcontrol_updateModeSettings
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801047DC
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_updateModeSettings(int param_1)
{
  double dVar1;
  float local_28;
  float local_24;
  float local_20;
  float local_1c;
  undefined4 local_18;
  uint uStack_14;
  undefined4 local_10;
  uint uStack_c;
  
  if (*(short *)((int)gCamcontrolModeSettings + 0x82) != 0) {
    *(ushort *)((int)gCamcontrolModeSettings + 0x82) =
         *(short *)((int)gCamcontrolModeSettings + 0x82) - (ushort)DAT_803dc070;
    if (*(short *)((int)gCamcontrolModeSettings + 0x82) < 0) {
      *(undefined2 *)((int)gCamcontrolModeSettings + 0x82) = 0;
    }
    uStack_14 = (int)*(short *)(gCamcontrolModeSettings + 0x21) -
                (int)*(short *)((int)gCamcontrolModeSettings + 0x82) ^
                0x80000000;
    local_18 = 0x43300000;
    uStack_c = (int)*(short *)(gCamcontrolModeSettings + 0x21) ^ 0x80000000;
    local_10 = 0x43300000;
    local_28 = FLOAT_803e232c;
    local_24 = FLOAT_803e2324;
    local_20 = FLOAT_803e232c;
    local_1c = FLOAT_803e232c;
    dVar1 = FUN_80010de0((double)((float)((double)CONCAT44(0x43300000,uStack_14) - DOUBLE_803e2318)
                                 / (float)((double)CONCAT44(0x43300000,uStack_c) - DOUBLE_803e2318))
                         ,&local_28,(float *)0x0);
    gCamcontrolModeSettings[0x23] = (float)(dVar1 *
                                           (double)(float)((double)gCamcontrolModeSettings[0x25] -
                                                          (double)gCamcontrolModeSettings[0x24]) +
                                           (double)gCamcontrolModeSettings[0x24]);
    *gCamcontrolModeSettings = (float)(dVar1 *
                                      (double)(float)((double)gCamcontrolModeSettings[0xc] -
                                                     (double)gCamcontrolModeSettings[0xb]) +
                                      (double)gCamcontrolModeSettings[0xb]);
    gCamcontrolModeSettings[1] = (float)(dVar1 *
                                        (double)(float)((double)gCamcontrolModeSettings[0xe] -
                                                       (double)gCamcontrolModeSettings[0xd]) +
                                        (double)gCamcontrolModeSettings[0xd]);
    gCamcontrolModeSettings[2] = (float)(dVar1 *
                                        (double)(float)((double)gCamcontrolModeSettings[0x10] -
                                                       (double)gCamcontrolModeSettings[0xf]) +
                                        (double)gCamcontrolModeSettings[0xf]);
    gCamcontrolModeSettings[3] = (float)(dVar1 *
                                        (double)(float)((double)gCamcontrolModeSettings[0x12] -
                                                       (double)gCamcontrolModeSettings[0x11]) +
                                        (double)gCamcontrolModeSettings[0x11]);
    gCamcontrolModeSettings[4] = (float)(dVar1 *
                                        (double)(float)((double)gCamcontrolModeSettings[0x14] -
                                                       (double)gCamcontrolModeSettings[0x13]) +
                                        (double)gCamcontrolModeSettings[0x13]);
    gCamcontrolModeSettings[5] = (float)(dVar1 *
                                        (double)(float)((double)gCamcontrolModeSettings[0x16] -
                                                       (double)gCamcontrolModeSettings[0x15]) +
                                        (double)gCamcontrolModeSettings[0x15]);
    gCamcontrolModeSettings[6] = (float)(dVar1 *
                                        (double)(float)((double)gCamcontrolModeSettings[0x18] -
                                                       (double)gCamcontrolModeSettings[0x17]) +
                                        (double)gCamcontrolModeSettings[0x17]);
    gCamcontrolModeSettings[7] = (float)(dVar1 *
                                        (double)(float)((double)gCamcontrolModeSettings[0x1a] -
                                                       (double)gCamcontrolModeSettings[0x19]) +
                                        (double)gCamcontrolModeSettings[0x19]);
    *(float *)(param_1 + 0xb4) =
         (float)(dVar1 *
                (double)(float)((double)gCamcontrolModeSettings[0x1c] -
                               (double)gCamcontrolModeSettings[0x1b]) +
                (double)gCamcontrolModeSettings[0x1b]);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: camcontrol_updateVerticalBounds
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x80104990
 * EN v1.1 Size: 700b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void camcontrol_updateVerticalBounds(undefined4 param_1,undefined4 param_2,undefined param_3,
                                     float *param_4,float *param_5)
{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  int iVar7;
  undefined uVar9;
  int iVar8;
  int iVar10;
  undefined4 uVar11;
  int iVar12;
  ulonglong uVar13;
  int local_40;
  float local_3c;
  undefined4 local_38;
  undefined4 local_34;
  uint auStack_30 [12];
  
  uVar13 = FUN_80286840();
  iVar7 = (int)(uVar13 >> 0x20);
  uVar11 = *(undefined4 *)(iVar7 + 0xa4);
  if ((uVar13 & 1) != 0) {
    *(float *)(iVar7 + 0x74) = FLOAT_803e2308;
    *(undefined *)(iVar7 + 0x84) = 0xff;
    *(undefined *)(iVar7 + 0x88) = param_3;
    uVar9 = FUN_80064248(iVar7 + 0xb8,iVar7 + 0x18,(float *)0x1,(int *)0x0,(int *)0x0,0x10,
                         0xffffffff,0xff,0);
    *(undefined *)(iVar7 + 0x142) = uVar9;
    local_3c = *(float *)(iVar7 + 0x18);
    local_38 = *(undefined4 *)(iVar7 + 0x1c);
    local_34 = *(undefined4 *)(iVar7 + 0x20);
    trackDolphin_buildSweptBounds(auStack_30,(float *)(iVar7 + 0xb8),&local_3c,
                                  (float *)(iVar7 + 0x74),1);
    FUN_8006933c(uVar11,auStack_30,0x240,'\x01');
    FUN_80067ad4();
    *(float *)(iVar7 + 0x18) = local_3c;
    *(undefined4 *)(iVar7 + 0x1c) = local_38;
    *(undefined4 *)(iVar7 + 0x20) = local_34;
  }
  if ((uVar13 & 2) != 0) {
    iVar8 = FUN_80065fcc((double)*(float *)(iVar7 + 0x18),(double)*(float *)(iVar7 + 0x1c),
                         (double)*(float *)(iVar7 + 0x20),uVar11,&local_40,1,0x40);
    *param_4 = FLOAT_803e2350;
    fVar5 = FLOAT_803e2354;
    *param_5 = FLOAT_803e2354;
    fVar2 = FLOAT_803e2334;
    fVar6 = FLOAT_803e232c;
    iVar10 = 0;
    iVar12 = iVar8;
    fVar3 = fVar5;
    if (0 < iVar8) {
      do {
        if ((*(float **)(local_40 + iVar10))[2] < fVar6) {
          fVar1 = **(float **)(local_40 + iVar10);
          if (*(float *)(iVar7 + 0x1c) - fVar2 < fVar1) {
            fVar4 = *(float *)(iVar7 + 0x1c) - fVar1;
            if (fVar4 < fVar6) {
              fVar4 = -fVar4;
            }
            if (fVar4 < fVar3) {
              *param_5 = fVar1;
              *(undefined4 *)(iVar7 + 300) = *(undefined4 *)(*(int *)(local_40 + iVar10) + 8);
              fVar3 = fVar4;
            }
          }
        }
        iVar10 = iVar10 + 4;
        iVar12 = iVar12 + -1;
      } while (iVar12 != 0);
    }
    fVar6 = FLOAT_803e2334;
    fVar3 = FLOAT_803e232c;
    iVar12 = 0;
    if (0 < iVar8) {
      do {
        if (fVar3 < (*(float **)(local_40 + iVar12))[2]) {
          fVar2 = **(float **)(local_40 + iVar12);
          if (fVar2 < fVar6 + *(float *)(iVar7 + 0x1c)) {
            fVar1 = *(float *)(iVar7 + 0x1c) - fVar2;
            if (fVar1 < fVar3) {
              fVar1 = -fVar1;
            }
            if (fVar1 < fVar5) {
              *param_4 = fVar2;
              *(undefined4 *)(iVar7 + 0x130) = *(undefined4 *)(*(int *)(local_40 + iVar12) + 8);
              fVar5 = fVar1;
            }
          }
        }
        iVar12 = iVar12 + 4;
        iVar8 = iVar8 + -1;
      } while (iVar8 != 0);
    }
  }
  FUN_8000e054((double)*(float *)(iVar7 + 0x18),(double)*(float *)(iVar7 + 0x1c),
               (double)*(float *)(iVar7 + 0x20),(float *)(iVar7 + 0xc),(float *)(iVar7 + 0x10),
               (float *)(iVar7 + 0x14),*(int *)(iVar7 + 0x30));
  FUN_8028688c();
  return;
}
