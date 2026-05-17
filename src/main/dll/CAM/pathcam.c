#include "ghidra_import.h"
#include "main/dll/CAM/pathcam.h"
#include "string.h"

extern void Obj_TransformWorldPointToLocal(f32 x,f32 y,f32 z,f32 *outX,f32 *outY,f32 *outZ,
                                           int model);
extern void Obj_TransformLocalPointToWorld(f32 x,f32 y,f32 z,f32 *outX,f32 *outY,f32 *outZ,
                                           int model);
extern s16 getAngle(f32 dx,f32 dz);
extern void *mmAlloc(int size,int heap,int flags);
extern undefined4 camcontrol_getTargetPosition();
extern f32 curveFn_80010dc0(f32 param_1, f32 *param_2, f32 *param_3);
extern undefined4 curveFn_80010320(f32 param_1, f32 *param_2);
extern void mm_free(void *ptr);

extern int *lbl_803DCA50;
extern f32 *cameraMtxVar57;
extern undefined4 lbl_803DD538;
extern f64 DOUBLE_803e1698;
extern f64 DOUBLE_803e16f8;
extern f32 lbl_803E16D0;
extern f32 lbl_803E16D4;
extern f32 lbl_803E16DC;
extern f32 lbl_803E16F0;
extern f32 lbl_803E1710;
extern f32 lbl_803E1714;
extern f32 lbl_803E1734;
extern f32 lbl_803E1738;
extern f32 lbl_803E1740;
extern f32 lbl_803E1744;
extern f32 lbl_803E1748;

#define gCamcontrolModeSettings cameraMtxVar57
#define gCamcontrolPathState lbl_803DD538

typedef struct CamcontrolPathSampleWork {
  u8 unk0[0xc];
  f32 sampleX;
  f32 sampleY;
  f32 sampleZ;
  f32 targetX;
  f32 targetY;
  f32 targetZ[4];
  int model;
  u8 unk34[0x70];
  undefined4 targetObj;
  f32 localX;
  f32 localY;
  f32 localZ;
  u8 unkB4[4];
  f32 worldX;
  f32 worldY;
  f32 worldZ[33];
} CamcontrolPathSampleWork;

static inline f64 PathCam_U32AsDouble(u32 value) {
  u64 bits = CONCAT44(0x43300000, value);
  return *(f64 *)&bits;
}

static inline f64 PathCam_S32AsDouble(s32 value) {
  u64 bits = CONCAT44(0x43300000, (u32)value ^ 0x80000000);
  return *(f64 *)&bits;
}

/*
 * --INFO--
 *
 * Function: pathcam_loadSettings
 * EN v1.0 Address: 0x80105E7C
 * EN v1.0 Size: 1900b
 * EN v1.1 Address: 0x80106118
 * EN v1.1 Size: 1904b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void pathcam_loadSettings(undefined2 *param_1,int param_2,int param_3)
{
  float *pfVar1;
  float fVar2;
  undefined4 uVar3;
  double dVar4;
  uint uVar5;
  short *psVar7;
  float local_58;
  undefined auStack_54 [4];
  float local_50;
  undefined auStack_4c [4];
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_20;
  uint uStack_1c;
  undefined4 local_18;
  uint uStack_14;
  
  *(byte *)((int)gCamcontrolModeSettings + 0xc6) =
       *(byte *)((int)gCamcontrolModeSettings + 0xc6) & 0x7f;
  *(undefined *)(gCamcontrolModeSettings + 0x31) = 0;
  *(undefined *)((int)gCamcontrolModeSettings + 0xc3) = 0;
  *(undefined *)((int)gCamcontrolModeSettings + 199) = 0;
  *(byte *)(gCamcontrolModeSettings + 0x32) = *(byte *)(gCamcontrolModeSettings + 0x32) & 0x7f;
  *(undefined *)((int)gCamcontrolModeSettings + 0xc2) = 8;
  psVar7 = *(short **)(param_1 + 0x52);
  if (param_2 != 2) {
    if (param_2 < 2) {
    if (param_2 == 0) {
      memset(gCamcontrolModeSettings,0,0xcc);
      dVar4 = DOUBLE_803e16f8;
      if (param_3 != 0) {
        uStack_44 = (uint)*(ushort *)(param_3 + 0x1c);
        local_48 = 0x43300000;
        fVar2 = (float)(PathCam_U32AsDouble(uStack_44) - DOUBLE_803e16f8);
        *gCamcontrolModeSettings = fVar2;
        gCamcontrolModeSettings[0xc] = fVar2;
        uStack_3c = (uint)*(ushort *)(param_3 + 0x1a);
        local_40 = 0x43300000;
        fVar2 = (float)(PathCam_U32AsDouble(uStack_3c) - dVar4);
        gCamcontrolModeSettings[1] = fVar2;
        gCamcontrolModeSettings[0xe] = fVar2;
        uStack_34 = (uint)*(byte *)(param_3 + 0x1f);
        local_38 = 0x43300000;
        fVar2 = (float)(PathCam_U32AsDouble(uStack_34) - dVar4);
        gCamcontrolModeSettings[0x26] = fVar2;
        gCamcontrolModeSettings[2] = fVar2;
        gCamcontrolModeSettings[0x10] = fVar2;
        uStack_2c = (uint)*(byte *)(param_3 + 0x1f);
        local_30 = 0x43300000;
        fVar2 = (float)(PathCam_U32AsDouble(uStack_2c) - dVar4);
        gCamcontrolModeSettings[0x27] = fVar2;
        gCamcontrolModeSettings[3] = fVar2;
        gCamcontrolModeSettings[0x12] = fVar2;
      }
      fVar2 = lbl_803E16F0;
      gCamcontrolModeSettings[0x23] = lbl_803E16F0;
      gCamcontrolModeSettings[0x25] = fVar2;
      fVar2 = lbl_803E1714;
      gCamcontrolModeSettings[4] = lbl_803E1714;
      gCamcontrolModeSettings[0x14] = fVar2;
      fVar2 = lbl_803E1734;
      gCamcontrolModeSettings[0x15] = lbl_803E1734;
      gCamcontrolModeSettings[5] = fVar2;
      gCamcontrolModeSettings[0x16] = fVar2;
      fVar2 = lbl_803E1738;
      gCamcontrolModeSettings[6] = lbl_803E1738;
      gCamcontrolModeSettings[0x18] = fVar2;
      fVar2 = lbl_803E16DC;
      gCamcontrolModeSettings[7] = lbl_803E16DC;
      gCamcontrolModeSettings[0x1a] = fVar2;
      gCamcontrolModeSettings[9] = lbl_803E16D0;
      gCamcontrolModeSettings[8] = lbl_803E16D4;
      *(undefined *)((int)gCamcontrolModeSettings + 0xc1) = 1;
      gCamcontrolModeSettings[0x1c] = *(float *)(param_1 + 0x5a);
      camcontrol_getTargetPosition((int)param_1,psVar7,(float *)(param_1 + 0xc),param_1 + 1);
      uVar3 = *(undefined4 *)(param_1 + 0xc);
      *(undefined4 *)(param_1 + 6) = uVar3;
      *(undefined4 *)(param_1 + 0x5c) = uVar3;
      *(undefined4 *)(param_1 + 0x54) = uVar3;
      uVar3 = *(undefined4 *)(param_1 + 0xe);
      *(undefined4 *)(param_1 + 8) = uVar3;
      *(undefined4 *)(param_1 + 0x5e) = uVar3;
      *(undefined4 *)(param_1 + 0x56) = uVar3;
      uVar3 = *(undefined4 *)(param_1 + 0x10);
      *(undefined4 *)(param_1 + 10) = uVar3;
      *(undefined4 *)(param_1 + 0x60) = uVar3;
      *(undefined4 *)(param_1 + 0x58) = uVar3;
      *param_1 = 0;
      param_1[2] = 0;
      if (param_3 != 0) {
        *(float *)(param_1 + 0x5a) =
             (float)(PathCam_U32AsDouble(*(u8 *)(param_3 + 0x19)) - DOUBLE_803e16f8)
        ;
      }
    }
    else if (-1 < param_2) {
      *(float *)(param_1 + 0x5a) = gCamcontrolModeSettings[0x1c];
      *(byte *)((int)gCamcontrolModeSettings + 0xc6) =
           (byte)((*(byte *)((int)gCamcontrolModeSettings + 0xc6) >> 6 & 1) << 7) |
           *(byte *)((int)gCamcontrolModeSettings + 0xc6) & 0x7f;
    }
  }
  else if (param_2 == 4) {
    camcontrol_getTargetPosition((int)param_1,psVar7,(float *)(param_1 + 0xc),param_1 + 1);
    Obj_TransformWorldPointToLocal(*(float *)(param_1 + 0xc),*(float *)(param_1 + 0xe),
                                    *(float *)(param_1 + 0x10),(float *)(param_1 + 6),
                                    (float *)(param_1 + 8),(float *)(param_1 + 10),
                                    *(int *)(param_1 + 0x18));
    (**(code **)(*lbl_803DCA50 + 0x38))
              ((double)gCamcontrolModeSettings[0x23],param_1,auStack_4c,&local_50,auStack_54,
               &local_58,0);
    local_50 = *(float *)(param_1 + 8) - (*(float *)(psVar7 + 8) + gCamcontrolModeSettings[0x23]);
    param_1[1] = getAngle(local_50,local_58);
    param_1[2] = 0;
    *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(param_1 + 0x5e) = *(undefined4 *)(param_1 + 0xe);
    *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x10);
    *(undefined4 *)(param_1 + 0x54) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0x56) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x58) = *(undefined4 *)(param_1 + 10);
    *(float *)(param_1 + 0x5a) = gCamcontrolModeSettings[0x1c];
    *(undefined2 *)((int)gCamcontrolModeSettings + 0x82) = 0;
  }
  else if (param_2 < 4) {
    *(float *)(param_1 + 0x5a) = gCamcontrolModeSettings[0x1c];
    *(float *)(param_1 + 0xc) = gCamcontrolModeSettings[0x1d];
    *(float *)(param_1 + 0xe) = gCamcontrolModeSettings[0x1e];
    *(float *)(param_1 + 0x10) = gCamcontrolModeSettings[0x1f];
    Obj_TransformWorldPointToLocal(*(float *)(param_1 + 0xc),*(float *)(param_1 + 0xe),
                                    *(float *)(param_1 + 0x10),(float *)(param_1 + 6),
                                    (float *)(param_1 + 8),(float *)(param_1 + 10),
                                    *(int *)(param_1 + 0x18));
    *param_1 = *(undefined2 *)((int)gCamcontrolModeSettings + 0x86);
    param_1[1] = *(undefined2 *)(gCamcontrolModeSettings + 0x22);
    param_1[2] = *(undefined2 *)((int)gCamcontrolModeSettings + 0x8a);
    *(undefined4 *)(param_1 + 0x54) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0x56) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x58) = *(undefined4 *)(param_1 + 10);
    *(undefined4 *)(param_1 + 0x5c) = *(undefined4 *)(param_1 + 0xc);
    *(undefined4 *)(param_1 + 0x5e) = *(undefined4 *)(param_1 + 0xe);
    *(undefined4 *)(param_1 + 0x60) = *(undefined4 *)(param_1 + 0x10);
    *(undefined2 *)((int)gCamcontrolModeSettings + 0x82) = 0;
  }
  }
  else {
    if (param_3 == 0) {
      gCamcontrolModeSettings[0x25] = gCamcontrolModeSettings[0x24];
      pfVar1 = gCamcontrolModeSettings + 0xf;
      gCamcontrolModeSettings[0x26] = *pfVar1;
      gCamcontrolModeSettings[0x10] = *pfVar1;
      pfVar1 = gCamcontrolModeSettings + 0x11;
      gCamcontrolModeSettings[0x27] = *pfVar1;
      gCamcontrolModeSettings[0x12] = *pfVar1;
      gCamcontrolModeSettings[0xc] = gCamcontrolModeSettings[0xb];
      gCamcontrolModeSettings[0xe] = gCamcontrolModeSettings[0xd];
      gCamcontrolModeSettings[0x1c] = gCamcontrolModeSettings[0x1b];
      gCamcontrolModeSettings[0x18] = gCamcontrolModeSettings[0x17];
      gCamcontrolModeSettings[0x1a] = gCamcontrolModeSettings[0x19];
      gCamcontrolModeSettings[0x14] = gCamcontrolModeSettings[0x13];
      gCamcontrolModeSettings[0x16] = gCamcontrolModeSettings[0x15];
      *(undefined2 *)((int)gCamcontrolModeSettings + 0x82) = 0x3c;
      *(undefined2 *)(gCamcontrolModeSettings + 0x21) = 0x3c;
    }
    else {
      gCamcontrolModeSettings[0x25] = lbl_803E16F0;
      dVar4 = DOUBLE_803e16f8;
      uStack_2c = (uint)*(byte *)(param_3 + 6);
      local_30 = 0x43300000;
      fVar2 = (float)(PathCam_U32AsDouble(uStack_2c) - DOUBLE_803e16f8);
      gCamcontrolModeSettings[0x26] = fVar2;
      gCamcontrolModeSettings[0x10] = fVar2;
      uStack_34 = (uint)*(byte *)(param_3 + 8);
      local_38 = 0x43300000;
      fVar2 = (float)(PathCam_U32AsDouble(uStack_34) - dVar4);
      gCamcontrolModeSettings[0x27] = fVar2;
      gCamcontrolModeSettings[0x12] = fVar2;
      uStack_3c = (uint)*(byte *)(param_3 + 3);
      local_40 = 0x43300000;
      gCamcontrolModeSettings[0xc] = (float)(PathCam_U32AsDouble(uStack_3c) - dVar4);
      uStack_44 = (uint)*(byte *)(param_3 + 4);
      local_48 = 0x43300000;
      gCamcontrolModeSettings[0xe] = (float)(PathCam_U32AsDouble(uStack_44) - dVar4);
      gCamcontrolModeSettings[0x1c] =
           (float)(PathCam_S32AsDouble(*(s8 *)(param_3 + 2)) - DOUBLE_803e1698);
      uStack_1c = (uint)*(byte *)(param_3 + 9);
      local_20 = 0x43300000;
      gCamcontrolModeSettings[0x18] = (float)(PathCam_U32AsDouble(uStack_1c) - dVar4);
      uStack_14 = (uint)*(byte *)(param_3 + 10);
      gCamcontrolModeSettings[0x1a] = (float)(PathCam_U32AsDouble(uStack_14) - dVar4);
      uVar5 = (uint)*(byte *)(param_3 + 0xb);
      if (uVar5 == 0) {
        gCamcontrolModeSettings[0x14] = lbl_803E1714;
      }
      else {
        gCamcontrolModeSettings[0x14] =
             (float)(PathCam_U32AsDouble(uVar5) - dVar4) / lbl_803E1710;
        uStack_14 = uVar5;
      }
      uVar5 = (uint)*(byte *)(param_3 + 0xc);
      if (uVar5 == 0) {
        gCamcontrolModeSettings[0x16] = lbl_803E1714;
      }
      else {
        gCamcontrolModeSettings[0x16] =
             (float)(PathCam_U32AsDouble(uVar5) - DOUBLE_803e16f8) / lbl_803E1710;
        uStack_14 = uVar5;
      }
      local_18 = 0x43300000;
      *(short *)((int)gCamcontrolModeSettings + 0x82) = (short)*(char *)(param_3 + 1);
      *(short *)(gCamcontrolModeSettings + 0x21) = (short)*(char *)(param_3 + 1);
      *(undefined *)((int)param_1 + 0x13b) = *(undefined *)(param_3 + 7);
    }
    gCamcontrolModeSettings[0x24] = gCamcontrolModeSettings[0x23];
    gCamcontrolModeSettings[0xf] = gCamcontrolModeSettings[2];
    gCamcontrolModeSettings[0x11] = gCamcontrolModeSettings[3];
    gCamcontrolModeSettings[0xb] = *gCamcontrolModeSettings;
    gCamcontrolModeSettings[0xd] = gCamcontrolModeSettings[1];
    gCamcontrolModeSettings[0x1b] = *(float *)(param_1 + 0x5a);
    gCamcontrolModeSettings[0x17] = gCamcontrolModeSettings[6];
    gCamcontrolModeSettings[0x19] = gCamcontrolModeSettings[7];
    gCamcontrolModeSettings[0x13] = gCamcontrolModeSettings[4];
    gCamcontrolModeSettings[0x15] = gCamcontrolModeSettings[5];
    if ((param_3 != 0) && (*(char *)(param_3 + 0xd) != '\0')) {
      camcontrol_getTargetPosition((int)param_1,psVar7,(float *)(param_1 + 0xc),param_1 + 1);
      Obj_TransformWorldPointToLocal(*(float *)(param_1 + 0xc),*(float *)(param_1 + 0xe),
                                      *(float *)(param_1 + 0x10),(float *)(param_1 + 6),
                                      (float *)(param_1 + 8),(float *)(param_1 + 10),
                                      *(int *)(param_1 + 0x18));
      *(undefined2 *)((int)gCamcontrolModeSettings + 0x82) = 0;
    }
  }
  *(byte *)((int)gCamcontrolModeSettings + 0xc6) =
       *(byte *)((int)gCamcontrolModeSettings + 0xc6) & 0xbf;
  *(undefined *)(param_1 + 0x9f) = 1;
  return;
}

#pragma scheduling off
#pragma peephole off
void camcontrol_releaseModeSettings(void) { mm_free(cameraMtxVar57); cameraMtxVar57 = 0; }
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void camcontrol_initialiseModeSettings(void)
{
  cameraMtxVar57 = (f32 *)mmAlloc(0xcc,0xf,0);
  memset(cameraMtxVar57,0,0xcc);
  return;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void camcontrol_samplePathState(f32 *outX,f32 *height,f32 *outZ,undefined4 param_4,int param_5)
{
  CamcontrolPathSampleWork work;
  int iVar1;
  int iVar2;
  f32 pathT;

  memset(&work,0,0x144);
  work.model = *(int *)(param_5 + 0x30);
  iVar1 = gCamcontrolPathState + *(int *)(gCamcontrolPathState + 0x1b0) * 4;
  work.sampleX = *(float *)(iVar1 + 0x14);
  work.sampleY = *height;
  work.sampleZ = *(float *)(iVar1 + 0xb4);
  work.localX = work.sampleX;
  work.localY = work.sampleY;
  work.localZ = work.sampleZ;
  Obj_TransformLocalPointToWorld((double)work.sampleX,(double)work.sampleY,(double)work.sampleZ,
                                 &work.worldX,&work.worldY,work.worldZ,work.model);
  work.targetObj = param_4;
  iVar1 = (*(code *)(*lbl_803DCA50 + 0x18))();
  (*(code *)(**(int **)(iVar1 + 4) + 0x14))(&work,param_4);
  Obj_TransformLocalPointToWorld(work.sampleX,work.sampleY,work.sampleZ,
                                 &work.targetX,&work.targetY,work.targetZ,work.model);
  (*(code *)(**(int **)(iVar1 + 4) + 0x24))
            (&work,1,3,gCamcontrolPathState + 0x14,gCamcontrolPathState + 0x18);
  iVar2 = *(int *)(gCamcontrolPathState + 0x1b0) + -3;
  iVar1 = iVar2 * 4;
  for (; iVar2 < *(int *)(gCamcontrolPathState + 0x1b0); iVar2 = iVar2 + 1) {
    *(float *)(gCamcontrolPathState + iVar1 + 0x1c) = work.sampleX;
    *(float *)(gCamcontrolPathState + iVar1 + 0xbc) = work.sampleZ;
    iVar1 = iVar1 + 4;
  }
  pathT = lbl_803E1740;
  if (pathT != *(float *)(gCamcontrolPathState + 300)) {
    pathT = *(float *)(gCamcontrolPathState + 0x128) /
            *(float *)(gCamcontrolPathState + 300);
  }
  if (pathT > lbl_803E1744) {
    pathT = lbl_803E1744;
  }
  else if (pathT < lbl_803E1740) {
    pathT = lbl_803E1740;
  }
  pathT = curveFn_80010dc0(pathT,(float *)(gCamcontrolPathState + 0x10c),(float *)0x0);
  if (pathT < lbl_803E1748) {
    pathT = lbl_803E1748;
  }
  curveFn_80010320(pathT,(float *)(gCamcontrolPathState + 0x120));
  *outX = *(float *)(gCamcontrolPathState + 0x188);
  *outZ = *(float *)(gCamcontrolPathState + 400);
  return;
}
#pragma peephole reset
#pragma scheduling reset
