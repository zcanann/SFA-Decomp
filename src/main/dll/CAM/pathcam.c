#include "ghidra_import.h"
#include "main/dll/CAM/pathcam.h"
#include "string.h"


#pragma peephole off
#pragma scheduling off
extern void Obj_TransformWorldPointToLocal(f32 x,f32 y,f32 z,f32 *outX,f32 *outY,f32 *outZ,
                                           int model);
extern void Obj_TransformLocalPointToWorld(f32 x,f32 y,f32 z,f32 *outX,f32 *outY,f32 *outZ,
                                           int model);
extern int getAngle(f32 dx,f32 dz);
extern void *mmAlloc(int size,int heap,int flags);
extern undefined4 camcontrol_getTargetPosition();
extern f32 Curve_EvalHermite(f32 param_1, f32 *param_2, f32 *param_3);
extern undefined4 Curve_AdvanceAlongPath(f32 param_1, f32 *param_2);
extern void mm_free(void *ptr);

extern int *gCameraInterface;
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

typedef struct {
    u8 b7 : 1;
    u8 b6 : 1;
    u8 rest : 6;
} CamcontrolFlagByte;

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
void pathcam_loadSettings(u16 *cam, int mode, u8 *data)
{
    s16 *target;
    f32 vOutA;
    f32 vOutB;
    f32 vOutC;
    f32 vOutD;
    f32 fVal;
    u32 uVal;

    ((CamcontrolFlagByte *)((char *)gCamcontrolModeSettings + 0xc6))->b7 = 0;
    *((char *)gCamcontrolModeSettings + 0xc4) = 0;
    *((char *)gCamcontrolModeSettings + 0xc3) = 0;
    *((char *)gCamcontrolModeSettings + 0xc7) = 0;
    ((CamcontrolFlagByte *)((char *)gCamcontrolModeSettings + 0xc8))->b7 = 0;
    *((char *)gCamcontrolModeSettings + 0xc2) = 8;
    target = *(s16 **)(cam + 0x52);
    switch (mode) {
    case 0:
        memset(gCamcontrolModeSettings, 0, 0xcc);
        if (data != NULL) {
            fVal = (f32)(u32)*(u16 *)(data + 0x1c);
            gCamcontrolModeSettings[0] = fVal;
            gCamcontrolModeSettings[0xc] = fVal;
            fVal = (f32)(u32)*(u16 *)(data + 0x1a);
            gCamcontrolModeSettings[1] = fVal;
            gCamcontrolModeSettings[0xe] = fVal;
            fVal = (f32)(u32)data[0x1f];
            gCamcontrolModeSettings[0x26] = fVal;
            gCamcontrolModeSettings[2] = fVal;
            gCamcontrolModeSettings[0x10] = fVal;
            fVal = (f32)(u32)data[0x1f];
            gCamcontrolModeSettings[0x27] = fVal;
            gCamcontrolModeSettings[3] = fVal;
            gCamcontrolModeSettings[0x12] = fVal;
        }
        fVal = lbl_803E16F0;
        gCamcontrolModeSettings[0x23] = fVal;
        gCamcontrolModeSettings[0x25] = fVal;
        fVal = lbl_803E1714;
        gCamcontrolModeSettings[4] = fVal;
        gCamcontrolModeSettings[0x14] = fVal;
        fVal = lbl_803E1734;
        gCamcontrolModeSettings[0x15] = fVal;
        gCamcontrolModeSettings[5] = fVal;
        gCamcontrolModeSettings[0x16] = fVal;
        fVal = lbl_803E1738;
        gCamcontrolModeSettings[6] = fVal;
        gCamcontrolModeSettings[0x18] = fVal;
        fVal = lbl_803E16DC;
        gCamcontrolModeSettings[7] = fVal;
        gCamcontrolModeSettings[0x1a] = fVal;
        gCamcontrolModeSettings[9] = lbl_803E16D0;
        gCamcontrolModeSettings[8] = lbl_803E16D4;
        *((char *)gCamcontrolModeSettings + 0xc1) = 1;
        gCamcontrolModeSettings[0x1c] = *(f32 *)(cam + 0x5a);
        camcontrol_getTargetPosition((int)cam, target, (f32 *)(cam + 0xc), cam + 1);
        fVal = *(f32 *)(cam + 0xc);
        *(f32 *)(cam + 6) = fVal;
        *(f32 *)(cam + 0x5c) = fVal;
        *(f32 *)(cam + 0x54) = fVal;
        fVal = *(f32 *)(cam + 0xe);
        *(f32 *)(cam + 8) = fVal;
        *(f32 *)(cam + 0x5e) = fVal;
        *(f32 *)(cam + 0x56) = fVal;
        fVal = *(f32 *)(cam + 0x10);
        *(f32 *)(cam + 10) = fVal;
        *(f32 *)(cam + 0x60) = fVal;
        *(f32 *)(cam + 0x58) = fVal;
        cam[0] = 0;
        cam[2] = 0;
        if (data != NULL) {
            *(f32 *)(cam + 0x5a) = (f32)(u32)data[0x19];
        }
        break;
    case 4:
        camcontrol_getTargetPosition((int)cam, target, (f32 *)(cam + 0xc), cam + 1);
        Obj_TransformWorldPointToLocal(*(f32 *)(cam + 0xc), *(f32 *)(cam + 0xe), *(f32 *)(cam + 0x10),
                                       (f32 *)(cam + 6), (f32 *)(cam + 8), (f32 *)(cam + 10),
                                       *(int *)(cam + 0x18));
        ((void (*)(u16 *, f32 *, f32 *, f32 *, f32 *, f32, int))*(void **)(*gCameraInterface + 0x38))(
            cam, &vOutA, &vOutB, &vOutC, &vOutD, gCamcontrolModeSettings[0x23], 0);
        vOutB = *(f32 *)(cam + 8) - (*(f32 *)(target + 8) + gCamcontrolModeSettings[0x23]);
        ((s16 *)cam)[1] = getAngle(vOutB, vOutD);
        cam[2] = 0;
        *(f32 *)(cam + 0x5c) = *(f32 *)(cam + 0xc);
        *(f32 *)(cam + 0x5e) = *(f32 *)(cam + 0xe);
        *(f32 *)(cam + 0x60) = *(f32 *)(cam + 0x10);
        *(f32 *)(cam + 0x54) = *(f32 *)(cam + 6);
        *(f32 *)(cam + 0x56) = *(f32 *)(cam + 8);
        *(f32 *)(cam + 0x58) = *(f32 *)(cam + 10);
        *(f32 *)(cam + 0x5a) = gCamcontrolModeSettings[0x1c];
        *(s16 *)((char *)gCamcontrolModeSettings + 0x82) = 0;
        break;
    case 2:
        if (data != NULL) {
            gCamcontrolModeSettings[0x25] = lbl_803E16F0;
            fVal = (f32)(u32)data[6];
            gCamcontrolModeSettings[0x26] = fVal;
            gCamcontrolModeSettings[0x10] = fVal;
            fVal = (f32)(u32)data[8];
            gCamcontrolModeSettings[0x27] = fVal;
            gCamcontrolModeSettings[0x12] = fVal;
            gCamcontrolModeSettings[0xc] = (f32)(u32)data[3];
            gCamcontrolModeSettings[0xe] = (f32)(u32)data[4];
            gCamcontrolModeSettings[0x1c] = (f32)*(s8 *)(data + 2);
            gCamcontrolModeSettings[0x18] = (f32)(u32)data[9];
            gCamcontrolModeSettings[0x1a] = (f32)(u32)data[0xa];
            uVal = data[0xb];
            if (uVal != 0) {
                gCamcontrolModeSettings[0x14] = (f32)uVal / lbl_803E1710;
            } else {
                gCamcontrolModeSettings[0x14] = lbl_803E1714;
            }
            uVal = data[0xc];
            if (uVal != 0) {
                gCamcontrolModeSettings[0x16] = (f32)uVal / lbl_803E1710;
            } else {
                gCamcontrolModeSettings[0x16] = lbl_803E1714;
            }
            *(s16 *)((char *)gCamcontrolModeSettings + 0x82) = (s16)*(s8 *)(data + 1);
            *(s16 *)((char *)gCamcontrolModeSettings + 0x84) = (s16)*(s8 *)(data + 1);
            *((u8 *)cam + 0x13b) = data[7];
        } else {
            gCamcontrolModeSettings[0x25] = gCamcontrolModeSettings[0x24];
            fVal = gCamcontrolModeSettings[0xf];
            gCamcontrolModeSettings[0x26] = fVal;
            gCamcontrolModeSettings[0x10] = fVal;
            fVal = gCamcontrolModeSettings[0x11];
            gCamcontrolModeSettings[0x27] = fVal;
            gCamcontrolModeSettings[0x12] = fVal;
            gCamcontrolModeSettings[0xc] = gCamcontrolModeSettings[0xb];
            gCamcontrolModeSettings[0xe] = gCamcontrolModeSettings[0xd];
            gCamcontrolModeSettings[0x1c] = gCamcontrolModeSettings[0x1b];
            gCamcontrolModeSettings[0x18] = gCamcontrolModeSettings[0x17];
            gCamcontrolModeSettings[0x1a] = gCamcontrolModeSettings[0x19];
            gCamcontrolModeSettings[0x14] = gCamcontrolModeSettings[0x13];
            gCamcontrolModeSettings[0x16] = gCamcontrolModeSettings[0x15];
            *(s16 *)((char *)gCamcontrolModeSettings + 0x82) = 0x3c;
            *(s16 *)((char *)gCamcontrolModeSettings + 0x84) = 0x3c;
        }
        gCamcontrolModeSettings[0x24] = gCamcontrolModeSettings[0x23];
        gCamcontrolModeSettings[0xf] = gCamcontrolModeSettings[2];
        gCamcontrolModeSettings[0x11] = gCamcontrolModeSettings[3];
        gCamcontrolModeSettings[0xb] = gCamcontrolModeSettings[0];
        gCamcontrolModeSettings[0xd] = gCamcontrolModeSettings[1];
        gCamcontrolModeSettings[0x1b] = *(f32 *)(cam + 0x5a);
        gCamcontrolModeSettings[0x17] = gCamcontrolModeSettings[6];
        gCamcontrolModeSettings[0x19] = gCamcontrolModeSettings[7];
        gCamcontrolModeSettings[0x13] = gCamcontrolModeSettings[4];
        gCamcontrolModeSettings[0x15] = gCamcontrolModeSettings[5];
        if ((data != NULL) && (data[0xd] != 0)) {
            camcontrol_getTargetPosition((int)cam, target, (f32 *)(cam + 0xc), cam + 1);
            Obj_TransformWorldPointToLocal(*(f32 *)(cam + 0xc), *(f32 *)(cam + 0xe), *(f32 *)(cam + 0x10),
                                           (f32 *)(cam + 6), (f32 *)(cam + 8), (f32 *)(cam + 10),
                                           *(int *)(cam + 0x18));
            *(s16 *)((char *)gCamcontrolModeSettings + 0x82) = 0;
        }
        break;
    case 3:
        *(f32 *)(cam + 0x5a) = gCamcontrolModeSettings[0x1c];
        *(f32 *)(cam + 0xc) = gCamcontrolModeSettings[0x1d];
        *(f32 *)(cam + 0xe) = gCamcontrolModeSettings[0x1e];
        *(f32 *)(cam + 0x10) = gCamcontrolModeSettings[0x1f];
        Obj_TransformWorldPointToLocal(*(f32 *)(cam + 0xc), *(f32 *)(cam + 0xe), *(f32 *)(cam + 0x10),
                                       (f32 *)(cam + 6), (f32 *)(cam + 8), (f32 *)(cam + 10),
                                       *(int *)(cam + 0x18));
        ((s16 *)cam)[0] = *(s16 *)((char *)gCamcontrolModeSettings + 0x86);
        ((s16 *)cam)[1] = *(s16 *)((char *)gCamcontrolModeSettings + 0x88);
        ((s16 *)cam)[2] = *(s16 *)((char *)gCamcontrolModeSettings + 0x8a);
        *(f32 *)(cam + 0x54) = *(f32 *)(cam + 6);
        *(f32 *)(cam + 0x56) = *(f32 *)(cam + 8);
        *(f32 *)(cam + 0x58) = *(f32 *)(cam + 10);
        *(f32 *)(cam + 0x5c) = *(f32 *)(cam + 0xc);
        *(f32 *)(cam + 0x5e) = *(f32 *)(cam + 0xe);
        *(f32 *)(cam + 0x60) = *(f32 *)(cam + 0x10);
        *(s16 *)((char *)gCamcontrolModeSettings + 0x82) = 0;
        break;
    case 1:
        *(f32 *)(cam + 0x5a) = gCamcontrolModeSettings[0x1c];
        ((CamcontrolFlagByte *)((char *)gCamcontrolModeSettings + 0xc6))->b7 =
            ((CamcontrolFlagByte *)((char *)gCamcontrolModeSettings + 0xc6))->b6;
        break;
    }
    ((CamcontrolFlagByte *)((char *)gCamcontrolModeSettings + 0xc6))->b6 = 0;
    *((u8 *)cam + 0x13e) = 1;
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
  iVar1 = (*(code *)(*gCameraInterface + 0x18))();
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
  if (lbl_803E1740 != *(float *)(gCamcontrolPathState + 300)) {
    pathT = *(float *)(gCamcontrolPathState + 0x128) /
            *(float *)(gCamcontrolPathState + 300);
  } else {
    pathT = lbl_803E1740;
  }
  if (pathT > lbl_803E1744) {
    pathT = lbl_803E1744;
  }
  else if (pathT < lbl_803E1740) {
    pathT = lbl_803E1740;
  }
  pathT = Curve_EvalHermite(pathT,(float *)(gCamcontrolPathState + 0x10c),(float *)0x0);
  if (pathT < lbl_803E1748) {
    pathT = lbl_803E1748;
  }
  Curve_AdvanceAlongPath(pathT,(float *)(gCamcontrolPathState + 0x120));
  *outX = *(float *)(gCamcontrolPathState + 0x188);
  *outZ = *(float *)(gCamcontrolPathState + 400);
  return;
}
#pragma peephole reset
#pragma scheduling reset
