#include "ghidra_import.h"
#include "dolphin/os.h"
#include "main/objHitReact.h"
#include "main/objanim_internal.h"

extern int fn_8000B5D0(int obj,u16 volumeId);
extern void fn_8000BB18(int obj,u16 volumeId);
extern void fn_80013E2C(void *handle);
extern void *fn_80013EC8(u32 effectId,u32 count);
extern int *fn_8002E0FC(undefined *param_1,undefined *param_2);
extern int fn_80036770(int obj,undefined4 *param_2,int *sphereIndex,uint *param_4,float *hitPos,
                       undefined *param_6,float *param_7);
extern void fn_8009A1DC(double param_1,int obj,undefined2 *pos,u32 count,int *param_5);
extern int ObjAnim_AdvanceCurrentMove(double moveStepScale,double deltaTime,int objAnim,int events);
extern void ObjAnim_SetCurrentMove(double moveProgress,int objAnim,int moveId,u32 flags);

extern undefined4 lbl_802C1B00;
extern undefined4 lbl_802C1B04;
extern undefined4 lbl_802C1B08;
extern undefined4 lbl_802C1B0C;
extern char sObjHitReactHitstateFrameString[];
extern char sObjHitReactSphereOverflowString[];
extern char sObjHitReactResetString[];
extern f32 lbl_803DB414;
extern f32 lbl_803DCDD8;
extern f32 lbl_803DCDDC;
extern f32 lbl_803DE910;
extern f32 lbl_803DE918;
extern f32 lbl_803DE964;
extern int gObjHitReactResetObjectCount;
extern int *gObjHitReactResetObjects;

typedef struct ObjHitReactEntry {
  s16 clearVolumeA;
  s16 clearVolumeB;
  s16 reactionAnim;
  u8 pad06[2];
  s8 hitFxMode;
  u8 pad09[3];
  f32 cooldown;
  u8 pad10[4];
} ObjHitReactEntry;

/*
 * --INFO--
 *
 * Function: objHitReact_update
 * EN v1.0 Address: 0x800353A4
 * EN v1.0 Size: 652b
 */
u8 objHitReact_update(int obj,void *entries,u32 entryCount,u32 reactionState,float *cooldown)
{
  ObjAnimComponent *objAnim;
  ObjAnimDef *animDef;
  int collisionType;
  int *effectHandle;
  bool volumeActive;
  ObjHitReactEntry *reactEntry;
  undefined4 local_44;
  undefined4 local_40;
  undefined4 local_3c;
  undefined4 local_38;
  undefined2 local_34;
  undefined2 local_32;
  undefined2 local_30;
  float local_2c;
  float local_28;
  undefined local_24[4];
  float local_20[8];
  int sphereIndex;

  objAnim = (ObjAnimComponent *)obj;
  local_44 = lbl_802C1B00;
  local_40 = lbl_802C1B04;
  local_3c = lbl_802C1B08;
  local_38 = lbl_802C1B0C;
  if ((reactionState & 0xff) != 0) {
    OSReport(sObjHitReactHitstateFrameString,objAnim->moveProgress);
    collisionType = ObjAnim_AdvanceCurrentMove((double)*cooldown,(double)lbl_803DB414,obj,0);
    if (collisionType != 0) {
      OSReport(sObjHitReactResetString);
      reactionState = 0;
    }
  }
  collisionType = fn_80036770(obj,0,&sphereIndex,0,&local_28,local_24,local_20);
  if (collisionType != 0) {
    animDef = ObjAnim_GetAnimDef(objAnim);
    local_28 = local_28 + lbl_803DCDD8;
    local_20[0] = local_20[0] + lbl_803DCDDC;
    local_2c = lbl_803DE918;
    local_30 = 0;
    local_32 = 0;
    local_34 = 0;
    sphereIndex = ObjAnim_GetHitReactEntryIndex(animDef,sphereIndex);
    if ((int)(entryCount & 0xff) <= sphereIndex) {
      OSReport(sObjHitReactSphereOverflowString);
      sphereIndex = 0;
    }
    reactEntry = (ObjHitReactEntry *)((u8 *)entries + sphereIndex * sizeof(ObjHitReactEntry));
    if (collisionType != 0x11) {
      if ((reactEntry->clearVolumeA != -1) &&
          (volumeActive = fn_8000B5D0(obj,(u16)reactEntry->clearVolumeA), !volumeActive)) {
        fn_8000BB18(obj,(u16)reactEntry->clearVolumeA);
      }
      if ((reactEntry->clearVolumeB != -1) &&
          (volumeActive = fn_8000B5D0(obj,(u16)reactEntry->clearVolumeB), !volumeActive)) {
        fn_8000BB18(obj,(u16)reactEntry->clearVolumeB);
      }
      if (reactEntry->hitFxMode == 1) {
        effectHandle = (int *)fn_80013EC8(0x5a,1);
        (**(code **)(*effectHandle + 4))(0,1,&local_34,0x401,-1,&local_44);
        if (effectHandle != (int *)0x0) {
          fn_80013E2C(effectHandle);
        }
      }
      else {
        fn_8009A1DC((double)lbl_803DE964,obj,&local_34,1,0);
      }
    }
    if (((reactionState & 0xff) == 0) && (reactEntry->reactionAnim != -1)) {
      ObjAnim_SetCurrentMove((double)lbl_803DE910,obj,(int)reactEntry->reactionAnim,0);
      *cooldown = reactEntry->cooldown;
      reactionState = 1;
    }
  }
  return reactionState;
}

void fn_80035630(int count)
{
  int obj;
  int hitState;
  int *objectList;
  undefined local_18[4];
  undefined local_14[16];

  objectList = fn_8002E0FC(local_18,local_14);
  gObjHitReactResetObjectCount = 0;
  if (0 < count) {
    do {
      obj = *objectList;
      hitState = *(int *)(obj + 0x54);
      if (((hitState != 0) && ((*(ushort *)(hitState + 0x60) & 1) != 0)) &&
         ((*(byte *)(hitState + 0x62) & 8) != 0)) {
        if (gObjHitReactResetObjectCount < 0x32) {
          gObjHitReactResetObjects[gObjHitReactResetObjectCount] = obj;
          gObjHitReactResetObjectCount = gObjHitReactResetObjectCount + 1;
        }
        *(int *)hitState = 0;
        *(ushort *)(hitState + 0x60) = *(ushort *)(hitState + 0x60) & 0xfff7;
        *(undefined2 *)(hitState + 0x58) = 0x400;
      }
      objectList = objectList + 1;
      count = count + -1;
    } while (count != 0);
  }
}
