#include "main/dll/SC/SClantern.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"

extern void Sfx_PlayAtPositionFromObject(int obj, f32 x, f32 y, f32 z, int sfxId);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern undefined4 ObjPath_GetPointWorldPosition();
extern uint objGetAnimStateFlags(int obj,u32 mask);
extern undefined4 FUN_8028683c();
extern undefined4 Obj_GetPlayerObject();

extern ObjAnimEventList gSClanternObjAnimEvents;
extern undefined4* gMapEventInterface;
extern f32 timeDelta;
extern f32 lbl_803E5498;

#define SCLANTERN_EVENT_LEFT_SPARK_A 1
#define SCLANTERN_EVENT_RIGHT_SPARK_A 2
#define SCLANTERN_EVENT_LEFT_SPARK_B 3
#define SCLANTERN_EVENT_RIGHT_SPARK_B 4
#define SCLANTERN_EVENT_LANTERN_SWING 9
#define SCLANTERN_SWING_SFX_ID 0x2f4
#define SCLANTERN_SPARK_SFX_ID 0x415
#define SCLANTERN_SPARK_SUPPRESS_MOVE 0x1b

typedef struct SClanternAnimObject {
  s16 facingAngle;
  u8 pad02[0x98 - 0x02];
  f32 moveProgress;
  u8 pad9C[0xA0 - 0x9C];
  s16 currentMove;
} SClanternAnimObject;

/*
 * --INFO--
 *
 * Function: SClantern_advanceAnimEvents
 * EN v1.0 Address: 0x801D6C04
 * EN v1.0 Size: 340b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 SClantern_advanceAnimEvents(f32 moveStepScale, int obj)
{
  undefined4 advanceResult;
  register s8 *event;
  SClanternAnimObject *lantern;
  int pointIndex;
  int i;
  float posZ;
  float posY;
  float posX;

  pointIndex = 0;
  lantern = (SClanternAnimObject *)obj;
  gSClanternObjAnimEvents.triggerCount = 0;
  gSClanternObjAnimEvents.rootCurveValid = 0;
  advanceResult = ObjAnim_AdvanceCurrentMove(moveStepScale,timeDelta,obj,&gSClanternObjAnimEvents);
  if (gSClanternObjAnimEvents.rootCurveValid != 0) {
    lantern->facingAngle += gSClanternObjAnimEvents.rootPitch;
  }
  i = 0;
  event = (s8 *)&gSClanternObjAnimEvents;
  while (i < (s8)gSClanternObjAnimEvents.triggerCount) {
    switch(event[0x13]) {
    case SCLANTERN_EVENT_LEFT_SPARK_A:
      pointIndex = 1;
      break;
    case SCLANTERN_EVENT_RIGHT_SPARK_A:
      pointIndex = 2;
      break;
    case SCLANTERN_EVENT_LEFT_SPARK_B:
      pointIndex = 1;
      break;
    case SCLANTERN_EVENT_RIGHT_SPARK_B:
      pointIndex = 2;
      break;
    case SCLANTERN_EVENT_LANTERN_SWING:
      Sfx_PlayFromObject(obj,SCLANTERN_SWING_SFX_ID);
      break;
    case 0:
    case 5:
    case 6:
    case 7:
    case 8:
    default:
      break;
    }
    event++;
    i++;
  }
  if (pointIndex != 0) {
    ObjPath_GetPointWorldPosition(obj,pointIndex - 1,&posX,&posY,&posZ,0);
    if (!((lantern->currentMove == SCLANTERN_SPARK_SUPPRESS_MOVE) &&
          (lantern->moveProgress < lbl_803E5498))) {
      Sfx_PlayAtPositionFromObject(obj,posX,posY,posZ,SCLANTERN_SPARK_SFX_ID);
    }
  }
  return advanceResult;
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: playerFn_801d6d58
 * EN v1.0 Address: 0x801D6D58
 * EN v1.0 Size: 64b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
undefined4 playerFn_801d6d58(void)
{
  undefined4 playerObj;

  (*(code *)(*gMapEventInterface + 0x74))();
  playerObj = Obj_GetPlayerObject();
  objGetAnimStateFlags(playerObj,0xff);
  return 2;
}
#pragma peephole reset
#pragma scheduling reset
