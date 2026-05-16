#include "main/dll/SC/SClantern.h"
#include "main/objanim.h"
#include "main/objanim_internal.h"

extern undefined4 Sfx_PlayAtPositionFromObject();
extern undefined4 Sfx_PlayFromObject();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 objGetAnimStateField35c_2();
extern undefined4 FUN_8028683c();
extern undefined4 Obj_GetPlayerObject();

extern ObjAnimEventList gSClanternObjAnimEvents;
extern undefined4* lbl_803DCAAC;
extern f32 timeDelta;
extern f32 lbl_803E5498;

/*
 * --INFO--
 *
 * Function: SHthorntail_init
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
undefined4 SHthorntail_init(f32 moveStepScale, int obj)
{
  undefined4 advanceResult;
  s8 *event;
  s16 *objYaw;
  int pointIndex;
  int i;
  float posZ;
  float posY;
  float posX;

  pointIndex = 0;
  objYaw = (s16 *)obj;
  gSClanternObjAnimEvents.triggerCount = 0;
  gSClanternObjAnimEvents.rootCurveValid = 0;
  advanceResult = ObjAnim_AdvanceCurrentMove(moveStepScale,timeDelta,obj,&gSClanternObjAnimEvents);
  if (gSClanternObjAnimEvents.rootCurveValid != 0) {
    *objYaw += gSClanternObjAnimEvents.rootPitch;
  }
  i = 0;
  event = (s8 *)&gSClanternObjAnimEvents;
  while (i < (s8)gSClanternObjAnimEvents.triggerCount) {
    switch(event[0x13]) {
    case 1:
      pointIndex = 1;
      break;
    case 2:
      pointIndex = 2;
      break;
    case 3:
      pointIndex = 1;
      break;
    case 4:
      pointIndex = 2;
      break;
    case 9:
      Sfx_PlayFromObject(obj,0x2f4);
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
    if (!((*(s16 *)(obj + 0xa0) == 0x1b) && (*(f32 *)(obj + 0x98) < lbl_803E5498))) {
      Sfx_PlayAtPositionFromObject((double)posX,(double)posY,(double)posZ,obj,0x415);
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

  (*(code *)(*lbl_803DCAAC + 0x74))();
  playerObj = Obj_GetPlayerObject();
  objGetAnimStateField35c_2(playerObj,0xff);
  return 2;
}
#pragma peephole reset
#pragma scheduling reset
