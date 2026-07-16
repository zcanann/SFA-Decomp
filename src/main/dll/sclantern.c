/*
 * sclantern - hanging lantern objects used in SharpClaw-themed areas.
 * SClantern_advanceAnimEvents drives the animation each frame: it fires
 * spark particle SFX at left/right attachment points (path points 0 and 1)
 * on events 1-4, and plays a swing SFX on event 9. Sparks are suppressed
 * during the early frames of move SCLANTERN_SPARK_SUPPRESS_MOVE (0x1b).
 * playerFn_801d6d58 probes the current player's anim-state flags and is
 * referenced externally.
 */
#include "main/dll/SC/SClantern.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_position_api.h"
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "main/object_api.h"
#include "main/mapEvent.h"
#include "main/obj_path.h"
#include "main/frame_timing.h"
#include "main/dll/SC/dll_01B0_shswapston.h"
#include "main/dll/SH/dll_01AE_shlevelcontrol.h"

#define SCLANTERN_EVENT_LEFT_SPARK_A  1
#define SCLANTERN_EVENT_RIGHT_SPARK_A 2
#define SCLANTERN_EVENT_LEFT_SPARK_B  3
#define SCLANTERN_EVENT_RIGHT_SPARK_B 4
#define SCLANTERN_EVENT_LANTERN_SWING 9
#define SCLANTERN_SWING_SFX_ID        0x2f4
#define SCLANTERN_SPARK_SFX_ID        0x415
#define SCLANTERN_SPARK_SUPPRESS_MOVE 0x1b

extern ObjAnimEventList gSClanternObjAnimEvents;

u32 SClantern_advanceAnimEvents(f32 moveStepScale, int obj)
{
    u32 advanceResult;
    GameObject* lantern;
    int pointIndex;
    int i;
    float posZ;
    float posY;
    float posX;

    pointIndex = 0;
    lantern = (GameObject*)obj;
    gSClanternObjAnimEvents.triggerCount = 0;
    gSClanternObjAnimEvents.rootCurveValid = 0;
    advanceResult = ObjAnim_AdvanceCurrentMove((int)obj, moveStepScale, timeDelta, &gSClanternObjAnimEvents);
    if (gSClanternObjAnimEvents.rootCurveValid != 0)
    {
        lantern->anim.rotX += gSClanternObjAnimEvents.rootPitch;
    }
    i = 0;
    while (i < gSClanternObjAnimEvents.triggerCount)
    {
        switch (gSClanternObjAnimEvents.triggeredIds[i])
        {
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
            Sfx_PlayFromObject(obj, SCLANTERN_SWING_SFX_ID);
            break;
        case 0:
        case 5:
        case 6:
        case 7:
        case 8:
        default:
            break;
        }
        i++;
    }
    if (pointIndex != 0)
    {
        ObjPath_GetPointWorldPosition((GameObject*)obj, pointIndex - 1, &posX, &posY, &posZ, 0);
        if (!((lantern->anim.currentMove == SCLANTERN_SPARK_SUPPRESS_MOVE) &&
              (lantern->anim.currentMoveProgress < 0.8f)))
        {
            Sfx_PlayAtPositionFromObjectIntFirstLegacy(obj, posX, posY, posZ, SCLANTERN_SPARK_SFX_ID);
        }
    }
    return advanceResult;
}

#pragma dont_inline on
u32 playerFn_801d6d58(void)
{
    u32 playerObj;

    (*gMapEventInterface)->getCurChar();
    playerObj = (u32)Obj_GetPlayerObject();
    objGetAnimStateFlags((GameObject*)playerObj, 0xff);
    return 2;
}
#pragma dont_inline reset
