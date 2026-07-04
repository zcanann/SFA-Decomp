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
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objlib.h"
extern void Sfx_PlayAtPositionFromObject(int obj, f32 x, f32 y, f32 z, int sfxId);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern int objGetAnimStateFlags(int obj, int flag);
extern u32 Obj_GetPlayerObject();
extern ObjAnimEventList gSClanternObjAnimEvents;
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
    advanceResult = ObjAnim_AdvanceCurrentMove(moveStepScale, timeDelta, obj, &gSClanternObjAnimEvents);
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
        ObjPath_GetPointWorldPosition(obj, pointIndex - 1, &posX, &posY, &posZ, 0);
        if (!((lantern->anim.currentMove == SCLANTERN_SPARK_SUPPRESS_MOVE) &&
            (lantern->anim.currentMoveProgress < lbl_803E5498)))
        {
            Sfx_PlayAtPositionFromObject(obj, posX, posY, posZ, SCLANTERN_SPARK_SFX_ID);
        }
    }
    return advanceResult;
}

u32 playerFn_801d6d58(void)
{
    u32 playerObj;

    (*gMapEventInterface)->getCurChar();
    playerObj = Obj_GetPlayerObject();
    objGetAnimStateFlags(playerObj, 0xff);
    return 2;
}

/*__DATA_EXTERNS__*/
extern void sh_levelcontrol_getExtraSize();
extern void sh_levelcontrol_free();
extern void sh_levelcontrol_update();
extern void sh_levelcontrol_init();
extern void warpstone_updateMenuAnimObj();
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* jumptable_803275C0[22] = { (void*)((u8*)warpstone_updateMenuAnimObj + 0x1B0), (void*)((u8*)warpstone_updateMenuAnimObj + 0x1BC), (void*)((u8*)warpstone_updateMenuAnimObj + 0x35C), (void*)((u8*)warpstone_updateMenuAnimObj + 0x1C8), (void*)((u8*)warpstone_updateMenuAnimObj + 0x1E8), (void*)((u8*)warpstone_updateMenuAnimObj + 0x35C), (void*)((u8*)warpstone_updateMenuAnimObj + 0x228), (void*)((u8*)warpstone_updateMenuAnimObj + 0x214), (void*)((u8*)warpstone_updateMenuAnimObj + 0x35C), (void*)((u8*)warpstone_updateMenuAnimObj + 0x274), (void*)((u8*)warpstone_updateMenuAnimObj + 0x294), (void*)((u8*)warpstone_updateMenuAnimObj + 0x298), (void*)((u8*)warpstone_updateMenuAnimObj + 0x298), (void*)((u8*)warpstone_updateMenuAnimObj + 0x298), (void*)((u8*)warpstone_updateMenuAnimObj + 0x298), (void*)((u8*)warpstone_updateMenuAnimObj + 0x2E0), (void*)((u8*)warpstone_updateMenuAnimObj + 0x35C), (void*)((u8*)warpstone_updateMenuAnimObj + 0x304), (void*)((u8*)warpstone_updateMenuAnimObj + 0x318), (void*)((u8*)warpstone_updateMenuAnimObj + 0x33C), (void*)((u8*)warpstone_updateMenuAnimObj + 0x190), (void*)0x00000000 };
u16 lbl_80327618[130] = { 5, 8, 19, 20, 146, 147, 153, 174, 175, 176, 190, 417, 196, 197, 198, 245, 260, 277, 434, 97, 97, 97, 434, 437, 440, 440, 434, 97, 97, 97, 97, 97, 437, 440, 440, 440, 434, 97, 97, 97, 97, 97, 434, 97, 97, 97, 435, 95, 95, 95, 435, 438, 441, 441, 435, 95, 95, 95, 95, 95, 438, 441, 441, 441, 435, 95, 95, 95, 95, 95, 435, 95, 95, 95, 436, 96, 96, 96, 436, 439, 442, 442, 436, 96, 96, 96, 96, 96, 439, 442, 442, 442, 436, 96, 96, 96, 96, 96, 436, 96, 96, 96, 65535, 65535, 65535, 65535, 65535, 65535, 424, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 424, 65535, 424, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535, 65535 };
void* gSH_LevelControlObjDescriptor[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, sh_levelcontrol_init, sh_levelcontrol_update, (void*)0x00000000, (void*)0x00000000, sh_levelcontrol_free, (void*)0x00000000, sh_levelcontrol_getExtraSize };
