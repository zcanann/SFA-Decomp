/*
 * nwgeyser (DLL 0x1A0) - the erupting geyser of SnowHorn Wastes (map
 * 'nwastes', 0x0A).
 *
 * The geyser plays a pair of looped object sounds and continuously runs
 * its trigger sequence; once GAMEBIT_GEYSER_OFF is set it hides, drops
 * its sounds and collision, and reports completion (GameBit 0x398). Its
 * SeqFn scrolls the geyser texture each frame.
 *
 * This TU also hosts two helpers shared with the SnowHorn mammoth (DLL
 * 0x1A1): nw_mammoth_SeqFn (nw_mammoth_SeqFn), which drives the mammoth's
 * looped audio / path state, and fn_801CDF94, which feeds the mammoth's
 * look-at target into the character eye-animation update.
 */
#include "main/mapEvent.h"
#include "main/game_object.h"
#include "main/objprint_character_api.h"
#include "main/objhits.h"
#include "main/objtexture.h"
#include "main/dll/dll_01A0_nwgeyser.h"
#include "main/dll/NW/dll_01A1_nwmammoth.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/frame_timing.h"
#include "main/newshadows_audio_api.h"

/* GameBit that erupts/retires the geyser (hides it, drops its sounds). */
#define GAMEBIT_GEYSER_OFF 0xa

/* looped object sounds played while the geyser is active */
#define SFX_GEYSER_LOOP_A 0x372
#define SFX_GEYSER_LOOP_B 0x373

#define NWGEYSER_OBJFLAG_HIDDEN             0x4000
#define NWGEYSER_OBJFLAG_HITDETECT_DISABLED 0x2000
#define NWGEYSER_OBJFLAG_UPDATE_DISABLED    0x8000

typedef struct NwGeyserTextureScrollParams
{
    f32 unitsPerSecond;
    f32 initialOffset;
} NwGeyserTextureScrollParams;

const NwGeyserTextureScrollParams gNwGeyserTextureScrollParams = {512.0f, 0.0f};


void fn_801CDF94(GameObject* obj, int state, int flag);

int NW_geyser_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    ObjTextureRuntimeSlot* tex0;
    u8* animUpdateBytes;

    animUpdateBytes = (u8*)animUpdate;
    if (mainGetBit(GAMEBIT_GEYSER_OFF) != 0)
    {
        animUpdateBytes[0x90] = (u8)(animUpdateBytes[0x90] | 4);
    }
    tex0 = objFindTexture((GameObject*)(obj), 0, 0);
    objFindTexture((GameObject*)(obj), 1, 0);
    tex0->offsetT =
        (s16)(tex0->offsetT + (s32)(gNwGeyserTextureScrollParams.unitsPerSecond * timeDelta));
    if (tex0->offsetT > 0x4e80)
    {
        tex0->offsetT -= 0x4e80;
    }
    animUpdate->hitVolumePair = (s16)(animUpdate->activeHitVolumePair & ~0x40);
    animUpdate->sequenceEventActive = 0;
    return 0;
}

void nw_geyser_free(int* obj)
{
    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0x1f, 0);
}

void nw_geyser_update(GameObject* obj)
{
    if (mainGetBit(GAMEBIT_GEYSER_OFF) != 0)
    {
        (obj)->anim.flags = OBJANIM_FLAG_HIDDEN;
        (obj)->objectFlags = (u16)((obj)->objectFlags | NWGEYSER_OBJFLAG_UPDATE_DISABLED);
        Sfx_RemoveLoopedObjectSound((int)obj, SFX_GEYSER_LOOP_A);
        Sfx_RemoveLoopedObjectSound((int)obj, SFX_GEYSER_LOOP_B);
        ObjHits_DisableObject(obj);
        mainSetBits(0x398, 1);
    }
    else
    {
        Sfx_AddLoopedObjectSound((int)obj, SFX_GEYSER_LOOP_A);
        Sfx_AddLoopedObjectSound((int)obj, SFX_GEYSER_LOOP_B);
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        ObjHits_EnableObject(obj);
    }
}

void nw_geyser_init(GameObject* obj)
{
    obj->objectFlags = (u16)(obj->objectFlags | (NWGEYSER_OBJFLAG_HIDDEN | NWGEYSER_OBJFLAG_HITDETECT_DISABLED));
    obj->animEventCallback = NW_geyser_SeqFn;
}

f32* fn_801CDE70(GameObject* obj)
{
    return (f32*)((u8*)obj->extra + 0xc);
}

int nw_mammoth_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    u8* state;
    void* audioEvents;
    void* audioPoints;
    void* audioScratch;

    state = (obj)->extra;
    if ((((NwMammothState*)state)->runtimeFlags & 0x20) == 0)
    {
        Sfx_StopObjectChannel((int)obj, 0x7f);
        ((NwMammothState*)state)->pathSpeed = 0.0f;
        ((NwMammothState*)state)->runtimeFlags = (u8)(((NwMammothState*)state)->runtimeFlags & ~0x10);
        ((NwMammothState*)state)->runtimeFlags = (u8)(((NwMammothState*)state)->runtimeFlags | 0x20);
    }
    if ((((NwMammothState*)state)->runtimeFlags & 4) != 0)
    {
        ((NwMammothState*)state)->playerDistanceSq = 0.0f;
        animUpdate->hitVolumePair = (s16)(animUpdate->hitVolumePair & ~8);
        animUpdate->hitVolumePair = (s16)(animUpdate->hitVolumePair & ~0x40);
        fn_801CDF94(obj, (int)state, 1);
    }
    audioEvents = state + 0x440;
    audioPoints = state + 0x45c;
    audioScratch = state + 0x16c;
    objAudioFn_8006ef38(obj, (ObjAnimEventList*)audioEvents, 8, audioPoints, audioScratch, 1.0f, 1.0f);
    if (animUpdate->eventCount != 0)
    {
        (obj)->objectFlags = (u16)((obj)->objectFlags & ~0x400);
        (obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
    }
    return 0;
}
