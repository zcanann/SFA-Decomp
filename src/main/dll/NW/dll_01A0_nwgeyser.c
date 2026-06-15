#include "main/mapEvent.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/objtexture.h"
#include "main/dll/dll_01A0_nwgeyser.h"
#include "main/dll/dim2conveyor.h"

extern uint GameBit_Get(int eventId);
extern void Sfx_AddLoopedObjectSound(int obj, int sfxId);
extern void Sfx_RemoveLoopedObjectSound(int obj, int sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern void GameBit_Set(int eventId, int value);
extern void objAudioFn_8006ef38(int obj, void* events, int pointCount, void* points,
                                void* scratch, f32 scaleX, f32 scaleZ);
extern f32 lbl_803E520C;
extern f32 lbl_803E5210;

void fn_801CDF94(int obj, int state, int flag);

extern f32 lbl_803E5200;
extern f32 timeDelta;
extern void fn_8003A168(int obj, void* p);
extern void fn_8003B228(int obj, void* p);
extern void fn_8003A230(int obj, void* p, f32 f);
extern void characterDoEyeAnims(int obj, void* p);
extern u8 lbl_803268B4[];
extern f32 lbl_803E5214;

void nw_geyser_init(int obj)
{
    ((GameObject*)obj)->objectFlags = (ushort)(((GameObject*)obj)->objectFlags | 0x6000);
    ((GameObject*)obj)->animEventCallback = (void*)NW_geyser_SeqFn;
}

char* fn_801CDE70(int* obj) { return *(char**)&((GameObject*)obj)->extra + 0xc; }

void nw_geyser_free(int* obj)
{
    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 0x1f, 0);
}

void nw_geyser_update(int obj)
{
    if (GameBit_Get(0xa) != 0)
    {
        ((GameObject*)obj)->anim.flags = OBJANIM_FLAG_HIDDEN;
        ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x8000);
        Sfx_RemoveLoopedObjectSound(obj, 0x372);
        Sfx_RemoveLoopedObjectSound(obj, 0x373);
        ObjHits_DisableObject((u32)obj);
        GameBit_Set(0x398, 1);
    }
    else
    {
        Sfx_AddLoopedObjectSound(obj, 0x372);
        Sfx_AddLoopedObjectSound(obj, 0x373);
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        ObjHits_EnableObject((u32)obj);
    }
}

int NW_geyser_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    ObjTextureRuntimeSlot* tex0;
    u8* animUpdateBytes;

    animUpdateBytes = (u8*)animUpdate;
    if (GameBit_Get(0xa) != 0)
    {
        animUpdateBytes[0x90] = (u8)(animUpdateBytes[0x90] | 4);
    }
    tex0 = objFindTexture(obj, 0, 0);
    objFindTexture(obj, 1, 0);
    tex0->offsetT = (s16)(tex0->offsetT + (s32)(lbl_803E5200 * timeDelta));
    if (tex0->offsetT > 0x4e80)
    {
        tex0->offsetT -= 0x4e80;
    }
    animUpdate->hitVolumePair = (s16)(animUpdate->activeHitVolumePair & ~0x40);
    animUpdate->sequenceEventActive = 0;
    return 0;
}

int fn_801CDE7C(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    u8* state;
    void* audioEvents;
    void* audioPoints;
    void* audioScratch;

    state = ((GameObject*)obj)->extra;
    if ((((NwMammothState*)state)->runtimeFlags & 0x20) == 0)
    {
        Sfx_StopObjectChannel(obj, 0x7f);
        ((NwMammothState*)state)->pathSpeed = lbl_803E520C;
        ((NwMammothState*)state)->runtimeFlags = (u8)(((NwMammothState*)state)->runtimeFlags & ~0x10);
        ((NwMammothState*)state)->runtimeFlags = (u8)(((NwMammothState*)state)->runtimeFlags | 0x20);
    }
    if ((((NwMammothState*)state)->runtimeFlags & 4) != 0)
    {
        ((NwMammothState*)state)->playerDistanceSq = lbl_803E520C;
        animUpdate->hitVolumePair = (s16)(animUpdate->hitVolumePair & ~8);
        animUpdate->hitVolumePair = (s16)(animUpdate->hitVolumePair & ~0x40);
        fn_801CDF94(obj, (int)state, 1);
    }
    audioEvents = state + 0x440;
    audioPoints = state + 0x45c;
    audioScratch = state + 0x16c;
    objAudioFn_8006ef38(obj, audioEvents, 8, audioPoints, audioScratch,
                        lbl_803E5210, *(f32*)&lbl_803E5210);
    if (animUpdate->eventCount != 0)
    {
        ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags & ~0x400);
        ((GameObject*)obj)->anim.modelState->flags |= OBJ_MODEL_STATE_SHADOW_VISIBLE;
    }
    return 0;
}

void fn_801CDF94(int obj, int state, int flag)
{
    if (flag != 0 && ((NwMammothState*)state)->playerObject != NULL && ((NwMammothState*)state)->playerDistanceSq < lbl_803E5214)
    {
        *(u8*)(state + 0x40c) = 1;
        *(f32*)(state + 0x410) = *(f32*)(*(int*)(state + 0x28) + 0xc);
        *(f32*)(state + 0x414) = *(f32*)(*(int*)(state + 0x28) + 0x10);
        *(f32*)(state + 0x418) = *(f32*)(*(int*)(state + 0x28) + 0x14);
    }
    else
    {
        *(u8*)(state + 0x40c) = 0;
    }
    if ((lbl_803268B4[((NwMammothState*)state)->stateIndex] & 0x2) != 0)
    {
        fn_8003A168(obj, (void*)(state + 0x40c));
        fn_8003B228(obj, (void*)(state + 0x40c));
    }
    else
    {
        fn_8003A230(obj, (void*)(state + 0x40c), lbl_803E520C);
        characterDoEyeAnims(obj, (void*)(state + 0x40c));
    }
}
