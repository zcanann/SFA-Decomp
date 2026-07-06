/*
 * arwlevelcon (DLL 0x2A1) - the level controller for one of the on-rails
 * Arwing flight courses. There is one instance per course, distinguished by
 * its mapEventSlot (0x3a-0x3e), which selects the course's audio stream id
 * and the ring-choice trigger id. On the first update it configures the sky
 * (colour/overcast), kicks off the intro sequence (or the alternate-route
 * sequence when the placement's routeSignature flags it) and starts the
 * course music/audio stream. Once the Arwing flies past a Z threshold it
 * fires the ring-count gate: comparing collected vs required rings it sets
 * the "enough rings" (0x9d8) or "not enough" (0x9d7) game bit, which steers
 * the branching exit. ringEventCallback drives the sequence's camera and
 * course-specific text; commitRingChoice picks the follow-up music.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/audio/music_trigger_ids.h"


typedef struct ARWLevelConSetup
{
    u8 pad00[0x14];
    int routeSignature;
} ARWLevelConSetup;

typedef struct ARWLevelConState
{
    f32 sequenceParam0;
    f32 sequenceParam1;
    f32 sequenceParam2;
    f32 sequenceParam3;
    u8 pad10[4];
    s16 sequenceSlot;
    s16 sequenceCameraId;
    u8 skyConfigured;
    u8 sequenceStarted;
    u8 ringChoiceTriggered;
    u8 alternateRoute;
    int streamId;
    u16 ringChoiceTriggerId;
    u8 pad22[2];
} ARWLevelConState;

STATIC_ASSERT(sizeof(ARWLevelConState) == 0x24);
STATIC_ASSERT(offsetof(ARWLevelConState, sequenceSlot) == 0x14);
STATIC_ASSERT(offsetof(ARWLevelConState, sequenceCameraId) == 0x16);
STATIC_ASSERT(offsetof(ARWLevelConState, skyConfigured) == 0x18);
STATIC_ASSERT(offsetof(ARWLevelConState, sequenceStarted) == 0x19);
STATIC_ASSERT(offsetof(ARWLevelConState, ringChoiceTriggered) == 0x1a);
STATIC_ASSERT(offsetof(ARWLevelConState, alternateRoute) == 0x1b);
STATIC_ASSERT(offsetof(ARWLevelConState, streamId) == 0x1c);
STATIC_ASSERT(offsetof(ARWLevelConState, ringChoiceTriggerId) == 0x20);
STATIC_ASSERT(offsetof(ARWLevelConSetup, routeSignature) == 0x14);

void arwlevelcon_commitRingChoice(int obj)
{
    ARWLevelConState* state = ((GameObject*)obj)->extra;

    if (state->alternateRoute != 0)
    {
        Music_Trigger(MUSICTRIG_Mound_Music, 1);
    }
    else
    {
        Music_Trigger(MUSICTRIG_starfox_rwing_1, 1);
    }
    arwingHudSetVisible(1);
}

int arwlevelcon_ringEventCallback(int obj, int p2, int data)
{
    int i;
    int textId;
    ObjSeqState* seq = (ObjSeqState*)data;

    seq->freeCallback = (ObjAnimSequenceFreeCallback)arwlevelcon_commitRingChoice;
    for (i = 0; i < seq->eventCount; i++)
    {
        u8 eventId = seq->eventIds[i];
        if (eventId == 1)
        {
            (*gObjectTriggerInterface)->setCamVars(0x56, 0, 0, 0);
        }
        else if (eventId == 4)
        {
            switch (((GameObject*)obj)->anim.mapEventSlot)
            {
            case 0x3a:
                textId = 0;
                break;
            case 0x3b:
                textId = 1;
                break;
            case 0x3c:
                textId = 2;
                break;
            case 0x3e:
                textId = 3;
                break;
            case 0x3d:
                textId = 4;
                break;
            }
            gameTextFn_80125ba4(textId);
        }
    }
    return 0;
}

int arwlevelcon_getExtraSize(void) { return 0x24; }

int arwlevelcon_getObjectTypeId(void) { return 0; }

void arwlevelcon_free(void)
{
    arwingHudSetVisible(2);
    fn_80125D04();
    setIsOvercast(1);
}

void arwlevelcon_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E70E0);
}

void arwlevelcon_hitDetect(void)
{
}

void arwlevelcon_update(int obj)
{
    extern u8 AudioStream_IsPreparing(void);
    ARWLevelConState* state = ((GameObject*)obj)->extra;
    int arwing = getArwing();

    if (state->skyConfigured == 0)
    {
        skyFn_80089710(7, 1, 0);
        if (state->alternateRoute != 0)
        {
            skyFn_800895e0(7, 0xaa, 0x78, 0xff, 0x69, 0x40);
        }
        else
        {
            skyFn_800895e0(7, 0x96, 0x64, 0xf0, 0, 0);
        }
        skyFn_800894a8(7, lbl_803E70E4, *(f32*)&lbl_803E70E4, lbl_803E70E0);
        getEnvfxAct(0, 0, 0x21f, 0);
        getEnvfxAct(0, 0, 0x22b, 0);
        setIsOvercast(0);
        state->skyConfigured = 1;
        setDrawLights(0);
    }
    if (state->sequenceStarted == 0)
    {
        int mode;
        if (state->alternateRoute != 0)
        {
            mode = 3;
        }
        else
        {
            if (AudioStream_IsPreparing() == 0)
            {
                AudioStream_Play(state->streamId, AudioStream_StartPrepared);
            }
            mode = 0;
        }
        (*gObjectTriggerInterface)->runSequence(mode, (void*)obj, -1);
        state->sequenceStarted = 1;
        GameBit_Set(0x9d6, 0);
        GameBit_Set(0x9d8, 0);
        GameBit_Set(0x9d7, 0);
    }
    if (state->ringChoiceTriggered == 0)
    {
        int mapBlock = mapBlockFn_800592e4();
        if (((GameObject*)arwing)->anim.localPosZ - *(f32*)(mapBlock + 0x28) > lbl_803E70E8 &&
            arwarwing_isDead(arwing) == 0 && arwarwing_isExplodingOrWarping(arwing) == 0)
        {
            int requiredRings, collectedRings;
            arwingHudSetVisible(2);
            (*gObjectTriggerInterface)->setObjects(state->ringChoiceTriggerId, 0, 0);
            requiredRings = arwarwing_getRequiredRingCount(arwing);
            collectedRings = arwarwing_getCollectedRingCount(arwing);
            if (collectedRings >= requiredRings)
            {
                GameBit_Set(0x9d8, 1);
            }
            else
            {
                GameBit_Set(0x9d7, 1);
            }
            state->ringChoiceTriggered = 1;
            Music_Trigger(MUSICTRIG_starfox_rwing_1, 0);
            Music_Trigger(MUSICTRIG_Mound_Music, 0);
        }
    }
}

void arwlevelcon_init(int obj, u8* setup)
{
    ARWLevelConState* state = ((GameObject*)obj)->extra;
    ARWLevelConSetup* mapData = (ARWLevelConSetup*)setup;

    ((GameObject*)obj)->animEventCallback = arwlevelcon_ringEventCallback;
    state->sequenceSlot = 1;
    state->sequenceCameraId = 0x50;
    {
        f32 seqParam = lbl_803E70EC;
        state->sequenceParam0 = seqParam;
        state->sequenceParam1 = seqParam;
    }
    state->sequenceParam2 = lbl_803E70F0;
    state->sequenceParam3 = lbl_803E70F4;
    if (mapData->routeSignature == 0x48f7e)
    {
        state->alternateRoute = 1;
    }
    if (state->sequenceStarted == 0)
    {
        GameBit_Set(0x9d6, 0);
        GameBit_Set(0x9d8, 0);
        GameBit_Set(0x9d7, 0);
        GameBit_Set(0xe74, 0);
    }
    arwingHudSetVisible(2);
    pauseMenuCreateHeads();
    switch (((GameObject*)obj)->anim.mapEventSlot)
    {
    case 0x3a:
        state->streamId = 0x51bc;
        state->ringChoiceTriggerId = 0x6e3;
        break;
    case 0x3b:
        state->streamId = 0x51bd;
        state->ringChoiceTriggerId = 0x6df;
        break;
    case 0x3d:
        state->streamId = 0x51bf;
        state->ringChoiceTriggerId = 0x6e2;
        break;
    case 0x3c:
        state->streamId = 0x51be;
        state->ringChoiceTriggerId = 0x6e1;
        break;
    case 0x3e:
    default:
        state->streamId = 0x51c0;
        state->ringChoiceTriggerId = 0x6e0;
        break;
    }
}

void arwlevelcon_release(void)
{
}

void arwlevelcon_initialise(void)
{
}
