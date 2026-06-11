#include "main/dll/WM/wm_shared.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objanim_update.h"
#include "main/obj_placement.h"

typedef struct WmSeqPointState
{
    f32 triggerRadius;
    s16 conditionGameBit;
    s16 disableGameBit;
    s16 sequenceId;
    s16 unk0A;
    u8 command;
    u8 doneLatch;
    u8 triggerMode;
    u8 skyEnabledLatch;
} WmSeqPointState;

typedef struct WmSeqPointMapData
{
    ObjPlacement base;
    s8 rotXByte;
    u8 triggerMode;
    s16 triggerRadius;
    s16 sequenceId;
    s16 conditionGameBit;
    s16 disableGameBit;
} WmSeqPointMapData;

STATIC_ASSERT (offsetof
(WmSeqPointState
,
triggerRadius
)
==
0x0
);
STATIC_ASSERT (offsetof
(WmSeqPointState
,
conditionGameBit
)
==
0x4
);
STATIC_ASSERT (offsetof
(WmSeqPointState
,
disableGameBit
)
==
0x6
);
STATIC_ASSERT (offsetof
(WmSeqPointState
,
sequenceId
)
==
0x8
);
STATIC_ASSERT (offsetof
(WmSeqPointState
,
command
)
==
0xC
);
STATIC_ASSERT (offsetof
(WmSeqPointState
,
doneLatch
)
==
0xD
);
STATIC_ASSERT (offsetof
(WmSeqPointState
,
triggerMode
)
==
0xE
);
STATIC_ASSERT (offsetof
(WmSeqPointState
,
skyEnabledLatch
)
==
0xF
);
STATIC_ASSERT (
sizeof
(WmSeqPointState)
==
0x10
);
STATIC_ASSERT (offsetof
(WmSeqPointMapData
,
rotXByte
)
==
0x18
);
STATIC_ASSERT (offsetof
(WmSeqPointMapData
,
triggerMode
)
==
0x19
);
STATIC_ASSERT (offsetof
(WmSeqPointMapData
,
triggerRadius
)
==
0x1A
);
STATIC_ASSERT (offsetof
(WmSeqPointMapData
,
sequenceId
)
==
0x1C
);
STATIC_ASSERT (offsetof
(WmSeqPointMapData
,
conditionGameBit
)
==
0x1E
);
STATIC_ASSERT (offsetof
(WmSeqPointMapData
,
disableGameBit
)
==
0x20
);
STATIC_ASSERT (
sizeof
(WmSeqPointMapData)
==
0x24
);

void fn_801F654C(int obj)
{
    WmSeqPointState* state;
    int skyOn;

    state = ((GameObject*)obj)->extra;
    if (state->sequenceId == 0x21)
    {
        GameBit_Set(0xd1b, 1);
    }
    else if (state->sequenceId == 1)
    {
        skyOn = getSkyColorFn_80088e08(0) & 0xff;
        if (state->skyEnabledLatch != 0 && skyOn == 0)
        {
            getEnvfxActImmediately(0, 0, 0x22d, 0);
            getEnvfxActImmediately(obj, obj, 0x22c, 0);
            getEnvfxActImmediately(obj, obj, 0x229, 0);
            getEnvfxActImmediately(obj, obj, 0x22a, 0);
            (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 4, 1);
            (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 10, 0);
            (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 0xb, 0);
        }
        else if (state->skyEnabledLatch == 0 && skyOn != 0)
        {
            getEnvfxActImmediately(0, 0, 0x217, 0);
            getEnvfxActImmediately(obj, obj, 0x216, 0);
            getEnvfxActImmediately(obj, obj, 0x84, 0);
            getEnvfxActImmediately(obj, obj, 0x8a, 0);
            (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 4, 0);
            (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 10, 1);
            (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 0xb, 1);
        }
    }
}


int wmseqpoint_SeqFn(int obj, int unused, ObjAnimUpdateState* actor)
{
    WmSeqPointState* state;
    int player;
    int i;

    state = ((GameObject*)obj)->extra;
    player = (int)Obj_GetPlayerObject();
    actor->sequenceEventActive = 0;
    actor->freeCallback = (ObjAnimSequenceFreeCallback)fn_801F654C;

    for (i = 0; i < actor->eventCount; i++)
    {
        switch (state->sequenceId)
        {
        case 0:
            if (actor->eventIds[i] != 0)
            {
                state->command = actor->eventIds[i];
                switch (actor->eventIds[i])
                {
                case 1:
                    GameBit_Set(0x143, 1);
                    break;
                case 2:
                    GameBit_Set(0x143, 0);
                    break;
                case 5:
                    GameBit_Set(0x21d, 1);
                    break;
                case 4:
                    GameBit_Set(0x21d, 1);
                    fn_80296518(player, 8, 0);
                    GameBit_Set(0x277, 1);
                    break;
                default:
                    break;
                }
            }
            break;
        default:
            switch (actor->eventIds[i])
            {
            case 0xb:
                if ((u32)(getSkyColorFn_80088e08(0) & 0xff) != 0)
                {
                    getEnvfxActImmediately(0, 0, 0x217, 0);
                    getEnvfxActImmediately(obj, obj, 0x216, 0);
                    getEnvfxActImmediately(obj, obj, 0x84, 0);
                    getEnvfxActImmediately(obj, obj, 0x8a, 0);
                    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 4, 0);
                    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 10, 1);
                    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 0xb, 1);
                }
                break;
            case 0xa:
                if ((u32)(getSkyColorFn_80088e08(0) & 0xff) == 0)
                {
                    getEnvfxActImmediately(0, 0, 0x22d, 0);
                    getEnvfxActImmediately(obj, obj, 0x22c, 0);
                    getEnvfxActImmediately(obj, obj, 0x229, 0);
                    getEnvfxActImmediately(obj, obj, 0x22a, 0);
                    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 4, 1);
                    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 10, 0);
                    (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 0xb, 0);
                }
                break;
            default:
                break;
            }
            break;
        }
        actor->eventIds[i] = 0;
    }

    return 0;
}

int wmseqpoint_getExtraSize(void) { return 0x10; }

int wmseqpoint_getObjectTypeId(void) { return 0x0; }

void wmseqpoint_free(void)
{
}

void wmseqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 isVisible;

    isVisible = visible;
    if (isVisible != 0)
    {
        objRenderFn_8003b8f4(lbl_803E5F10);
    }
}

void wmseqpoint_hitDetect(void)
{
}

void wmseqpoint_update(int obj)
{
    WmSeqPointState* state;
    int player;
    int target;
    int i;
    extern u8 getSkyColorFn_80088e08(int skyId);

    player = (int)Obj_GetPlayerObject();
    state = ((GameObject*)obj)->extra;

    if (state->disableGameBit != -1)
    {
        if (state->doneLatch != 0)
        {
            if (GameBit_Get(state->disableGameBit) != 0)
            {
                return;
            }
            GameBit_Set(state->disableGameBit, 1);
            state->doneLatch = 1;
            return;
        }
        if (GameBit_Get(state->disableGameBit) != 0)
        {
            state->doneLatch = 1;
            return;
        }
    }

    if (state->doneLatch != 0)
    {
        return;
    }

    switch (state->triggerMode)
    {
    case 0:
        if (Vec_distance((void*)&((GameObject*)obj)->anim.worldPosX, (void*)(player + 0x18)) < state->triggerRadius)
        {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
            state->doneLatch = 1;
        }
        break;
    case 1:
        if (state->conditionGameBit != -1 && GameBit_Get(state->conditionGameBit) != 0)
        {
            if (state->sequenceId == 0x22)
            {
                for (i = 0; i < 5; i++)
                {
                    GameBit_Set(lbl_80328CC8[i * 2], 0);
                    target = ObjList_FindObjectById(lbl_80328CC8[i * 2 + 1]);
                    *(u8*)(*(int*)(target + 0xb8) + 0xd) = 0;
                    if (*(s16*)(target + 0xb4) != -1)
                    {
                        (*gObjectTriggerInterface)->endSequence(*(s16*)(target + 0xb4));
                    }
                }
            }
            else if (state->sequenceId == 1)
            {
                state->skyEnabledLatch = getSkyColorFn_80088e08(0);
            }
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
            state->doneLatch = 1;
        }
        break;
    case 2:
        if (Vec_distance((void*)&((GameObject*)obj)->anim.worldPosX, (void*)(player + 0x18)) < state->triggerRadius &&
            state->conditionGameBit != -1 && GameBit_Get(state->conditionGameBit) != 0)
        {
            if (state->sequenceId == 0x21)
            {
                GameBit_Set(0xd1b, 0);
                target = ObjList_FindObjectById(0x4aeb1);
                *(u8*)(*(int*)(target + 0xb8) + 0xd) = 0;
                if (*(s16*)(target + 0xb4) != -1)
                {
                    (*gObjectTriggerInterface)->endSequence(*(s16*)(target + 0xb4));
                }
            }
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
            state->doneLatch = 1;
        }
        break;
    case 3:
        if (Vec_distance((void*)&((GameObject*)obj)->anim.worldPosX, (void*)(player + 0x18)) < state->triggerRadius &&
            state->conditionGameBit != -1 && GameBit_Get(state->conditionGameBit) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
            GameBit_Set(state->conditionGameBit, 1);
            state->doneLatch = 1;
        }
        break;
    case 4:
        if (state->conditionGameBit != -1 && GameBit_Get(state->conditionGameBit) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
            GameBit_Set(state->conditionGameBit, 1);
            state->doneLatch = 1;
        }
        break;
    case 5:
        if (state->conditionGameBit != -1 && GameBit_Get(state->conditionGameBit) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->sequenceId, (void*)obj, -1);
        }
        break;
    default:
        break;
    }
}

void wmseqpoint_init(int obj, int setup)
{
    WmSeqPointState* state;
    WmSeqPointMapData* mapData;

    state = ((GameObject*)obj)->extra;
    mapData = (WmSeqPointMapData*)setup;
    ((GameObject*)obj)->animEventCallback = (void*)wmseqpoint_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)(mapData->rotXByte << 8);
    state->triggerRadius = (f32)mapData->triggerRadius;
    state->sequenceId = mapData->sequenceId;
    state->doneLatch = 0;
    state->triggerMode = mapData->triggerMode;
    state->conditionGameBit = mapData->conditionGameBit;
    state->disableGameBit = mapData->disableGameBit;
    state->command = 0;
    state->unk0A = 0;
}

void wmseqpoint_release(void)
{
}

void wmseqpoint_initialise(void)
{
}
