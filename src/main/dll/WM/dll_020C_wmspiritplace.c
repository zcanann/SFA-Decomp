#include "main/dll/WM/wm_shared.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/objanim_update.h"
#include "main/obj_placement.h"

typedef struct WmSpiritPlaceState
{
    f32 heightOffset;
    int unk_04;
    s16 unk_08;
    s16 unk_0A;
    s16 promptGameBit;
    s16 sequenceGameBit;
    s16 setupParam;
    u8 flags12;
    u8 mapEventState;
    u8 transitionDelay;
    u8 f80 : 1;
    u8 f40 : 1;
    u8 flags15rest : 6;
    u8 pad16[2];
} WmSpiritPlaceState;

typedef struct WmSpiritPlaceMapData
{
    ObjPlacement base;
    s8 rotXByte;
    s8 setupParam;
    s16 rotYAngle;
    s16 heightOffset;
    s16 sequenceGameBit;
    s16 promptGameBit;
} WmSpiritPlaceMapData;

STATIC_ASSERT (offsetof
(WmSpiritPlaceState
,
promptGameBit
)
==
0x0C
);
STATIC_ASSERT (offsetof
(WmSpiritPlaceState
,
sequenceGameBit
)
==
0x0E
);
STATIC_ASSERT (offsetof
(WmSpiritPlaceState
,
setupParam
)
==
0x10
);
STATIC_ASSERT (offsetof
(WmSpiritPlaceState
,
transitionDelay
)
==
0x14
);
STATIC_ASSERT (
sizeof
(WmSpiritPlaceState)
==
0x18
);
STATIC_ASSERT (offsetof
(WmSpiritPlaceMapData
,
rotXByte
)
==
0x18
);
STATIC_ASSERT (offsetof
(WmSpiritPlaceMapData
,
setupParam
)
==
0x19
);
STATIC_ASSERT (offsetof
(WmSpiritPlaceMapData
,
rotYAngle
)
==
0x1A
);
STATIC_ASSERT (offsetof
(WmSpiritPlaceMapData
,
heightOffset
)
==
0x1C
);
STATIC_ASSERT (offsetof
(WmSpiritPlaceMapData
,
sequenceGameBit
)
==
0x1E
);
STATIC_ASSERT (offsetof
(WmSpiritPlaceMapData
,
promptGameBit
)
==
0x20
);
STATIC_ASSERT (
sizeof
(WmSpiritPlaceMapData)
==
0x24
);

void fn_801F568C(void)
{
}

int wmspiritplace_SeqFn(int obj, int unused, ObjAnimUpdateState* actor)
{
    int i;
    WmSpiritPlaceState* state;
    int mapId;
    u8 action;
    u8 fxPos[24];

    state = ((GameObject*)obj)->extra;
    if ((state->flags12 & 1) != 0)
    {
        (*gPartfxInterface)->spawnObject((void*)obj, 0x7d8, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject((void*)obj, 0x7d8, fxPos, 2, -1, NULL);
    }

    actor->sequenceEventActive = 0;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~0x8);
    actor->freeCallback = (ObjAnimSequenceFreeCallback)fn_801F568C;

    for (i = 0; i < actor->eventCount; i++)
    {
        action = actor->eventIds[i];
        switch (action)
        {
        case 1:
            unlockLevel(0, 0, 1);
            break;
        case 3:
            mapId = *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
            switch (mapId)
            {
            case 0x47295:
                warpToMap(0x7e, 0);
                break;
            case 0x49781:
                warpToMap(0x7e, 0);
                break;
            case 0x4a1c0:
                warpToMap(0x7e, 0);
                break;
            }
            break;
        case 4:
            mapId = *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
            switch (mapId)
            {
            case 0x47295:
            case 0x49781:
            case 0x4a1c0:
            case 0x4a250:
            case 0x4a5e6:
                state->transitionDelay = 1;
                break;
            }
            break;
        case 5:
            state->flags12 = (u8)(state->flags12 | 1);
            break;
        case 6:
            state->flags12 = (u8)(state->flags12 & ~1);
            break;
        case 7:
            skyFn_80088c94(7, 0);
            setDrawCloudsAndLights(1);
            getEnvfxAct(obj, obj, 0x84, 0);
            getEnvfxAct(obj, obj, 0x8a, 0);
            getEnvfxActImmediately(0, 0, 0x217, 0);
            getEnvfxActImmediately(0, 0, 0x216, 0);
            break;
        case 8:
            Rcp_SetSpiritVisionEnabled(1);
            break;
        case 9:
            Rcp_SetSpiritVisionEnabled(0);
            break;
        case 2:
            mapId = *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
            switch (mapId)
            {
            case 0x2183:
                lockLevel(mapGetDirIdx(0x41), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                (*(void (**)(int))((u8*)*gMapEventInterface + 0x78))(1);
                break;
            case 0x47295:
                loadMapAndParent(0x42);
                lockLevel(mapGetDirIdx(0x42), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                (*gMapEventInterface)->setMode(0x42, 3);
                (*gMapEventInterface)->setMode(7, 4);
                break;
            case 0x49781:
                loadMapAndParent(0x42);
                lockLevel(mapGetDirIdx(0x42), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                (*gMapEventInterface)->setMode(0x42, 3);
                (*gMapEventInterface)->setMode(7, 5);
                break;
            case 0x4a1c0:
                loadMapAndParent(0x42);
                lockLevel(mapGetDirIdx(0x42), 0);
                lockLevel(mapGetDirIdx(0xb), 1);
                (*gMapEventInterface)->setMode(0x42, 3);
                (*gMapEventInterface)->setMode(7, 7);
                break;
            }
            break;
        }
    }

    return 0;
}

int wmspiritplace_getExtraSize(void) { return 0x18; }

int wmspiritplace_getObjectTypeId(void) { return 0x0; }

void wmspiritplace_free(void)
{
}

void wmspiritplace_render(undefined4 p1, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, s8 visible)
{
    if (visible == 0)
    {
        return;
    }
}

void wmspiritplace_hitDetect(int obj)
{
    if (*(void**)(obj + 0x74) != NULL)
    {
        objRenderFn_80041018(obj);
    }
}

void wmspiritplace_update(int obj)
{
    WmSpiritPlaceState* state;
    uint mapId;

    state = ((GameObject*)obj)->extra;
    if (state->transitionDelay != 0)
    {
        state->transitionDelay--;
        if (state->transitionDelay == 0)
        {
            GameBit_Set(state->sequenceGameBit, 1);
        }
    }
    else
    {
        state->flags12 &= ~1;
        mapId = *(uint*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
        if (mapId == 0x47295)
        {
            if (state->mapEventState == 2)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 b = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode;
                    if ((b & 0x10) != 0)
                    {
                        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(b & ~0x10);
                    }
                    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                        GameBit_Set(state->promptGameBit, 0);
                        state->f80 = 1;
                    }
                }
                else if (GameBit_Get(state->sequenceGameBit) != 0 && GameBit_Get(0x29b) != 0)
                {
                    (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                    GameBit_Set(state->promptGameBit, 0);
                    GameBit_Set(state->sequenceGameBit, 0);
                    GameBit_Set(0xbfd, 0);
                }
                else
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
                }
            }
            else
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            }
        }
        else if (mapId == 0x2183)
        {
            if (state->mapEventState == 1)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 b = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode;
                    if ((b & 0x10) != 0)
                    {
                        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(b & ~0x10);
                    }
                    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
                    {
                        GameBit_Set(state->sequenceGameBit, 1);
                        GameBit_Set(state->promptGameBit, 0);
                    }
                }
                else
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
                }
            }
            else
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            }
        }
        else if (mapId == 0x49781)
        {
            if (state->mapEventState == 3)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 b = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode;
                    if ((b & 0x10) != 0)
                    {
                        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(b & ~0x10);
                    }
                    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                        GameBit_Set(state->promptGameBit, 0);
                        state->f80 = 1;
                    }
                }
                else if (GameBit_Get(state->sequenceGameBit) != 0 && GameBit_Get(0x8a2) != 0)
                {
                    (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                    GameBit_Set(state->promptGameBit, 0);
                    GameBit_Set(state->sequenceGameBit, 0);
                }
                else
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
                }
            }
            else
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            }
        }
        else if (mapId == 0x4a1c0)
        {
            if (state->mapEventState == 4)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 b = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode;
                    if ((b & 0x10) != 0)
                    {
                        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(b & ~0x10);
                    }
                    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                        GameBit_Set(state->promptGameBit, 0);
                        state->f80 = 1;
                    }
                }
                else if (GameBit_Get(state->sequenceGameBit) != 0 && GameBit_Get(0xc71) != 0)
                {
                    (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                    GameBit_Set(state->promptGameBit, 0);
                    GameBit_Set(state->sequenceGameBit, 0);
                }
                else
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
                }
            }
            else
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            }
        }
        else if (mapId == 0x4a250)
        {
            if (state->mapEventState == 5)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 b = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode;
                    if ((b & 0x10) != 0)
                    {
                        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(b & ~0x10);
                    }
                    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
                    {
                        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                        GameBit_Set(state->promptGameBit, 0);
                        state->f80 = 1;
                        state->f40 = 1;
                    }
                }
                else if (GameBit_Get(state->sequenceGameBit) != 0 && GameBit_Get(0xcb6) != 0)
                {
                    if (state->f40)
                    {
                        state->f40 = 0;
                        GameBit_Set(state->promptGameBit, 0);
                        GameBit_Set(0xd1f, 1);
                        getEnvfxActImmediately(0, 0, 0x217, 0);
                        getEnvfxActImmediately(obj, obj, 0x216, 0);
                        getEnvfxActImmediately(obj, obj, 0x229, 0);
                        getEnvfxActImmediately(obj, obj, 0x22a, 0);
                        (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 4, 1);
                        (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 10, 0);
                        (*gMapEventInterface)->setAnimEvent(((GameObject*)obj)->anim.mapEventSlot, 0xb, 1);
                    }
                }
                else
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
                }
            }
            else
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            }
        }
        else if (mapId == 0x4a5e6)
        {
            if (state->mapEventState == 6)
            {
                if (GameBit_Get(state->promptGameBit) == 0)
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
                }
                if (GameBit_Get(state->promptGameBit) != 0)
                {
                    u8 b = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode;
                    if ((b & 0x10) != 0)
                    {
                        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(b & ~0x10);
                    }
                    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) != 0)
                    {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
                    {
                        state->f80 = 1;
                        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                        GameBit_Set(state->promptGameBit, 0);
                    }
                }
                else if (GameBit_Get(state->sequenceGameBit) != 0 && GameBit_Get(0xcb8) != 0)
                {
                    GameBit_Set(state->promptGameBit, 0);
                    GameBit_Set(state->sequenceGameBit, 1);
                }
                else
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
                }
            }
            else
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            }
        }
        if (state->f80)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
        }
    }
}

void wmspiritplace_init(int obj, int setup)
{
    WmSpiritPlaceState* state;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)wmspiritplace_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)((s8) * (u8*)(setup + 0x18) << 8);
    ((GameObject*)obj)->anim.rotY = (s16)(*(s16*)(setup + 0x1a) << 8);
    state->heightOffset = ((f32)(*(s16*)(setup + 0x1c)) / lbl_803E5EF8) / lbl_803E5EFC;
    state->unk_04 = 0;
    state->unk_08 = 0;
    state->unk_0A = 0;
    state->sequenceGameBit = *(s16*)(setup + 0x1e);
    state->promptGameBit = *(s16*)(setup + 0x20);
    state->setupParam = (s16) * (s8*)(setup + 0x19);
    state->f80 = 0;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x6000);
    state->mapEventState = (*gMapEventInterface)->getMode(((GameObject*)obj)->anim.mapEventSlot);

    if (*(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14) == 0x47295)
    {
        if (GameBit_Get(0x1fc) != 0 || GameBit_Get(0xeaf) != 0 || state->mapEventState > 2)
        {
            ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX - lbl_803E5F00;
        }
    }
    else if (*(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14) == 0x4a5e6 && state->mapEventState >= 6)
    {
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX + lbl_803E5F00;
    }
}

void wmspiritplace_release(void)
{
}

void wmspiritplace_initialise(void)
{
}
