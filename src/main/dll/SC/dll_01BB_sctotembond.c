/*
 * sctotembond (DLL 0x1BB) + the tail of sctotempuzzle (DLL 0x1BA).
 * The sc_totempuzzle and sc_totembond fns interleave across this range
 * (one original TU).
 *
 * Behaviour: the CloudRunner fire-breathing capture minigame. Eight LightFoot
 * villagers surround the player with spears; you command the CloudRunner to
 * breathe fire on whichever one attacks, via a quick-time event (a slider
 * sweeps left-right, tap A as it crosses the middle). The hit window shrinks
 * with each villager burned; a miss takes damage and a new random villager
 * attacks. The code's "orbs"/ring (gTotemBondRingGameBits/70, ORB_COUNT 8) are the eight
 * villagers, and the ring rotation is the QTE targeting. Burning all 8 sets
 * GameBit 0x2bc, which a seqobject (placement 0x2829: trigger 0x2bc -> open
 * 0x2d0) turns into 0x2d0; sclevelcontrol then advances the village to
 * map-event 0xe mode 6, spawning the chief. START_ORBS is anim event 1; anim
 * event 2 also calls setMode(0xe, 6) directly.
 */
#include "main/audio/sfx_ids.h"
#include "main/obj_placement.h"
#include "main/camera_interface.h"
#include "main/game_ui_interface.h"
#include "main/mapEventTypes.h"
#include "main/dll/SC/sctotembond.h"
#include "main/dll/SC/sc_shared.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/screen_transition.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/music_trigger_ids.h"
extern f32 timeDelta;

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_GetPlayerObject(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int Obj_SetupObject(u8* setup, int mode, int mapLayer, int objIndex, int parent);
extern float mathSinf(float x);
extern float mathCosf(float x);
extern u16 gTotemBondRingGameBits[];
extern u16 gTotemBondOrbGameBits[];
extern f32 gTotemBondOrbSpawnRadius;
extern f32 lbl_803E563C;
extern const f32 lbl_803E5654;
extern f32 lbl_803E5658;
extern f32 gTotemBondRingRotateSpeed;
extern f32 gTotemBondCameraDistance;
extern void hudFn_8011f38c(u8 x);
extern void fn_80296124(int player, void* pos, void* obj, int arg);
extern f32 lbl_803E5650;
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void Music_Trigger(int id, int arg);
extern void fn_8011F6D4(u32 x);

#define SC_TOTEMBOND_ORB_COUNT 8
#define SC_TOTEMBOND_ORB_SETUP_SIZE 0x38
#define SC_TOTEMBOND_ORB_OBJECT_ID 0x27b
#define SC_TOTEMBOND_ORB_TRIGGER_EVENT 0x64c
#define SC_TOTEMBOND_ORB_ANGLE_STEP 0x2000
#define SC_TOTEMBOND_EVENT_START_ORBS 0x01
#define SC_TOTEMBOND_EVENT_ORBS_ACTIVE 0x02
#define SC_TOTEMBOND_EVENT_SET_MAP_MODE 0x10

#define SC_TOTEMBOND_OBJFLAG_HIDDEN 0x4000
#define SC_TOTEMBOND_OBJFLAG_HITDETECT_DISABLED 0x2000

/*
 * Placement record written for each spawned villager/"orb" object
 * (Obj_AllocObjectSetup size 0x38). The ObjPlacement head carries the
 * orbit position and the RGBA color block copied from the totem's own
 * definition; the class-specific tail holds the trigger event id and the
 * per-orb game-bit ids.
 */
typedef struct TotemBondOrbPlacement
{
    ObjPlacement base;
    s16 unk18;
    s16 triggerEvent;
    s16 orbGameBit;
    u8 pad1E[0x2A - 0x1E];
    s8 yawByte;
    u8 pad2B[0x30 - 0x2B];
    s16 ringGameBit;
    u8 unk32;
    u8 pad33[0x38 - 0x33];
} TotemBondOrbPlacement;
STATIC_ASSERT(sizeof(TotemBondOrbPlacement) == 0x38);

void sc_totembond_spawnGameBitOrbs(ScTotemBondObject* obj, ScTotemBondState* state, f32 radius)
{
    s32 angleOffset;
    u8* setup;
    u8* definition;
    s8 i;
    s8 orbIndex;

    if (Obj_IsLoadingLocked() != 0)
    {
        i = 0;
        orbIndex = 1;
        angleOffset = 0;
        while (i < SC_TOTEMBOND_ORB_COUNT)
        {
            definition = obj->definition;
            setup = Obj_AllocObjectSetup(SC_TOTEMBOND_ORB_SETUP_SIZE,SC_TOTEMBOND_ORB_OBJECT_ID);
            ((ObjPlacement*)setup)->posX = radius * mathSinf(
                (3.1415927f * (f32)(s32)(obj->yaw + angleOffset)) / 32768.0f) + obj->x;
            ((ObjPlacement*)setup)->posY = obj->y;
            ((ObjPlacement*)setup)->posZ = radius * mathCosf(
                (3.1415927f * (f32)(s32)(obj->yaw + angleOffset)) / 32768.0f) + obj->z;
            setup[0x04] = definition[0x04];
            setup[0x05] = (definition[0x05] & ~1) | 4;
            setup[0x06] = definition[0x06];
            setup[0x07] = 0x1e;
            ((TotemBondOrbPlacement*)setup)->unk18 = -1;
            ((TotemBondOrbPlacement*)setup)->triggerEvent = SC_TOTEMBOND_ORB_TRIGGER_EVENT;
            ((TotemBondOrbPlacement*)setup)->orbGameBit = gTotemBondOrbGameBits[orbIndex];
            ((TotemBondOrbPlacement*)setup)->ringGameBit = gTotemBondRingGameBits[orbIndex];
            ((TotemBondOrbPlacement*)setup)->yawByte = (s8)(((obj->yaw + 0x8000) + angleOffset) >> 8);
            ((TotemBondOrbPlacement*)setup)->unk32 = 1;
            Obj_SetupObject(setup, 5, -1, -1, 0);
            orbIndex++;
            if (orbIndex > 7)
            {
                orbIndex = 0;
            }
            angleOffset += SC_TOTEMBOND_ORB_ANGLE_STEP;
            i++;
        }
    }
}

u32 sc_totempuzzle_processAnimEvents(ScTotemBondObject* obj, u32 unused, ObjAnimUpdateState* animUpdate)
{
    ScTotemBondState* state;
    int countForEvent2;
    int startForEvent2;
    int countForEvent3;
    int startForEvent3;
    int* objects;
    int eventIndex;
    int eventId;

    state = obj->state;
    animUpdate->sequenceEventActive = 0;
    for (eventIndex = 0; eventIndex < animUpdate->eventCount; eventIndex++)
    {
        eventId = animUpdate->eventIds[eventIndex];
        switch (eventId)
        {
        case 1:
            state->eventFlags |= 1;
            (*gObjectTriggerInterface)->setCamVars(0x44, 1, 0, 0);
            break;
        case 2:
            objects = ObjList_GetObjects(&startForEvent2, &countForEvent2);
            for (; startForEvent2 < countForEvent2; startForEvent2++)
            {
                if ((ScTotemBondObject*)objects[startForEvent2] != obj &&
                    ((ScTotemBondObject*)objects[startForEvent2])->objectType ==
                        SC_SEQ_TOTEMPOLE)
                {
                    (*(VtableFn*)(**(int**)(objects[startForEvent2] + 0x68) + SC_VT_HANDLE_EVENT))(
                        objects[startForEvent2], 2);
                    break;
                }
            }
            state->eventFlags |= SC_TOTEMBOND_EVENT_SET_MAP_MODE;
            break;
        case 3:
            objects = ObjList_GetObjects(&startForEvent3, &countForEvent3);
            for (; startForEvent3 < countForEvent3; startForEvent3++)
            {
                if ((ScTotemBondObject*)objects[startForEvent3] != obj &&
                    ((ScTotemBondObject*)objects[startForEvent3])->objectType ==
                        SC_SEQ_TOTEMPOLE)
                {
                    (*(VtableFn*)(**(int**)(objects[startForEvent3] + 0x68) + SC_VT_HANDLE_EVENT))(
                        objects[startForEvent3], 1);
                    break;
                }
            }
            break;
        }
    }
    return 0;
}

void sc_totembond_hitDetect(void)
{
}

void sc_totembond_release(void)
{
}

void sc_totembond_initialise(void)
{
}

int sc_totembond_getExtraSize(void) { return 0x28; }
int sc_totembond_getObjectTypeId(void) { return 0x0; }

void sc_totembond_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E5650);
}

void sc_totembond_free(int obj)
{
    Music_Trigger(MUSICTRIG_WLC_Puzzle_f0, 0);
    fn_8011F6D4(0);
}

#pragma dont_inline on
void sc_totembond_update(ScTotemBondObject* obj)
{
    ScTotemBondState* state;
    int player;
    u8 availableOrbs[8];
    u8 availableCount;
    u8 orbIndex;
    u8 nextRing;
    u8 allOrbsCollected;

    state = obj->state;
    player = Obj_GetPlayerObject();
    if ((state->eventFlags & SC_TOTEMBOND_EVENT_START_ORBS) != 0)
    {
        state->active = 1;
        obj->yaw = 0x3fff;
        state->ringIndex = (s16)(u16)((s32)obj->yaw / SC_TOTEMBOND_ORB_ANGLE_STEP);
        ObjHits_DisableObject((u32)obj);
        sc_totembond_spawnGameBitOrbs(obj, state, gTotemBondOrbSpawnRadius);
        GameBit_Set(gTotemBondRingGameBits[state->ringIndex], 1);
        obj->mapAlpha = 0;
        state->eventFlags &= ~SC_TOTEMBOND_EVENT_START_ORBS;
        state->eventFlags |= SC_TOTEMBOND_EVENT_ORBS_ACTIVE;
        (*gGameUIInterface)->setShowWorldMapHud(1);
        hudFn_8011f38c(1);
        (*gScreenTransitionInterface)->step(0x1e, 1);
        state->spawnTimer = lbl_803E563C;
        Music_Trigger(MUSICTRIG_WLC_Puzzle_f0, 1);
    }

    if ((state->eventFlags & SC_TOTEMBOND_EVENT_ORBS_ACTIVE) != 0)
    {
        if (state->spawnTimer != lbl_803E5654)
        {
            state->spawnTimer -= timeDelta;
            if (state->spawnTimer < lbl_803E5654)
            {
                state->spawnTimer = lbl_803E5654;
            }
        }
        else if (state->completionTimer != lbl_803E5654)
        {
            state->completionTimer -= timeDelta;
            if (state->completionTimer <= lbl_803E5654)
            {
                state->completionTimer = lbl_803E5654;
                player = Obj_GetPlayerObject();
                (*gMapEventInterface)->clearRestartPoint();
                (*gCameraInterface)->setMode(0x42, 0, 3, 0, NULL, 0, 0);
                obj->mapAlpha = 0xff;
                fn_80296124(player, NULL, NULL, 0);
                ObjHits_EnableObject((u32)obj);
                hudFn_8011f38c(0);
                GameBit_Set(0x2bc, 1);
                state->eventFlags = 0;
                Music_Trigger(MUSICTRIG_WLC_Puzzle_f0, 0);
                return;
            }
        }
        else
        {
            if (GameBit_Get(SC_TOTEMBOND_ORB_TRIGGER_EVENT) != 0)
            {
                GameBit_Set(SC_TOTEMBOND_ORB_TRIGGER_EVENT, 0);
                availableCount = orbIndex = 0;
                for (; orbIndex < SC_TOTEMBOND_ORB_COUNT; orbIndex++)
                {
                    if (GameBit_Get(gTotemBondOrbGameBits[orbIndex]) == 0)
                    {
                        availableOrbs[availableCount++] = orbIndex;
                    }
                }
                if (availableCount == 0)
                {
                    allOrbsCollected = 1;
                }
                else
                {
                    nextRing = availableOrbs[randomGetRange(0, availableCount - 1)];
                    if (state->ringIndex == nextRing)
                    {
                        GameBit_Set(gTotemBondRingGameBits[state->ringIndex], 1);
                    }
                    if (state->ringIndex != nextRing)
                    {
                        state->ringIndex = nextRing;
                        Sfx_PlayFromObject((int)obj, SFXtr_jbike_whine2);
                    }
                    allOrbsCollected = 0;
                }
                if (allOrbsCollected)
                {
                    state->completionTimer = lbl_803E5658;
                    fn_8011F6D4(0);
                    (*gScreenTransitionInterface)->start(0x1e, 1);
                }
            }
            if ((int)((u32)(u16)obj->yaw >> 13
            )
            !=
            state->ringIndex
            )
            {
                obj->yaw = (s16) - ((gTotemBondRingRotateSpeed * timeDelta) - (f32)(s32)
                obj->yaw
                )
                ;
                if ((int)((u32)(u16)obj->yaw >> 13
                )
                ==
                state->ringIndex
                )
                {
                    GameBit_Set(gTotemBondRingGameBits[state->ringIndex], 1);
                }
            }
        }

        fn_80296124(player, &obj->x, obj, 0);
        state->x = obj->x;
        state->y = lbl_803E563C + obj->y;
        state->z = obj->z;
        state->yaw = (s16)(0x8000 - obj->yaw);
        state->pitch = obj->pitch;
        state->roll = obj->roll;
        state->cameraDistance = gTotemBondCameraDistance;
        (*gCameraInterface)->releaseAction(state, 0x18);
    }

    if ((state->eventFlags & SC_TOTEMBOND_EVENT_SET_MAP_MODE) != 0)
    {
        (*gMapEventInterface)->setMapAct(0xe, 6);
        state->eventFlags &= ~SC_TOTEMBOND_EVENT_SET_MAP_MODE;
    }
}
#pragma dont_inline reset

void sc_totembond_init(ScTotemBondObject* obj, int params)
{
    ScTotemBondState* state;
    u32 v;
    s16 hi = (s16)(u16)((s32)obj->yaw / 8192);
    state = obj->state;
    state->ringIndex = hi;
    obj->animEventCallback = sc_totempuzzle_processAnimEvents;
    v = obj->objectFlags | (SC_TOTEMBOND_OBJFLAG_HIDDEN | SC_TOTEMBOND_OBJFLAG_HITDETECT_DISABLED);
    obj->objectFlags = v;
}

int fn_801DE320(u16* gameBitIds, u16 newValue)
{
    u16 values[4];
    u8 i, j;
    s32 changed = 0;

    for (i = 0; i < 3; i++)
    {
        u16 v = GameBit_Get(gameBitIds[i]);
        values[i] = v;
    }
    values[3] = newValue;
    for (j = 0; j < 3; j++)
    {
        for (i = 0; i < 3; i++)
        {
            if (values[i + 1] != 0)
            {
                if ((values[i + 1] < values[i]) || (values[i] == 0))
                {
                    u16 tmp = values[i];
                    values[i] = values[i + 1];
                    values[i + 1] = tmp;
                    changed = 1;
                }
            }
        }
    }
    for (i = 0; i < 3; i++)
    {
        GameBit_Set(gameBitIds[i], values[i]);
    }
    return changed;
}

u16 gTotemBondRingGameBits[] = {
    0x064D, 0x064E, 0x064F, 0x0650, 0x0A4C, 0x0A4D, 0x0A4E, 0x0A4F,
};

u16 gTotemBondOrbGameBits[] = {
    0x0768, 0x0769, 0x076A, 0x076B, 0x0A50, 0x0A51, 0x0A52, 0x0A53,
};
