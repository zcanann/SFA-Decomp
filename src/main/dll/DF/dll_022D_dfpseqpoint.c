/*
 * DragonRock Palace sequence point (DLL 0x22D; "DFP_seqpoint") - a
 * trigger volume: when the player enters its radius and the gate gamebit
 * is set it fires a trigger sequence, latches done, and sets the done
 * gamebit.
 */
#include "main/dll/dfp_types.h"
#include "main/gamebits.h"
#include "main/main.h"
#include "main/game_object.h"
#include "main/dll/anim.h"
#include "main/objseq.h"
#include "main/dll/fx_800944A0_shared.h"

#define DFPSEQPOINT_OBJFLAG_HITDETECT_DISABLED 0x2000

/* Placement trigger-mode selector (DfpSeqPointState::triggerMode). */
#define DFPSEQPOINT_MODE_RADIUS 0            /* player within radius */
#define DFPSEQPOINT_MODE_GATE 1              /* gate gamebit set */
#define DFPSEQPOINT_MODE_RADIUS_AND_GATE 2   /* within radius and gate set */
#define DFPSEQPOINT_MODE_RADIUS_AND_UNSET 3  /* within radius and gate clear, then set gate */
#define DFPSEQPOINT_MODE_GATE_UNSET 4        /* gate clear, then set gate */
#define DFPSEQPOINT_MODE_GATE_REPEAT 5       /* gate set, fire every frame (no latch) */

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);

STATIC_ASSERT(sizeof(DfpSeqPointState) == 0x10);

typedef struct DfpseqpointPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX; /* 0x08 */
    f32 posY; /* 0x0C */
    f32 posZ; /* 0x10 */
    s32 mapId; /* 0x14 */
    u8 pad18[0x19 - 0x18];
    u8 unk19;
    u8 pad1A[0x1E - 0x1A];
    s8 unk1E;
    u8 pad1F[0x24 - 0x1F];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DfpseqpointPlacement;

extern f32 lbl_803E63B8;
extern int unlockLevel(s32 val, int idx, int flag);

void dfpseqpoint_free(void)
{
}

void dfpseqpoint_hitDetect(void)
{
}

void dfpseqpoint_release(void)
{
}

void dfpseqpoint_initialise(void)
{
}

void dfpseqpoint_init(int* obj, u8* init)
{
    DfpSeqPointState* sub;
    sub = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = dfpseqpoint_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)init[0x18] << 8);
    sub->triggerRadius = (f32)(s32) * (s16*)(init + 0x1a);
    sub->triggerId = *(s16*)(init + 0x1c);
    sub->triggerMode = init[0x19];
    sub->gameBitGate = *(s16*)(init + 0x1e);
    sub->gameBitDone = *(s16*)(init + 0x20);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | DFPSEQPOINT_OBJFLAG_HITDETECT_DISABLED);
    ((DfpFlags7*)&sub->flags0F)->b80 = 0;
}

int dfpseqpoint_getExtraSize(void) { return 0x10; }
int dfpseqpoint_getObjectTypeId(void) { return 0x0; }

void dfpseqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E63B8);
}

int dfpseqpoint_SeqFn(int obj, int p2, ObjAnimUpdateState* animUpdate)
{
    extern int unlockLevel(s32 val, int idx, int flag);
    extern int mapGetDirIdx(int idx);
    extern int lockLevel(s32 val, int idx);
    extern void warpToMap(int idx, s8 transType);
    int blob = *(int*)&((GameObject*)obj)->extra;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    int i;

    animUpdate->activeHitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (((DfpSeqPointState*)blob)->triggerId)
        {
        case 1:
            switch (animUpdate->eventIds[i])
            {
            case 1:
                if ((*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) == 1)
                {
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 5, 0);
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 6, 0);
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 7, 0);
                }
                else if ((*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) == 2)
                {
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 5, 0);
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 6, 0);
                    (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 7, 0);
                }
                break;
            }
            break;
        case 0xa:
            switch (animUpdate->eventIds[i])
            {
            case 0x14:
                if (*(u32*)&((DfpseqpointPlacement*)data)->mapId == 0x49de8)
                {
                    ((DfpFlags7*)&((DfpSeqPointState*)blob)->flags0F)->b80 = 1;
                }
                else
                {
                    if ((*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) == 1 ||
                        (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) == 2)
                    {
                        unlockLevel(0, 0, 1);
                        lockLevel(mapGetDirIdx(0x32), 0);
                        (*gMapEventInterface)->setMapAct(0x32, 2);
                        warpToMap(0x73, 0);
                    }
                }
                break;
            }
            break;
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}

void dfpseqpoint_update(int obj)
{

    extern f32 Vec_distance(f32* a, f32* b);
    GameObject* self;
    GameObject* player;
    DfpSeqPointState* state;
    int h;

    self = (GameObject*)obj;
    player = (GameObject*)Obj_GetPlayerObject();
    state = self->extra;
    if (((u32)state->flags0F >> 7 & 1) != 0)
    {
        GameBit_Set(0xef7, 1);
        ((DfpFlags7*)&state->flags0F)->b80 = 0;
    }
    h = state->gameBitDone;
    if (h != -1)
    {
        if (state->doneLatch != 0)
        {
            if (GameBit_Get(h) != 0)
            {
                return;
            }
            GameBit_Set(state->gameBitDone, 1);
            state->doneLatch = 1;
            return;
        }
        if (GameBit_Get(h) != 0)
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
    case DFPSEQPOINT_MODE_RADIUS:
        if (Vec_distance(&self->anim.worldPosX, &player->anim.worldPosX) < state->triggerRadius)
        {
            (*gObjectTriggerInterface)->runSequence(state->triggerId,
                                                    (void*)obj, -1);
            state->doneLatch = 1;
        }
        break;
    case DFPSEQPOINT_MODE_GATE:
        h = state->gameBitGate;
        if (h != -1 && GameBit_Get(h) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->triggerId,
                                                    (void*)obj, -1);
            state->doneLatch = 1;
        }
        break;
    case DFPSEQPOINT_MODE_RADIUS_AND_GATE:
        if (Vec_distance(&self->anim.worldPosX, &player->anim.worldPosX) < state->triggerRadius)
        {
            h = state->gameBitGate;
            if (h != -1 && GameBit_Get(h) != 0)
            {
                (*gObjectTriggerInterface)->runSequence(state->triggerId,
                                                        (void*)obj, -1);
                state->doneLatch = 1;
            }
        }
        break;
    case DFPSEQPOINT_MODE_RADIUS_AND_UNSET:
        if (Vec_distance(&self->anim.worldPosX, &player->anim.worldPosX) < state->triggerRadius)
        {
            h = state->gameBitGate;
            if (h != -1 && GameBit_Get(h) == 0)
            {
                (*gObjectTriggerInterface)->runSequence(state->triggerId,
                                                        (void*)obj, -1);
                GameBit_Set(state->gameBitGate, 1);
                state->doneLatch = 1;
            }
        }
        break;
    case DFPSEQPOINT_MODE_GATE_UNSET:
        h = state->gameBitGate;
        if (h != -1 && GameBit_Get(h) == 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->triggerId,
                                                    (void*)obj, -1);
            GameBit_Set(state->gameBitGate, 1);
            state->doneLatch = 1;
        }
        break;
    case DFPSEQPOINT_MODE_GATE_REPEAT:
        h = state->gameBitGate;
        if (h != -1 && GameBit_Get(h) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(state->triggerId,
                                                    (void*)obj, -1);
        }
        break;
    }
}
