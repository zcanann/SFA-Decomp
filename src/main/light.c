/* Light functions and VFP block 1 object [0x801FB9AC-0x801FD4A8). */
#include "main/dll/VF/vf_shared.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/audio/sfx_ids.h"
#include "main/game_ui_interface.h"
#include "main/light.h"
#include "main/objlib.h"
#include "main/resource.h"
#include "main/audio/sfx_trigger_ids.h"

#define LIGHT_OBJFLAG_HIDDEN 0x4000
#define LIGHT_OBJFLAG_HITDETECT_DISABLED 0x2000

/*
 * DLL 0x021E (gVFP_Block1ObjDescriptor) fragment.
 * Only getExtraSize/getObjectTypeId/free/render/hitDetect fall in this object's
 * .text range here (0x801FB9AC-0x801FB9F4); update/init/release/initialise for
 * this DLL live in the adjacent unit main/light.c (next .text range).
 */

extern f32 lbl_803E6100;
extern f32 lbl_803E6144;
extern f32 lbl_803E6148;
extern f32 lbl_803E6150;
extern ModgfxInterface** gModgfxInterface;
extern void* gVfpDragHeadResource;
extern f32 lbl_803E6138;
extern int fn_801FC6F4(int, int, ObjAnimUpdateState*);
extern f32 lbl_803E6128;
extern f32 lbl_803E610C;
extern f32 lbl_803E611C;
extern f32 lbl_803E6140;
extern int Camera_GetCurrentViewSlot(void);
extern void PSVECSubtract(void* a, void* b, void* ab);
extern void PSVECNormalize(void* in, void* out);
extern void PSVECScale(void* in, void* out, f32 scale);
extern void PSVECAdd(void* a, void* b, void* ab);
extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern f32 lbl_803E6118;
extern f32 lbl_803E6120;
extern f32 lbl_803E6124;
extern s16 gVfpDragHeadSpawnTimer;
extern u8 gVfpDragHeadActiveIndex;
extern f32 lbl_803E6108;

int vfpblock1_getExtraSize(void) { return 0x2; }

int vfpblock1_getObjectTypeId(void) { return 0x0; }

void vfpblock1_render(void)
{
}

void vfpblock1_hitDetect(void)
{
}

void vfpblock1_free(int obj)
{
    (*gExpgfxInterface)->freeSource2(obj);
}

/* Per-object extra state for SeqPoint (seqpoint_getExtraSize == 0x10). */
/* SeqPointState.mode: which predicate must hold for the seq point to fire. */
typedef enum SeqPointMode {
  SEQPOINT_MODE_RADIUS = 0,          /* fire when player is within triggerRadius */
  SEQPOINT_MODE_BIT = 1,             /* fire when conditionBit is set */
  SEQPOINT_MODE_RADIUS_AND_BIT = 2,  /* fire when in radius AND conditionBit set */
  SEQPOINT_MODE_RADIUS_BIT_ONCE = 3, /* fire in radius with conditionBit clear, then set it */
  SEQPOINT_MODE_BIT_ONCE = 4,        /* fire with conditionBit clear, then set it */
  SEQPOINT_MODE_BIT_REPEAT = 5       /* fire whenever conditionBit is set (no done latch) */
} SeqPointMode;

typedef struct SeqPointState
{
    f32 triggerRadius;
    s16 conditionBit; /* gamebit gating modes 1-5 */
    s16 disableBit; /* gamebit that permanently disables the point */
    s16 sequenceId; /* trigger id fired at the player; switched in the SeqFn */
    u8 pad0A[3];
    u8 done;
    u8 mode; /* 0 radius, 1 bit, 2 radius+bit, 3/4 bit-once (sets it), 5 bit repeat */
    u8 pad0F;
} SeqPointState;

STATIC_ASSERT(sizeof(SeqPointState) == 0x10);

#pragma scheduling off
void vfpblock1_update(int obj)
{
    int player = (int)Obj_GetPlayerObject();
    f32 dist = Vec_distance((void*)(player + 0x18), &((GameObject*)obj)->anim.worldPosX);
    if (Sfx_IsPlayingFromObjectChannel(obj, 0x40) != 0)
    {
        if (dist < lbl_803E6100)
        {
            Sfx_PlayFromObject(obj, SFXsp_guardian_call2);
        }
    }
    else
    {
        if (dist >= lbl_803E6100)
        {
            Sfx_StopObjectChannel(obj, 0x40);
        }
    }
}

#pragma scheduling on
void vfpblock1_release(void)
{
}

void vfpblock1_initialise(void)
{
}

void vfpplatform_hitDetect(void)
{
}

void vfpplatform_release(void)
{
}

void vfpplatform_initialise(void)
{
}

void vfpdoorswitch_hitDetect(void)
{
}

void vfpdoorswitch_release(void)
{
}

void vfpdoorswitch_initialise(void)
{
}

void seqpoint_free(void)
{
}

void seqpoint_hitDetect(void)
{
}

void seqpoint_release(void)
{
}

void seqpoint_initialise(void)
{
}

void vfpdraghead_render(void)
{
}

void vfpdraghead_hitDetect(void)
{
}

void vfpdraghead_release(void)
{
}

void vfpdraghead_initialise(void)
{
}

void vfpcoreplat_hitDetect(void)
{
}

void vfpcoreplat_update(void)
{
}

void vfpcoreplat_release(void)
{
}

void vfpcoreplat_initialise(void)
{
}

void dll_224_free_nop(void)
{
}

int vfpplatform_getExtraSize(void) { return 0x6; }
int vfpplatform_getObjectTypeId(void) { return 0x0; }
int vfpdoorswitch_getExtraSize(void) { return 0x4; }
int vfpdoorswitch_getObjectTypeId(void) { return 0x0; }
int seqpoint_getExtraSize(void) { return 0x10; }
int seqpoint_getObjectTypeId(void) { return 0x0; }
int vfpdraghead_getExtraSize(void) { return 0xc; }
int vfpdraghead_getObjectTypeId(void) { return 0x0; }
int return0_801FD13C(void) { return 0x0; }
int vfpcoreplat_getExtraSize(void) { return 0x4; }
int vfpcoreplat_getObjectTypeId(void) { return 0x0; }
int dll_224_getExtraSize_ret_6(void) { return 0x6; }
int dll_224_getObjectTypeId(void) { return 0x0; }

void vfpplatform_free(int obj)
{
    (*gExpgfxInterface)->freeSource2(obj);
}

void vfpdoorswitch_free(int obj)
{
    (*gExpgfxInterface)->freeSource2(obj);
}

void vfpcoreplat_free(int obj)
{
    (*gExpgfxInterface)->freeSource2(obj);
}

/* Per-object extra state for the VFP platform family (vfpplatform/vfpblock1/
 * vfpcoreplat). vfpplatform_getExtraSize == 0x6. */
typedef struct VfpPlatformState
{
    s16 gameBitId;  /* drives the open/close state machine */
    u8 state;       /* state-machine mode (cases 0-6) */
    u8 axisMode;    /* 0/3 = move axis, 10 = trigger-on-bit, 99/0x63 = inert */
    s16 timer;      /* dwell countdown */
} VfpPlatformState;

STATIC_ASSERT(sizeof(VfpPlatformState) == 0x6);

#pragma scheduling off
#pragma peephole off
void vfpblock1_init(int obj, int data)
{
    VfpPlatformState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (((s32) * (s8*)(data + 0x18)) << 8);
    state->gameBitId = *(s16*)(data + 0x1e);
    ((GameObject*)obj)->objectFlags |= (LIGHT_OBJFLAG_HIDDEN | LIGHT_OBJFLAG_HITDETECT_DISABLED);
}

void vfpplatform_init(int obj, int data)
{
    VfpPlatformState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (((s32) * (s8*)(data + 0x18)) << 8);
    state->gameBitId = *(s16*)(data + 0x20);
    state->state = 0;
    state->axisMode = *(u8*)(data + 0x19);
    ((GameObject*)obj)->objectFlags |= LIGHT_OBJFLAG_HITDETECT_DISABLED;
}

void vfpcoreplat_init(int obj, int data)
{
    VfpPlatformState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (((s32) * (s8*)(data + 0x18)) << 8);
    state->gameBitId = *(s16*)(data + 0x20);
    *(int (**)(void))(obj + 0xBC) = return0_801FD13C;
    if (((GameObject*)obj)->anim.seqId == 0x3cb)
    {
        if (GameBit_Get(0x4e9) != 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale =
                lbl_803E6144 * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
        }
        if (GameBit_Get(0x63c) != 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale =
                lbl_803E6148 * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
        }
    }
    ((GameObject*)obj)->objectFlags |= LIGHT_OBJFLAG_HITDETECT_DISABLED;
}

typedef struct SpellStoneUseState
{
    s16 completeGameBit;
    s16 requiredGameBit;
    u8 used;
} SpellStoneUseState;

void spellStoneUseFn_801fd270(int obj)
{
    extern u32 gSpellStoneEventId; /* #57 */
    SpellStoneUseState* state = ((GameObject*)obj)->extra;
    s16 cond = 1;
    void* player = Obj_GetPlayerObject();
    if (player == NULL) return;
    if (state->requiredGameBit != -1)
    {
        cond = GameBit_Get(state->requiredGameBit);
    }
    if ((s16)GameBit_Get(state->completeGameBit) != 0 || state->used != 0) return;
    if (cond == 0) return;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
    if ((*gGameUIInterface)->isEventReady(gSpellStoneEventId) != 0)
    {
        if (Vec_distance(&((GameObject*)obj)->anim.worldPosX, (char*)player + 0x18) < lbl_803E6150)
        {
            GameBit_Set(state->completeGameBit, 1);
            state->used = 1;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
    }
}

#pragma peephole on
void vfpdraghead_free(int obj)
{
    (*gExpgfxInterface)->freeSource2(obj);
    (*gModgfxInterface)->freeSourceEffects((void*)obj);
    if (gVfpDragHeadResource != NULL)
    {
        Resource_Release(gVfpDragHeadResource);
    }
    gVfpDragHeadResource = NULL;
}

/* Per-object extra state for VFPDragHead (vfpdraghead_getExtraSize == 0xC). */
typedef struct VfpDragHeadState
{
    s16 gameBitA; /* toggled by hits; drives the 0x390 breath fx */
    s16 gameBitB; /* suppresses idle fx when set (variant 2) */
    s16 unk_04; /* init: 100 */
    s16 despawnTimer; /* variant 0x3C5: init 0x78, counts down to free */
    u8 pad08[3];
    u8 headIndex; /* from def+0x1A; matched against gVfpDragHeadActiveIndex */
} VfpDragHeadState;

STATIC_ASSERT(sizeof(VfpDragHeadState) == 0xC);

#pragma peephole off
void vfpdraghead_init(int obj, int data)
{
    VfpDragHeadState* state = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId == 0x3c5)
    {
        state->despawnTimer = 0x78;
        ((GameObject*)obj)->anim.rootMotionScale =
            ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase * lbl_803E6138;
        ObjHits_SetHitVolumeSlot(obj, 0xE, 1, 0);
    }
    else
    {
        ((GameObject*)obj)->anim.rotX = (((s32) * (s8*)(data + 0x18)) << 8);
    }
    state->gameBitA = *(s16*)(data + 0x1e);
    state->gameBitB = *(s16*)(data + 0x20);
    state->unk_04 = 0x64;
    state->headIndex =  * (s16*)(data + 0x1a);
    if (*(s8*)(data + 0x19) == 1)
    {
        ((GameObject*)obj)->anim.rootMotionScale =
            ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase * lbl_803E6138;
    }
    ((GameObject*)obj)->objectFlags |= (LIGHT_OBJFLAG_HIDDEN | LIGHT_OBJFLAG_HITDETECT_DISABLED);
    gVfpDragHeadResource = Resource_Acquire(0xA5, 1);
}

void seqpoint_init(int obj, int data)
{
    SeqPointState* state = ((GameObject*)obj)->extra;
    *(void (**)(int))(obj + 0xBC) = (void (*)(int))fn_801FC6F4;
    ((GameObject*)obj)->anim.rotX = (((s32) * (s8*)(data + 0x18)) << 8);
    state->triggerRadius =  * (s16*)(data + 0x1a);
    state->sequenceId = *(s16*)(data + 0x1c);
    state->mode = *(u8*)(data + 0x19);
    state->conditionBit = *(s16*)(data + 0x1e);
    state->disableBit = *(s16*)(data + 0x20);
    ((GameObject*)obj)->objectFlags |= LIGHT_OBJFLAG_HITDETECT_DISABLED;
}

void seqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E6128);
}

void vfpplatform_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    VfpPlatformState* state = ((GameObject*)obj)->extra;
    s32 v = visible;
    if (v != 0 && state->axisMode != 0x63)
    {
        ((void(*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E610C);
    }
}

void vfpdoorswitch_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E611C); }
void vfpcoreplat_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E6140); }

typedef struct
{
    s16 gameBitId;
    u8 activated : 1;
    u8 exploded : 1;
    u8 _state2_lo : 6;
} VfpDoorSwitchState;

void vfpdoorswitch_update(int obj)
{
    VfpDoorSwitchState* state;
    if (((GameObject*)obj)->anim.seqId != 0x3e7)
    {
        vfpdoorswitch_updateExplodingVariant(obj);
        return;
    }
    state = ((GameObject*)obj)->extra;
    if (state->activated != 0) return;
    if (GameBit_Get(state->gameBitId) == 0) return;
    Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
    Sfx_PlayFromObject(obj, SFXsp_skeep_mumb4);
    Sfx_PlayFromObject(obj, SFXTRIG_gate_stops);
    Obj_SetActiveModelIndex(obj, 1);
    state->activated = 1;
}

void vfpdoorswitch_init(int obj, int data)
{
    VfpDoorSwitchState* state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (((s32) * (s8*)(data + 0x18)) << 8);
    ((GameObject*)obj)->anim.rotZ = (((s32) * (s8*)(data + 0x19)) << 8);
    ((GameObject*)obj)->anim.rotY = *(s16*)(data + 0x1c);
    state->gameBitId = *(s16*)(data + 0x1e);
    if (GameBit_Get(state->gameBitId) != 0)
    {
        ((ObjAnimSetProgressObjectFirstFn)ObjAnim_SetMoveProgress)(obj, lbl_803E611C);
        state->activated = 1;
        state->exploded = 1;
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    if (((GameObject*)obj)->anim.seqId == 0x3e7 && state->activated != 0)
    {
        *&((GameObject*)obj)->anim.bankIndex = 1;
    }
    ((GameObject*)obj)->objectFlags |= LIGHT_OBJFLAG_HITDETECT_DISABLED;
}

void vfpdoorswitch_updateExplodingVariant(int obj)
{
    VfpDoorSwitchState* state = ((GameObject*)obj)->extra;
    int camView = Camera_GetCurrentViewSlot();

    if (state->activated == 0)
    {
        if (GameBit_Get(state->gameBitId) != 0)
        {
            Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            Sfx_PlayFromObject(obj, SFXsp_skeep_mumb4);
            Sfx_PlayFromObject(obj, SFXTRIG_gate_stops);
            state->activated = 1;
        }
    }
    if (state->activated != 0)
    {
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E6118, timeDelta, NULL);
        if (state->exploded == 0)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E611C)
            {
                f32 vec[3];
                PSVECSubtract((void*)(camView + 0xC), (void*)(obj + 0xC), vec);
                PSVECNormalize(vec, vec);
                PSVECScale(vec, vec, lbl_803E6120);
                PSVECAdd((void*)(obj + 0xC), vec, (void*)(obj + 0xC));
                ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
                ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
                ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
                spawnExplosion(obj, lbl_803E6124, 1, 1, 0, 0, 0, 0, 0);
                state->exploded = 1;
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
    }
}

void dll_224_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

#pragma peephole on
void seqpoint_update(int* obj)
{
    void* player = Obj_GetPlayerObject();
    SeqPointState* self = ((GameObject*)obj)->extra;
    int key = self->disableBit;

    if (key != -1)
    {
        if (self->done != 0)
        {
            if (GameBit_Get(key) != 0) return;
            GameBit_Set(self->disableBit, 1);
            self->done = 1;
            return;
        }
        if (GameBit_Get(key) != 0)
        {
            self->done = 1;
            return;
        }
    }
    if (self->done != 0) return;
    switch (self->mode)
    {
    case SEQPOINT_MODE_RADIUS:
        if (!(Vec_distance((char*)obj + 0x18, (char*)player + 0x18) < self->triggerRadius)) return;
        (*gObjectTriggerInterface)->runSequence(self->sequenceId, obj, -1);
        self->done = 1;
        break;
    case SEQPOINT_MODE_BIT:
        if (self->conditionBit == -1) return;
        if (GameBit_Get(self->conditionBit) == 0) return;
        (*gObjectTriggerInterface)->runSequence(self->sequenceId, obj, -1);
        self->done = 1;
        break;
    case SEQPOINT_MODE_RADIUS_AND_BIT:
        if (!(Vec_distance((char*)obj + 0x18, (char*)player + 0x18) < self->triggerRadius)) return;
        if (self->conditionBit == -1) return;
        if (GameBit_Get(self->conditionBit) == 0) return;
        (*gObjectTriggerInterface)->runSequence(self->sequenceId, obj, -1);
        self->done = 1;
        break;
    case SEQPOINT_MODE_RADIUS_BIT_ONCE:
        if (!(Vec_distance((char*)obj + 0x18, (char*)player + 0x18) < self->triggerRadius)) return;
        if (self->conditionBit == -1) return;
        if (GameBit_Get(self->conditionBit) != 0) return;
        (*gObjectTriggerInterface)->runSequence(self->sequenceId, obj, -1);
        GameBit_Set(self->conditionBit, 1);
        self->done = 1;
        break;
    case SEQPOINT_MODE_BIT_ONCE:
        if (self->conditionBit == -1) return;
        if (GameBit_Get(self->conditionBit) != 0) return;
        (*gObjectTriggerInterface)->runSequence(self->sequenceId, obj, -1);
        GameBit_Set(self->conditionBit, 1);
        self->done = 1;
        break;
    case SEQPOINT_MODE_BIT_REPEAT:
        if (self->conditionBit == -1) return;
        if (GameBit_Get(self->conditionBit) == 0) return;
        (*gObjectTriggerInterface)->runSequence(self->sequenceId, obj, -1);
        break;
    }
}

#pragma peephole off
void vfpdraghead_update(int* obj)
{
    extern void Obj_FreeObject(int* obj);
    extern int randomGetRange(int lo, int hi);
    int state = (s8)(*(s8**)&((GameObject*)obj)->anim.placementData)[0x19];
    VfpDragHeadState* self2;

    if (state == 2)
    {
        self2 = ((GameObject*)obj)->extra;
        gVfpDragHeadSpawnTimer -= (s16)timeDelta;
        if (GameBit_Get(self2->gameBitB) != 0) return;
        if (gVfpDragHeadSpawnTimer > 0xc8) return;
        if (self2->headIndex != gVfpDragHeadActiveIndex) return;
        if (randomGetRange(0, 2) != 0) return;
        (*gPartfxInterface)->spawnObject(obj, 0x391, NULL, 4, -1, NULL);
    }
    else if (((GameObject*)obj)->anim.seqId == 0x3c5)
    {
        self2 = ((GameObject*)obj)->extra;
        self2->despawnTimer -= (s16)timeDelta;
        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.velocityX * timeDelta + ((GameObject*)obj)->anim.
            localPosX;
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.
            localPosY;
        ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.velocityZ * timeDelta + ((GameObject*)obj)->anim.
            localPosZ;
        if (self2->despawnTimer > 0) return;
        Obj_FreeObject(obj);
    }
    else if (state == 0)
    {
        self2 = ((GameObject*)obj)->extra;
        gVfpDragHeadSpawnTimer -= (s16)timeDelta;
        if (GameBit_Get(0x522) != 0) return;
        if (gVfpDragHeadSpawnTimer > 0xc8) return;
        if (self2->headIndex != gVfpDragHeadActiveIndex) return;
        if (randomGetRange(0, 2) != 0) return;
        (*gPartfxInterface)->spawnObject(obj, 0x391, NULL, 4, -1, NULL);
    }
    else if (state == 1)
    {
        self2 = ((GameObject*)obj)->extra;
        if (GameBit_Get(self2->gameBitA) != 0)
        {
            (*gPartfxInterface)->spawnObject(obj, 0x390, NULL, 4, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, 0x390, NULL, 4, -1, NULL);
            if (randomGetRange(0, 1) != 0)
            {
                (*gPartfxInterface)->spawnObject(obj, 0x391, NULL, 4, -1, NULL);
            }
        }
        if ((s16)ObjHits_GetPriorityHit((int)obj, 0, 0, 0) != 0)
        {
            GameBit_Set(self2->gameBitA, 1 - GameBit_Get(self2->gameBitA));
        }
    }
}

int fn_801FC6F4(int obj, int param2, ObjAnimUpdateState* ctx)
{
    SeqPointState* state = ((GameObject*)obj)->extra;
    int i;

    ctx->activeHitVolumePair = -1;
    ctx->sequenceEventActive = 0;
    for (i = 0; i < ctx->eventCount; i++)
    {
        switch (state->sequenceId)
        {
        case 0:
            break;
        case 13:
            switch (ctx->eventIds[i])
            {
            case 20:
                GameBit_Set(0x500, 0);
                GameBit_Set(0xd72, 1);
                GameBit_Set(0xd44, 1);
                (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 1, 1);
                (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 2, 1);
                (*gMapEventInterface)->setObjGroupStatus(((GameObject*)obj)->anim.mapEventSlot, 22, 1);
                if ((*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) == 1)
                {
                    unlockLevel(0, 0, 1);
                    lockLevel(mapGetDirIdx(70), 1);
                    lockLevel(mapGetDirIdx(4), 0);
                    loadMapAndParent(70);
                    (*gMapEventInterface)->setMapAct(18, 2);
                    warpToMap(124, 0);
                }
                else if ((*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot) == 2)
                {
                    unlockLevel(0, 0, 1);
                    lockLevel(mapGetDirIdx(70), 1);
                    lockLevel(mapGetDirIdx(4), 0);
                    loadMapAndParent(70);
                    (*gMapEventInterface)->setMapAct(11, 4);
                    (*gMapEventInterface)->setMapAct(8, 6);
                    warpToMap(124, 0);
                }
                break;
            }
            break;
        }
        ctx->eventIds[i] = 0;
    }
    return 0;
}

void fn_801FBAC8(int obj)
{
    int params = *(int*)&((GameObject*)obj)->anim.placementData;
    VfpPlatformState* state = ((GameObject*)obj)->extra;
    if (GameBit_Get(state->gameBitId) != 0)
    {
        state->state = 6;
    }
    switch (state->state)
    {
    case 6:
        if (((GameObject*)obj)->anim.localPosZ < ((ObjPlacement*)params)->posZ)
        {
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ + timeDelta;
            if (((GameObject*)obj)->anim.localPosZ >= ((ObjPlacement*)params)->posZ)
            {
                ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)params)->posZ;
            }
        }
        else if (((GameObject*)obj)->anim.localPosZ > ((ObjPlacement*)params)->posZ)
        {
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ - timeDelta;
            if (((GameObject*)obj)->anim.localPosZ <= ((ObjPlacement*)params)->posZ)
            {
                ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)params)->posZ;
            }
        }
        else
        {
            if (GameBit_Get(state->gameBitId) == 0)
            {
                state->state = 3;
            }
        }
        break;
    case 0:
        if (GameBit_Get(state->gameBitId) == 0)
        {
            state->state = 3;
        }
        break;
    case 1:
        {
            s16 timer = state->timer;
            if (timer != 0)
            {
                state->timer -= (s16)timeDelta;
                if (state->timer <= 0)
                {
                    state->timer = 0;
                }
            }
            else if (state->axisMode == 0)
            {
                if (((GameObject*)obj)->anim.localPosZ == ((ObjPlacement*)params)->posZ - lbl_803E6108)
                {
                    state->state = 2;
                }
                if (((GameObject*)obj)->anim.localPosZ == lbl_803E6108 + ((ObjPlacement*)params)->posZ)
                {
                    state->state = 3;
                }
            }
            else
            {
                if (((GameObject*)obj)->anim.localPosZ == ((ObjPlacement*)params)->posZ - lbl_803E6108)
                {
                    state->state = 4;
                }
                if (((GameObject*)obj)->anim.localPosZ == lbl_803E6108 + ((ObjPlacement*)params)->posZ)
                {
                    state->state = 5;
                }
            }
            break;
        }
    case 2:
        {
            f32 thr;
            f32 z = ((GameObject*)obj)->anim.localPosZ;
            if (z < (thr = lbl_803E6108, thr + ((ObjPlacement*)params)->posZ))
            {
                ((GameObject*)obj)->anim.localPosZ = z + timeDelta;
                if (((GameObject*)obj)->anim.localPosZ >= thr + ((ObjPlacement*)params)->posZ)
                {
                    ((GameObject*)obj)->anim.localPosZ = thr + ((ObjPlacement*)params)->posZ;
                    state->state = 1;
                    state->timer = 20;
                }
            }
            break;
        }
    case 3:
        {
            f32 thr;
            if (((GameObject*)obj)->anim.localPosZ > ((ObjPlacement*)params)->posZ - (thr = lbl_803E6108))
            {
                ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ - timeDelta;
                if (((GameObject*)obj)->anim.localPosZ <= ((ObjPlacement*)params)->posZ - thr)
                {
                    ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)params)->posZ - thr;
                    state->state = 1;
                    state->timer = 20;
                }
            }
            break;
        }
    }
}

void vfpplatform_update(int obj)
{
    int params = *(int*)&((GameObject*)obj)->anim.placementData;
    VfpPlatformState* state = ((GameObject*)obj)->extra;
    int xi;
    int yi;
    int txi;
    int tyi;
    u8 s3 = state->axisMode;
    if (s3 == 10)
    {
        if (GameBit_Get(state->gameBitId) != 0)
        {
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        }
    }
    else
    {
        xi = ((GameObject*)obj)->anim.localPosX;
        yi = ((GameObject*)obj)->anim.localPosZ;
        txi = ((ObjPlacement*)params)->posX;
        tyi = ((ObjPlacement*)params)->posZ;
        if (s3 != 99)
        {
            if (((GameObject*)obj)->anim.seqId == 960)
            {
                fn_801FBAC8(obj);
            }
            else
            {
                switch (state->state)
                {
                case 0:
                    if (GameBit_Get(state->gameBitId) != 0)
                    {
                        state->state = 1;
                    }
                    break;
                case 1:
                    {
                        s16 timer = state->timer;
                        if (timer != 0)
                        {
                            state->timer -= (s16)timeDelta;
                            if (state->timer <= 0)
                            {
                                state->timer = 0;
                            }
                        }
                        else if (s3 == 0)
                        {
                            if (yi == tyi - 60)
                            {
                                state->state = 2;
                                Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt5);
                            }
                            if (yi == tyi)
                            {
                                state->state = 3;
                                Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt5);
                            }
                        }
                        else if (s3 == 3)
                        {
                            if (xi == txi - 60)
                            {
                                state->state = 2;
                                Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt5);
                            }
                            if (xi == txi)
                            {
                                state->state = 3;
                                Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt5);
                            }
                        }
                        else
                        {
                            if (yi == tyi + 60)
                            {
                                state->state = 4;
                                Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt5);
                            }
                            if (yi == tyi)
                            {
                                state->state = 5;
                                Sfx_PlayFromObject(obj, SFXsp_lfoot_taunt5);
                            }
                        }
                        break;
                    }
                case 2:
                    if (s3 == 3 && xi < txi)
                    {
                        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX + timeDelta;
                        if ((int)((GameObject*)obj)->anim.localPosX >= txi)
                        {
                            ((GameObject*)obj)->anim.localPosX = txi;
                            state->state = 1;
                        }
                    }
                    else if (yi < tyi)
                    {
                        ((GameObject*)obj)->anim.localPosZ = *(f32*)&((GameObject*)obj)->anim.localPosZ + timeDelta;
                        if ((int)((GameObject*)obj)->anim.localPosZ >= tyi)
                        {
                            ((GameObject*)obj)->anim.localPosZ = tyi;
                            state->state = 1;
                        }
                    }
                    break;
                case 3:
                    if (s3 == 3 && xi > txi - 60)
                    {
                        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX - timeDelta;
                        if ((int)((GameObject*)obj)->anim.localPosX <= txi - 60)
                        {
                            ((GameObject*)obj)->anim.localPosX = (txi - 60);
                            state->state = 1;
                            state->timer = 200;
                        }
                    }
                    else if (yi > tyi - 60)
                    {
                        ((GameObject*)obj)->anim.localPosZ = *(f32*)&((GameObject*)obj)->anim.localPosZ - timeDelta;
                        if ((int)((GameObject*)obj)->anim.localPosZ <= tyi - 60)
                        {
                            ((GameObject*)obj)->anim.localPosZ = (tyi - 60);
                            state->state = 1;
                            state->timer = 200;
                        }
                    }
                    break;
                case 4:
                    if (s3 == 3 && xi > txi)
                    {
                        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX - timeDelta;
                        if ((int)((GameObject*)obj)->anim.localPosX <= txi)
                        {
                            ((GameObject*)obj)->anim.localPosX = txi;
                            state->state = 1;
                        }
                    }
                    else if (yi > tyi)
                    {
                        ((GameObject*)obj)->anim.localPosZ = *(f32*)&((GameObject*)obj)->anim.localPosZ - timeDelta;
                        if ((int)((GameObject*)obj)->anim.localPosZ <= tyi)
                        {
                            ((GameObject*)obj)->anim.localPosZ = tyi;
                            state->state = 1;
                        }
                    }
                    break;
                case 5:
                    if (s3 == 3 && xi < txi + 60)
                    {
                        ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX + timeDelta;
                        if ((int)((GameObject*)obj)->anim.localPosX >= txi + 60)
                        {
                            ((GameObject*)obj)->anim.localPosX = (txi + 60);
                            state->state = 1;
                            state->timer = 200;
                        }
                    }
                    else if (yi < tyi + 60)
                    {
                        ((GameObject*)obj)->anim.localPosZ = *(f32*)&((GameObject*)obj)->anim.localPosZ + timeDelta;
                        if ((int)((GameObject*)obj)->anim.localPosZ >= tyi + 60)
                        {
                            ((GameObject*)obj)->anim.localPosZ = (tyi + 60);
                            state->state = 1;
                            state->timer = 200;
                        }
                    }
                    break;
                }
            }
        }
    }
}

#pragma scheduling on
#pragma peephole on
void dll_224_release_nop(void)
{
}

void dll_224_initialise_nop(void)
{
}

void dll_224_hitDetect(void* obj)
{
    extern void objRenderFn_80041018(int* obj); /* #57 */
    if (*(void**)((char*)obj + 0x74) != NULL)
    {
        objRenderFn_80041018(obj);
    }
}

#pragma scheduling off
#pragma peephole off
void dll_224_update(void* obj)
{
    extern void spellStoneUseFn_801fd270(void* obj); /* #57 */
    extern int gSpellStoneEventId; /* #57 */
    int v;
    v = (*gMapEventInterface)->getMapAct(((GameObject*)obj)->anim.mapEventSlot);
    switch (v)
    {
    case 1:
        gSpellStoneEventId = 0x123;
        break;
    case 2:
        gSpellStoneEventId = 0x83b;
        break;
    case 3:
        gSpellStoneEventId = 0x83c;
        break;
    default:
        gSpellStoneEventId = 0x123;
        break;
    }
    spellStoneUseFn_801fd270(obj);
}

void dll_224_init(void* obj, void* other)
{
    SpellStoneUseState* extra = ((GameObject*)obj)->extra;
    s16 v = ((s8) * ((s8*)other + 0x18) << 8);
    u8 t;
    ((GameObject*)obj)->anim.rotX = v;
    extra->completeGameBit = *(s16*)((char*)other + 0x1e);
    extra->requiredGameBit = *(s16*)((char*)other + 0x20);
    t = (*&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = t;
}

ObjectDescriptor gVFP_Block1ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)vfpblock1_initialise,
    (ObjectDescriptorCallback)vfpblock1_release,
    0,
    (ObjectDescriptorCallback)vfpblock1_init,
    (ObjectDescriptorCallback)vfpblock1_update,
    (ObjectDescriptorCallback)vfpblock1_hitDetect,
    (ObjectDescriptorCallback)vfpblock1_render,
    (ObjectDescriptorCallback)vfpblock1_free,
    (ObjectDescriptorCallback)vfpblock1_getObjectTypeId,
    vfpblock1_getExtraSize,
};
