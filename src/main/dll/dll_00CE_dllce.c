/*
 * DLL 0xCE - a GroundBaddie-derived enemy plus two companion objects
 * (the ChukChuk ice-spitter and its IceBall projectile).
 *
 * The enemy runs as a baddie-control state machine: dll_CE_init wires it
 * into gBaddieControlInterface (mode 7/6, obj type id 0x49) and dll_CE_update
 * ticks the control interface each frame, dispatching melee/move/hit events.
 * dll_CE_initialise installs the two per-object handler tables
 * (gChukChukMoveHandlers = the move/attack handlers, gChukChukCheckHandlers = the
 * begin/check handlers) used by the control interface; each fn_8015E*
 * entry implements one move state. Handlers coordinate sibling instances
 * of the same DLL by walking the object list and calling their
 * vtable[0x24] with message 129 (0x81); the shared anim sequence id is
 * 774 (0x306). dll_CE_func0B is the inbound message handler (0x80 -> take
 * damage / enter substate 4; 0x81 -> clear the "no-target" config bit).
 *
 * gChukChukObjDescriptor / gIceBallObjDescriptor expose the two companion
 * objects (defined in sibling TUs); their callbacks are forward-declared
 * here only so the descriptor tables can take their addresses.
 */
#include "main/dll/partfx_interface.h"
#include "main/objanim.h"
#include "main/audio/sfx_play_api.h"
#include "main/object_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/obj_placement.h"
#include "main/dll/chukchukstate_struct.h"
#include "main/dll/baddie_control_interface.h"
#include "main/game_object.h"
#include "main/objprint_api.h"
#include "main/object.h"
#include "main/object_descriptor.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/baddie_state.h"
#include "main/dll/dll_00CA_icebaddie.h"
#include "main/dll/dll_00CE_dllce.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/sky_interface.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/obj_group.h"
#include "main/obj_list.h"
#include "main/obj_message.h"
#include "main/player_control_interface.h"
#include "main/object_render.h"
#include "main/frame_timing.h"

/* object group this object belongs to */
#define DLLCE_OBJGROUP 3

/* child object id spawned in chukChuk_spawnIceBall (role un-pinnable per gate: generic locals, no cache field/spawn-fn/docstring) */
#define DLLCE_CHILD_OBJ 778

/* dust burst spawned once when the baddie-control fx flag bit 2 is set */
#define DLLCE_PARTFX_DUST 0x345
/* spray burst spawned 10x when the baddie-control fx flag bit 4 is set */
#define DLLCE_PARTFX_SPRAY    0x343
#define DLLCE_HIT_VOLUME_SLOT 10
u8 lbl_803AC580[0x18];

STATIC_ASSERT(sizeof(ChukChukState) == 0x18);
STATIC_ASSERT(offsetof(ChukChukState, flags) == 0x12);

extern void* gChukChukMoveHandlers[];
extern void* gChukChukCheckHandlers[];
extern void* gIceBaddieStateHandlersB[];
extern void* gIceBaddieStateHandlersA[];

u8 lbl_8031FEA8[] = {
    0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0,
    0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 2,
    0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0,
    0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5, 0, 0, 0, 5,
};

u8 lbl_8031FF20[] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0,   0,
};

ObjectDescriptor12 dll_CE = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)dll_CE_initialise,
    (ObjectDescriptorCallback)dll_CE_release_nop,
    0,
    (ObjectDescriptorCallback)dll_CE_init,
    (ObjectDescriptorCallback)dll_CE_update,
    (ObjectDescriptorCallback)dll_CE_hitDetect_nop,
    (ObjectDescriptorCallback)dll_CE_render,
    (ObjectDescriptorCallback)dll_CE_free,
    (ObjectDescriptorCallback)dll_CE_getObjectTypeId,
    dll_CE_getExtraSize_ret_1052,
    (ObjectDescriptorCallback)dll_CE_setScale,
    (ObjectDescriptorCallback)dll_CE_func0B,
};

void iceBaddie_installStateHandlers(void)
{

    gIceBaddieStateHandlersA[0] = iceBaddie_updateOpenHitState;
    gIceBaddieStateHandlersA[1] = iceBaddie_updateOpenState;
    gIceBaddieStateHandlersA[2] = iceBaddie_updateHideResetState;
    gIceBaddieStateHandlersA[3] = iceBaddie_updateImpactHitState;
    gIceBaddieStateHandlersA[4] = iceBaddie_updateSpinState;
    gIceBaddieStateHandlersA[5] = iceBaddie_stateHandlerA05;
    gIceBaddieStateHandlersA[6] = iceBaddie_stateHandlerA06;
    gIceBaddieStateHandlersA[7] = iceBaddie_updateHeightBlendState;
    gIceBaddieStateHandlersA[8] = iceBaddie_updateControlMove5State;
    gIceBaddieStateHandlersA[9] = iceBaddie_updateCommDownState;
    gIceBaddieStateHandlersA[10] = iceBaddie_updateDropState;
    gIceBaddieStateHandlersA[11] = iceBaddie_stateHandlerA0B;
    gIceBaddieStateHandlersA[12] = iceBaddie_updateContactHitState;
    gIceBaddieStateHandlersA[13] = iceBaddie_updateLandingState;
    gIceBaddieStateHandlersB[0] = iceBaddie_checkTargetState;
    gIceBaddieStateHandlersB[1] = iceBaddie_stateHandlerB01;
    gIceBaddieStateHandlersB[2] = iceBaddie_stateHandlerB02;
    gIceBaddieStateHandlersB[3] = iceBaddie_stateHandlerB03;
    gIceBaddieStateHandlersB[4] = iceBaddie_stateHandlerB04;
    gIceBaddieStateHandlersB[5] = iceBaddie_stateHandlerB05;
    gIceBaddieStateHandlersB[6] = iceBaddie_stateHandlerB06;
    gIceBaddieStateHandlersB[7] = iceBaddie_stateHandlerB07;
}
int chukChuk_checkChooseAttackState(int obj, GroundBaddieState* state)
{

    int count;
    int i;
    GroundBaddieState* sub;
    u8* hit;
    int maxr;
    int four;
    int* objs;
    int result;
    int rnd;

    sub = ((GameObject*)obj)->extra;
    if (*(char*)&state->baddie.moveDone != '\0' || *(char*)&state->baddie.moveJustStartedB != '\0')
    {
        hit = *(u8**)&sub->control;
        result = (*(int (**)(int, u8*, f32, int))(*(int*)gBaddieControlInterface + 0x44))(obj, (u8*)state,
                                                                                          (f32)(u32)sub->aggroRange, 1);
        if (result != 0)
        {
            hit[9] &= ~2;
            return 5;
        }
        four = 0;
        maxr = 0;
        objs = ObjList_GetObjects(&i, &count);
        for (; i < count; i++)
        {
            void* o = (void*)objs[i];
            if (o != (void*)obj && ((GameObject*)o)->anim.seqId == 774)
            {
                int v = (*(int (**)(void*, int))(**(int**)&((GameObject*)o)->anim.dll + 0x20))(o, 0);
                if (v > maxr)
                {
                    maxr = v;
                }
                if (v == 4)
                {
                    four++;
                }
            }
        }
        rnd = randomGetRange(0, sub->aggression);
        if (maxr >= 5 || (hit[9] & 1) != 0)
        {
            if ((sub->configFlags & 2) != 0)
            {
                hit[9] |= 1;
            }
            (*gPlayerInterface)->setState((void*)obj, state, 4);
        }
        else if (rnd > 32)
        {
            if (four > 1)
            {
                (*gPlayerInterface)->setState((void*)obj, state, 2);
            }
            else
            {
                (*gPlayerInterface)->setState((void*)obj, state, 4);
            }
        }
        else if (rnd > 16)
        {
            (*gPlayerInterface)->setState((void*)obj, state, 2);
        }
        else
        {
            (*gPlayerInterface)->setState((void*)obj, state, 3);
        }
    }
    return 0;
}

int chukChuk_checkSubmergeState(int* obj, GroundBaddieState* state)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        f32 fz;
        (*gPlayerInterface)->setState(obj, state, 1);
        {
            f32* p = *(f32**)&sub->control;
            fz = 0.0f;
            p[0] = fz;
            p[1] = fz;
        }
    }
    return 0;
}

int chukChuk_checkYieldState(int* obj, GroundBaddieState* state)
{
    GroundBaddieState* sub;
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        sub = ((GameObject*)obj)->extra;
        sub->subMode = 0;
        if (sub->gameBitB != -1)
        {
            mainSetBits(sub->gameBitB, 0);
        }
        if (sub->gameBitA != -1)
        {
            mainSetBits(sub->gameBitA, 1);
        }
    }
    return 0;
}

int chukChuk_checkDeathState(GameObject* obj, GroundBaddieState* state)
{
    GroundBaddieState* sub = obj->extra;
    f32 z;
    f32* v;

    if (*(char*)&state->baddie.moveJustStartedB != '\0')
    {
        v = *(f32**)&sub->control;
        z = 0.0f;
        v[0] = z;
        v[1] = z;
        (*gPlayerInterface)->setState(obj, state, 6);
        *(int*)&state->baddie.targetObj = 0;
        *(s8*)&state->baddie.physicsActive = 0;
        *(s8*)&state->baddie.hasTarget = 0;
        ObjHits_DisableObject(obj);
        *(u8*)&obj->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    else if (*(char*)&state->baddie.moveDone != '\0')
    {
        ObjMsg_SendToObjects(0, 3, obj, 0xe0000, (u32)obj);
        if (obj->anim.placementData == NULL)
        {
            Obj_FreeObject((GameObject*)obj);
            return 0;
        }
        return 4;
    }
    return 0;
}

int chukChuk_checkHealthState(int obj, u8* state)
{
    if ((s8)((GroundBaddieState*)state)->baddie.hitPoints < 1)
        return 3;
    if ((s8)((GroundBaddieState*)state)->baddie.moveDone != 0)
        return 6;
    return 0;
}

int chukChuk_checkTargetState(int* obj, GroundBaddieState* state)
{
    if (*(int**)&state->baddie.targetObj != NULL)
    {
        if ((s8)state->baddie.moveJustStartedB != 0)
        {
            f32 fz = 0.0f;
            state->baddie.animSpeedB = fz;
            state->baddie.animSpeedA = fz;
            (*gPlayerInterface)->setState(obj, state, 0);
        }
        if ((s8)state->baddie.moveDone != 0)
        {
            return 6;
        }
    }
    return 0;
}

int chukChuk_updateWindupState(GameObject* obj, GroundBaddieState* state)
{
            GroundBaddieState* sub;
    f32 spd;

    sub = (obj)->extra;
    *(s8*)&state->baddie.stateTag = 3;
    state->baddie.moveSpeed = 0.008f;
    spd = 0.0f;
    state->baddie.animSpeedA = spd;
    state->baddie.animSpeedB = spd;
    if (*(char*)&state->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 1, spd, 0);
        *(s8*)&state->baddie.moveDone = 0;
    }
    if ((state->baddie.moveEventFlags & 1) == 0)
    {
        if (((GameObject*)Obj_GetPlayerObject())->anim.seqId != 0)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_wp_stftest122_1f2);
        }
        else
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_swd);
        }
        Sfx_PlayFromObject((u32)obj, SFXTRIG_en_rfall5_c);
        Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_seal4_c_263);
        state->baddie.moveEventFlags |= 1;
    }
    if ((state->baddie.moveEventFlags & 2) == 0 && (obj)->anim.currentMoveProgress > 0.3f)
    {
        Sfx_PlayFromObject((u32)obj, SFXTRIG_wp_iceywindlp16_233);
        state->baddie.moveEventFlags |= 2;
        ((BaddieControlInterface*)*gBaddieControlInterface)->spawnChild(obj, sub->triggerId, -1, 0);
    }
    return 0;
}

int chukChuk_updateAlertState(int* obj, GroundBaddieState* state)
{

        int* objs;
    int count;
    int i;
    int* playerChild;
    GameObject* player;
    int result;

    if (*(char*)&state->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 0, 0.0f, 0);
        *(s8*)&state->baddie.moveDone = 0;
    }
    if (*(char*)&state->baddie.moveJustStartedA != '\0')
    {
        objs = ObjList_GetObjects(&i, &count);
        for (; i < count; i++)
        {
            void* o = (void*)objs[i];
            if (o != obj && ((GameObject*)o)->anim.seqId == 774)
            {
                (*(void (**)(void*, int, int))(**(int**)&((GameObject*)o)->anim.dll + 0x24))(o, 129, 0);
            }
        }
        playerChild = *(int**)((char*)Obj_GetPlayerObject() + 0xc8);
        player = Obj_GetPlayerObject();
        result = (**(int (**)(int*))(*(int*)(*(int*)&((GameObject*)playerChild)->anim.dll) + 0x44))(playerChild);
        if (result != 0)
        {
            if (((GameObject*)player)->anim.seqId != 0)
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_wp_stftest122_1f2);
            }
            else
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_boar1_c_95);
            }
        }
        else
        {
            if (((GameObject*)player)->anim.seqId != 0)
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_wp_stftest122_1f2);
            }
            else
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_swd);
            }
        }
        Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_boar1_c_267);
    }
    *(s8*)&state->baddie.stateTag = 3;
    state->baddie.moveSpeed = 0.015f;
    state->baddie.animSpeedA = 0.0f;
    return 0;
}

int chukChuk_updateSpitState(GameObject* obj, int state)
{

        GroundBaddieState* sub = (obj)->extra;
    int count;
    int idx;

    if ((s32)(s8) * (u8*)(state + 0x27a) != 0)
    {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DLLCE_HIT_VOLUME_SLOT, 1, -1);
    ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->objectPairPriority = 10;
    ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);

    if ((s32)(s8) * (u8*)(state + 0x27a) != 0)
    {
        int* objs = ObjList_GetObjects(&idx, &count);
        while (idx < count)
        {
            int o = objs[idx];
            if ((void*)o != (void*)obj && ((GameObject*)o)->anim.seqId == 774)
            {
                (*(int (**)(int, int, int))(**(int**)&((GameObject*)o)->anim.dll + 0x24))(o, 129, 0);
            }
            idx++;
        }
    }

    ((GroundBaddieState*)state)->baddie.moveSpeed = 0.01f;

    if ((s32)(s8) * (u8*)(state + 0x27a) != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 10, 0.0f, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.stateTag = 1;

    if ((((GroundBaddieState*)state)->baddie.eventFlags & BADDIE_EVENT_FOOTSTEP) != 0U)
    {
        int child = *(int*)&sub->control;
        ((GroundBaddieState*)state)->baddie.eventFlags =
            ((GroundBaddieState*)state)->baddie.eventFlags & ~BADDIE_EVENT_FOOTSTEP;
        *(u8*)(child + 0x8) = (u8)(*(u8*)(child + 0x8) | 0x1);
        Sfx_PlayFromObject((u32)obj, SFXTRIG_baddie_rach_bite_266);
    }
    return 0;
}

int chukChuk_updateState3(int* obj, GroundBaddieState* state)
{
    if ((s8)state->baddie.moveJustStartedA != 0)
    {
        ObjHits_EnableObject((GameObject*)obj);
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DLLCE_HIT_VOLUME_SLOT, 1, -1);
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairPriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject((GameObject*)obj);
    state->baddie.moveSpeed = 0.01f;
    if ((s8)state->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 5, 0.0f, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.stateTag = 1;
    return 0;
}

int chukChuk_updateAttackState(short* obj, GroundBaddieState* state)
{

            int count;
    int i;
    GroundBaddieState* sub;
    int* objs;

    sub = ((GameObject*)obj)->extra;
    if (*(char*)&state->baddie.moveJustStartedA != '\0')
    {
        ObjHits_EnableObject((GameObject*)obj);
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DLLCE_HIT_VOLUME_SLOT, 1, -1);
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairPriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject((GameObject*)obj);
    if (*(char*)&state->baddie.moveJustStartedA != '\0')
    {
        objs = ObjList_GetObjects(&i, &count);
        for (; i < count; i++)
        {
            void* o = (void*)objs[i];
            if (o != obj && ((GameObject*)o)->anim.seqId == 774)
            {
                (*(void (**)(void*, int, int))(**(int**)&((GameObject*)o)->anim.dll + 0x24))(o, 129, 0);
            }
        }
        if (randomGetRange(0, 1) != 0)
        {
            if (*(char*)&state->baddie.moveJustStartedA != '\0')
            {
                ObjAnim_SetCurrentMove((int)obj, 6, 0.0f, 0);
                *(s8*)&state->baddie.moveDone = 0;
            }
        }
        else
        {
            if (*(char*)&state->baddie.moveJustStartedA != '\0')
            {
                ObjAnim_SetCurrentMove((int)obj, 7, 0.0f, 0);
                *(s8*)&state->baddie.moveDone = 0;
            }
        }
        *(s8*)&state->baddie.stateTag = 1;
        state->baddie.moveSpeed = 0.005f + (f32)(u32)sub->aggression / 20000.0f;
    }
    state->baddie.animSpeedA = 0.0f;
    return 0;
}

int chukChuk_updateSubmergeState(GameObject* obj, GroundBaddieState* state)
{

            GroundBaddieState* sub;
    u8* hit;

    sub = (obj)->extra;
    if (*(char*)&state->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 14, 0.0f, 0);
        *(s8*)&state->baddie.moveDone = 0;
    }
    if ((obj)->anim.currentMoveProgress > 0.25f)
    {
        hit = *(u8**)&sub->control;
        hit[8] |= 2;
    }
    if (*(char*)&state->baddie.moveJustStartedA != '\0')
    {
        ObjHits_DisableObject(obj);
        state->baddie.moveSpeed = 0.01f;
        state->baddie.animSpeedA = 0.0f;
    }
    if (*(char*)&state->baddie.moveDone != '\0')
    {
        mainSetBits(sub->gameBitB, 0);
        ObjAnim_SetCurrentMove((int)obj, 8, 0.0f, 0);
        *(int*)&state->baddie.targetObj = 0;
        *(s8*)&state->baddie.physicsActive = 0;
        *(s8*)&state->baddie.hasTarget = 0;
        sub->targetState = 0;
        if ((hit[9] & 2) == 0)
        {
            *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
    }
    return 0;
}

int chukChuk_updateEmergeState(GameObject* obj, GroundBaddieState* state)
{

                GroundBaddieState* sub;
    u8* hit;
    int flags;

    sub = (obj)->extra;
    hit = *(u8**)&sub->control;
    if (*(char*)&state->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 11, 0.0f, 0);
        *(s8*)&state->baddie.moveDone = 0;
    }
    if (*(char*)&state->baddie.moveJustStartedA != '\0')
    {
        *(s8*)&state->baddie.physicsActive = 1;
        mainSetBits(sub->gameBitB, 1);
        *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        (obj)->anim.alpha = 0xff;
        *(s8*)&state->baddie.stateTag = 1;
        state->baddie.moveSpeed = 0.012f + (f32)(u32)sub->aggression / 10000.0f;
        ObjHits_EnableObject(obj);
    }
    else
    {
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DLLCE_HIT_VOLUME_SLOT, 1, -1);
        ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->objectPairPriority = 10;
        ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->objectPairHitVolume = 1;
        ObjHits_RegisterActiveHitVolumeObject(obj);
    }
    if (*(char*)&state->baddie.moveDone != '\0')
    {
        sub->targetState = 1;
    }
    flags = state->baddie.eventFlags;
    if ((flags & 0x200) != 0)
    {
        state->baddie.eventFlags = flags & ~BADDIE_EVENT_LANDING;
        hit[8] |= 4;
    }
    if ((obj)->anim.currentMoveProgress < 0.7f)
    {
        hit[8] |= 2;
    }
    return 0;
}

void chukChuk_spawnIceBall(GameObject* obj, GroundBaddieState* state);

void chukChuk_spawnIceBall(GameObject* obj, GroundBaddieState* state)
{
                f32 dur;
    f32 t;
    int setup;
    u8* o;

    if (Obj_IsLoadingLocked() == 0)
    {
        setup = (int)Obj_AllocObjectSetup(36, DLLCE_CHILD_OBJ);
        ((ObjPlacement*)setup)->posX = (obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = 15.0f + (obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = (obj)->anim.localPosZ;
        ((ObjPlacement*)setup)->color[0] = 1;
        ((ObjPlacement*)setup)->color[1] = 1;
        ((ObjPlacement*)setup)->color[2] = 0xff;
        ((ObjPlacement*)setup)->color[3] = 0xff;
        o = (u8*)Obj_SetupObject((ObjPlacement*)setup, 5, -1, -1, 0);
        if (o != NULL)
        {
            t = state->baddie.targetDistance / (f32)(u32)state->aggroRange;
            dur = 50.0f * t;
            ((GameObject*)o)->anim.velocityX =
                (((GameObject*)state->baddie.targetObj)->anim.localPosX - (obj)->anim.localPosX) / dur;
            ((GameObject*)o)->anim.velocityY =
                ((90.0f * t + ((GameObject*)state->baddie.targetObj)->anim.localPosY) - (obj)->anim.localPosY) /
                dur;
            ((GameObject*)o)->anim.velocityZ =
                (((GameObject*)state->baddie.targetObj)->anim.localPosZ - (obj)->anim.localPosZ) / dur;
            *(int*)&((GameObject*)o)->ownerObj = (int)obj;
        }
    }
}

void chukChuk_acquireTarget(GameObject* obj, int state, int target)
{
            int sub = *(int*)&((GroundBaddieState*)state)->control;
    GameObject* r;

    r = ((BaddieControlInterface*)*gBaddieControlInterface)
            ->findAggroTarget(obj, (void*)target, (f32)(u32)((GroundBaddieState*)state)->aggroRange, 0x8000);

    if (r != NULL && (((GroundBaddieState*)state)->configFlags & 0x4) == 0)
    {
        int v = -1;
        ((BaddieControlInterface*)*gBaddieControlInterface)
            ->startHitReaction(obj, (void*)target, (char*)state + 0x35c,
                               ((GroundBaddieState*)state)->gameBitB, NULL, 0, 0, 8, v);
        *(int*)&((GroundBaddieState*)target)->baddie.targetObj = (int)r;
        ((GroundBaddieState*)target)->baddie.hasTarget = 0;
        ((GroundBaddieState*)state)->targetState = 1;
    }
    else
    {
        void* player = Obj_GetPlayerObject();
        f32 dist;
        struct
        {
            f32 x, y, z;
        } d;
        f32* dp = &d.x;
        if (player != NULL)
        {
            d.x = ((GameObject*)player)->anim.worldPosX - obj->anim.worldPosX;
            d.y = ((GameObject*)player)->anim.worldPosY - obj->anim.worldPosY;
            d.z = ((GameObject*)player)->anim.worldPosZ - obj->anim.worldPosZ;
            dist = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
        }
        else
        {
            dist = 10000.0f;
        }
        if (*(f32*)(sub + 0) > *(f32*)(sub + 4))
        {
            if (dist < 400.0f)
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_boar1_c_265);
                *(f32*)(sub + 4) += (f32)(s32)randomGetRange(50, 250);
            }
        }
        *(f32*)(sub + 0) += timeDelta;
    }
}

void chukChuk_updateTargeting(int obj, int state, int target)
{
    void* player;
    char* targetObj;
    int result;
    struct
    {
        f32 x, y, z;
    } d;
    f32* dp = &d.x;

    player = Obj_GetPlayerObject();
    targetObj = *(char**)&((GroundBaddieState*)target)->baddie.targetObj;
    if (targetObj != NULL)
    {
        d.x = ((GameObject*)targetObj)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        d.y = ((GameObject*)targetObj)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        d.z = ((GameObject*)targetObj)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        ((GroundBaddieState*)target)->baddie.targetDistance = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
    }

    if ((((GroundBaddieState*)state)->configFlags & 0x20) == 0)
    {
        (**(void (**)(int, int, int, int, int, int, int))((char*)(*gBaddieControlInterface) + 0x3c))(
            obj, target, state + 0x400, 2, 3, (s32)((GroundBaddieState*)state)->soundIdA,
            (s32)((GroundBaddieState*)state)->soundIdB);
    }

    ((BaddieControlInterface*)*gBaddieControlInterface)
        ->processMessages((GameObject*)obj, (void*)target, (void*)(state + 0x35c),
                          ((GroundBaddieState*)state)->gameBitB, NULL, 0, 0, 8);

    result = ((BaddieControlInterface*)*gBaddieControlInterface)
                 ->updateHitReaction((GameObject*)obj, (void*)target, (char*)state + 0x35c,
                                     ((GroundBaddieState*)state)->gameBitB, (int*)lbl_8031FEA8, lbl_8031FF20, 1,
                                     lbl_803AC580);

    if (result != 0)
    {
        void* pc8 = ((GameObject*)player)->childObjs[0];
        (*(void (**)(void*))(**(int**)&((GameObject*)pc8)->anim.dll + 0x50))(pc8);
    }
}

void dll_CE_func0B(GameObject* obj, int v)
{
    GroundBaddieState* sub = obj->extra;
    GroundBaddieState* sub2 = (GroundBaddieState*)(int)sub;

    switch ((u8)v)
    {
    case 0x80:
        *(u8*)(*(int*)&sub->control + 9) |= 2;
        Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_boar1_c_264);
        (*gPlayerInterface)->setState((void*)obj, (void*)sub2, 1);
        sub2->baddie.substate = 4;
        *(s8*)&sub2->baddie.moveJustStartedB = 1;
        break;
    case 0x81:
        sub->configFlags &= ~4;
        break;
    }
}

s16 dll_CE_setScale(int* obj)
{
    return ((BaddieState*)((GameObject*)obj)->extra)->controlMode;
}

int dll_CE_getExtraSize_ret_1052(void)
{
    return 0x41c;
}

int dll_CE_getObjectTypeId(void)
{
    return 0x49;
}

void dll_CE_free(int* obj)
{
    GroundBaddieState* state = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject((int)obj, DLLCE_OBJGROUP);
    {
        int* sub = ((GameObject*)obj)->childObjs[0];
        if (sub != NULL)
        {
            Obj_FreeObject((GameObject*)sub);
            ((GameObject*)obj)->childObjs[0] = NULL;
        }
    }
    ((BaddieControlInterface*)*gBaddieControlInterface)->releaseState((GameObject*)obj, state, 32);
}

void dll_CE_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
        GroundBaddieState* sub = ((GameObject*)p1)->extra;
    f32 t;
    f32 zero = 0.0f;

    if (visible == 0 || ((GameObject*)p1)->userData1 != 0 || sub->targetState == 0)
    {
        return;
    }
    t = sub->glowAlpha;
    if (t != zero)
    {
        fn_8003B5E0(200, 0, 0, t);
    }
    objRenderModelAndHitVolumes((GameObject*)p1, p2, p3, p4, p5, 1.0f);
}

void dll_CE_hitDetect_nop(void)
{
}

void dll_CE_update(GameObject* obj, int unusedA, int unusedB)
{
            GroundBaddieState* sub;
    int setup;
    u8* hit;
    int spawnCount;
    f32 sunTime;

    sub = obj->extra;
    setup = *(int*)&obj->anim.placementData;
    if (obj->userData1 != 0)
    {
        if ((sub->baddie.substate != 3 || (sub->configFlags & 1) != 0) &&
            (*gMapEventInterface)->shouldNotSaveTime(((ObjPlacement*)setup)->mapId) != 0)
        {
            (*(void (**)(void*, int, int, int, int, int, int, f32))(*(int*)gBaddieControlInterface + 0x58))(
                obj, setup, (int)sub, 7, 6, 0x102, 0x26, 20.0f);
            sub->targetState = 0;
            Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_seal4_c_263);
            ObjAnim_SetCurrentMove((int)obj, 8, 0.0f, OBJANIM_MOVE_CONTROL_SKIP_EVENT_COUNTDOWN);
            *(s8*)&sub->baddie.moveDone = 0;
            obj->anim.alpha = 0xff;
            *(u8*)&obj->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
    }
    else if (obj->userData2 == 0)
    {
        obj->anim.localPosX = ((ObjPlacement*)setup)->posX;
        obj->anim.localPosY = ((ObjPlacement*)setup)->posY;
        obj->anim.localPosZ = ((ObjPlacement*)setup)->posZ;
        (*gObjectTriggerInterface)->runSequence(*(s8*)(setup + 0x2e), (void*)obj, -1);
        obj->userData2 = 1;
    }
    else
    {
        if (((BaddieControlInterface*)*gBaddieControlInterface)->isObjectValid(obj, sub, 0) == 0)
        {
            sub->targetState = 0;
        }
        else if ((sub->configFlags & 0x10) != 0 && (*gSkyInterface)->getSunPosition(&sunTime) == 0)
        {
            sub->targetState = 0;
        }
        else
        {
            chukChuk_updateTargeting((int)obj, (int)sub, (int)sub);
            if (sub->targetState == 0)
            {
                chukChuk_acquireTarget(obj, (int)sub, (int)sub);
            }
            else
            {
                hit = *(u8**)&sub->control;
                if ((hit[8] & 1) != 0)
                {
                    chukChuk_spawnIceBall(obj, sub);
                }
                if ((hit[8] & 2) != 0)
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, DLLCE_PARTFX_DUST, NULL, 1, -1, NULL);
                }
                if ((hit[8] & 4) != 0)
                {
                    spawnCount = 0;
                    do
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, DLLCE_PARTFX_SPRAY, NULL, 1, -1, NULL);
                        spawnCount++;
                    } while (spawnCount < 10);
                }
                hit[8] = 0;
                ((BaddieControlInterface*)*gBaddieControlInterface)->updateGravity(obj, sub, 0.0f, -1);
                (*gPlayerInterface)->rotateTowardTarget(obj, sub, timeDelta, 4);
                sub->savedObjC0 = *(int*)&obj->pendingParentObj;
                *(int*)&obj->pendingParentObj = 0;
                (*gPlayerInterface)->update(obj, sub, timeDelta, timeDelta, gChukChukMoveHandlers,
                                            gChukChukCheckHandlers);
                *(int*)&obj->pendingParentObj = sub->savedObjC0;
            }
            obj->anim.localPosY = ((ObjPlacement*)setup)->posY - 2.0f;
        }
    }
}

void dll_CE_init(GameObject* obj, u8* def, int flags)
{
        GroundBaddieState* sub;
    u8 mode;
    f32* v;

    sub = (obj)->extra;
    mode = 6;
    if (flags != 0)
    {
        mode |= 1;
    }
    if ((*(u8*)(def + 0x2b) & 0x20) == 0)
    {
        mode |= 8;
    }
    (*(void (**)(int, u8*, int, int, int, int, u8, f32))(*(int*)gBaddieControlInterface + 0x58))(
        (int)obj, def, (int)sub, 7, 6, 0x102, mode, 20.0f);
    (obj)->animEventCallback = NULL;
    v = *(f32**)&sub->control;
    *v = (f32)(int)randomGetRange(10, 300);
    ObjAnim_SetCurrentMove((int)obj, 8, 0.0f, 0);
    *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    (*gPlayerInterface)->setState(obj, sub, 0);
    sub->baddie.substate = 0;
    *(s8*)&sub->baddie.physicsActive = 0;
    ObjHits_DisableObject(obj);
}

void dll_CE_release_nop(void)
{
}

void dll_CE_initialise(void)
{
    gChukChukMoveHandlers[0] = chukChuk_updateEmergeState;
    gChukChukMoveHandlers[1] = chukChuk_updateSubmergeState;
    gChukChukMoveHandlers[2] = chukChuk_updateAttackState;
    gChukChukMoveHandlers[3] = chukChuk_updateState3;
    gChukChukMoveHandlers[4] = chukChuk_updateSpitState;
    gChukChukMoveHandlers[5] = chukChuk_updateAlertState;
    gChukChukMoveHandlers[6] = chukChuk_updateWindupState;
    gChukChukCheckHandlers[0] = chukChuk_checkTargetState;
    gChukChukCheckHandlers[1] = chukChuk_checkHealthState;
    gChukChukCheckHandlers[2] = chukChuk_checkDeathState;
    gChukChukCheckHandlers[3] = chukChuk_checkYieldState;
    gChukChukCheckHandlers[4] = chukChuk_checkSubmergeState;
    gChukChukCheckHandlers[5] = chukChuk_checkChooseAttackState;
}
