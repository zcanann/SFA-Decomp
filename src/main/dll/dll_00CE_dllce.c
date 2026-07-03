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
#include "main/obj_placement.h"
#include "main/dll/chukchukstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll/scarab.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/sky_interface.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/objlib.h"
extern int randomGetRange(int lo, int hi);
extern void ObjHits_RegisterActiveHitVolumeObject();
extern void ObjHits_SetHitVolumeSlot();
extern void ObjHits_EnableObject();
extern void ObjGroup_RemoveObject();
extern void ObjMsg_SendToObjects();

int fn_8015E3A0(int obj, int state)
{

    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2DD8;
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    int count;
    int idx;

    if ((s32)(s8) * (u8*)(state + 0x27a) != 0)
    {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairPriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairHitVolume = 1;
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

    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2DD8;

    if ((s32)(s8) * (u8*)(state + 0x27a) != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 10, lbl_803E2DC8, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.unk34D = 1;

    if ((((GroundBaddieState*)state)->baddie.eventFlags & 0x1) != 0U)
    {
        int child = *(int*)&sub->control;
        ((GroundBaddieState*)state)->baddie.eventFlags = ((GroundBaddieState*)state)->baddie.eventFlags & ~0x1;
        *(u8*)(child + 0x8) = (u8)(*(u8*)(child + 0x8) | 0x1);
        Sfx_PlayFromObject(obj, SFXfoxcom_heel);
    }
    return 0;
}

int fn_8015E210(int* obj, GroundBaddieState* state)
{

    extern void* Obj_GetPlayerObject(void);
    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2DD4;
    int* objs;
    int count;
    int i;
    int* playerChild;
    int* player;
    int result;

    if (*(char*)&state->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2DC8, 0);
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
                (*(void (**)(void*, int, int))(**(int**)&((GameObject*)o)->anim.dll + 0x24))(
                    o, 129, 0);
            }
        }
        playerChild = *(int**)((char*)Obj_GetPlayerObject() + 0xc8);
        player = Obj_GetPlayerObject();
        result = (**(int (**)(int*))(*(int*)(*(int*)&((GameObject*)playerChild)->anim.dll) + 0x44))(playerChild);
        if (result != 0)
        {
            if (((GameObject*)player)->anim.seqId != 0)
            {
                Sfx_PlayFromObject(obj, SFXfoot_metal_run_2);
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXmv_ropecreak22);
            }
        }
        else
        {
            if (((GameObject*)player)->anim.seqId != 0)
            {
                Sfx_PlayFromObject(obj, SFXfoot_metal_run_2);
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXfox_treadwater322);
            }
        }
        Sfx_PlayFromObject(obj, SFXfoxcom_stay);
    }
    *(s8*)&state->baddie.unk34D = 3;
    state->baddie.moveSpeed = lbl_803E2DD4;
    state->baddie.animSpeedA = lbl_803E2DC8;
    return 0;
}

int fn_8015DC04(int obj, GroundBaddieState* p)
{

    extern int* gBaddieControlInterface;
    extern int* gPlayerInterface;
    extern f64 lbl_803E2DC0;
    int count;
    int i;
    GroundBaddieState* sub;
    u8* hit;
    int maxr;
    int four;
    int* objs;
    int r;
    int rnd;

    sub = ((GameObject*)obj)->extra;
    if (*(char*)&p->baddie.moveDone != '\0' || *(char*)&p->baddie.moveJustStartedB != '\0')
    {
        hit = *(u8**)&sub->control;
        r = (*(int (**)(int, u8*, f32, int))(*(int*)gBaddieControlInterface + 0x44))(
            obj, (u8*)p, (f32)(u32)sub->aggroRange, 1);
        if (r != 0)
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
            (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, (u8*)p, 4);
        }
        else if (rnd > 32)
        {
            if (four > 1)
            {
                (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, (u8*)p, 2);
            }
            else
            {
                (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, (u8*)p, 4);
            }
        }
        else if (rnd > 16)
        {
            (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, (u8*)p, 2);
        }
        else
        {
            (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, (u8*)p, 3);
        }
    }
    return 0;
}

#pragma dont_inline on
void fn_8015DAE8(void)
{
    extern void* gIceBaddieStateHandlersB[];
    extern void* gIceBaddieStateHandlersA[];
    extern int iceBaddie_updateOpenHitState();
    extern int iceBaddie_updateOpenState();
    extern int iceBaddie_updateHideResetState();
    extern int iceBaddie_updateImpactHitState();
    extern int iceBaddie_updateSpinState();
    extern int iceBaddie_stateHandlerA05();
    extern int iceBaddie_stateHandlerA06();
    extern int iceBaddie_updateHeightBlendState();
    extern int iceBaddie_updateControlMove5State();
    extern int iceBaddie_updateCommDownState();
    extern int iceBaddie_updateDropState();
    extern int iceBaddie_stateHandlerA0B();
    extern int iceBaddie_updateContactHitState();
    extern int iceBaddie_updateLandingState();
    extern int iceBaddie_checkTargetState();
    extern int iceBaddie_stateHandlerB01();
    extern int iceBaddie_stateHandlerB02();
    extern int iceBaddie_stateHandlerB03();
    extern int iceBaddie_stateHandlerB04();
    extern int iceBaddie_stateHandlerB05();
    extern int iceBaddie_stateHandlerB06();
    extern int iceBaddie_stateHandlerB07();

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
#pragma dont_inline reset

int fn_8015E5DC(short* obj, GroundBaddieState* p)
{

    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2DDC;
    extern f32 lbl_803E2DE0;
    int count;
    int i;
    GroundBaddieState* sub;
    int* objs;

    sub = ((GameObject*)obj)->extra;
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairPriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        objs = ObjList_GetObjects(&i, &count);
        for (; i < count; i++)
        {
            void* o = (void*)objs[i];
            if (o != obj && ((GameObject*)o)->anim.seqId == 774)
            {
                (*(void (**)(void*, int, int))(**(int**)&((GameObject*)o)->anim.dll + 0x24))(
                    o, 129, 0);
            }
        }
        if (randomGetRange(0, 1) != 0)
        {
            if (*(char*)&p->baddie.moveJustStartedA != '\0')
            {
                ObjAnim_SetCurrentMove((int)obj, 6, lbl_803E2DC8, 0);
                *(s8*)&p->baddie.moveDone = 0;
            }
        }
        else
        {
            if (*(char*)&p->baddie.moveJustStartedA != '\0')
            {
                ObjAnim_SetCurrentMove((int)obj, 7, lbl_803E2DC8, 0);
                *(s8*)&p->baddie.moveDone = 0;
            }
        }
        *(s8*)&p->baddie.unk34D = 1;
        p->baddie.moveSpeed = lbl_803E2DDC + (f32)(u32)
        sub->aggression / lbl_803E2DE0;
    }
    p->baddie.animSpeedA = lbl_803E2DC8;
    return 0;
}

int fn_8015DF20(int obj, GroundBaddieState* p)
{
    extern int* gPlayerInterface;
    extern void Obj_FreeObject(int* obj);
    extern f32 lbl_803E2DC8;
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    f32* v;
    f32 z;

    if (*(char*)&p->baddie.moveJustStartedB != '\0')
    {
        v = *(f32**)&sub->control;
        z = lbl_803E2DC8;
        v[0] = z;
        v[1] = z;
        (*(void (**)(int, u8*, int))(*(int*)gPlayerInterface + 0x14))(obj, (u8*)p, 6);
        *(int*)&p->baddie.targetObj = 0;
        *(s8*)&p->baddie.physicsActive = 0;
        *(s8*)&p->baddie.hasTarget = 0;
        ObjHits_DisableObject(obj);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    else if (*(char*)&p->baddie.moveDone != '\0')
    {
        ObjMsg_SendToObjects(0, 3, obj, 0xe0000, obj);
        if (((GameObject*)obj)->anim.placementData == NULL)
        {
            Obj_FreeObject((int*)obj);
            return 0;
        }
        return 4;
    }
    return 0;
}

int fn_8015E0C8(int obj, GroundBaddieState* p)
{
    extern void* Obj_GetPlayerObject(void);
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern int* gBaddieControlInterface;
    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2DCC;
    extern f32 lbl_803E2DD0;
    GroundBaddieState* sub;
    f32 spd;

    sub = ((GameObject*)obj)->extra;
    *(s8*)&p->baddie.unk34D = 3;
    p->baddie.moveSpeed = lbl_803E2DCC;
    spd = lbl_803E2DC8;
    p->baddie.animSpeedA = spd;
    p->baddie.animSpeedB = spd;
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 1, spd, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    if ((p->baddie.moveEventFlags & 1) == 0)
    {
        if (((GameObject*)Obj_GetPlayerObject())->anim.seqId != 0)
        {
            Sfx_PlayFromObject(obj, SFXfoot_metal_run_2);
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXfox_treadwater322);
        }
        Sfx_PlayFromObject(obj, SFXdoor_unlocked);
        Sfx_PlayFromObject(obj, SFXfoxcom_find);
        p->baddie.moveEventFlags |= 1;
    }
    if ((p->baddie.moveEventFlags & 2) == 0 && ((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2DD0)
    {
        Sfx_PlayFromObject(obj, SFXdoor_creak);
        p->baddie.moveEventFlags |= 2;
        (*(void (**)(int, int, int, int))(*(int*)gBaddieControlInterface + 0x4c))(
            obj, sub->unk3F0, -1, 0);
    }
    return 0;
}

int fn_8015E798(int obj, GroundBaddieState* p)
{

    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2DD8;
    extern f32 lbl_803E2DE4;
    GroundBaddieState* sub;
    u8* hit;

    sub = ((GameObject*)obj)->extra;
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 14, lbl_803E2DC8, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E2DE4)
    {
        hit = *(u8**)&sub->control;
        hit[8] |= 2;
    }
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjHits_DisableObject(obj);
        p->baddie.moveSpeed = lbl_803E2DD8;
        p->baddie.animSpeedA = lbl_803E2DC8;
    }
    if (*(char*)&p->baddie.moveDone != '\0')
    {
        GameBit_Set(sub->gameBitB, 0);
        ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2DC8, 0);
        *(int*)&p->baddie.targetObj = 0;
        *(s8*)&p->baddie.physicsActive = 0;
        *(s8*)&p->baddie.hasTarget = 0;
        sub->targetState = 0;
        if ((hit[9] & 2) == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
    }
    return 0;
}

int fn_8015E8BC(int obj, GroundBaddieState* p)
{

    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2DE8;
    extern f32 lbl_803E2DEC;
    extern f32 lbl_803E2DF0;
    GroundBaddieState* sub;
    u8* hit;
    int flags;

    sub = ((GameObject*)obj)->extra;
    hit = *(u8**)&sub->control;
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 11, lbl_803E2DC8, 0);
        *(s8*)&p->baddie.moveDone = 0;
    }
    if (*(char*)&p->baddie.moveJustStartedA != '\0')
    {
        *(s8*)&p->baddie.physicsActive = 1;
        GameBit_Set(sub->gameBitB, 1);
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        ((GameObject*)obj)->anim.alpha = 0xff;
        *(s8*)&p->baddie.unk34D = 1;
        p->baddie.moveSpeed =
            lbl_803E2DE8 + (f32)(u32)
        sub->aggression / lbl_803E2DEC;
        ObjHits_EnableObject(obj);
    }
    else
    {
        ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairPriority = 10;
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairHitVolume = 1;
        ObjHits_RegisterActiveHitVolumeObject(obj);
    }
    if (*(char*)&p->baddie.moveDone != '\0')
    {
        sub->targetState = 1;
    }
    flags = p->baddie.eventFlags;
    if ((flags & 0x200) != 0)
    {
        p->baddie.eventFlags = flags & ~0x200;
        hit[8] |= 4;
    }
    if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2DF0)
    {
        hit[8] |= 2;
    }
    return 0;
}

void fn_8015EA48(int obj, GroundBaddieState* state)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern int Obj_AllocObjectSetup(int size, int id);
    extern void* Obj_SetupObject(int a, int b, int c, int d, int e);
    extern f64 lbl_803E2DC0;
    extern f32 lbl_803E2DF4;
    extern f32 lbl_803E2DF8;
    extern f32 lbl_803E2DFC;
    f32 dur;
    f32 t;
    int setup;
    u8* o;

    if (Obj_IsLoadingLocked() == 0)
    {
        setup = Obj_AllocObjectSetup(36, 778);
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = lbl_803E2DF4 + ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        ((ObjPlacement*)setup)->color[0] = 1;
        ((ObjPlacement*)setup)->color[1] = 1;
        ((ObjPlacement*)setup)->color[2] = 0xff;
        ((ObjPlacement*)setup)->color[3] = 0xff;
        o = Obj_SetupObject(setup, 5, -1, -1, 0);
        if (o != NULL)
        {
            t = state->baddie.targetDistance / (f32)(u32)
            state->aggroRange;
            dur = lbl_803E2DF8 * t;
            ((GameObject*)o)->anim.velocityX =
                (((GameObject*)state->baddie.targetObj)->anim.localPosX - ((GameObject*)obj)->anim.localPosX) / dur;
            ((GameObject*)o)->anim.velocityY =
            ((lbl_803E2DFC * t + ((GameObject*)state->baddie.targetObj)->anim.localPosY) - ((GameObject*)obj)->anim.
                localPosY) / dur;
            ((GameObject*)o)->anim.velocityZ =
                (((GameObject*)state->baddie.targetObj)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ) / dur;
            *(int*)&((GameObject*)o)->ownerObj = obj;
        }
    }
}

void fn_8015EB6C(int obj, int state, int target)
{
    extern int* gBaddieControlInterface;
    extern void* Obj_GetPlayerObject(void);
    extern f32 sqrtf(f32);
    extern f32 timeDelta;
    extern f32 lbl_803E2DEC;
    extern f32 lbl_803E2E00;
    int sub = *(int*)&((GroundBaddieState*)state)->control;
    char* r;

    r = (char*)(**(int (**)(int, int, f32, int))((char*)(*gBaddieControlInterface) + 0x48))(
        obj, target, (f32)(u32)((GroundBaddieState*)state)->aggroRange, 0x8000);

    if (r != NULL && (((GroundBaddieState*)state)->configFlags & 0x4) == 0)
    {
        int v = -1;
        (**(void (**)(int, int, int, int, int, int, int, int, int))((char*)(*gBaddieControlInterface) + 0x28))(
            obj, target, state + 0x35c, (s32)((GroundBaddieState*)state)->gameBitB, 0, 0, 0, 8, v);
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
            d.x = ((GameObject*)player)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
            d.y = ((GameObject*)player)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
            d.z = ((GameObject*)player)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
            dist = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
        }
        else
        {
            dist = lbl_803E2DEC;
        }
        if (*(f32*)(sub + 0) > *(f32*)(sub + 4))
        {
            if (dist < lbl_803E2E00)
            {
                Sfx_PlayFromObject(obj, SFXfoxcom_gogetit);
                *(f32*)(sub + 4) += (f32)(s32)
                randomGetRange(50, 250);
            }
        }
        *(f32*)(sub + 0) += timeDelta;
    }
}

void fn_8015ED1C(int obj, int state, int target)
{
    extern int* gBaddieControlInterface;
    extern void* Obj_GetPlayerObject(void);
    extern f32 sqrtf(f32);
    extern u8 lbl_8031FEA8[];
    extern u8 lbl_8031FF20[];
    extern u8 lbl_803AC580[];
    void* player;
    char* t;
    int r;
    struct
    {
        f32 x, y, z;
    } d;
    f32* dp = &d.x;

    player = Obj_GetPlayerObject();
    t = *(char**)&((GroundBaddieState*)target)->baddie.targetObj;
    if (t != NULL)
    {
        d.x = ((GameObject*)t)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        d.y = ((GameObject*)t)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        d.z = ((GameObject*)t)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        ((GroundBaddieState*)target)->baddie.targetDistance = sqrtf(d.z * d.z + (d.x * d.x + d.y * d.y));
    }

    if ((((GroundBaddieState*)state)->configFlags & 0x20) == 0)
    {
        (**(void (**)(int, int, int, int, int, int, int))((char*)(*gBaddieControlInterface) + 0x3c))(
            obj, target, state + 0x400, 2, 3, (s32)((GroundBaddieState*)state)->unk3FA, (s32)((GroundBaddieState*)state)->unk3FC);
    }

    (**(void (**)(int, int, int, int, int, int, int, int))((char*)(*gBaddieControlInterface) + 0x54))(
        obj, target, state + 0x35c, (s32)((GroundBaddieState*)state)->gameBitB, 0, 0, 0, 8);

    r = (int)
    (**(int (**)(int, int, int, int, u8*, u8*, int, u8*))((char*)(*gBaddieControlInterface) + 0x50))(
        obj, target, state + 0x35c, (s32)((GroundBaddieState*)state)->gameBitB, lbl_8031FEA8, lbl_8031FF20, 1, lbl_803AC580);

    if (r != 0)
    {
        void* pc8 = ((GameObject*)player)->childObjs[0];
        (*(void (**)(void*))(**(int**)&((GameObject*)pc8)->anim.dll + 0x50))(pc8);
    }
}

void dll_CE_func0B(int obj, int v)
{
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern int* gPlayerInterface;
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    GroundBaddieState* sub2 = (GroundBaddieState*)(int)sub;

    switch ((u8)v)
    {
    case 0x80:
        *(u8*)(*(int*)&sub->control + 9) |= 2;
        Sfx_PlayFromObject(obj, SFXfoxcom_flame);
        (*(void (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, (int)sub2, 1);
        sub2->baddie.substate = 4;
        *(s8*)&sub2->baddie.moveJustStartedB = 1;
        break;
    case 0x81:
        sub->configFlags &= ~4;
        break;
    }
}

void dll_CE_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(int* obj);
    extern void fn_8003B5E0(int a, int b, int c, u8 d);
    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2E10;
    GroundBaddieState* sub = ((GameObject*)p1)->extra;
    f32 t;

    if (visible == 0 || ((GameObject*)p1)->unkF4 != 0 || sub->targetState == 0)
    {
        return;
    }
    t = sub->glowAlpha;
    if (t != lbl_803E2DC8)
    {
        fn_8003B5E0(200, 0, 0, t);
    }
    ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5,
                                                                   lbl_803E2E10);
}

void dll_CE_init(int obj, u8* p, int flags)
{
    extern int* gBaddieControlInterface;
    extern int* gPlayerInterface;
    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2E14;
    GroundBaddieState* sub;
    u8 mode;
    f32* v;

    sub = ((GameObject*)obj)->extra;
    mode = 6;
    if (flags != 0)
    {
        mode |= 1;
    }
    if ((*(u8*)(p + 0x2b) & 0x20) == 0)
    {
        mode |= 8;
    }
    (*(void (**)(int, u8*, int, int, int, int, u8, f32))(*(int*)gBaddieControlInterface + 0x58))(
        obj, p, (int)sub, 7, 6, 0x102, mode, lbl_803E2E14);
    ((GameObject*)obj)->animEventCallback = NULL;
    v = *(f32**)&sub->control;
    *v = (f32)(int)
    randomGetRange(10, 300);
    ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2DC8, 0);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    (*(void (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, (int)sub, 0);
    sub->baddie.substate = 0;
    *(s8*)&sub->baddie.physicsActive = 0;
    ObjHits_DisableObject(obj);
}

void dll_CE_update(int obj, int p2, int p3)
{
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern void fn_8015ED1C(int p1, int p2, int p3);
    extern void fn_8015EB6C(int obj, int p2, int p3);
    extern void fn_8015EA48(int obj, u8* p);
    extern int* gBaddieControlInterface;
    extern int* gPlayerInterface;
    extern void* gChukChukMoveHandlers[];
    extern void* gChukChukCheckHandlers[];
    extern f32 timeDelta;
    extern f32 lbl_803E2DC8;
    extern f32 lbl_803E2E14;
    extern f32 lbl_803E2E18;
    GroundBaddieState* sub;
    int setup;
    u8* hit;
    int n;
    f32 sunTime;

    sub = ((GameObject*)obj)->extra;
    setup = *(int*)&((GameObject*)obj)->anim.placementData;
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if ((sub->baddie.substate != 3 || (sub->configFlags & 1) != 0) &&
            (*gMapEventInterface)->shouldNotSaveTime(((ObjPlacement*)setup)->mapId) != 0)
        {
            (*(void (**)(int, int, int, int, int, int, int, f32))(*(int*)gBaddieControlInterface +
                0x58))(
                obj, setup, (int)sub, 7, 6, 0x102, 0x26, lbl_803E2E14);
            sub->targetState = 0;
            Sfx_PlayFromObject(obj, SFXfoxcom_find);
            ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2DC8, 0x10);
            *(s8*)&sub->baddie.moveDone = 0;
            ((GameObject*)obj)->anim.alpha = 0xff;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
    }
    else if (((GameObject*)obj)->unkF8 == 0)
    {
        ((GameObject*)obj)->anim.localPosX = ((ObjPlacement*)setup)->posX;
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((ObjPlacement*)setup)->posZ;
        (*gObjectTriggerInterface)->runSequence(*(s8*)(setup + 0x2e), (void*)obj, -1);
        ((GameObject*)obj)->unkF8 = 1;
    }
    else
    {
        if ((*(int (**)(int, int, int))(*(int*)gBaddieControlInterface + 0x30))(obj, (int)sub, 0) == 0)
        {
            sub->targetState = 0;
        }
        else if ((sub->configFlags & 0x10) != 0 &&
            (*gSkyInterface)->getSunPosition(&sunTime) == 0)
        {
            sub->targetState = 0;
        }
        else
        {
            fn_8015ED1C(obj, (int)sub, (int)sub);
            if (sub->targetState == 0)
            {
                fn_8015EB6C(obj, (int)sub, (int)sub);
            }
            else
            {
                hit = *(u8**)&sub->control;
                if ((hit[8] & 1) != 0)
                {
                    fn_8015EA48(obj, (u8*)sub);
                }
                if ((hit[8] & 2) != 0)
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x345, NULL, 1, -1, NULL);
                }
                if ((hit[8] & 4) != 0)
                {
                    n = 0;
                    do
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x343, NULL, 1, -1, NULL);
                        n++;
                    }
                    while (n < 10);
                }
                hit[8] = 0;
                (*(void (**)(int, int, f32, int))(*(int*)gBaddieControlInterface + 0x2c))(
                    obj, (int)sub, lbl_803E2DC8, -1);
                (*(void (**)(int, int, f32, int))(*(int*)gPlayerInterface + 0x30))(obj, (int)sub, timeDelta,
                    4);
                sub->savedObjC0 = *(int*)&((GameObject*)obj)->pendingParentObj;
                *(int*)&((GameObject*)obj)->pendingParentObj = 0;
                (*(void (**)(int, int, f32, f32, void*, void*))(*(int*)gPlayerInterface + 8))(
                    obj, (int)sub, timeDelta, timeDelta, gChukChukMoveHandlers, gChukChukCheckHandlers);
                *(int*)&((GameObject*)obj)->pendingParentObj = sub->savedObjC0;
            }
            ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY - lbl_803E2E18;
        }
    }
}


extern void Obj_FreeObject(int* obj);

void dll_CE_hitDetect_nop(void)
{
}

void dll_CE_release_nop(void)
{
}

void chukchuk_free(void);

void chukchuk_hitDetect(void);

void chukchuk_release(void);

void chukchuk_initialise(void);

STATIC_ASSERT(sizeof(ChukChukState) == 0x18);
STATIC_ASSERT(offsetof(ChukChukState, flags) == 0x12);

void chukchuk_init(u8* obj, u8* params);
void iceball_hitDetect(void);

void iceball_release(void);

void iceball_initialise(void);

int dll_CE_getExtraSize_ret_1052(void) { return 0x41c; }
int dll_CE_getObjectTypeId(void) { return 0x49; }
int chukchuk_getExtraSize(void);
int chukchuk_getObjectTypeId(void);
int iceball_getExtraSize(void);
int iceball_getObjectTypeId(void);

s16 dll_CE_setScale(int* obj) { return ((BaddieState*)((GameObject*)obj)->extra)->controlMode; }

void chukchuk_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void iceball_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void iceball_free(void);

void chukchuk_update(short* obj);

void chukchuk_setScale(int obj, int v);

void iceball_init(void* obj);

int fn_8015E00C(int p1, u8* obj)
{
    if ((s8)((GroundBaddieState*)obj)->baddie.hitPoints < 1) return 3;
    if ((s8)((GroundBaddieState*)obj)->baddie.moveDone != 0) return 6;
    return 0;
}

extern int* gBaddieControlInterface;
extern int* gPlayerInterface;
extern f32 lbl_803E2DC8;

int fn_8015DE50(int* obj, GroundBaddieState* state)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        f32 fz;
        ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 1);
        {
            f32* p = *(f32**)&sub->control;
            fz = lbl_803E2DC8;
            p[0] = fz;
            p[1] = fz;
        }
    }
    return 0;
}

int fn_8015DEB4(int* obj, GroundBaddieState* state)
{
    GroundBaddieState* sub;
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        sub = ((GameObject*)obj)->extra;
        sub->unk405 = 0;
        if (sub->gameBitB != -1)
        {
            GameBit_Set(sub->gameBitB, 0);
        }
        if (sub->gameBitA != -1)
        {
            GameBit_Set(sub->gameBitA, 1);
        }
    }
    return 0;
}

int fn_8015E044(int* obj, GroundBaddieState* state)
{
    if (*(int**)&state->baddie.targetObj != NULL)
    {
        if ((s8)state->baddie.moveJustStartedB != 0)
        {
            f32 fz = lbl_803E2DC8;
            state->baddie.animSpeedB = fz;
            state->baddie.animSpeedA = fz;
            ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 0);
        }
        if ((s8)state->baddie.moveDone != 0)
        {
            return 6;
        }
    }
    return 0;
}

extern f32 lbl_803E2DD8;

int fn_8015E520(int* obj, GroundBaddieState* state)
{
    if ((s8)state->baddie.moveJustStartedA != 0)
    {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairPriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->objectPairHitVolume = 1;
    ObjHits_RegisterActiveHitVolumeObject(obj);
    state->baddie.moveSpeed = lbl_803E2DD8;
    if ((s8)state->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 5, lbl_803E2DC8, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.unk34D = 1;
    return 0;
}

extern void* gChukChukMoveHandlers[];
extern void* gChukChukCheckHandlers[];

void dll_CE_initialise(void)
{
    gChukChukMoveHandlers[0] = fn_8015E8BC;
    gChukChukMoveHandlers[1] = fn_8015E798;
    gChukChukMoveHandlers[2] = fn_8015E5DC;
    gChukChukMoveHandlers[3] = fn_8015E520;
    gChukChukMoveHandlers[4] = fn_8015E3A0;
    gChukChukMoveHandlers[5] = fn_8015E210;
    gChukChukMoveHandlers[6] = fn_8015E0C8;
    gChukChukCheckHandlers[0] = fn_8015E044;
    gChukChukCheckHandlers[1] = fn_8015E00C;
    gChukChukCheckHandlers[2] = fn_8015DF20;
    gChukChukCheckHandlers[3] = fn_8015DEB4;
    gChukChukCheckHandlers[4] = fn_8015DE50;
    gChukChukCheckHandlers[5] = fn_8015DC04;
}

void dll_CE_free(int* obj)
{
    GroundBaddieState* state = ((GameObject*)obj)->extra;
    ObjGroup_RemoveObject(obj, 3);
    {
        int* sub = ((GameObject*)obj)->childObjs[0];
        if (sub != NULL)
        {
            Obj_FreeObject(sub);
            ((GameObject*)obj)->childObjs[0] = NULL;
        }
    }
    ((void(*)(int*, int*, int))((void**)*gBaddieControlInterface)[16])(obj, (int*)state, 32);
}

ObjectDescriptor11WithPadding gChukChukObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)chukchuk_initialise,
        (ObjectDescriptorCallback)chukchuk_release,
        0,
        (ObjectDescriptorCallback)chukchuk_init,
        (ObjectDescriptorCallback)chukchuk_update,
        (ObjectDescriptorCallback)chukchuk_hitDetect,
        (ObjectDescriptorCallback)chukchuk_render,
        (ObjectDescriptorCallback)chukchuk_free,
        (ObjectDescriptorCallback)chukchuk_getObjectTypeId,
        chukchuk_getExtraSize,
        (ObjectDescriptorCallback)chukchuk_setScale,
    },
    0,
};

ObjectDescriptor gIceBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)iceball_initialise,
    (ObjectDescriptorCallback)iceball_release,
    0,
    (ObjectDescriptorCallback)iceball_init,
    (ObjectDescriptorCallback)iceball_update,
    (ObjectDescriptorCallback)iceball_hitDetect,
    (ObjectDescriptorCallback)iceball_render,
    (ObjectDescriptorCallback)iceball_free,
    (ObjectDescriptorCallback)iceball_getObjectTypeId,
    iceball_getExtraSize,
};
