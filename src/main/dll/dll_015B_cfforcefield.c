/* DLL 0x015B — cfforcefield (CloudRunner Fortress force field barrier). TU: 0x801A39B4–0x801A3E9C. */
#include "main/dll/DR/dll_015A_explodable.h"
#include "main/dll/drexplodable_types.h"
#include "main/obj_placement.h"

extern u32 randomGetRange(int min, int max);

#pragma scheduling on
#pragma peephole on
void cfforcefield_free(void)
{
}

void cfforcefield_render(void)
{
}

void cfforcefield_hitDetect(void)
{
}

STATIC_ASSERT(sizeof(DrExplodableChunk) == 0x70);

STATIC_ASSERT(offsetof(DrExplodableState, children) == 0x690);
STATIC_ASSERT(sizeof(DrExplodableState) == 0x6e8);

int cfforcefield_getExtraSize(void) { return 0x8; }
int cfforcefield_getObjectTypeId(void) { return 0x0; }

extern void Obj_FreeObject(int obj);

/* segment pragma-stack balance (re-split): */

#include "main/audio/sfx_ids.h"
#include "main/camera_interface.h"
#include "main/mapEvent.h"
#include "main/dll/IM/IMicicle.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"

typedef struct CfforcefieldPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x28 - 0x22];
} CfforcefieldPlacement;

extern undefined8 FUN_80017698();
extern undefined4 FUN_80041ff8();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern uint GameBit_Get(int eventId);
extern void Obj_BuildWorldTransformMatrix(void* obj, f32* mtx, int flags);
extern void PSMTXMultVecSR(f32 * mtx, f32 * src, f32 * dst);
extern f32 mathCosf(f32 angle);
extern f32 mathSinf(f32 angle);
extern int fn_80080150(void* timer);
extern void s16toFloat(void* p, int duration);
extern int timerCountDown(void* timer);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern EffectInterface** gPartfxInterface;
extern f32 timeDelta;
extern f32 lbl_803DBE90;
extern int lbl_803DBE94;
extern int lbl_803DBE98;
extern int lbl_80322ED8[];
extern f32 lbl_803E4390;
extern f32 lbl_803E4394;
extern f32 lbl_803E4398;
extern f32 lbl_803E439C;
extern f32 lbl_803E43A0;
extern f32 lbl_803E43A4;
extern f32 lbl_803E43A8;
extern f32 lbl_803E43AC;

#pragma scheduling off
#pragma peephole off
void cfforcefield_update(u8* obj)
{
    typedef struct ForceFieldEmitter
    {
        int effectId;
        int pad04;
        int angleStep;
        int pad0c;
        int pad10;
        f32 waveScale;
    } ForceFieldEmitter;
    typedef struct ForceFieldFlags
    {
        u8 disabled : 1;
        u8 rest : 7;
    } ForceFieldFlags;
    f32* wavePtr;
    int* stepPtr;
    ForceFieldEmitter* emitter;
    int angle;
    u8* data;
    u8* state;
    int style;
    f32 val;
    int isZero;
    f32 kA4;
    f32 kA8;
    f32 kAC;
    f32 kA0;
    f32 strength;
    f32 kZero;
    f32 z;
    f32 mtx[3][4];
    f32 world[6];
    f32 local[3];

    data = *(u8**)&((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    z = lbl_803E4390;
    ((GameObject*)obj)->anim.velocityZ = z;
    ((GameObject*)obj)->anim.velocityY = z;
    ((GameObject*)obj)->anim.velocityX = z;

    if (GameBit_Get(((CfforcefieldPlacement*)data)->unk1E) != 0)
    {
        if (!((ForceFieldFlags*)state)->disabled)
        {
            style = (s8)data[0x19] % 3;
            val = *(f32*)(state + 4);
            isZero = (val != lbl_803E4390);
            isZero = !isZero;
            if (isZero)
            {
                strength = lbl_803E4394;
            }
            else
            {
                strength = lbl_803E4398 * val;
            }

            {
                Obj_BuildWorldTransformMatrix(obj, (f32*)mtx, 0);
                ((GameObject*)obj)->anim.rotZ = (s16)(
                    lbl_803E439C * timeDelta + (f32)(s32)((GameObject*)obj)->anim.rotZ);

                angle = -0x7fff;
                emitter = (ForceFieldEmitter*)((u8*)lbl_80322ED8 + style * 0x18);
                wavePtr = &emitter->waveScale;
                stepPtr = &emitter->angleStep;
                kA4 = lbl_803E43A4;
                kA8 = lbl_803E43A8;
                kAC = lbl_803E43AC;
                kA0 = lbl_803E43A0;
                kZero = lbl_803E4390;
                for (; angle < 0x7fff; angle += *stepPtr)
                {
                    local[0] = (f32)(int)
                    randomGetRange(-lbl_803DBE94, lbl_803DBE94) +
                        kA0 * (strength * lbl_803DBE90) *
                        mathCosf(kA4 * (f32)(angle + (s32)(kA8 * *wavePtr)) / kAC);
                    local[1] = (f32)(int)
                    randomGetRange(-lbl_803DBE94, lbl_803DBE94) +
                        kA0 * (strength * lbl_803DBE90) *
                        mathSinf(kA4 * (f32)(angle + (s32)(kA8 * *wavePtr)) / kAC);
                    local[2] = kZero;
                    PSMTXMultVecSR((f32*)mtx, local, local);
                    world[3] = local[0] + ((GameObject*)obj)->anim.localPosX;
                    world[4] = local[1] + ((GameObject*)obj)->anim.localPosY;
                    world[5] = local[2] + ((GameObject*)obj)->anim.localPosZ;
                    (*gPartfxInterface)->spawnObject(obj, emitter->effectId, world, 0x200001, -1, obj + 0x24);
                    (*gPartfxInterface)->spawnObject(obj, emitter->effectId, world, 0x200001, -1, obj + 0x24);
                    (*gPartfxInterface)->spawnObject(obj, emitter->effectId, world, 0x200001, -1, obj + 0x24);
                }
            }

            if (fn_80080150(state + 4) != 0)
            {
                ((GameObject*)obj)->anim.rotY = (s16)(
                    (f32)(s32)lbl_803DBE98 * timeDelta + (f32)(s32)((GameObject*)obj)->anim.rotY);
                if (timerCountDown(state + 4) != 0)
                {
                    ((ForceFieldFlags*)state)->disabled = 1;
                    ((GameObject*)obj)->anim.rotY = 0;
                }
            }
            else if (GameBit_Get(((CfforcefieldPlacement*)data)->unk20) != 0)
            {
                s16toFloat(state + 4, 0x3c);
                Sfx_PlayFromObject((int)obj, 0x366);
                if (*(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14) != 0x47f5e)
                {
                    Sfx_PlayFromObject((int)obj, 0x409);
                }
            }
        }
        else
        {
            ((ForceFieldFlags*)state)->disabled = (u8)GameBit_Get(((CfforcefieldPlacement*)data)->unk20);
        }
    }
}

void FUN_801a4520(int param_1)
{
    int iVar1;

    if (((GameObject*)param_1)->unkF4 == 0)
    {
        iVar1 = *(int*)&((GameObject*)param_1)->anim.placementData;
        if ((*(short*)(iVar1 + 0x1c) != 0) && (**(byte**)&((GameObject*)param_1)->extra >> 5 != 0))
        {
            (*gObjectTriggerInterface)->preempt(param_1, *(s16*)(iVar1 + 0x1c));
        }
        iVar1 = (int)*(char*)(iVar1 + 0x1e);
        if (iVar1 != -1)
        {
            (*gObjectTriggerInterface)->runSequence(iVar1, (void*)param_1, -1);
        }
        ((GameObject*)param_1)->unkF4 = 1;
    }
    return;
}

void FUN_801a45cc(short* param_1, int param_2)
{
}

void cflevelcontrol_free(int param_1);

undefined4
FUN_801a4810(undefined8 param_1, undefined8 param_2, undefined8 param_3, undefined8 param_4,
             undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
             undefined4 param_9, undefined4 param_10, int param_11)
{
    undefined4 uVar1;
    int iVar2;
    undefined8 uVar3;

    for (iVar2 = 0; iVar2 < (int)(uint) * (byte*)(param_11 + 0x8b); iVar2 = iVar2 + 1)
    {
        if (*(char*)(param_11 + iVar2 + 0x81) == '\x01')
        {
            FUN_80017698(0xdcb, 1);
            uVar3 = FUN_80017698(0x4a3, 0);
            FUN_80041ff8(uVar3, param_2, param_3, param_4, param_5, param_6, param_7, param_8, 0x2b);
            FUN_80042b9c(0, 0, 1);
            uVar1 = FUN_80044404(0x2b);
            FUN_80042bec(uVar1, 0);
        }
    }
    return 0;
}

void cfforcefield_release(void)
{
}

void cfforcefield_initialise(void)
{
}

void slidingdoor_free(void);

extern void storeZeroToFloatParam(void* p);

/* slidingdoor_SeqFn: slidingdoor "think" routine. Tracks whether the player or
 * tricky is within lbl_803E43B8 xz-distance and steps a 3-bit state field
 * (state[0] bits 5..7) through the door's open/close machine. Returns 1
 * while in the static states (0/1) and 0 while in transition (2/3). */

/* slidingdoor_update: triggered-once handler. If obj->_f4 is already set,
 * skip. Otherwise: if data->_1c (event id) is non-zero AND obj->_b8->_0
 * bits 5..7 are set, preempt the event. Then if (s8)data->_1e is not -1,
 * run that sequence with obj, -1.
 * Finally latch obj->_f4 = 1. */

/* exploded_init: store the map object tag, scale the model using the map
 * byte, then enable physics if any initial velocity/acceleration is present. */

/* attractor_func0B: dispatch on (s8)obj->_4c->_19 - state 0/3+ store NULL,
 * state 1 stores obj, state 2 computes atan2 of (player - obj) deltas
 * (truncated to int), latches angle+0x8000 into obj+0, then stores obj. */

/* slidingdoor_init: clear obj+0xf4, copy data[0x1f]<<8 into obj+0; install
 * slidingdoor_SeqFn as obj->thinkRoutine; convert data[0x21] to f32, scale by
 * lbl_803E43C0 and obj->_50->[4], stash at obj+0x8; then clear bits 5..7 of
 * obj->_b8->_0. */

void cfforcefield_init(s16* obj, void* data)
{
    typedef struct ForceFieldInitFlags
    {
        u8 disabled : 1;
        u8 rest : 7;
    } ForceFieldInitFlags;
    register u8* flagPtr = (u8*)((int**)obj)[0xb8 / 4];
    {
        s8 v = *((s8*)data + 0x18);
        s16 t = v << 8;
        *obj = t;
    }
    ((ForceFieldInitFlags*)flagPtr)->disabled = (u8)GameBit_Get(*(s16*)((char*)data + 0x20));
    storeZeroToFloatParam(flagPtr + 4);
}

extern void Obj_TransformLocalPointByWorldMatrix(void* obj, void* state, f32* out, int flags);

/* Exploded debris setup: seed object angles, linear velocity, angular velocity,
 * ground clearance, and the randomized lifetime countdown. */

/* Exploded debris physics step: integrate local velocity and spin, bounce from
 * the stored floor height, and return nonzero once the shard comes to rest. */
