#include "main/dll/CF/dll_012B_fxemit.h"
#include "main/dll_000A_expgfx.h"
#include "main/resource.h"


extern u32 GameBit_Get(int bit);
extern u32 randomGetRange(int min, int max);


extern ModgfxInterface** gModgfxInterface;
extern EffectInterface** gPartfxInterface;
extern u8 framesThisStep;
extern f32 lbl_803E3E48;
extern char sCFTreasSharpyDebugFormat[];
extern void fn_80137948(char* fmt, ...);


/*
 * --INFO--
 *
 * Function: cfccrate_init
 * EN v1.0 Address: 0x8018E0A4
 * EN v1.0 Size: 1560b
 */

typedef struct CFTreasSharpyFxSpawnArgs
{
    s16 yaw;
    s16 pitch;
    s16 roll;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} CFTreasSharpyFxSpawnArgs;

#define CFTREAS_PARTFX_SPAWN(obj, id, data, flags, model, arg) \
    (*gPartfxInterface)->spawnObject((void *)(obj), id, data, flags, model, (void *)(arg))

void fxemit_emitEffect(FxEmitObject* obj)
{
    FxEmitState* state;
    FxEmitPlacement* def;
    int spawnFlags;
    s16 i;

    state = obj->state;
    def = (FxEmitPlacement*)obj->objAnim.placementData;
    spawnFlags = 0;
    if (state->effectId == 0x11)
    {
        fn_80137948(sCFTreasSharpyDebugFormat, (int)obj, obj->objAnim.localPosX, obj->objAnim.localPosZ);
    }

    switch (def->spawnMode)
    {
    case FXEMIT_SPAWN_MODE_OBJECT:
        {
            s16 mode = state->effectMode;
            if (mode == 0)
            {
                spawnFlags = 2;
            }
            if (mode == 1)
            {
                spawnFlags = 2;
            }
            if (mode == 2)
            {
                spawnFlags = 2;
            }
            break;
        }
    case FXEMIT_SPAWN_MODE_OBJECT_ALT:
        {
            s16 mode = state->effectMode;
            if (mode == 0)
            {
                spawnFlags = 4;
            }
            if (mode == 1)
            {
                spawnFlags = 4;
            }
            if (mode == 2)
            {
                spawnFlags = 4;
            }
            break;
        }
    case FXEMIT_SPAWN_MODE_WORLD:
        {
            s16 mode = state->effectMode;
            if (mode == 0)
            {
                spawnFlags = 0x200001;
            }
            if (mode == 1)
            {
                spawnFlags = 1;
            }
            if (mode == 2)
            {
                spawnFlags = 1;
            }
            break;
        }
    case FXEMIT_SPAWN_MODE_NONE:
        spawnFlags = 0;
        break;
    default:
        spawnFlags = 2;
        break;
    }

    if ((spawnFlags & 1) != 0)
    {
        CFTreasSharpyFxSpawnArgs args;

        args.x = obj->objAnim.localPosX;
        args.y = obj->objAnim.localPosY;
        args.z = obj->objAnim.localPosZ;
        args.yaw = obj->objAnim.rotX;
        args.roll = obj->objAnim.rotZ;
        args.pitch = obj->objAnim.rotY;
        args.scale = lbl_803E3E48;
        if (state->emitCount > 0)
        {
            for (i = 0; i < state->emitCount; i++)
            {
                CFTREAS_PARTFX_SPAWN(obj, state->effectId, &args, spawnFlags, -1, 0);
            }
        }
        else
        {
            CFTREAS_PARTFX_SPAWN(obj, state->altEffectId, &args, spawnFlags, -1, 0);
        }
    }
    else
    {
        void* resource;
        s16 mode = state->effectMode;

        if (mode == 0)
        {
            if (state->emitCount > 0)
            {
                for (i = 0; i < state->emitCount; i++)
                {
                    CFTREAS_PARTFX_SPAWN(obj, state->effectId, NULL, spawnFlags, -1, 0);
                }
            }
            else
            {
                CFTREAS_PARTFX_SPAWN(obj, state->effectId, NULL, spawnFlags, -1, 0);
            }
        }
        else if (mode == 1)
        {
            resource = Resource_Acquire((u16)(state->effectId + 0x58), 1);
            if (state->emitCount > 0)
            {
                for (i = 0; i < state->emitCount; i++)
                {
                    ((void (*)(int, int, int, int, int, int))((void**)*(int*)resource)[1])(
                        (int)obj, 0, 0, spawnFlags, -1, 0);
                }
            }
            else
            {
                ((void (*)(int, int, int, int, int, int))((void**)*(int*)resource)[1])(
                    (int)obj, 0, 0, spawnFlags, -1, 0);
            }
            Resource_Release(resource);
        }
        else if (mode == 2)
        {
            resource = Resource_Acquire((u16)(state->effectId + 0xab), 1);
            if (state->emitCount > 0)
            {
                for (i = 0; i < state->emitCount; i++)
                {
                    ((void (*)(int, int, int, int, int, int, int))((void**)*(int*)resource)[1])
                        ((int)obj, 0, 0, spawnFlags, -1, state->effectId & 0xff, 0);
                }
            }
            else
            {
                ((void (*)(int, int, int, int, int, int, int))((void**)*(int*)resource)[1])
                    ((int)obj, 0, 0, spawnFlags, -1, state->effectId & 0xff, 0);
            }
            Resource_Release(resource);
        }
    }
}

#undef CFTREAS_PARTFX_SPAWN

int fxemit_SeqFn(FxEmitObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    FxEmitState* state;
    FxEmitPlacement* def;
    u8 event;
    int i;
    s8 delta;

    state = obj->state;
    def = (FxEmitPlacement*)obj->objAnim.placementData;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        event = animUpdate->eventIds[i];
        if (event == 1)
        {
            fxemit_emitEffect(obj);
        }
        if (animUpdate->eventIds[i] == 2)
        {
            state->seqToggle = (u8)(1 - state->seqToggle);
        }
        animUpdate->eventIds[i] = 0;
    }

    if (state->seqToggle != 0)
    {
        delta = def->yawStep;
        if (delta == FXEMIT_ROTATION_STEP_AUTO)
        {
            obj->objAnim.rotX = obj->objAnim.rotX + framesThisStep * 10;
        }
        else
        {
            obj->objAnim.rotX = obj->objAnim.rotX + delta * framesThisStep * 100;
        }

        delta = def->pitchStep;
        if (delta == FXEMIT_ROTATION_STEP_AUTO)
        {
            obj->objAnim.rotY = obj->objAnim.rotY + framesThisStep * 10;
        }
        else
        {
            obj->objAnim.rotY = obj->objAnim.rotY + delta * framesThisStep * 100;
        }

        delta = def->rollStep;
        if (delta == FXEMIT_ROTATION_STEP_AUTO)
        {
            obj->objAnim.rotZ = obj->objAnim.rotZ + framesThisStep * 10;
        }
        else
        {
            obj->objAnim.rotZ = obj->objAnim.rotZ + delta * framesThisStep * 100;
        }
        fxemit_emitEffect(obj);
    }

    return 0;
}

/*
 * --INFO--
 *
 * Function: cfccrate_release
 * EN v1.0 Address: 0x8018E6BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018E69C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: cfccrate_initialise
 * EN v1.0 Address: 0x8018E6C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018E6A0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: fxemit_getExtraSize
 * EN v1.0 Address: 0x8018EC20
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018ED50
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fxemit_getExtraSize(void)
{
    return 0x20;
}

/*
 * --INFO--
 *
 * Function: fxemit_getObjectTypeId
 * EN v1.0 Address: 0x8018EC28
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018ED58
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int fxemit_getObjectTypeId(void)
{
    return 0;
}

void fxemit_free(FxEmitObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    (*gModgfxInterface)->freeSourceEffects(obj);
}

/*
 * --INFO--
 *
 * Function: fxemit_hitDetect
 * EN v1.0 Address: 0x8018EC90
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018EDC0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fxemit_hitDetect(void)
{
}

void fxemit_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

extern f32 timeDelta;
extern f32 sqrtf(f32);
extern int Sfx_PlayFromObject(int obj, int sfx);
extern f32 lbl_803E3E4C;

void fxemit_update(FxEmitObject* obj)
{
    extern ObjAnimComponent* Obj_GetPlayerObject(void);
    FxEmitState* state;
    FxEmitPlacement* def;
    ObjAnimComponent* player;
    s16 e;
    s8 delta;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 dist;

    state = obj->state;
    def = (FxEmitPlacement*)obj->objAnim.placementData;
    if (state->startDelay != 0)
    {
        state->startDelay -= (s16)timeDelta;
        if (state->startDelay < 0)
        {
            state->startDelay = 0;
        }
    }
    else
    {
        obj->objAnim.localPosX = obj->objAnim.velocityX * timeDelta + obj->objAnim.localPosX;
        obj->objAnim.localPosY = obj->objAnim.velocityY * timeDelta + obj->objAnim.localPosY;
        obj->objAnim.localPosZ = obj->objAnim.velocityZ * timeDelta + obj->objAnim.localPosZ;
        obj->objAnim.worldPosX = obj->objAnim.localPosX;
        obj->objAnim.worldPosY = obj->objAnim.localPosY;
        obj->objAnim.worldPosZ = obj->objAnim.localPosZ;
        player = Obj_GetPlayerObject();
        if (player == NULL || def == NULL)
        {
            return;
        }
        if (def->sfxPeriod != 0 && def->sfxPeriod != FXEMIT_SFX_SUPPRESS)
        {
            if (state->sfxTimer <= 0)
            {
                int sfx;
                state->suppressed = 0;
                state->sfxTimer = def->sfxPeriod * 100;
                sfx = def->sfxId;
                if (sfx != 0)
                {
                    Sfx_PlayFromObject((int)obj, (u16)sfx);
                }
            }
            else
            {
                state->suppressed = 1;
            }
            state->sfxTimer -= framesThisStep;
        }

        delta = def->yawStep;
        if (delta == FXEMIT_ROTATION_STEP_AUTO)
        {
            obj->objAnim.rotX = obj->objAnim.rotX + framesThisStep * 10;
        }
        else
        {
            obj->objAnim.rotX = obj->objAnim.rotX + delta * framesThisStep * 100;
        }

        delta = def->pitchStep;
        if (delta == FXEMIT_ROTATION_STEP_AUTO)
        {
            obj->objAnim.rotY = obj->objAnim.rotY + framesThisStep * 10;
        }
        else
        {
            obj->objAnim.rotY = obj->objAnim.rotY + delta * framesThisStep * 100;
        }

        delta = def->rollStep;
        if (delta == FXEMIT_ROTATION_STEP_AUTO)
        {
            obj->objAnim.rotZ = obj->objAnim.rotZ + framesThisStep * 10;
        }
        else
        {
            obj->objAnim.rotZ = obj->objAnim.rotZ + delta * framesThisStep * 100;
        }

        if (state->enableBit == -1 || GameBit_Get(state->enableBit) != 0)
        {
            switch (state->suppressed)
            {
            case 0:
                {
                    if (state->stopBit != -1 && GameBit_Get(state->stopBit) != 0)
                    {
                        state->suppressed = 1;
                    }
                    if (def->sfxPeriod == FXEMIT_SFX_SUPPRESS)
                    {
                        state->suppressed = 1;
                    }
                    e = state->emitCount;
                    if (e >= 0 || (e < 0 && obj->emitCooldown <= 0))
                    {
                        dx = obj->objAnim.worldPosX - player->worldPosX;
                        dy = obj->objAnim.worldPosY - player->worldPosY;
                        dz = obj->objAnim.worldPosZ - player->worldPosZ;
                        if (e == 0)
                        {
                            state->suppressed = 1;
                        }
                        dist = sqrtf(dx * dx + dy * dy + dz * dz);
                        if (dist <= state->triggerRadius || lbl_803E3E4C == state->triggerRadius)
                        {
                            fxemit_emitEffect(obj);
                        }
                        obj->emitCooldown = -(int)state->emitCount;
                    }
                    else if (e < 0 && obj->emitCooldown > 0)
                    {
                        obj->emitCooldown -= framesThisStep;
                    }
                    break;
                }
            }
        }
    }
}

/* === moved from main/dll/CF/CFchuckobj.c [8018EFE0-8018F148) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/CF/CFchuckobj.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/CF/dll_012B_fxemit.h"
#include "main/objseq.h"
#include "main/resource.h"



extern uint GameBit_Get(int eventId);
extern f32 sqrtf(f32 value);

extern f32 lbl_803E3E50;


/*
 * --INFO--
 *
 * Function: fxemit_init
 * EN v1.0 Address: 0x8018EFE0
 * EN v1.0 Size: 376b
 * EN v1.1 Address: 0x8018F020
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void fxemit_init(FxEmitObject* obj, FxEmitPlacement* setup)
{
    FxEmitState* state;

    obj->objAnim.rotX = 0;
    obj->seqCallback = fxemit_SeqFn;
    state = obj->state;

    state->triggerRadius = (f32)((s32)setup->triggerRadius << 2);
    state->effectMode = setup->effectMode;
    state->effectId = setup->effectId;
    state->emitCount = setup->emitCount;
    obj->objAnim.rootMotionScale = lbl_803E3E50;
    state->enableBit = setup->enableBit;
    state->stopBit = setup->stopBit;
    state->suppressed = 0;

    if (state->emitCount < 1)
    {
        obj->emitCooldown = state->emitCount;
    }
    else
    {
        obj->emitCooldown = 0;
    }

    if (state->stopBit != -1 && GameBit_Get(state->stopBit) != 0)
    {
        state->suppressed = 1;
    }

    obj->objAnim.rotX = (s16)(setup->initialYaw << 8);
    obj->objAnim.rotY = (s16)(setup->initialPitch << 8);
    obj->objAnim.rotZ = (s16)(setup->initialRoll << 8);
    state->sfxTimer = (s16)(setup->sfxPeriod * 100);
    state->initialX = obj->objAnim.localPosX;
    state->startDelay = (s16)randomGetRange(0, 10);
    state->altEffectId = 0;
}

#pragma dont_inline on
#pragma dont_inline reset

/*
 * --INFO--
 *
 * Function: FUN_8018f158
 * EN v1.0 Address: 0x8018F158
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x8018F1B0
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8018f4fc
 * EN v1.0 Address: 0x8018F4FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018F55C
 * EN v1.1 Size: 360b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8018f500
 * EN v1.0 Address: 0x8018F500
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x8018F6C4
 * EN v1.1 Size: 400b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8018f650
 * EN v1.0 Address: 0x8018F650
 * EN v1.0 Size: 1620b
 * EN v1.1 Address: 0x8018F854
 * EN v1.1 Size: 2220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_8018fd14
 * EN v1.0 Address: 0x8018FD14
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8019018C
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8018fd48
 * EN v1.0 Address: 0x8018FD48
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x801901CC
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_8018fec4
 * EN v1.0 Address: 0x8018FEC4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80190354
 * EN v1.1 Size: 368b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_8018ffbc
 * EN v1.0 Address: 0x8018FFBC
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x801905C8
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_80190004
 * EN v1.0 Address: 0x80190004
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80190618
 * EN v1.1 Size: 580b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_80190008
 * EN v1.0 Address: 0x80190008
 * EN v1.0 Size: 320b
 * EN v1.1 Address: 0x8019085C
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: warpPadFn_8019042c
 * EN v1.0 Address: 0x80190148
 * EN v1.0 Size: 1148b
 * EN v1.1 Address: 0x801909A8
 * EN v1.1 Size: 1376b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off

/* Drift-recovery: add new fns with v1.0 names. */
extern u8 lbl_803AC7B0[];






















/* Trivial 4b 0-arg blr leaves. */
void fxemit_release(void)
{
}

void fxemit_initialise(void)
{
}







/* 8b "li r3, N; blr" returners. */
