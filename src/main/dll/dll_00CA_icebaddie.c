/*
 * dll_00CA "icebaddie" (formerly mislabeled "mediumbasket") - CUT / UNUSED content.
 *
 * This is a fully-implemented GroundBaddie enemy (object type id 0x49, extra
 * size 0x458 = GroundBaddieState) that NEVER spawns in the retail game:
 *   - no OBJECTS.bin definition references dll-id 0xCA (no retail name -> the
 *     "mediumbasket" name is a placeholder guessed from the DLL's numeric id);
 *   - it appears in ZERO map romlists (no placement anywhere);
 *   - nothing in the game reads gResourceDescriptors[0xCA] or otherwise spawns
 *     it, even though iceBaddie_update reads placementData (it was designed to be
 *     placed, but the placements were removed before release).
 *
 * What it is (recovered from its code): a cut ice baddie in the ChukChuk
 * family. It pursues the player (aggression/aggroRange, hit points), spits the
 * retail "IceBall" projectile (object id 100, see iceBaddie_spawnIceBall),
 * and runs a state machine of drop/land (camera-shake stomp), spin, open, hide,
 * impact/contact-hit and height-blend states, plus an A/B target-engagement
 * dispatch via the gIceBaddieStateHandlersA/B tables (filled in dll_CE).
 * The whirlpool helpers here (enter/leave/initWhirlpool) are SHARED engine
 * utilities also called by the generic enemy DLL (dll_00C9), not specific to
 * this creature.
 *
 * NOTE: there is no canonical retail name (cut object); "iceBaddie" is a
 * descriptive placeholder. See docs/dll_00CA_rename_proposal.md for the
 * investigation that established this is cut content.
 *
 * This TU also defines the descriptor structs and DLL glue for two sibling
 * objects whose handler bodies live elsewhere: the ChukChuk ice-spitter
 * (gChukChukObjDescriptor) and its IceBall projectile (gIceBallObjDescriptor).
 */
#include "main/game_object.h"
#include "main/object.h"
#include "main/audio/sfx.h"
#include "main/object_api.h"
#include "main/vecmath.h"
#include "main/objanim.h"
#include "main/dll/chukchukstate_struct.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/effect_interfaces.h"
#include "main/obj_placement.h"
#include "main/dll/scarab.h"
#include "main/mapEventTypes.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "string.h"
#include "main/gamebits.h"
#include "main/dll/dll_00CA_icebaddie.h"
#include "main/camera.h"
#include "main/objlib_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/dll_00CD_iceball.h"
#include "main/voxmaps.h"

/*
 * The per-object "control" sub-block (at GroundBaddieState + 0x40c). Only the
 * fields this TU touches are named; the rest is padding. effectFlags is a
 * per-frame bitmask consumed (and cleared) by iceBaddie_updateControlEffects
 * to drive the contact-spawn / dust / camera-shake bursts.
 */
typedef struct IceBaddieControl
{
    u8 pad0[0x4 - 0x0];
    s16 attackPatternIndex;  /* 0x04: cycles 0..6 through the attack-move tables */
    s16 consecutiveHitCount; /* 0x06: quick re-hit counter -> ground-pound state */
    u8 pad8[0x28 - 0x8];
    f32 fxScale;    /* 0x28: size-scaled effect/shake magnitude */
    f32 effectPosX; /* 0x2c: computed effect/impact anchor (world) */
    f32 effectPosY; /* 0x30 */
    f32 effectPosZ; /* 0x34 */
    u8 pad38[0x44 - 0x38];
    u8 effectFlags; /* 0x44: per-frame fx request bits (see updateControlEffects) */
    u8 pad45[0x46 - 0x45];
    u16 ambientSfxTimer; /* 0x46: counts up to ~300 then plays an ambient grunt */
} IceBaddieControl;

/* Spawn-setup buffer for the ice-ball projectile: ObjPlacement head (pos +
 * color) plus two class-specific s16 slots the parent seeds at +0x1e/+0x20. */
typedef struct IceBallSetup
{
    ObjPlacement head; /* 0x00: pos/color/mapId */
    u8 pad18[0x1e - 0x18];
    s16 gameBit;  /* 0x1e (-1 = none) */
    s16 gameBit2; /* 0x20 (-1 = none) */
} IceBallSetup;

STATIC_ASSERT(sizeof(ChukChukState) == 0x18);
STATIC_ASSERT(offsetof(ChukChukState, flags) == 0x12);

/* object groups this ice baddie joins */
#define ICEBADDIE_OBJGROUP           3
#define ICEBADDIE_OBJGROUP_SECONDARY 80
#define ICEBADDIE_HIT_VOLUME_SLOT    10

/*
 * IceBaddieControl.effectFlags (u8 at +0x44) request bits. Set by the per-move
 * state handlers, then consumed and cleared once per frame by
 * iceBaddie_updateControlEffects, which dispatches each bit to a specific
 * spawn / camera-shake burst.
 */
#define ICEBADDIE_FX_SPAWN_ICEBALL 0x01 /* fire the armed ice-ball projectile */
#define ICEBADDIE_FX_ARM_ICEBALL   0x02 /* stash spawn transform, then request SPAWN_ICEBALL */
#define ICEBADDIE_FX_BURST         0x04 /* 4x contact particle (obj 0x56) */
#define ICEBADDIE_FX_PUFF          0x08 /* one puff particle (obj 0x57) */
#define ICEBADDIE_FX_IMPACT        0x10 /* camera shake + 0x28x particle 0x57 */
#define ICEBADDIE_FX_LANDING       0x20 /* bigger shake + 0x57 burst + 0x58 debris (anim event 0x200) */

/* child object id spawned by iceBaddie_spawnIceBall (IceBallSetup cast; the armed ice-ball projectile) */
#define ICEBADDIE_CHILD_OBJ_ICEBALL 100

/* particle-effect object ids spawned via gPartfxInterface (docblock: contact/puff/debris particles) */
#define ICEBADDIE_PARTICLE_CONTACT 0x56 /* 4x contact particle */
#define ICEBADDIE_PARTICLE_PUFF    0x57 /* puff / impact burst particle */
#define ICEBADDIE_PARTICLE_DEBRIS  0x58 /* landing debris particle */


extern u8 lbl_803DDA78;
extern u8 lbl_803DDA79;

extern f32 lbl_803E2CD8;
extern f32 lbl_803E2D00;
extern f32 lbl_803E2D14;
extern f32 lbl_803E2D10;
extern f32 lbl_803E2D18;
extern f32 lbl_803E2D1C;
extern f32 lbl_803E2D20;
extern f32 lbl_803E2D24;
extern f32 lbl_803E2D28;
extern f32 lbl_803E2D2C;
extern f32 lbl_803E2D30;
extern f32 lbl_803E2D34;
extern f32 gIceBaddieMinMoveSpeed;
extern f32 lbl_803E2D3C;
extern f32 gIceBaddieMaxMoveSpeed;
extern f32 lbl_803E2D44;
extern f32 lbl_803E2D48;
extern f32 lbl_803E2D4C;
extern f32 lbl_803E2D50;
extern f32 lbl_803E2D54;
extern f32 lbl_803E2D58;
extern f32 lbl_803E2D5C;
extern f32 lbl_803E2D60;
extern f32 lbl_803E2D84;
extern f32 lbl_803E2D88;
extern f32 lbl_803E2D8C;
extern f32 gIceBaddieYOffset;
extern f32 lbl_803E2D94;
extern f32 gIceBaddiePi;
extern f32 lbl_803E2D9C;
extern f32 lbl_803E2DA0;
extern f32 lbl_803E2DA4;
extern f32 lbl_803E2DA8;
extern f32 lbl_803E2DAC;
extern f32 lbl_803E2DB0;
extern f32 lbl_803E2DB4;
extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 lbl_803E2CE8;
extern f32 lbl_803E2CEC;
extern f32 lbl_803E2CF0;
extern f32 lbl_803E2CF4;
extern f32 lbl_803E2CF8;
extern f32 lbl_803E2CFC;
extern void ObjModel_SetRenderCallback(int* model, void* cb);
extern void renderWhirlpool(void);

extern void fn_8003B5E0(int a, int b, int c, u8 d);

extern u8 gIceBaddieStateHandlersA[];
extern u8 gIceBaddieStateHandlersB[];
extern u8 lbl_8031FDA0[];
extern u8 lbl_8031FE18[];
extern s16 gIceBaddieAttackMoves[];
extern s16 gIceBaddieAttackMovesAlt[];
extern u8 gIceBaddieParticleArgsTable[];
extern u8 gIceBaddiePaletteIndexTable[];

extern int* gPlayerInterface;
extern f32 lbl_803E2D70;
extern f32 lbl_803E2D74;
extern f32 lbl_803E2D78;
extern f32 lbl_803E2D7C;
extern f32 lbl_803E2D80;
extern int* gBaddieControlInterface;
extern f32 lbl_803E2DB8;
extern void objRenderModelAndHitVolumes(int obj, int arg1, int arg2, int arg3, int arg4, f32 scale);

#pragma scheduling off
#pragma peephole off
int iceBaddie_updateOpenState(GameObject* obj, int state)
{
    GroundBaddieState* sub;
    IceBaddieControl* control;
    ObjHitsPriorityState* hitState;

    sub = (obj)->extra;
    control = (IceBaddieControl*)sub->control;
    hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
    hitState->flags |= 1;
    ((GroundBaddieState*)state)->baddie.physicsActive = 1;
    if (*(char*)&((GroundBaddieState*)state)->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 11, lbl_803E2D14, 0);
        *(s8*)&((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    if (*(char*)&((GroundBaddieState*)state)->baddie.moveJustStartedA != '\0')
    {
        mainSetBits(sub->gameBitB, 1);
        *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        (obj)->anim.alpha = 0xff;
        *(s8*)&((GroundBaddieState*)state)->baddie.stateTag = 1;
        ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D70 + (f32)(u32)sub->aggression / lbl_803E2D74;
    }
    if (*(s8*)&((GroundBaddieState*)state)->baddie.moveDone != 0)
    {
        sub->targetState = 1;
    }
    {
        int v = *(int*)&((GroundBaddieState*)state)->baddie.eventFlags;
        if ((v & BADDIE_EVENT_LANDING) != 0)
        {
            ((GroundBaddieState*)state)->baddie.eventFlags = v & ~BADDIE_EVENT_LANDING;
            control->effectFlags |= ICEBADDIE_FX_LANDING;
        }
    }
    control->effectFlags |= ICEBADDIE_FX_BURST;
    if ((obj)->anim.currentMoveProgress < lbl_803E2D78)
    {
        control->effectFlags |= ICEBADDIE_FX_PUFF;
    }
    (*(int (**)(int, int, f32, int))(*gPlayerInterface + 0x30))((int)obj, state, timeDelta, 4);
    return 0;
}

#pragma opt_common_subs off
int iceBaddie_updateOpenHitState(GameObject* obj, int state)
{
    GroundBaddieState* sub;
    IceBaddieControl* control;

    sub = obj->extra;
    control = (IceBaddieControl*)sub->control;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->flags |= OBJHITS_PRIORITY_STATE_ENABLED;
    ((GroundBaddieState*)state)->baddie.physicsActive = 1;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = 9;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject((int)obj);
    if (*(char*)&((GroundBaddieState*)state)->baddie.moveJustStartedA != '\0')
    {
        ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2D14, 0);
        *(s8*)&((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    if (*(char*)&((GroundBaddieState*)state)->baddie.moveJustStartedA != '\0')
    {
        mainSetBits(sub->gameBitB, 1);
        *(u8*)&obj->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
        obj->anim.alpha = 0xff;
        *(s8*)&((GroundBaddieState*)state)->baddie.stateTag = 1;
        ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D7C + (f32)(u32)sub->aggression / lbl_803E2D80;
    }
    if (*(s8*)&((GroundBaddieState*)state)->baddie.moveDone != 0)
    {
        sub->targetState = 1;
    }
    {
        int v = *(int*)&((GroundBaddieState*)state)->baddie.eventFlags;
        if ((v & BADDIE_EVENT_LANDING) != 0)
        {
            ((GroundBaddieState*)state)->baddie.eventFlags = v & ~BADDIE_EVENT_LANDING;
            control->effectFlags |= ICEBADDIE_FX_LANDING;
        }
    }
    control->effectFlags |= ICEBADDIE_FX_BURST;
    if (obj->anim.currentMoveProgress < lbl_803E2D78)
    {
        control->effectFlags |= ICEBADDIE_FX_PUFF;
    }
    (*(int (**)(int, int, f32, int))(*gPlayerInterface + 0x30))((int)obj, state, timeDelta, 4);
    return 0;
}
#pragma opt_common_subs reset

#pragma scheduling on
#pragma peephole on
void iceBaddie_spawnIceBall(int* obj, int* state);

#pragma scheduling off
void iceBaddie_func0B(int obj, int message)
{
    GroundBaddieState* state = ((GameObject*)obj)->extra;

    switch ((u8)message)
    {
    case 0x80:
        ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, (int)state, 2);
        state->baddie.substate = 4;
        state->baddie.moveJustStartedB = 1;
        break;
    }
}

#pragma peephole off
int iceBaddie_stateHandlerB04(int obj, int state)
{
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedB != 0)
    {
        ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 2);
    }
    return 0;
}

int iceBaddie_stateHandlerB03(GameObject* obj, int state)
{
    GroundBaddieState* sub;

    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedB != 0)
    {
        sub = obj->extra;
        sub->subMode = 0;
        mainSetBits((s32)sub->gameBitB, 0);
        mainSetBits((s32)sub->gameBitA, 1);
    }
    return 0;
}

#pragma opt_common_subs off
int iceBaddie_stateHandlerB02(GameObject* obj, int state)
{
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedB != 0)
    {
        ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])((int)obj, state, 0xd);
        *(int*)&((GroundBaddieState*)state)->baddie.targetObj = 0;
        ((GroundBaddieState*)state)->baddie.physicsActive = 0;
        ((GroundBaddieState*)state)->baddie.hasTarget = 0;
        ObjHits_DisableObject((int)obj);
        *(u8*)&obj->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    else if ((s8)((GroundBaddieState*)state)->baddie.moveDone != 0)
    {
            ObjMsg_SendToObjects(0, 3, obj, 0xe0000, (int)obj);
        if (obj->anim.placementData == NULL)
        {
            Obj_FreeObject(obj);
            return 0;
        }
        return 4;
    }
    return 0;
}
#pragma opt_common_subs reset

int iceBaddie_updateLandingState(GameObject* obj, int state)
{
    GroundBaddieState* sub = (obj)->extra;
    int player;
    f32 noBlend;

    ((GroundBaddieState*)state)->baddie.stateTag = 3;
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D28;
    noBlend = lbl_803E2D14;
    ((GroundBaddieState*)state)->baddie.animSpeedA = noBlend;
    ((GroundBaddieState*)state)->baddie.animSpeedB = noBlend;
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 1, noBlend, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    if ((((GroundBaddieState*)state)->baddie.moveEventFlags & 1) == 0)
    {
        player = (int)Obj_GetPlayerObject();
        if (((GameObject*)player)->anim.seqId == 0)
            goto playGroundLandSound;
        Sfx_PlayFromObject((int)obj, SFXTRIG_wp_stftest122_1f2);
        goto playLandingExtras;
    playGroundLandSound:
        Sfx_PlayFromObject((int)obj, SFXTRIG_swd);
    playLandingExtras:
        Sfx_PlayFromObject((int)obj, SFXTRIG_en_rfall5_c);
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_26f);
        ((GroundBaddieState*)state)->baddie.moveEventFlags |= 1;
    }
    if ((((GroundBaddieState*)state)->baddie.moveEventFlags & 2) == 0 && (obj)->anim.currentMoveProgress > lbl_803E2D2C)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_wp_iceywindlp16_233);
        ((GroundBaddieState*)state)->baddie.moveEventFlags |= 2;
        ((void (*)(int, int, int, int))((void**)*gBaddieControlInterface)[19])((int)obj, sub->triggerId, -1, 0);
    }
    return 0;
}

int iceBaddie_updateContactHitState(GameObject* obj, int state)
{
    GroundBaddieState* sub = (obj)->extra;
    int control;
    f32 noBlend;

    ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject((int)obj);
    if (sub->aggression > 0x32)
    {
        if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 4, lbl_803E2D14, 0);
            ((GroundBaddieState*)state)->baddie.moveDone = 0;
        }
    }
    else if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0xe, lbl_803E2D14, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.stateTag = 3;
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D28;
    control = *(int*)&sub->control;
    ((IceBaddieControl*)control)->effectFlags |= (ICEBADDIE_FX_BURST | ICEBADDIE_FX_PUFF);
    noBlend = lbl_803E2D14;
    ((GroundBaddieState*)state)->baddie.animSpeedA = noBlend;
    ((GroundBaddieState*)state)->baddie.animSpeedB = noBlend;
    if ((sub->configFlags & 2) == 0)
    {
        ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D30 + (obj)->anim.currentMoveProgress;
    }
    return 0;
}

int iceBaddie_stateHandlerA0B(GameObject* obj, int state)
{
    GroundBaddieState* sub = (obj)->extra;
    int control;

    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 2, lbl_803E2D14, 0);
            ((GroundBaddieState*)state)->baddie.moveDone = 0;
        }
        sub->targetState = 2;
        ((GroundBaddieState*)state)->baddie.stateTag = 1;
        ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D34;
    }
    else
    {
        if ((s8)((GroundBaddieState*)state)->baddie.moveDone != 0)
        {
            sub->targetState = 3;
        }
    }
    control = *(int*)&sub->control;
    ((IceBaddieControl*)control)->effectFlags |= ICEBADDIE_FX_BURST;
    if ((s32)(((GroundBaddieState*)state)->baddie.eventFlags & BADDIE_EVENT_LANDING) != 0)
    {
        ((GroundBaddieState*)state)->baddie.eventFlags &= ~BADDIE_EVENT_LANDING;
        ((IceBaddieControl*)control)->effectFlags |= ICEBADDIE_FX_IMPACT;
    }
    ((IceBaddieControl*)control)->effectFlags |= (ICEBADDIE_FX_BURST | ICEBADDIE_FX_PUFF);
    ((GroundBaddieState*)state)->baddie.animSpeedA = (obj)->anim.currentMoveProgress;
    return 0;
}

int iceBaddie_updateDropState(GameObject* obj, int state)
{
    int control = *(int*)(*(int*)&(obj)->extra + 0x40c);
    int player;

    ((IceBaddieControl*)control)->effectFlags |= ICEBADDIE_FX_BURST;
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2D14, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        Obj_GetPlayerObject();
        player = (int)Obj_GetPlayerObject();
        if (((GameObject*)player)->anim.seqId == 0)
            goto playGroundDropSound;
        Sfx_PlayFromObject((int)obj, SFXTRIG_wp_stftest122_1f2);
        goto playDropExtras;
    playGroundDropSound:
        Sfx_PlayFromObject((int)obj, SFXTRIG_swd);
    playDropExtras:
        Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_26e);
    }
    ((GroundBaddieState*)state)->baddie.stateTag = 3;
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D34;
    ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D14;
    return 0;
}

int iceBaddie_updateCommDownState(GameObject* obj, int state)
{
    GroundBaddieState* sub = (obj)->extra;
    int control = *(int*)&sub->control;

    ((IceBaddieControl*)control)->effectFlags |= ICEBADDIE_FX_BURST;
    ((GroundBaddieState*)state)->baddie.moveSpeed = gIceBaddieMinMoveSpeed;
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 10, lbl_803E2D14, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.stateTag = 1;
    if ((*(s32*)&((GroundBaddieState*)state)->baddie.eventFlags & 1) != 0)
    {
        control = *(int*)&sub->control;
        ((GroundBaddieState*)state)->baddie.eventFlags &= ~BADDIE_EVENT_FOOTSTEP;
        ((IceBaddieControl*)control)->effectFlags |= ICEBADDIE_FX_ARM_ICEBALL;
        Sfx_PlayFromObject((int)obj, SFXTRIG_wp_dsmk2_c_cf);
    }
    ((void (*)(int, int, f32, int))((void**)*gPlayerInterface)[12])((int)obj, state, timeDelta, 4);
    return 0;
}

int iceBaddie_updateHeightBlendState(GameObject* obj, int state)
{
    int control = *(int*)(*(int*)&(obj)->extra + 0x40c);
    f32 height;

    ((IceBaddieControl*)control)->effectFlags |= (ICEBADDIE_FX_BURST | ICEBADDIE_FX_PUFF);
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
        {
            ObjAnim_SetCurrentMove((int)obj, 0xf, lbl_803E2D14, 0);
            ((GroundBaddieState*)state)->baddie.moveDone = 0;
        }
        ((GroundBaddieState*)state)->baddie.stateTag = 1;
    }
    ((GroundBaddieState*)state)->baddie.moveSpeed = ((GroundBaddieState*)state)->baddie.targetDistance / lbl_803E2D3C;
    if (((GroundBaddieState*)state)->baddie.moveSpeed > gIceBaddieMaxMoveSpeed)
    {
        ((GroundBaddieState*)state)->baddie.moveSpeed = gIceBaddieMaxMoveSpeed;
    }
    else if (((GroundBaddieState*)state)->baddie.moveSpeed < gIceBaddieMinMoveSpeed)
    {
        ((GroundBaddieState*)state)->baddie.moveSpeed = gIceBaddieMinMoveSpeed;
    }
    height = (obj)->anim.currentMoveProgress;
    if (height < lbl_803E2D24)
    {
        ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D44 * height;
    }
    else
    {
        ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D44 * (lbl_803E2D48 - height);
    }
    ((void (*)(int, int, f32, int))((void**)*gPlayerInterface)[12])((int)obj, state, timeDelta, 4);
    return 0;
}

#pragma opt_common_subs off
int iceBaddie_stateHandlerA06(GameObject* obj, int state)
{
    GroundBaddieState* sub = obj->extra;
    int choice;

    ((IceBaddieControl*)sub->control)->effectFlags |= ICEBADDIE_FX_BURST;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject((int)obj);
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        lbl_803DDA79 = randomGetRange(0, 2);
        choice = randomGetRange(0, 1);
        if (choice != 0)
        {
            if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove((int)obj, 7, lbl_803E2D14, 0);
                ((GroundBaddieState*)state)->baddie.moveDone = 0;
            }
        }
        else
        {
            if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove((int)obj, 3, lbl_803E2D14, 0);
                ((GroundBaddieState*)state)->baddie.moveDone = 0;
            }
        }
        ((GroundBaddieState*)state)->baddie.stateTag = 1;
        ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D4C + sub->aggression / lbl_803E2D50;
    }
    if (sub->aggression > 50 && (sub->configFlags & 2) == 0)
    {
        if (((GroundBaddieState*)state)->baddie.targetDistance > lbl_803E2D54 &&
            (s8)((GroundBaddieState*)state)->baddie.moveDone == 0)
        {
            ((GroundBaddieState*)state)->baddie.animSpeedA =
                ((GroundBaddieState*)state)->baddie.targetDistance / lbl_803E2D54 - lbl_803E2D48;
            ((GroundBaddieState*)state)->baddie.animSpeedA =
                ((GroundBaddieState*)state)->baddie.animSpeedA * ((f32)sub->aggression / lbl_803E2D58);
        }
        else
        {
            ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D14;
        }
    }
    else
    {
        ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D14;
    }
    ((void (*)(int, int, f32, int))((void**)*gPlayerInterface)[12])((int)obj, state, timeDelta, 4);
    return 0;
}
#pragma opt_common_subs reset

#pragma opt_common_subs off
int iceBaddie_stateHandlerA05(GameObject* obj, int state)
{
    GroundBaddieState* sub = obj->extra;
    int choice;

    ((IceBaddieControl*)sub->control)->effectFlags |= ICEBADDIE_FX_BURST;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject((int)obj);
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        choice = randomGetRange(0, 1);
        if (choice != 0)
        {
            lbl_803DDA78 = randomGetRange(0, 2);
            if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove((int)obj, 6, lbl_803E2D14, 0);
                ((GroundBaddieState*)state)->baddie.moveDone = 0;
            }
        }
        else
        {
            lbl_803DDA78 = 3;
            if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
            {
                ObjAnim_SetCurrentMove((int)obj, 10, lbl_803E2D14, 0);
                ((GroundBaddieState*)state)->baddie.moveDone = 0;
            }
        }
        ((GroundBaddieState*)state)->baddie.stateTag = 1;
        ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D4C + sub->aggression / lbl_803E2D50;
    }
    if (sub->aggression > 50 && (sub->configFlags & 2) == 0)
    {
        if (((GroundBaddieState*)state)->baddie.targetDistance > lbl_803E2D54 &&
            (s8)((GroundBaddieState*)state)->baddie.moveDone == 0)
        {
            ((GroundBaddieState*)state)->baddie.animSpeedA =
                ((GroundBaddieState*)state)->baddie.targetDistance / lbl_803E2D54 - lbl_803E2D48;
            ((GroundBaddieState*)state)->baddie.animSpeedA =
                ((GroundBaddieState*)state)->baddie.animSpeedA * ((f32)sub->aggression / lbl_803E2D58);
        }
        else
        {
            ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D14;
        }
    }
    else
    {
        ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D14;
    }
    ((void (*)(int, int, f32, int))((void**)*gPlayerInterface)[12])((int)obj, state, timeDelta, 4);
    return 0;
}
#pragma opt_common_subs reset

int iceBaddie_updateSpinState(GameObject* obj, int state)
{
    GroundBaddieState* sub = (obj)->extra;
    int control;

    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 9, lbl_803E2D14, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    control = *(int*)&sub->control;
    ((IceBaddieControl*)control)->effectFlags |= (ICEBADDIE_FX_BURST | ICEBADDIE_FX_PUFF);
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        sub->targetState = 4;
    }
    (obj)->anim.rotX =
        (s16)(lbl_803E2D5C * (((f32)((GroundBaddieState*)state)->baddie.turnRate * timeDelta) / lbl_803E2D60) +
              (f32) * (s16*)obj);
    ((GroundBaddieState*)state)->baddie.moveSpeed = gIceBaddieMinMoveSpeed;
    ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D48;
    return 0;
}

#pragma opt_common_subs off
int iceBaddie_updateImpactHitState(GameObject* obj, int state)
{
    GroundBaddieState* sub = obj->extra;
    int control = *(int*)&sub->control;

    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = 1;
    ObjHits_RegisterActiveHitVolumeObject((int)obj);
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 4, lbl_803E2D14, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((GroundBaddieState*)state)->baddie.stateTag = 3;
    ((GroundBaddieState*)state)->baddie.moveSpeed = lbl_803E2D28;
    if ((s32)(((GroundBaddieState*)state)->baddie.eventFlags & BADDIE_EVENT_LANDING) != 0)
    {
        ((GroundBaddieState*)state)->baddie.eventFlags &= ~BADDIE_EVENT_LANDING;
        ((IceBaddieControl*)control)->effectFlags |= ICEBADDIE_FX_IMPACT;
    }
    ((IceBaddieControl*)control)->effectFlags |= (ICEBADDIE_FX_BURST | ICEBADDIE_FX_PUFF);
    return 0;
}
#pragma opt_common_subs reset

int iceBaddie_updateHideResetState(GameObject* obj, int state)
{
    GroundBaddieState* sub = (obj)->extra;
    ObjHitsPriorityState* hitState;

    if (((GroundBaddieState*)state)->baddie.prevControlMode != 4 &&
        (s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 0xe, lbl_803E2D14, 0);
        ((GroundBaddieState*)state)->baddie.moveDone = 0;
    }
    ((IceBaddieControl*)sub->control)->effectFlags |= (ICEBADDIE_FX_BURST | ICEBADDIE_FX_PUFF);
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedA != 0)
    {
        hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
        hitState->flags &= ~1;
        ((GroundBaddieState*)state)->baddie.moveSpeed = gIceBaddieMinMoveSpeed;
        ((GroundBaddieState*)state)->baddie.animSpeedA = lbl_803E2D14;
    }
    if ((s8)((GroundBaddieState*)state)->baddie.moveDone != 0)
    {
        mainSetBits((s32)sub->gameBitB, 0);
        ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2D14, 0);
        *(int*)&((GroundBaddieState*)state)->baddie.targetObj = 0;
        ((GroundBaddieState*)state)->baddie.physicsActive = 0;
        ((GroundBaddieState*)state)->baddie.hasTarget = 0;
        sub->targetState = 0;
        *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    }
    return 0;
}

int iceBaddie_stateHandlerB06(int obj, int state)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    int route;
    f32 neutralBlend;

    if ((s8)((GroundBaddieState*)state)->baddie.moveDone != 0 &&
        (((u8)((int (*)(int, int, f32))((void**)*gBaddieControlInterface)[6])(obj, state, lbl_803E2D00) & 1) == 0))
    {
        return 5;
    }
    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedB != 0)
    {
        ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 0xb);
    }
    else if (sub->targetState == 3)
    {
        ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 4);
    }
    else if (sub->targetState == 4)
    {
        if (((GroundBaddieState*)state)->baddie.targetDistance < lbl_803E2D10 &&
            (s8)((GroundBaddieState*)state)->baddie.moveDone != 0)
        {
            if (sub->aggression > 50)
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 0);
            }
            else
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 1);
            }
        }
    }
    else if (sub->targetState == 1)
    {
        return 8;
    }
    route = (int)&sub->routeNav;
    neutralBlend = lbl_803E2D14;
    ((GroundBaddieState*)state)->baddie.moveInputX = neutralBlend;
    ((GroundBaddieState*)state)->baddie.moveInputZ = neutralBlend;
    memcpy((void*)route, &((GameObject*)obj)->anim.localPosX, 0xc);
    memcpy((void*)sub->routeNav.curPos,
           (void*)&((GameObject*)((GroundBaddieState*)state)->baddie.targetObj)->anim.localPosX, 0xc);
    voxmaps_updateRoutePath(&sub->routeNav, &sub->routeState);
    if (*(u8*)(route + 0x25) == 0)
    {
        ((void (*)(int, int, f32, f32, f32, f32, f32))((void**)*gPlayerInterface)[7])(
            obj, state, *(f32*)(route + 0x18), *(f32*)(route + 0x20), *(f32*)&lbl_803E2D14, lbl_803E2D14, lbl_803E2D18);
    }
    else
    {
        ((void (*)(int, int, f32, f32, f32, f32, f32))((void**)*gPlayerInterface)[7])(
            obj, state, *(f32*)(route + 0x18), *(f32*)(route + 0x20), lbl_803E2D1C, lbl_803E2D20, lbl_803E2D18);
    }
    if (((GroundBaddieState*)state)->baddie.stateTimer > 0x78 &&
        ((int (*)(int, int, f32, int))((void**)*gBaddieControlInterface)[17])(obj, state, sub->aggroRange, 1) != 0)
    {
        return 5;
    }
    return 0;
}

int iceBaddie_stateHandlerB07(int obj, int state)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;

    if ((s8)((GroundBaddieState*)state)->baddie.moveJustStartedB != 0)
    {
        if ((s32)((GroundBaddieState*)state)->baddie.targetDistance > 0x37)
        {
            if ((sub->configFlags & 2) == 0)
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 7);
            }
            else
            {
                IceBaddieControl* control = (IceBaddieControl*)*(int*)&sub->control;
                if ((sub->configFlags & 0x10) != 0)
                {
                    ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(
                        obj, state, gIceBaddieAttackMovesAlt[control->attackPatternIndex++]);
                }
                else
                {
                    ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(
                        obj, state, gIceBaddieAttackMoves[control->attackPatternIndex++]);
                }
                if (control->attackPatternIndex >= 7)
                {
                    control->attackPatternIndex = 0;
                }
            }
        }
        else
        {
            if (((GroundBaddieState*)state)->baddie.controlMode == 6)
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 5);
            }
            else
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 6);
            }
        }
    }
    else if ((s8)((GroundBaddieState*)state)->baddie.moveDone != 0)
    {
        if ((((u8)((int (*)(int, int, f32))((void**)*gBaddieControlInterface)[6])(obj, state, lbl_803E2D00) & 1) == 0))
        {
            return 5;
        }
        if (((int (*)(int, int, f32, int))((void**)*gBaddieControlInterface)[17])(obj, state, sub->aggroRange, 1) != 0)
        {
            return 5;
        }
        if ((s32)((GroundBaddieState*)state)->baddie.targetDistance > 0x37)
        {
            if ((sub->configFlags & 2) == 0)
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 7);
            }
            else
            {
                int control = *(int*)&sub->control;
                if ((sub->configFlags & 0x10) != 0)
                {
                    ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(
                        obj, state, gIceBaddieAttackMovesAlt[((IceBaddieControl*)control)->attackPatternIndex++]);
                }
                else
                {
                    ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(
                        obj, state, gIceBaddieAttackMoves[((IceBaddieControl*)control)->attackPatternIndex++]);
                }
                if (((IceBaddieControl*)control)->attackPatternIndex >= 7)
                {
                    ((IceBaddieControl*)control)->attackPatternIndex = 0;
                }
            }
        }
        else
        {
            if (((GroundBaddieState*)state)->baddie.controlMode == 6)
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 5);
            }
            else
            {
                ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 6);
            }
        }
    }
    else if (((GroundBaddieState*)state)->baddie.controlMode == 7 &&
             (s32)((GroundBaddieState*)state)->baddie.targetDistance < 0x37)
    {
        if (((GroundBaddieState*)state)->baddie.controlMode == 6)
        {
            ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 5);
        }
        else
        {
            ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 6);
        }
    }
    return 0;
}

void iceBaddie_updateEffectAnchors(GameObject* obj, int state)
{
    int control = (int)((GroundBaddieState*)state)->control;
    f32 transformed[3];
#define transformedX (transformed[0])
#define transformedY (transformed[1])
#define transformedZ (transformed[2])
    f32 transformScratch[6];
#define pathX (transformScratch[3])
#define pathY (transformScratch[4])
#define pathZ (transformScratch[5])
    f32 pathMtx[16];
    f32 scale;
    f32 minScale;
    f32 angle;

    memcpy(pathMtx, (void*)ObjPath_GetPointModelMtx(obj, 1), 0x40);
    pathMtx[14] = lbl_803E2D14;
    pathMtx[13] = lbl_803E2D14;
    pathMtx[12] = lbl_803E2D14;
    if ((obj)->anim.seqId == 99)
    {
        minScale = lbl_803E2D48;
    }
    else
    {
        minScale = lbl_803E2D2C;
    }
    if (((GroundBaddieState*)state)->baddie.animSpeedA < minScale)
    {
        scale = minScale;
    }
    else
    {
        scale = ((GroundBaddieState*)state)->baddie.animSpeedA;
    }
    if (((GroundBaddieState*)state)->baddie.controlMode != 4)
    {
        ObjPath_GetPointWorldPosition((int)obj, 2, &((IceBaddieControl*)control)->effectPosX,
                                      &((IceBaddieControl*)control)->effectPosY,
                                      &((IceBaddieControl*)control)->effectPosZ, 0);
    }
    else
    {
        ObjPath_GetPointWorldPosition((int)obj, 0, &((IceBaddieControl*)control)->effectPosX,
                                      &((IceBaddieControl*)control)->effectPosY,
                                      &((IceBaddieControl*)control)->effectPosZ, 0);
    }
    ((IceBaddieControl*)control)->effectPosY = gIceBaddieYOffset + (obj)->anim.localPosY;
    angle = (gIceBaddiePi * (f32) * (s16*)obj) / lbl_803E2D9C;
    ((IceBaddieControl*)control)->effectPosX =
        ((IceBaddieControl*)control)->effectPosX - scale * (lbl_803E2D94 * mathSinf(angle));
    angle = (gIceBaddiePi * (f32) * (s16*)obj) / lbl_803E2D9C;
    ((IceBaddieControl*)control)->effectPosZ =
        ((IceBaddieControl*)control)->effectPosZ - scale * (lbl_803E2D94 * mathCosf(angle));
    pathX = lbl_803E2D14;
    pathY = lbl_803E2DA0;
    pathZ = lbl_803E2DA4;
    ObjPath_GetPointWorldPosition((int)obj, 0, &pathX, &pathY, &pathZ, 1);
    if ((((IceBaddieControl*)control)->effectFlags & ICEBADDIE_FX_ARM_ICEBALL) != 0)
    {
        transformedX = lbl_803E2DA8;
        transformedY = lbl_803E2DAC;
        transformedZ = lbl_803E2DA4;
        Matrix_TransformPoint(pathMtx, transformedX, transformedY, transformedZ, &transformedX, &transformedY,
                              &transformedZ);
        memcpy((void*)(control + 0x38), transformed, 0xc);
        memcpy((void*)(control + 8), transformScratch, 0x18);
        ((IceBaddieControl*)control)->effectFlags |= ICEBADDIE_FX_SPAWN_ICEBALL;
    }
}
#undef transformedX
#undef transformedY
#undef transformedZ
#undef pathX
#undef pathY
#undef pathZ

void iceBaddie_updateControlEffects(GameObject* obj, int state)
{
    int control = (int)((GroundBaddieState*)state)->control;
    int paletteIndex;
    u8* particleArgs;
    int i;
    f32 shakeScale;
    f32 contactScale;

    if (obj->anim.seqId == 99)
    {
        ((IceBaddieControl*)control)->fxScale = lbl_803E2D84;
        shakeScale = lbl_803E2D88;
    }
    else
    {
        contactScale = lbl_803E2D48;
        ((IceBaddieControl*)control)->fxScale = contactScale;
        shakeScale = contactScale;
    }
    paletteIndex = 0;
    if ((s8)((GroundBaddieState*)state)->baddie.physicsActive != 0)
    {
        paletteIndex = gIceBaddiePaletteIndexTable[(s8)((GroundBaddieState*)state)->baddie.paletteSlot];
        if (paletteIndex > 0x1e)
        {
            paletteIndex = 0;
        }
    }
    particleArgs = &gIceBaddieParticleArgsTable[paletteIndex * 3];
    if ((((IceBaddieControl*)control)->effectFlags & ICEBADDIE_FX_SPAWN_ICEBALL) != 0)
    {
        iceBaddie_spawnIceBall((int*)obj, (int*)control);
        ((IceBaddieControl*)control)->effectFlags &= ~ICEBADDIE_FX_SPAWN_ICEBALL;
    }
    if ((((IceBaddieControl*)control)->effectFlags & ICEBADDIE_FX_BURST) != 0 &&
        (((GroundBaddieState*)state)->configFlags & 0x40) == 0)
    {
        for (i = 0; i < 4; i++)
        {
            (*gPartfxInterface)
                ->spawnObject((void*)obj, ICEBADDIE_PARTICLE_CONTACT, (void*)(control + 0x20), 0x200001, -1,
                              particleArgs);
        }
    }
    if ((((IceBaddieControl*)control)->effectFlags & ICEBADDIE_FX_PUFF) != 0 &&
        (((GroundBaddieState*)state)->configFlags & 0x40) == 0)
    {
        (*gPartfxInterface)
            ->spawnObject((void*)obj, ICEBADDIE_PARTICLE_PUFF, (void*)(control + 0x20), 0x200001, -1, particleArgs);
    }
    if ((((IceBaddieControl*)control)->effectFlags & ICEBADDIE_FX_IMPACT) != 0)
    {
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(lbl_803E2D88 * shakeScale);
        for (i = 0; i < 0x28; i++)
        {
            (*gPartfxInterface)
                ->spawnObject((void*)obj, ICEBADDIE_PARTICLE_PUFF, (void*)(control + 0x20), 0x200001, -1, particleArgs);
        }
    }
    if ((((IceBaddieControl*)control)->effectFlags & ICEBADDIE_FX_LANDING) != 0)
    {
        Camera_EnableViewYOffset();
        CameraShake_SetAllMagnitudes(lbl_803E2D8C * shakeScale);
        for (i = 0; i < 0x28; i++)
        {
            (*gPartfxInterface)
                ->spawnObject((void*)obj, ICEBADDIE_PARTICLE_PUFF, (void*)(control + 0x20), 0x200001, -1, particleArgs);
        }
        for (i = 0; i < 10; i++)
        {
            (*gPartfxInterface)
                ->spawnObject((void*)obj, ICEBADDIE_PARTICLE_DEBRIS, (void*)(control + 0x20), 0x200001, -1,
                              particleArgs);
        }
    }
    ((IceBaddieControl*)control)->effectFlags = 0;
}

void iceBaddie_updateTargetMotion(GameObject* obj, int sub, int state)
{
    int control = *(int*)&((GroundBaddieState*)sub)->control;

    ((IceBaddieControl*)control)->ambientSfxTimer += framesThisStep;
    if (((IceBaddieControl*)control)->ambientSfxTimer >= 300)
    {
        ((IceBaddieControl*)control)->ambientSfxTimer = randomGetRange(0, 200);
        if (((GroundBaddieState*)state)->baddie.controlMode == 7 ||
            ((GroundBaddieState*)state)->baddie.controlMode == 8)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_26c);
        }
    }
    if ((((GroundBaddieState*)sub)->configFlags & 2) != 0)
    {
        ((void (*)(int, int, f32, int))((void**)*gBaddieControlInterface)[11])((int)obj, state, lbl_803E2D14, -1);
    }
    else
    {
        ((void (*)(int, int, f32, int))((void**)*gBaddieControlInterface)[11])((int)obj, state, lbl_803E2DB0, -1);
    }
    ((GroundBaddieState*)sub)->savedObjC0 = *(int*)&(obj)->pendingParentObj;
    *(int*)&(obj)->pendingParentObj = 0;
    ((void (*)(int, int, f32, f32, u8*, u8*))((void**)*gPlayerInterface)[2])(
        (int)obj, state, timeDelta, timeDelta, gIceBaddieStateHandlersA, gIceBaddieStateHandlersB);
    *(int*)&(obj)->pendingParentObj = ((GroundBaddieState*)sub)->savedObjC0;
}

#pragma fp_contract off
void iceBaddie_updateTargetCollision(int obj, int sub, int state)
{
    int control = *(int*)&((GroundBaddieState*)sub)->control;
    u8* target;
    int hitInfo[7];
    f32 targetDelta[3];
    f32 distSq;

    Obj_GetPlayerObject();
    target = ((GroundBaddieState*)state)->baddie.targetObj;
    if (target != NULL)
    {
        f32* d = targetDelta;
        d[0] = ((GameObject*)target)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
        d[1] = ((GameObject*)target)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
        d[2] = ((GameObject*)target)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
        ((GroundBaddieState*)state)->baddie.targetDistance = sqrtf(d[2] * d[2] + (d[0] * d[0] + d[1] * d[1]));
    }
    if ((((GroundBaddieState*)sub)->configFlags & 0x20) == 0)
    {
        ((void (*)(int, int, int, int, int, int, int))((void**)*gBaddieControlInterface)[15])(
            obj, state, sub + 0x400, 2, 3, (s32)((GroundBaddieState*)sub)->soundIdB,
            (s32)((GroundBaddieState*)sub)->soundIdA);
    }
    ((void (*)(int, int, int, int, int, int, int, int))((void**)*gBaddieControlInterface)[21])(
        obj, state, sub + 0x35c, (s32)((GroundBaddieState*)sub)->gameBitB, 0, 0, 0, 8);
    *(f32*)control += timeDelta;
    if (((GroundBaddieState*)state)->baddie.controlMode != 3 &&
        ((int (*)(int, int, int, int, u8*, u8*, int, int*))((void**)*gBaddieControlInterface)[20])(
            obj, state, sub + 0x35c, (s32)((GroundBaddieState*)sub)->gameBitB, lbl_8031FDA0, lbl_8031FE18, 1,
            hitInfo) != 0)
    {
        if (*(f32*)control < lbl_803E2DB4)
        {
            ((IceBaddieControl*)control)->consecutiveHitCount += 1;
        }
        else
        {
            ((IceBaddieControl*)control)->consecutiveHitCount = 0;
        }
        *(f32*)control = lbl_803E2D14;
        if ((s8)((GroundBaddieState*)state)->baddie.hitPoints > 0 &&
            ((IceBaddieControl*)control)->consecutiveHitCount >= 2)
        {
            ((void (*)(int, int, int))((void**)*gPlayerInterface)[5])(obj, state, 3);
            ((IceBaddieControl*)control)->consecutiveHitCount = 0;
            ((GroundBaddieState*)state)->baddie.substate = 5;
        }
    }
}
#pragma fp_contract reset

s16 iceBaddie_setScale(int* obj)
{
    return ((GroundBaddieState*)((GameObject*)obj)->extra)->baddie.controlMode;
}

int iceBaddie_getExtraSize(void)
{
    return 0x458;
}
int iceBaddie_getObjectTypeId(void)
{
    return 0x49;
}

#pragma opt_common_subs off
void iceBaddie_free(GameObject* obj)
{
    GroundBaddieState* state = obj->extra;

    Camera_DisableViewYOffset();
    ObjGroup_RemoveObject((int)obj, ICEBADDIE_OBJGROUP);
    if (obj->childObjs[0] != NULL)
    {
        Obj_FreeObject(*(GameObject**)&obj->childObjs[0]);
        *(int*)&obj->childObjs[0] = 0;
    }
    ((void (*)(int, int, int))((void**)*gBaddieControlInterface)[16])((int)obj, (int)state, 0x20);
}
#pragma opt_common_subs reset

void iceBaddie_render(GameObject* obj, int arg1, int arg2, int arg3, int arg4, s8 visible)
{
    GroundBaddieState* state = (obj)->extra;

    if (visible == 0 || (obj)->unkF4 != 0 || state->targetState == 0)
    {
        return;
    }

    if (state->glowAlpha != lbl_803E2D14)
    {
        fn_8003B5E0(0xc8, 0, 0, state->glowAlpha);
    }
    objRenderModelAndHitVolumes((int)obj, arg1, arg2, arg3, arg4, lbl_803E2D48);
    iceBaddie_updateEffectAnchors((GameObject*)obj, (int)state);
}

#pragma peephole on
void iceBaddie_hitDetect(int obj)
{
    ((void (*)(int, int, u8*))((void**)*gPlayerInterface)[3])(obj, *(int*)&((GameObject*)obj)->extra,
                                                              gIceBaddieStateHandlersA);
}

void baddie_initWhirlpoolState(int* obj, GroundBaddieState* state)
{
    f32 fz;
    state->baddie.speedScale = lbl_803E2CE8;
    *(char*)&state->baddie.inWhirlpoolGroup = state->baddie.unk2A8;
    state->baddie.unk2A8 = lbl_803E2CEC;
    state->baddie.unk2E4 = 0x42001;
    state->baddie.unk308 = lbl_803E2CF0;
    state->baddie.animDeltaScale = lbl_803E2CF4;
    state->baddie.unk304 = lbl_803E2CF8;
    state->baddie.unk320 = 0;
    fz = lbl_803E2CFC;
    *(f32*)&state->baddie.eventFlags = fz;
    state->baddie.unk321 = 5;
    state->baddie.unk318 = fz;
    state->baddie.unk322 = 7;
    state->baddie.unk31C = fz;
    state->baddie.seqEntryIndex = 1;
    state->baddie.inWhirlpoolGroup = 0;
    ObjModel_SetRenderCallback((int*)Obj_GetActiveModel((GameObject*)obj), renderWhirlpool);
}

#pragma peephole off
void iceBaddie_spawnIceBall(int* obj, int* state)
{
    IceBallSetup* alloc;
    GameObject* new_obj;
    if ((u8)Obj_IsLoadingLocked() != 0)
    {
        alloc = (IceBallSetup*)Obj_AllocObjectSetup(36, ICEBADDIE_CHILD_OBJ_ICEBALL);
        alloc->head.posX = ((GroundBaddieState*)state)->baddie.posX;
        alloc->head.posY = ((GroundBaddieState*)state)->baddie.posY;
        alloc->head.posZ = ((GroundBaddieState*)state)->baddie.posZ;
        alloc->head.color[0] = 1;
        alloc->head.color[1] = 1;
        alloc->head.color[2] = 255;
        alloc->head.color[3] = 255;
        alloc->gameBit = -1;
        alloc->gameBit2 = -1;
        new_obj = Obj_SetupObject(&alloc->head, 5, -1, -1, NULL);
        if (new_obj != NULL)
        {
            new_obj->anim.velocityX = ((GroundBaddieState*)state)->baddie.velX;
            new_obj->anim.velocityY = ((GroundBaddieState*)state)->baddie.velY;
            new_obj->anim.velocityZ = ((GroundBaddieState*)state)->baddie.velZ;
            *(int**)&new_obj->ownerObj = obj;
        }
    }
}

int iceBaddie_updateControlMove5State(int* obj, GroundBaddieState* state)
{
    IceBaddieControl* control = (IceBaddieControl*)((GroundBaddieState*)((GameObject*)obj)->extra)->control;
    control->effectFlags |= ICEBADDIE_FX_BURST;
    state->baddie.moveSpeed = gIceBaddieMinMoveSpeed;
    if ((s8)state->baddie.moveJustStartedA != 0)
    {
        ObjAnim_SetCurrentMove((int)obj, 5, lbl_803E2D14, 0);
        state->baddie.moveDone = 0;
    }
    state->baddie.stateTag = 1;
    ((void (*)(int*, u8*, f32, int))((void**)*gPlayerInterface)[12])(obj, (u8*)state, timeDelta, 4);
    return 0;
}

int iceBaddie_stateHandlerB05(int* obj, GroundBaddieState* state)
{
    if ((s8)state->baddie.moveJustStartedB != 0)
    {
        ((void (*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 3);
    }
    if ((s8)state->baddie.moveDone != 0)
    {
        if (state->baddie.controlMode == 3)
        {
            ((void (*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 0);
        }
        else
        {
            return 8;
        }
    }
    return 0;
}

int iceBaddie_stateHandlerB01(int* obj, GroundBaddieState* state)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    if ((s8)state->baddie.hitPoints < 1)
        return 3;
    if ((s8)state->baddie.moveDone != 0)
    {
        if (state->baddie.controlMode == 12)
        {
            if (sub->aggression > 50)
            {
                ((void (*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 0);
            }
            else
            {
                ((void (*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, (u8*)state, 1);
            }
        }
        else
        {
            return 8;
        }
    }
    return 0;
}

void iceBaddie_leaveWhirlpoolGroup(GameObject* obj, GroundBaddieState* state)
{
    if (state->baddie.inWhirlpoolGroup != 0)
    {
        ObjGroup_RemoveObject((int)obj, ICEBADDIE_OBJGROUP_SECONDARY);
        state->baddie.inWhirlpoolGroup = 0;
    }
    *(u16*)obj = (float)(int)(obj)->anim.rotX - lbl_803E2CD8 * timeDelta;
}

void iceBaddie_enterWhirlpoolGroup(GameObject* obj, GroundBaddieState* state)
{
    ObjHitsPriorityState* hitState;

    if (state->baddie.inWhirlpoolGroup == 0)
    {
        ObjGroup_AddObject((int)obj, ICEBADDIE_OBJGROUP_SECONDARY);
        state->baddie.inWhirlpoolGroup = 1;
    }
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, ICEBADDIE_HIT_VOLUME_SLOT, 1, 0);
    hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
    hitState->suppressOutgoingHits = 0;
    (obj)->anim.rotX -= 256;
}

void iceBaddie_tryAcquireTarget(int obj, int sub, int state)
{
    u32 acquired;

    ObjHits_DisableObject(obj);

    if ((((GroundBaddieState*)sub)->configFlags & 0x4) != 0)
    {
        acquired = (**(u32(**)(int, int, f32, int))((char*)(*gBaddieControlInterface) + 0x48))(obj, state, lbl_803E2D54,
                                                                                               0x8000);
    }
    else if ((((GroundBaddieState*)sub)->configFlags & 0x8) != 0)
    {
        acquired = (**(u32(**)(int, int, f32, int))((char*)(*gBaddieControlInterface) + 0x48))(
            obj, state, lbl_803E2D24 * (f32)(u32)((GroundBaddieState*)sub)->aggroRange, 0x8000);
    }
    else
    {
        acquired = (**(u32(**)(int, int, f32, int))((char*)(*gBaddieControlInterface) + 0x48))(
            obj, state, (f32)(u32)((GroundBaddieState*)sub)->aggroRange, 0x8000);
    }

    if (acquired != 0)
    {
        (**(void (**)(int, int, f32, int))((char*)(*gPlayerInterface) + 0x30))(obj, state, timeDelta, 4);
        if (((u8)(**(int (**)(int, int, f32))((char*)(*gBaddieControlInterface) + 0x18))(obj, state, lbl_803E2D00) &
             1) == 0)
        {
            acquired = 0;
        }
    }

    if (acquired != 0)
    {
        int v = -1;
        (**(void (**)(int, int, int, int, int, int, int, int, int))((char*)(*gBaddieControlInterface) + 0x28))(
            obj, state, sub + 0x35c, (s32)((GroundBaddieState*)sub)->gameBitB, 0, 0, 0, 8, v);
        *(int*)&((BaddieState*)state)->targetObj = acquired;
        ((BaddieState*)state)->hasTarget = 0;
        ((GroundBaddieState*)sub)->targetState = 1;
    }
}

int iceBaddie_checkTargetState(int obj, int state)
{
    GroundBaddieState* sub = ((GameObject*)obj)->extra;
    f32 neutralBlend;

    if (((GroundBaddieState*)state)->baddie.targetObj == NULL)
        goto return0;

    if ((s32)(s8)((GroundBaddieState*)state)->baddie.moveJustStartedB != 0)
    {
        neutralBlend = lbl_803E2D14;
        ((GroundBaddieState*)state)->baddie.animSpeedB = neutralBlend;
        ((GroundBaddieState*)state)->baddie.animSpeedA = neutralBlend;
        if ((u32)sub->aggression > 50)
        {
            if (((GroundBaddieState*)state)->baddie.targetDistance < lbl_803E2D24 * (f32)(u32)sub->aggroRange ||
                (sub->configFlags & 0x2) != 0)
            {
                (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, state, 0);
            }
            else
            {
                (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, state, 1);
            }
        }
        else
        {
            (**(void (**)(int, int, int))((char*)(*gPlayerInterface) + 0x14))(obj, state, 1);
        }
    }

    if ((s32)(s8)((GroundBaddieState*)state)->baddie.moveDone == 0)
        goto return0;

    (**(void (**)(int, int, f32, int))((char*)(*gPlayerInterface) + 0x30))(obj, state, timeDelta, 4);
    if (((u8)(**(int (**)(int, int, f32))((char*)(*gBaddieControlInterface) + 0x18))(obj, state, lbl_803E2D00) & 1) ==
        0)
    {
        return 5;
    }

    if (((GroundBaddieState*)state)->baddie.targetDistance < lbl_803E2D24 * (f32)(u32)sub->aggroRange ||
        (sub->configFlags & 0x2) != 0)
    {
        return 8;
    }
    return 7;

return0:
    return 0;
}

void iceBaddie_update(GameObject* obj, int unusedA, int unusedB)
{
    extern void Sfx_PlayFromObject(int obj, int sfx);
    extern int iceBaddie_updateTargetCollision(int obj, int sub, int sub2);
    extern void iceBaddie_updateControlEffects(GameObject * obj, int sub);
    extern void iceBaddie_tryAcquireTarget(int obj, int sub, int sub2);
    extern void iceBaddie_updateTargetMotion(GameObject * obj, int sub, int sub2);
    GroundBaddieState* sub;
    int setup;

    sub = (obj)->extra;
    setup = *(int*)&(obj)->anim.placementData;
    if ((obj)->unkF4 != 0)
    {
        if ((sub->baddie.substate != 3 || (sub->configFlags & 1) != 0) &&
            (*gMapEventInterface)->shouldNotSaveTime(((ObjPlacement*)setup)->mapId) != 0)
        {
            (*(void (**)(int, int, int, int, int, int, int, f32))(*(int*)gBaddieControlInterface + 0x58))(
                (int)obj, setup, (int)sub, 14, 8, 0x102, 0x26, lbl_803E2DB8);
            sub->targetState = 0;
            Sfx_PlayFromObject((int)obj, SFXTRIG_dn_seal4_c_263);
            ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2D14, OBJANIM_MOVE_CONTROL_SKIP_EVENT_COUNTDOWN);
            *(s8*)&sub->baddie.moveDone = 0;
            (obj)->anim.alpha = 0xff;
            *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
    }
    else if ((obj)->unkF8 == 0)
    {
        (obj)->anim.localPosX = ((ObjPlacement*)setup)->posX;
        (obj)->anim.localPosY = ((ObjPlacement*)setup)->posY;
        (obj)->anim.localPosZ = ((ObjPlacement*)setup)->posZ;
        (*gObjectTriggerInterface)->runSequence(*(s8*)(setup + 0x2e), (void*)obj, -1);
        (obj)->unkF8 = 1;
    }
    else
    {
        if ((*(int (**)(int, int, int))(*(int*)gBaddieControlInterface + 0x30))((int)obj, (int)sub, 0) == 0)
        {
            sub->targetState = 0;
        }
        else
        {
            iceBaddie_updateTargetCollision((int)obj, (int)sub, (int)sub);
            iceBaddie_updateControlEffects(obj, (int)sub);
            if (sub->targetState == 0)
            {
                iceBaddie_tryAcquireTarget((int)obj, (int)sub, (int)sub);
            }
            else
            {
                iceBaddie_updateTargetMotion(obj, (int)sub, (int)sub);
            }
            if ((sub->configFlags & 2) != 0)
            {
                (obj)->anim.localPosY = ((ObjPlacement*)setup)->posY - gIceBaddieYOffset;
            }
        }
    }
}

#pragma dont_inline on
void fn_8015DAE8(void);
#pragma dont_inline reset

void iceBaddie_init(int obj, u8* params, int flags)
{
    GroundBaddieState* sub;
    u8 mode;

    sub = ((GameObject*)obj)->extra;
    mode = 6;
    if (flags != 0)
    {
        mode |= 1;
    }
    if ((*(u8*)(params + 0x2b) & 0x20) == 0)
    {
        mode |= 8;
    }
    (*(void (**)(int, u8*, int, int, int, int, u8, f32))(*(int*)gBaddieControlInterface + 0x58))(
        obj, params, (int)sub, 14, 8, 0x102, mode, lbl_803E2DB8);
    ((GameObject*)obj)->animEventCallback = NULL;
    if (lbl_803E2D24 * (f32)(u32)sub->aggroRange < lbl_803E2D54)
    {
        *(s16*)&sub->aggroRange = 0x6e;
    }
    ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E2D14, 0);
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    (*(void (**)(int, int, int))(*(int*)gPlayerInterface + 0x14))(obj, (int)sub, 0);
    sub->baddie.substate = 0;
    *(s8*)&sub->baddie.physicsActive = 0;
}

void iceBaddie_release_nop(void)
{
}

void ChukChuk_free(void);
void ChukChuk_hitDetect(void);
void ChukChuk_release(void);
void ChukChuk_initialise(void);
void ChukChuk_init(u8* obj, u8* params);
int ChukChuk_getExtraSize(void);
int ChukChuk_getObjectTypeId(void);
void ChukChuk_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void ChukChuk_update(short* obj);
void ChukChuk_setScale(int obj, int v);

void iceBaddie_initialise(void)
{
    fn_8015DAE8();
}

ObjectDescriptor11WithPadding gChukChukObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)ChukChuk_initialise,
        (ObjectDescriptorCallback)ChukChuk_release,
        0,
        (ObjectDescriptorCallback)ChukChuk_init,
        (ObjectDescriptorCallback)ChukChuk_update,
        (ObjectDescriptorCallback)ChukChuk_hitDetect,
        (ObjectDescriptorCallback)ChukChuk_render,
        (ObjectDescriptorCallback)ChukChuk_free,
        (ObjectDescriptorCallback)ChukChuk_getObjectTypeId,
        ChukChuk_getExtraSize,
        (ObjectDescriptorCallback)ChukChuk_setScale,
    },
    0,
};

ObjectDescriptor gIceBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)IceBall_initialise,
    (ObjectDescriptorCallback)IceBall_release,
    0,
    (ObjectDescriptorCallback)IceBall_init,
    (ObjectDescriptorCallback)IceBall_update,
    (ObjectDescriptorCallback)IceBall_hitDetect,
    (ObjectDescriptorCallback)IceBall_render,
    (ObjectDescriptorCallback)IceBall_free,
    (ObjectDescriptorCallback)IceBall_getObjectTypeId,
    IceBall_getExtraSize,
};

/* --- icebaddie .data reconstruction (0x8031FD80-0x8031FEA8) --- */
#include "main/object_descriptor.h"

s16 gIceBaddieAttackMoves[8] = {5, 6, 8, 6, 5, 8, 6, 0};
s16 gIceBaddieAttackMovesAlt[8] = {8, 6, 9, 8, 6, 9, 9, 0};
u8 lbl_8031FDA0[120] = {0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
                        0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00,
                        0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00,
                        0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0C,
                        0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00,
                        0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00,
                        0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00,
                        0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x0A};
u8 lbl_8031FE18[32] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                       0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00};
u8 gIceBaddieParticleArgsTable[16] = {0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0x00, 0xFF, 0xC0,
                                      0x96, 0x5A, 0x5A, 0x64, 0xFF, 0x5A, 0x00, 0x00};
u8 gIceBaddiePaletteIndexTable[32] = {0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x00, 0x00,
                                      0x00, 0x00, 0x03, 0x03, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00};
ObjectDescriptor12 gIceBaddieObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)iceBaddie_initialise,
    (ObjectDescriptorCallback)iceBaddie_release_nop,
    0,
    (ObjectDescriptorCallback)iceBaddie_init,
    (ObjectDescriptorCallback)iceBaddie_update,
    (ObjectDescriptorCallback)iceBaddie_hitDetect,
    (ObjectDescriptorCallback)iceBaddie_render,
    (ObjectDescriptorCallback)iceBaddie_free,
    (ObjectDescriptorCallback)iceBaddie_getObjectTypeId,
    iceBaddie_getExtraSize,
    (ObjectDescriptorCallback)iceBaddie_setScale,
    (ObjectDescriptorCallback)iceBaddie_func0B,
};
