#include "main/dll/DR/cannontargetControl.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/DR/gasvent.h"
#include "main/dll/DR/gunpowderbarrel_state.h"
#include "main/objhits_types.h"

typedef struct GunpowderbarrelPlacement {
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    u8 pad1E[0x20 - 0x1E];
} GunpowderbarrelPlacement;


extern undefined4 FUN_800033a8();
extern undefined4 FUN_80006824();
extern undefined4 FUN_8001777c();
extern undefined4 FUN_80017a88();
extern undefined4 FUN_80017a98();
extern undefined4 FUN_80017ad0();
extern undefined4 ObjHitbox_SetCapsuleBounds();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_MarkObjectPositionDirty();
extern undefined4 ObjHits_SyncObjectPositionIfDirty();
extern undefined4 ObjHits_DisableObject();
extern undefined8 ObjHits_EnableObject();
extern undefined4 ObjHits_RefreshObjectState();
extern undefined4 ObjHits_AddContactObject();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern int Obj_IsObjectAlive();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 FUN_8003b818();
extern int FUN_8005b398();
extern int FUN_80061a78();
extern undefined4 FUN_80061a80();
extern int FUN_800620e8();
extern uint FUN_8007f6c8();
extern undefined4 FUN_8007f6e4();
extern undefined4 FUN_8007f718();
extern int FUN_8007f764();
extern undefined4 FUN_800e8630();
extern undefined4 FUN_8011e868();
extern undefined4 FUN_8019f1dc();
extern int FUN_8020a468();
extern undefined4 FUN_8020a470();
extern undefined4 FUN_8020a90c();
extern undefined4 FUN_8020a910();
extern uint FUN_8020a914();
extern byte FUN_8020a91c();
extern double SeekTwiceBeforeRead();
extern undefined8 FUN_80286838();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern byte FUN_80294c20();
extern double FUN_80294c6c();
extern uint FUN_80294ce8();
extern uint FUN_80294cf0();
extern uint FUN_80294db4();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd740;
extern f64 DOUBLE_803e4f90;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803DCAE8;
extern f32 lbl_803DCAEC;
extern f32 lbl_803DCAF0;
extern f32 lbl_803E4F58;
extern f32 lbl_803E4F74;
extern f32 lbl_803E4FA4;
extern f32 lbl_803E4FA8;
extern f32 lbl_803E4FAC;
extern f32 lbl_803E4FB0;
extern f32 lbl_803E4FB4;
extern f32 lbl_803E4FB8;
extern f32 lbl_803E4FBC;
extern f32 lbl_803E4FC0;
extern f32 lbl_803E4FC8;
extern f32 lbl_803E4FCC;
extern f32 lbl_803E4FD0;

extern f32 oneOverTimeDelta;
extern f32 lbl_803DBE84;
extern f32 lbl_803E42C0;
extern f32 lbl_803E4324;
extern f32 lbl_803E4328;
extern f32 lbl_803E432C;
extern f32 lbl_803E4330;
extern f32 lbl_803E4334;

extern int fn_80080150(void *p1);
extern int objHitDetectFn_80062e84(int p1, int p2, int p3);
extern int objBboxFn_800640cc(int p1, int p2, f32 r, int p4, int p5, int obj, int p7, int p8, int p9, int p10);
extern void Vec3_ReflectAgainstNormal(void *normal, void *velocity, void *out);
extern f32 PSVECMag(f32 *v);
extern int gunpowderbarrel_setPlayerHeldState(int p1, int p2);
extern void Sfx_PlayFromObject(int obj, int sfx);
extern void objRenderFn_8003b8f4(f32 alpha);
extern f32 lbl_803E4348;

/*
 * --INFO--
 *
 * Function: gunpowderbarrel_hitDetect
 * EN v1.0 Address: 0x801A1A60
 * EN v1.0 Size: 920b
 * EN v1.1 Address: 0x801A1A78
 * EN v1.1 Size: 984b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void gunpowderbarrel_hitDetect(int param_1)
{
    GameObject *barrel;
    GunpowderBarrelState *state;
    f32 sp10[3];
    f32 sp1c[3];
    f32 collision_buf[26];

    barrel = (GameObject *)param_1;
    state = barrel->extra;

    if (Obj_IsObjectAlive(state->linkedTimerObject) == 0) {
        if (state->linkedTimerObject != 0) {
            ObjLink_DetachChild(param_1);
            state->linkedTimerObject = 0;
        }
    }

    if (state->fuseFrames != 0) {
        return;
    }

    if (fn_80080150(&state->respawnTimer) != 0) {
        return;
    }
    if (fn_80080150(&state->releaseTimer) != 0) {
        return;
    }

    if (state->queuedHitObject != 0) {
        objHitDetectFn_80062e84(param_1, state->queuedHitObject, 1);
        state->queuedHitObject = 0;
    }

    if (((state->heldFlags >> 7) & 1) != 0) {
        sp1c[0] = barrel->anim.localPosX - barrel->anim.previousLocalPosX;
        sp1c[1] = barrel->anim.localPosY - barrel->anim.previousLocalPosY;
        sp1c[2] = barrel->anim.localPosZ - barrel->anim.previousLocalPosZ;
        {
            f32 inv = lbl_803E4324 * oneOverTimeDelta;
            sp1c[0] = sp1c[0] * inv;
            sp1c[1] = sp1c[1] * inv;
            sp1c[2] = sp1c[2] * inv;
        }
        state->throwVelX = sp1c[0] + state->throwVelX;
        state->throwVelY = sp1c[1] + state->throwVelY;
        state->throwVelZ = sp1c[2] + state->throwVelZ;
        sp1c[1] = lbl_803E42C0;
        state->throwVelX = lbl_803E4328 * state->throwVelX;
        state->throwVelY = lbl_803E4328 * state->throwVelY;
        state->throwVelZ = lbl_803E4328 * state->throwVelZ;
        state->throwVelY = sp1c[1];
        state->motionFlags = (u8)(state->motionFlags | 1);
    }

    if (state->heldByCarryInterface != 0) {
        goto copy_end;
    }

    if (objBboxFn_800640cc(param_1 + 0x80, param_1 + 0xc, lbl_803E432C, 1,
                    (int)&collision_buf[0], param_1, 8, -1, 0xff, 0) == 0) {
        goto copy_end;
    }

    if ((s8)*((u8 *)&collision_buf[0] + 0x51) == 0x14) {
        state->unk16 = 4;
    }

    if (((state->heldFlags >> 7) & 1) != 0 &&
        (s8)*((u8 *)&collision_buf[0] + 0x51) == 3) {
        gunpowderbarrel_setPlayerHeldState(param_1, 0);
        ObjGroup_RemoveObject(param_1, 0x16);
        goto copy_end;
    }

    sp10[0] = *((f32 *)&collision_buf[0] + 7);
    sp10[1] = *((f32 *)&collision_buf[0] + 8);
    sp10[2] = *((f32 *)&collision_buf[0] + 9);
    Vec3_ReflectAgainstNormal(sp10, (void *)(param_1 + 0x24), (void *)(param_1 + 0x24));
    Vec3_ReflectAgainstNormal(sp10, &state->throwVelX, &state->throwVelX);

    barrel->anim.velocityX = lbl_803E4330 * barrel->anim.velocityX;
    barrel->anim.velocityY = lbl_803E4330 * barrel->anim.velocityY;
    barrel->anim.velocityZ = lbl_803E4330 * barrel->anim.velocityZ;
    state->throwVelX = lbl_803E4330 * state->throwVelX;
    state->throwVelY = lbl_803E4330 * state->throwVelY;
    state->throwVelZ = lbl_803E4330 * state->throwVelZ;
    /* mark sp1c live: target stores into sp+0x1c..0x24 the dx/dy/dz */
    (void)sp1c;

    if (state->impactSoundCooldown > lbl_803E4334) {
        if (PSVECMag(&state->throwVelX) > lbl_803DBE84) {
            Sfx_PlayFromObject(param_1, 0x446);
        }
        state->impactSoundCooldown = lbl_803E42C0;
    }

copy_end:
    barrel->anim.previousLocalPosX = barrel->anim.localPosX;
    barrel->anim.previousLocalPosY = barrel->anim.localPosY;
    barrel->anim.previousLocalPosZ = barrel->anim.localPosZ;
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_801a1df8
 * EN v1.0 Address: 0x801A1DF8
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x801A1E50
 * EN v1.1 Size: 196b
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
 * Function: blasted_getExtraSize
 * EN v1.0 Address: 0x801A24A8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801A2690
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
int blasted_getExtraSize(void)
{
  return 0x14;
}

/*
 * --INFO--
 *
 * Function: blasted_getObjectTypeId
 * EN v1.0 Address: 0x801A24B0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x801A2698
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int blasted_getObjectTypeId(void)
{
  return 0;
}

/*
 * --INFO--
 *
 * Function: blasted_free
 * EN v1.0 Address: 0x801A24B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A26A0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void blasted_free(void)
{
}

/*
 * --INFO--
 *
 * Function: blasted_hitDetect
 * EN v1.0 Address: 0x801A24FC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801A26E4
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void blasted_hitDetect(void)
{
}

void blasted_render(int *obj, int p2, int p3, int p4, int p5, s8 visible)
{
  int *state = ((GameObject *)obj)->extra;
  if (visible != 0 && state[3] == 0) {
    objRenderFn_8003b8f4(lbl_803E4348);
  }
}

/*
 * --INFO--
 *
 * Function: FUN_801a1fb8
 * EN v1.0 Address: 0x801A1FB8
 * EN v1.0 Size: 920b
 * EN v1.1 Address: 0x801A2014
 * EN v1.1 Size: 744b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


extern int *lbl_803DCAC0; /* carryable-object interface singleton */
extern void ObjMsg_AllocQueue(int obj, int capacity);
extern void storeZeroToFloatParam(void *p);

typedef struct {
    u8 b7 : 1;
    u8 b6 : 1;
    u8 b5 : 1;
    u8 b4 : 1;
    u8 b3 : 1;
    u8 b2 : 1;
    u8 b1 : 1;
    u8 b0 : 1;
} BarrelBits;

/* EN v1.0 0x801A25E8  size: 464b  Gunpowder-barrel setup: registers with the
 * carryable interface and obj groups, zeroes the roll/contact state, seeds
 * the hit radius from the model's bound halfword, and latches the
 * indestructible bit for the cannon-range variant (type 0x754). */
#pragma scheduling off
#pragma peephole off
void gunpowderbarrel_init(int obj, u8 *def)
{
    GunpowderBarrelState *state = ((GameObject *)obj)->extra;

    state->unk07 |= 2;
    (*(void (**)(int, GunpowderBarrelState *, int))((char *)*lbl_803DCAC0 + 0x4))(obj, state, 5);
    ObjGroup_AddObject(obj, 0x19);
    ObjGroup_AddObject(obj, 0x16);
    ObjMsg_AllocQueue(obj, 8);
    ((GameObject *)obj)->unkF8 = 0;
    state->unk44 = 0;
    state->unk46 = 0;
    state->heldByCarryInterface = 0;
    state->unk3C = 0;
    state->unk16 = 0;
    state->fuseFrames = 0;
    state->unk3E = 0;
    state->unk40 = 0;
    state->unk30 = lbl_803E42C0;
    state->motionFlags = 0;
    storeZeroToFloatParam(&state->respawnTimer);
    storeZeroToFloatParam(&state->releaseTimer);
    state->motionFlags |= 1;
    {
        u8 v;
        if ((s8)def[0x19] >= 1) {
            v = 0;
        } else {
            v = 1;
        }
        ((BarrelBits *)&state->configFlags)->b7 = v;
        if (*(s16 *)(def + 0x1c) == 0) {
            v = 0;
        } else {
            v = 1;
        }
        ((BarrelBits *)&state->configFlags)->b6 = v;
    }
    ObjHits_EnableObject(obj);
    {
        ObjHitsPriorityState *hitState = (ObjHitsPriorityState *)((GameObject *)obj)->anim.hitReactState;
        state->hitRadius = (f32)hitState->primaryRadius;
        if (hitState != NULL) {
            hitState->trackContactMask = 1;
        }
    }
    ((BarrelBits *)&state->heldFlags)->b5 = 0;
    state->unk38 = lbl_803E42C0;
    state->linkedTimerObject = 0;
    (*(void (**)(GunpowderBarrelState *, int))((char *)*lbl_803DCAC0 + 0x2c))(state, 1);
    if (((GameObject *)obj)->anim.seqId == 0x754) {
        ((BarrelBits *)&state->heldFlags)->b1 = 1;
    }
}

extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern u8 *mapGetBlock(int idx);
extern u8 *mapBlockFn_800606ec(void *block, int idx);
extern int mapBlockFn_80060678(void *entry);
extern u8 *fn_8006070C(void *block, int idx);

/* EN v1.0 0x801A27B8  size: 280b  Flags every trigger/volume in the map
 * block under the object that carries the given event id: sets bits 0..1
 * on matching block entries and bit 1 on matching group records. Returns 0
 * when the block is missing or not trigger-enabled. */
#pragma dont_inline on
int fn_801A27B8(int obj, int id)
{
    u8 *block;

    block = mapGetBlock(objPosToMapBlockIdx(((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY,
                                            ((GameObject *)obj)->anim.localPosZ));
    if (block == NULL || (*(u16 *)(block + 4) & 0x8) == 0) {
        return 0;
    }
    {
        int j;
        int i;
        for (i = 0; i < *(u16 *)(block + 0x9a); i++) {
            u8 *e = mapBlockFn_800606ec(block, i);
            if (id == mapBlockFn_80060678(e)) {
                *(int *)(e + 0x10) |= 3;
            }
        }
        for (j = 0; j < *(u8 *)(block + 0xa2); j++) {
            u8 *g = fn_8006070C(block, j);
            u8 *p;
            int k;
            k = 0;
            p = g;
            for (; k < *(u8 *)(g + 0x41); k++) {
                if (*(u8 *)(p + 0x29) == id) {
                    *(int *)(g + 0x3c) |= 2;
                }
                p += 8;
            }
        }
    }
    return 1;
}
#pragma dont_inline reset

extern int  GameBit_Get(int bit);
extern void GameBit_Set(int bit, int val);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern int  lbl_803DDB18;

typedef struct BlastedTargetSetup {
    u8 pad00[0x1A];
    s16 pieceCount;
    s16 triggerId;
    s16 completedGameBit;
    s16 progressGameBit;
} BlastedTargetSetup;

typedef struct BlastedTargetState {
    u32 destroyedHitObjects[3];
    int triggerFired;
    u8 pad10;
    u8 damageStep;
    u8 pad12[2];
} BlastedTargetState;

STATIC_ASSERT(offsetof(BlastedTargetSetup, pieceCount) == 0x1A);
STATIC_ASSERT(offsetof(BlastedTargetSetup, triggerId) == 0x1C);
STATIC_ASSERT(offsetof(BlastedTargetSetup, completedGameBit) == 0x1E);
STATIC_ASSERT(offsetof(BlastedTargetSetup, progressGameBit) == 0x20);
STATIC_ASSERT(offsetof(BlastedTargetState, triggerFired) == 0x0C);
STATIC_ASSERT(offsetof(BlastedTargetState, damageStep) == 0x11);
STATIC_ASSERT(sizeof(BlastedTargetState) == 0x14);

/* EN v1.0 0x801A2928  size: 464b  Blasted-target update: once the target's
 * GameBit is latched, fires the map trigger; otherwise scans the model's
 * hit nodes for newly-destroyed (state 5) pieces, records each unique piece,
 * advances the damage model index, and on the final piece latches the
 * GameBit, fires the trigger, and swaps to the destroyed model. */
void blasted_update(int obj)
{
    BlastedTargetSetup *setup = (BlastedTargetSetup *)((GameObject *)obj)->anim.placementData;
    BlastedTargetState *state = ((GameObject *)obj)->extra;
    s16 total = setup->pieceCount;

    if (state->triggerFired != 0) {
        return;
    }
    if ((u32)GameBit_Get(setup->completedGameBit) != 0) {
        state->triggerFired = fn_801A27B8(obj, setup->triggerId);
        return;
    }
    {
        int i;
        for (i = 0; i < (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->priorityHitCount; i++) {
            u32 v;
            s8 m;
            int found;
            m = *(u8 *)&(*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->priorities[i];
            v = (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->hitObjects[i];
            found = 0;
            if (m != 5) {
                continue;
            }
            if (total == 0) {
                GameBit_Set(setup->completedGameBit, 1);
                return;
            }
            if (m == 5) {
                int k = 0;
                int cnt = state->damageStep;
                while (k != cnt) {
                    if (v == state->destroyedHitObjects[k++]) {
                        k = cnt;
                        found = 1;
                    }
                }
            }
            if (found == 0) {
                state->destroyedHitObjects[state->damageStep] = v;
                GameBit_Set(state->damageStep + 0x2de, 0);
                GameBit_Set(state->damageStep + 0x2df, 1);
                if (setup->progressGameBit != -1) {
                    GameBit_Set(setup->progressGameBit, state->damageStep + 1);
                }
                lbl_803DDB18 = 0x12c;
                if (state->damageStep + 1 > total) {
                    int n;
                    int lim;
                    lim = total + 1;
                    for (n = 0; n < lim; n++) {
                        GameBit_Set(n + 0x2de, 0);
                    }
                    GameBit_Set(setup->completedGameBit, 1);
                    fn_801A27B8(obj, setup->triggerId);
                    Obj_SetActiveModelIndex(obj, 2);
                    state->triggerFired = 1;
                } else {
                    state->damageStep = state->damageStep + 1;
                    Obj_SetActiveModelIndex(obj, state->damageStep);
                }
            }
        }
    }
}

extern int  timerCountDown(void *p);
extern void s16toFloat(void *p, int v);
extern void memset(void *p, int c, int n);
extern int  playerIsDisguised(u8 *player);
extern int  timer_isEffectMode(int obj);
extern void timer_clearManualFlags(int obj);
extern void timer_forceStart(int obj);
extern int  timer_hasExpired(int obj);
extern int  barrelgener_getLinkId(int gen);
extern void barrelgener_queueObjectRelease(int gen, int obj, int code);
extern void Obj_RemoveFromUpdateList(int obj);
extern u32  playerGetStateFlag310(u8 *player);
extern void setAButtonIcon(int kind);
extern void saveGame_saveObjectPos(int obj);
extern int  fn_802966B4(u8 *player);
extern int  fn_8029669C(u8 *player);
extern f32  fn_80296214(u8 *player);
extern f32  mathSinf(f32 x);
extern f32  mathCosf(f32 x);
extern void gunpowderbarrel_updatePhysics(int obj);
extern void fn_801A1230(int obj);
extern u8  *Obj_GetPlayerObject(void);
extern u8   framesThisStep;
extern f32  timeDelta;
extern f32  lbl_803E4338;
extern f32  lbl_803E42DC;
extern f32  lbl_803E433C;
extern f32  lbl_803E4340;
extern f32  lbl_803DBE80;

/* EN v1.0 0x801A1D48  size: 2208b  Gunpowder-barrel per-frame driver: runs
 * the fuse/respawn timers, manages the cannon attach link, drains the
 * held/released message queue, grows the hitbox while the fuse burns and
 * hands the barrel back to its generator, and handles the pickup/steal/toss
 * transitions against the player's carry state. */
void gunpowderbarrel_update(int obj)
{
    GunpowderBarrelState *state = ((GameObject *)obj)->extra;
    u8 *player = Obj_GetPlayerObject();
    int def = *(int *)&((GameObject *)obj)->anim.placementData;

    if (state->impactSoundCooldown <= lbl_803E4334) {
        state->impactSoundCooldown += timeDelta;
    }
    if (fn_80080150(&state->respawnTimer) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        if (timerCountDown(&state->respawnTimer) != 0) {
            state->fuseFrames = 0;
            state->unk16 = 0;
            state->motionFlags |= 1;
            ((GameObject *)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ObjHits_ClearHitVolumes(obj);
            ObjHitbox_SetCapsuleBounds(obj, 8, -2, 0x19);
            ObjHits_EnableObject(obj);
            ObjHits_SyncObjectPositionIfDirty(obj);
            gunpowderbarrel_updatePhysics(obj);
            gunpowderbarrel_setPlayerHeldState(obj, 0);
        }
        return;
    }
    if (fn_80080150(&state->releaseTimer) != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        timerCountDown(&state->releaseTimer);
        memset(&state->throwVelX, 0, 0xc);
        memset((void *)&((GameObject *)obj)->anim.velocityX, 0, 0xc);
        return;
    }
    if (((BarrelBits *)&state->heldFlags)->b5 == 0) {
        if (((BarrelBits *)&state->heldFlags)->b1 != 0 && playerIsDisguised(player) == 0) {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x10;
        } else {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~0x10;
        }
    }
    if (((GameObject *)obj)->unkC8 == NULL) {
        f32 range = lbl_803E4338;
        if ((u32)(state->linkedTimerObject = ObjGroup_FindNearestObject(0x4c, obj, &range)) != 0 &&
            timer_isEffectMode(state->linkedTimerObject) != 0 &&
            *(void **)(state->linkedTimerObject + 0xc4) == NULL) {
            ObjLink_AttachChild(obj, state->linkedTimerObject, 0);
        }
    } else {
        if (Obj_IsObjectAlive(state->linkedTimerObject) == 0 && *(void * *)&state->linkedTimerObject != NULL) {
            ObjLink_DetachChild(obj, state->linkedTimerObject);
            state->linkedTimerObject = 0;
        }
    }
    {
        u32 arg;
        int msg;
        msg = 0;
        arg = 0;
        while (ObjMsg_Pop(obj, &msg, 0, &arg) != 0) {
            switch (msg) {
            case 0xf:
                gunpowderbarrel_setPlayerHeldState(obj, 1);
                break;
            case 0x10:
                gunpowderbarrel_setPlayerHeldState(obj, 0);
                if (arg != 0) {
                    ObjGroup_AddObject(obj, 0x16);
                }
                break;
            }
        }
    }
    if (((BarrelBits *)&state->heldFlags)->b5 != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    } else {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
    }
    if (state->fuseFrames != 0) {
        state->fuseFrames += framesThisStep;
        state->hitRadius = state->radiusGrowthPerFrame * (f32)(u32)state->fuseFrames + lbl_803E42DC;
        ObjHitbox_SetCapsuleBounds(obj, (s32)state->hitRadius,
                                   (s32)(-state->hitRadius * lbl_803E4328),
                                   (s32)(state->hitRadius * lbl_803E4328));
        if (*(void * *)&state->linkedTimerObject != NULL) {
            timer_clearManualFlags(state->linkedTimerObject);
        }
        if (state->fuseFrames > 0x14) {
            int i;
            u32 gen;
            if (((BarrelBits *)&state->heldFlags)->b7 != 0) {
                gunpowderbarrel_setPlayerHeldState(obj, 0);
            }
            gen = 0;
            if (((GunpowderbarrelPlacement *)def)->unk1A != 0) {
                int cnt;
                int *objs = ObjGroup_GetObjects(0x3a, &cnt);
                int *p;
                i = 0;
                p = objs;
                for (; i < cnt; i++) {
                    if (((GunpowderbarrelPlacement *)def)->unk1A == barrelgener_getLinkId(*p)) {
                        gen = objs[i];
                        break;
                    }
                    p++;
                }
            } else {
                gen = ObjGroup_FindNearestObject(0x3a, obj, 0);
            }
            if (gen == 0) {
                Obj_RemoveFromUpdateList(obj);
                ObjHits_DisableObject(obj);
                ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                s16toFloat(&state->respawnTimer, 0x3c);
                return;
            }
            memset(&state->throwVelX, 0, 0xc);
            memset((void *)&((GameObject *)obj)->anim.velocityX, 0, 0xc);
            state->motionFlags &= ~2;
            ObjHits_RefreshObjectState(obj);
            if (((BarrelBits *)&state->configFlags)->b7 != 0) {
                s16toFloat(&state->respawnTimer, 0x3c);
                storeZeroToFloatParam(&state->releaseTimer);
                s16toFloat(&state->releaseTimer, 0x5a);
                barrelgener_queueObjectRelease(gen, obj, 0x46);
                ObjHits_ClearHitVolumes(obj);
                ObjHits_DisableObject(obj);
                ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                return;
            }
            Obj_RemoveFromUpdateList(obj);
            ObjHits_DisableObject(obj);
            ((GameObject *)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            return;
        }
        return;
    }
    if (state->heldByCarryInterface != 0) {
        if ((playerGetStateFlag310(player) & 0x4000) != 0) {
            setAButtonIcon(5);
        } else {
            setAButtonIcon(4);
        }
    } else {
        if (((BarrelBits *)&state->configFlags)->b6 != 0 && ((BarrelBits *)&state->heldFlags)->b4 != 0 &&
            (state->motionFlags & 2) == 0) {
            saveGame_saveObjectPos(obj);
        }
    }
    if ((state->motionFlags & 2) != 0 || ((BarrelBits *)&state->heldFlags)->b5 != 0 ||
        (*(int (**)(int, GunpowderBarrelState *))((char *)*lbl_803DCAC0 + 0x8))(obj, state) == 0 ||
        (((BarrelBits *)&state->heldFlags)->b1 != 0 && playerIsDisguised(player) == 0)) {
        ObjHits_EnableObject(obj);
        fn_801A1230(obj);
        ((GameObject *)obj)->anim.alpha = 0xff;
        if (state->heldByCarryInterface != 0) {
            state->heldByCarryInterface = 0;
            if (fn_802966B4(player) != 0) {
                ObjHits_SyncObjectPositionIfDirty(obj);
            } else if (fn_8029669C(player) != 0) {
                ObjHits_MarkObjectPositionDirty(obj);
                gunpowderbarrel_launchAtTarget(obj, 1);
            } else if (lbl_803E42C0 == fn_80296214(player)) {
                ObjHits_SyncObjectPositionIfDirty(obj);
                gunpowderbarrel_launchAtTarget(obj, 0);
            } else if (state->fuseFrames == 0) {
                ((GameObject *)obj)->anim.velocityX = state->throwVelX =
                    mathSinf(lbl_803E433C * (f32)*(s16 *)player / lbl_803E4340);
                ((GameObject *)obj)->anim.velocityY = state->throwVelY = lbl_803E42C0;
                ((GameObject *)obj)->anim.velocityZ = state->throwVelZ =
                    mathCosf(lbl_803E433C * (f32)*(s16 *)player / lbl_803E4340);
                ((GameObject *)obj)->anim.localPosX =
                    lbl_803DBE80 * -mathSinf(lbl_803E433C * (f32)*(s16 *)player /
                                                lbl_803E4340) +
                    ((GameObject *)obj)->anim.localPosX;
                ((GameObject *)obj)->anim.localPosZ =
                    lbl_803DBE80 * -mathCosf(lbl_803E433C * (f32)*(s16 *)player / lbl_803E4340) +
                    ((GameObject *)obj)->anim.localPosZ;
                ObjGroup_AddObject(obj, 0x16);
            }
            ObjGroup_AddObject(obj, 0x16);
        }
        gunpowderbarrel_updatePhysics(obj);
    } else {
        state->motionFlags |= 1;
        if (state->heldByCarryInterface == 0) {
            if (*(void * *)&state->linkedTimerObject != NULL) {
                timer_forceStart(state->linkedTimerObject);
            }
            ObjGroup_RemoveObject(obj, 0x16);
        }
        state->heldByCarryInterface = 1;
        ((BarrelBits *)&state->heldFlags)->b6 = 1;
        state->launchYaw = *(s16 *)player;
        fn_801A1230(obj);
    }
    if (((BarrelBits *)&state->heldFlags)->b5 != 0) {
        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
        if (((BarrelBits *)&state->heldFlags)->b6 != 0 && ((BarrelBits *)&state->heldFlags)->b7 != 0) {
            state->throwVelX = ((GameObject *)obj)->anim.velocityX;
            state->throwVelY = ((GameObject *)obj)->anim.velocityY;
            state->throwVelZ = ((GameObject *)obj)->anim.velocityZ;
            state->throwVelY = lbl_803E42C0;
            ((BarrelBits *)&state->heldFlags)->b6 = 0;
        }
    }
    if (*(void * *)&state->linkedTimerObject != NULL) {
        if (timer_hasExpired(state->linkedTimerObject) != 0) {
            state->unk16 = 0xa;
        }
    }
}
