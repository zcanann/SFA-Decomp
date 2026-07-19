#include "main/dll/partfx_interface.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/mtx.h"
#include "main/audio/sfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/maketex_timer_api.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/obj_list.h"
#include "main/obj_path.h"
#include "main/vecmath.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/dll/rom_curve_interface.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/objfx.h"
#include "main/dll/dll_029B_arwingandrossstuff.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/dll/ARW/dll_02A6_arwsquadron.h"
#include "main/dll/headdisplay.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"

#define ARW_SQUADRON_PARTFX_SMOKE 0x7d0 /* damage smoke effect (pfx.f8 = damageSmokeScale) */
#define ARW_SQUADRON_PARTFX_FIRE  0x7d1 /* fire effect (pfx.f8 = fireFxScale) */

#define ARWSQUADRON_HIT_VOLUME_SLOT 0x13

#define ARW_SQUADRON_STATE_WAITING  0
#define ARW_SQUADRON_STATE_ACTIVE   1
#define ARW_SQUADRON_STATE_DEAD     3
#define ARW_SQUADRON_STATE_DISABLED 4

/* Object defNos (ObjPlacement.objectId) handled by this DLL; names read from
 * retail OBJECTS.bin at def+0x91, all gating to this file's own DLL 0x2A6. */
#define ARW_SQUADRON_OBJ                0x7f0
#define ARW_SQUADRON_BIGASTEROID_OBJ    0x616
#define ARW_SQUADRON_SMALLASTEROID_OBJ  0x617

/* variant 1 is the gun-armed fighter (it reads a muzzle/projectile seq table
 * below); 2 is ARW_SQUADRON_OBJ itself; 3 is the two asteroid defNos, which are
 * the only variant seeded with random per-axis tumble in arwsquadron_init. */
#define ARW_SQUADRON_VARIANT_FIGHTER  1
#define ARW_SQUADRON_VARIANT_SQUADRON 2
#define ARW_SQUADRON_VARIANT_ASTEROID 3

/* fighter-variant seqIds (retail OBJECTS.bin names, all DLL 0x2A6) */
#define ARW_SQUADRON_SEQID_SHIP_FLY   0x6d5 /* "ARWShipFly" */
#define ARW_SQUADRON_SEQID_SHIP_TWIN  0x6d6 /* "ARWShipTwin" */
#define ARW_SQUADRON_SEQID_SHIP_ANGE  0x6d7 /* "ARWShipAnge..." */

#define ARWSQUADRON_CHILD_OBJ_PROJECTILE 0x6ae



static const int kArwSquadronDefaultCurveMode[1] = {40};
static const f32 kArwSquadronPlayerRangeMinZ[1] = { -100.0f };


static inline int arwsquadron_isPlayerWithinRangeZ(GameObject* obj, f32 range)
{
    GameObject* craft = (GameObject*)getArwing();
    f32 distZ;
    if (craft == NULL)
        craft = Obj_GetPlayerObject();
    distZ = obj->anim.localPosZ - craft->anim.localPosZ;
    return distZ < range && distZ > kArwSquadronPlayerRangeMinZ[0];
}

void arwsquadron_emitEffects(GameObject* obj, ArwSquadronState* state)
{
    u8 flag = 1;
    SquadPfx pfx;

    if ((s8)state->health <= 2)
    {
        if (state->fxFrameCounter++ % 2 != 0)
        {
            ObjPath_GetPointLocalPosition(obj, 4, &pfx.fx, &pfx.fy, &pfx.fz);
            pfx.f8 = state->damageSmokeScale;
            if ((s8)state->health <= 1)
                pfx.s6 = 0x61a8;
            else
                pfx.s6 = -0x63c0;
            (*gPartfxInterface)->spawnObject(obj, ARW_SQUADRON_PARTFX_SMOKE, &pfx, 4, -1, &flag);
        }
    }
    if ((s8)state->health <= 1)
    {
        pfx.s6 = 0xc0a;
        ObjPath_GetPointLocalPosition(obj, 5, &pfx.fx, &pfx.fy, &pfx.fz);
        pfx.f8 = state->fireFxScale;
        (*gPartfxInterface)->spawnObject(obj, ARW_SQUADRON_PARTFX_FIRE, &pfx, 4, -1, &flag);
    }
    if (state->muzzleCount != 0 && (s8)state->health > 1)
    {
        pfx.s0 = 0;
        pfx.s2 = 0;
        pfx.s4 = 0;
        pfx.f8 = 0.0f;
        ObjPath_GetPointLocalPosition(obj, 2, &pfx.fx, &pfx.fy, &pfx.fz);
        objfx_spawnLightPulse(obj, state->muzzleLightRadius, 2, 0, 0, state->muzzleLightIntensity, &pfx);
    }
    if (state->muzzleCount > 1 && (s8)state->health > 1)
    {
        ObjPath_GetPointLocalPosition(obj, 3, &pfx.fx, &pfx.fy, &pfx.fz);
        objfx_spawnLightPulse(obj, state->muzzleLightRadius, 2, 0, 0, state->muzzleLightIntensity, &pfx);
    }
}

void arwsquadron_applyCommandParams(GameObject* obj, ArwSquadronState* state)
{
    SquadCmdFlags* flags = &state->flags.cmd;
    ArwSquadronPathCommand* cmds = (ArwSquadronPathCommand*)state->curve.node9C;
    int i;

    if (cmds->signature == 0x28)
    {
        for (i = 0; i < 2; i++)
        {
            int cmd;
            f32 val;
            f32 speedScale = 0.25f;
            if (i == 0)
            {
                cmd = cmds->primaryCommand;
                cmd |= cmds->primaryCommand;
                val = cmds->primaryValue;
            }
            else
            {
                cmd = cmds->secondaryCommand;
                val = cmds->secondaryValue;
            }
            switch ((u8)cmd)
            {
            case 3:
                state->targetPathSpeed = val * speedScale;
                break;
            case 1:
                if (!flags->attackWindowOpen)
                {
                    ArwSquadronSetup* setup;
                    flags->attackWindowOpen = 1;
                    setup = (ArwSquadronSetup*)obj->anim.placementData;
                    if (state->variant == ARW_SQUADRON_VARIANT_FIGHTER)
                    {
                        flags->volleyInProgress = 0;
                        storeZeroToFloatParam(&state->volleyCooldownTimer);
                        s16toFloat(&state->volleyCooldownTimer, setup->volleyCooldown);
                    }
                }
                break;
            case 2:
                flags->attackWindowOpen = 0;
                break;
            case 4:
                if (!flags->rollCmdActive)
                {
                    flags->rollCmdActive = 1;
                    state->rotZSpeed = 4.0f * val;
                }
                break;
            case 5:
                flags->rollCmdActive = 0;
                break;
            }
        }
    }
}

void arwsquadron_followLeader(GameObject* obj, ArwSquadronState* state)
{
    ObjAnimComponent* objAnim = &obj->anim;
    GameObject* leaderObj = state->leaderObj;
    ObjAnimComponent* leaderAnim = &leaderObj->anim;
    ArwSquadronState* leaderState = (ArwSquadronState*)leaderObj->extra;
    ArwSquadronSetup* setup = (ArwSquadronSetup*)objAnim->placementData;
    MatrixTransform src;
    f32 mtx[16];
    f32 out[3];

    *(s16*)&state->swayPhaseX = state->swaySpeedX * timeDelta + state->swayPhaseX;
    *(s16*)&state->swayPhaseY = state->swaySpeedY * timeDelta + state->swayPhaseY;
    src.x = leaderAnim->localPosX;
    src.y = leaderAnim->localPosY;
    src.z = leaderAnim->localPosZ;
    src.scale = 1.0f;
    src.rotX = leaderAnim->rotX;
    src.rotY = leaderAnim->rotY;
    src.rotZ = leaderAnim->rotZ;
    out[0] = 15.0f * mathSinf(3.14159265f * state->swayPhaseX / 32768.0f) +
             5.0f * setup->leaderOffsetX;
    out[1] = 15.0f * mathSinf(3.14159265f * state->swayPhaseY / 32768.0f) +
             5.0f * setup->leaderOffsetY;
    out[2] = 5.0f * setup->leaderOffsetZ;
    setMatrixFromObjectTransposed(&src, mtx);
    PSMTXMultVec((MtxP)mtx, (const Vec*)out, (Vec*)&objAnim->localPosX);
    objAnim->velocityX = leaderAnim->velocityX;
    objAnim->velocityY = leaderAnim->velocityY;
    objAnim->velocityZ = leaderAnim->velocityZ;
    objAnim->rotX = leaderAnim->rotX;
    objAnim->rotY = leaderAnim->rotY;
    if (!state->flags.cmd.rollCmdActive)
    {
        objAnim->rotZ = state->rollAmplitude *
                            mathSinf(3.14159265f * state->swayPhaseX / 32768.0f) +
                        leaderAnim->rotZ;
    }
    state->flags.cmd.attackWindowOpen = leaderState->flags.cmd.attackWindowOpen;
    if (state->rotZSpeed > 0)
        state->flags.cmd.rollCmdActive = leaderState->flags.cmd.rollCmdActive;
    if (leaderState->phase == ARW_SQUADRON_STATE_DISABLED)
    {
        objAnim->flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject(obj);
        state->phase = ARW_SQUADRON_STATE_DISABLED;
        state->phase = ARW_SQUADRON_STATE_DISABLED;
    }
}

void arwsquadron_followPath(GameObject* obj, ArwSquadronState* state)
{
    ObjAnimComponent* objAnim = &obj->anim;
    ArwSquadronSetup* setup = (ArwSquadronSetup*)objAnim->placementData;
    int pathResult;

    pathResult = Obj_UpdateRomCurveFollowVelocity(obj, &state->curve, state->pathSpeed, 100.0f,
                                                  state->pathSpeed, 1);
    if (pathResult == -1)
    {
        objAnim->flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject(obj);
        state->phase = ARW_SQUADRON_STATE_DISABLED;
    }
    else
    {
        if (pathResult != 0)
            arwsquadron_applyCommandParams(obj, state);
        if (setup->pathMode == 2)
        {
            if (state->variant == ARW_SQUADRON_VARIANT_SQUADRON)
                Obj_SmoothTurnAnglesTowardVelocity(obj, (const Vec3f*)&objAnim->velocityX, 0xf, 50.0f,
                                                   1.0f);
            else
                Obj_SmoothTurnAnglesTowardVelocity(obj, (const Vec3f*)&objAnim->velocityX, 0xf,
                                                   state->flags.cmd.rollCmdActive ? 0.0f : 50.0f, 1.0f);
        }
        state->pathSpeed += interpolate(state->targetPathSpeed - state->pathSpeed, 0.1f, timeDelta);
        objMove((GameObject*)obj, objAnim->velocityX * timeDelta, objAnim->velocityY * timeDelta,
                objAnim->velocityZ * timeDelta);
    }
}

void arwsquadron_spawnProjectile(GameObject* obj, int pathIdx, int angle, int flag)
{
    f32 pz, py, px;
    GameObject* proj;
    ArwSquadronProjectileSetup* setup;
    if (Obj_IsLoadingLocked() == 0)
        return;
    ObjPath_GetPointWorldPosition(obj, pathIdx, &px, &py, &pz, 0);
    setup = (ArwSquadronProjectileSetup*)Obj_AllocObjectSetup(0x20, ARWSQUADRON_CHILD_OBJ_PROJECTILE);
    ((ArwSquadronProjectileSetup*)setup)->posX = px;
    ((ArwSquadronProjectileSetup*)setup)->posY = py;
    ((ArwSquadronProjectileSetup*)setup)->posZ = pz;
    ((ArwSquadronProjectileSetup*)setup)->rotX = ((obj)->anim.rotX + 0x10000 + angle - 0x8000) >> 8;
    ((ArwSquadronProjectileSetup*)setup)->rotY = -(obj)->anim.rotY >> 8;
    ((ArwSquadronProjectileSetup*)setup)->rotZ = 0;
    ((ArwSquadronProjectileSetup*)setup)->field04 = 1;
    ((ArwSquadronProjectileSetup*)setup)->field05 = 1;
    proj = loadObjectAtObject(obj, (ObjPlacement*)setup);
    if (proj == NULL)
        return;
    if ((u8)flag != 0)
        arwprojectile_createLinkedEffect(proj, 1);
    arwprojectile_setLifetime(proj, 0x4b);
    arwprojectile_placeForward(proj, 40.0f);
    Sfx_PlayFromObjectLimited((int)proj, SFXTRIG_wp_blaserhit16, 4);
}

void arwsquadron_handleDamage(GameObject* obj, ArwSquadronState* squad)
{
    SquadCmdFlags* flags = &squad->flags.cmd;
    int hitObj;
    u32 hitVol;
    int arwing;

    if ((obj)->anim.hitReactState == NULL)
        return;
    if (squad->hitFlashActive != 0)
    {
        squad->hitFlashTimer -= timeDelta;
        if (squad->hitFlashTimer <= 0.0f)
            squad->hitFlashActive = 0;
        if (flags->acceptsDamage)
        {
            squad->hitFadeRed = 12816.0f * timeDelta + (f32) * (u16*)&squad->hitFadeRed;
            squad->hitFadeGreen = 10304.0f * timeDelta + (f32) * (u16*)&squad->hitFadeGreen;
        }
    }
    if (ObjHits_GetPriorityHit(obj, &hitObj, 0, &hitVol) != 0 ||
        ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->lastHitObject != 0)
    {
        if (flags->acceptsDamage)
        {
            if (squad->hitFlashActive == 0)
                Sfx_PlayFromObjectLimited((int)obj, SFXTRIG_wmap_nameoff_29e, 4);
            Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
            squad->hitFlashTimer = 25.0f;
            squad->hitFlashActive = 1;
            squad->hitFadeRed = 0;
            squad->hitFadeGreen = 0;
            *(s8*)&squad->health = squad->health - hitVol;
            if ((s8)squad->health <= 0)
            {
                storeZeroToFloatParam(&squad->deathTimer);
                s16toFloat(&squad->deathTimer, 0x78);
                if (squad->variant == ARW_SQUADRON_VARIANT_FIGHTER)
                {
                    spawnExplosion((GameObject*)(int)obj, 100.0f, 1, 0, 1, 1, 0, 0, 0);
                    (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    ObjHits_DisableObject(obj);
                    squad->phase = ARW_SQUADRON_STATE_DISABLED;
                    squad->phase = ARW_SQUADRON_STATE_DEAD;
                    if (squad->dialogueVariant == 3)
                        gameTextFn_80125ba4(0xe);
                }
                else
                {
                    spawnExplosion((GameObject*)(int)obj, 100.0f, 1, 0, 0, 1, 0, 0, 3);
                    (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    ObjHits_DisableObject(obj);
                    squad->phase = ARW_SQUADRON_STATE_DEAD;
                }
                arwing = (int)getArwing();
                if ((u32)arwing != 0)
                    arwarwing_addScore((GameObject*)arwing, squad->deathScore);
            }
            else
            {
                arwing = (int)getArwing();
                if ((u32)arwing != 0)
                    arwarwing_addScore((GameObject*)arwing, squad->hitScore);
            }
        }
        else
        {
            if (squad->hitFlashActive == 0)
                Sfx_PlayFromObjectLimited((int)obj, SFXTRIG_ar_laser116, 4);
            squad->hitFlashTimer = 25.0f;
            squad->hitFlashActive = 1;
        }
    }
}

void arwsquadron_updateVolley(GameObject* obj, ArwSquadronState* state, ArwSquadronSetup* setup)
{
    SquadCmdFlags* flags = &state->flags.cmd;

    if (!flags->volleyInProgress)
    {
        if (timerCountDown(&state->volleyCooldownTimer) != 0)
        {
            flags->volleyInProgress = 1;
            storeZeroToFloatParam(&state->shotIntervalTimer);
            s16toFloat(&state->shotIntervalTimer, setup->shotInterval);
            *(s8*)&state->volleyShotsRemaining = setup->shotsPerVolley;
            state->volleyAngle = -setup->volleyAngleSpread;
        }
    }
    else if (timerCountDown(&state->shotIntervalTimer) != 0)
    {
        arwsquadron_spawnProjectile(obj, 0, state->volleyAngle,
                                    (s8)state->volleyShotsRemaining == setup->shotsPerVolley ? 1 : 0);
        if (state->projectilePathCount > 1)
            arwsquadron_spawnProjectile(obj, 1, state->volleyAngle, 0);
        state->volleyShotsRemaining--;
        storeZeroToFloatParam(&state->shotIntervalTimer);
        s16toFloat(&state->shotIntervalTimer, setup->shotInterval);
        state->volleyAngle += setup->volleyAngleSpread * 2 / setup->shotsPerVolley;
        if ((s8)state->volleyShotsRemaining <= 0)
        {
            flags->volleyInProgress = 0;
            storeZeroToFloatParam(&state->volleyCooldownTimer);
            s16toFloat(&state->volleyCooldownTimer, setup->volleyCooldown);
        }
    }
}

int ARWSquadron_getExtraSize(void)
{
    return 0x164;
}

int ARWSquadron_getObjectTypeId(void)
{
    return 0;
}

void ARWSquadron_free(void)
{
}


ObjectDescriptor gARWSquadronObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS, 0, 0, 0,
    (ObjectDescriptorCallback)ARWSquadron_init, (ObjectDescriptorCallback)ARWSquadron_update,
    (ObjectDescriptorCallback)ARWSquadron_hitDetect, (ObjectDescriptorCallback)ARWSquadron_render,
    (ObjectDescriptorCallback)ARWSquadron_free, (ObjectDescriptorCallback)ARWSquadron_getObjectTypeId,
    ARWSquadron_getExtraSize,
};
void ARWSquadron_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderModelAndHitVolumes((GameObject*)obj, p2, p3, p4, p5, 1.0f);
}

void ARWSquadron_hitDetect(void)
{
}

void ARWSquadron_update(int obj)
{
    ArwSquadronState* state = *(ArwSquadronState**)&((GameObject*)obj)->extra;
    ArwSquadronSetup* setup = *(ArwSquadronSetup**)&((GameObject*)obj)->anim.placementData;
    SquadCmdFlags* flags = &state->flags.cmd;
    u8 phase = state->phase;

    if (phase == ARW_SQUADRON_STATE_DISABLED || phase == ARW_SQUADRON_STATE_DEAD)
        return;

    if (state->dialogueVariant == 1)
    {
        if (arwsquadron_isPlayerWithinRangeZ((GameObject*)obj, 2700.0f))
        {
            if (randomGetRange(0, 1) != 0)
                gameTextFn_80125ba4(0x10);
            else
                gameTextFn_80125ba4(0xd);
            state->dialogueVariant = 0;
        }
    }

    switch (state->phase)
    {
    case ARW_SQUADRON_STATE_WAITING:
    {
        GameObject* leader;
        ArwSquadronSetup* placement = *(ArwSquadronSetup**)&((GameObject*)obj)->anim.placementData;
        int activate;
        getArwing();
        leader = (GameObject*)obj;
        if (placement->leaderObjectId > 0)
        {
            if (state->leaderObj == NULL)
                state->leaderObj = ObjList_FindObjectById(placement->leaderObjectId);
            leader = state->leaderObj;
        }
        if (leader != NULL && arwsquadron_isPlayerWithinRangeZ(leader, state->activationDistance) &&
            ((placement->gameBit <= 0 && arwsquadron_isPlayerWithinRangeZ(leader, state->exitDistance)) ||
             mainGetBit(placement->gameBit) != 0))
            activate = 1;
        else
            activate = 0;
        if (activate)
        {
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ObjHits_EnableObject((GameObject*)obj);
            state->phase = ARW_SQUADRON_STATE_ACTIVE;
            {
                ArwSquadronSetup* volleyPlacement = *(ArwSquadronSetup**)&((GameObject*)obj)->anim.placementData;
                if (state->variant == ARW_SQUADRON_VARIANT_FIGHTER)
                {
                    flags->volleyInProgress = 0;
                    storeZeroToFloatParam(&state->volleyCooldownTimer);
                    s16toFloat(&state->volleyCooldownTimer, volleyPlacement->volleyCooldown);
                }
            }
        }
        return;
    }
    case ARW_SQUADRON_STATE_ACTIVE:
    {
        GameObject* leader;
        ArwSquadronSetup* placement;
        int deactivate;
        ((GameObject*)obj)->anim.alpha = 0xff;
        placement = *(ArwSquadronSetup**)&((GameObject*)obj)->anim.placementData;
        getArwing();
        leader = (GameObject*)obj;
        if (state->leaderObj != NULL)
            leader = state->leaderObj;
        if (leader != NULL && !arwsquadron_isPlayerWithinRangeZ(leader, state->activationDistance) &&
            ((placement->gameBit <= 0 && !arwsquadron_isPlayerWithinRangeZ(leader, state->exitDistance)) ||
             mainGetBit(placement->gameBit) == 0))
            deactivate = 1;
        else
            deactivate = 0;
        if (deactivate)
        {
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_DisableObject((GameObject*)obj);
            state->phase = ARW_SQUADRON_STATE_DISABLED;
            return;
        }
        if (state->variant != ARW_SQUADRON_VARIANT_SQUADRON)
        {
            if (setup->pathMode != 2)
            {
                ((GameObject*)obj)->anim.rotX = state->rotXSpeed * timeDelta + (f32)((GameObject*)obj)->anim.rotX;
                ((GameObject*)obj)->anim.rotY = state->rotYSpeed * timeDelta + (f32)((GameObject*)obj)->anim.rotY;
            }
            if (flags->rollCmdActive || setup->pathMode != 2)
            {
                ((GameObject*)obj)->anim.rotZ = state->rotZSpeed * timeDelta + (f32)((GameObject*)obj)->anim.rotZ;
            }
        }
        if (state->leaderObj != NULL)
        {
            arwsquadron_followLeader((GameObject*)obj, state);
        }
        else if (flags->followingCurve)
        {
            arwsquadron_followPath((GameObject*)obj, state);
        }
        if (flags->attackWindowOpen)
        {
            ArwSquadronSetup* volleyPlacement = *(ArwSquadronSetup**)&((GameObject*)obj)->anim.placementData;
            ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, ARWSQUADRON_HIT_VOLUME_SLOT, state->hitVolumeMode, 0);
            if (state->variant == ARW_SQUADRON_VARIANT_FIGHTER)
                arwsquadron_updateVolley((GameObject*)obj, state, volleyPlacement);
        }
        break;
    }
    case ARW_SQUADRON_STATE_DEAD:
    case ARW_SQUADRON_STATE_DISABLED:
        return;
    default:
        break;
    }

    arwsquadron_handleDamage((GameObject*)obj, state);
    if (state->variant == ARW_SQUADRON_VARIANT_FIGHTER)
        arwsquadron_emitEffects((GameObject*)obj, state);
    if (((GameObject*)obj)->anim.modelInstance->flags == 0)
        ObjAnim_AdvanceCurrentMove((int)obj, 0.01f, timeDelta, 0);
}

void ARWSquadron_init(GameObject* obj, ArwSquadronSetup* setup)
{
    SquadFlags* flags;
    ArwSquadronState* state;
    ArwSquadronSetup* setupData;
    int curveMode;
    f32 fxScale;
    f32 pathSpeedScale = 0.25f;

    curveMode = kArwSquadronDefaultCurveMode[0];
    state = (ArwSquadronState*)obj->extra;
    setupData = setup;
    flags = &state->flags.init;

    obj->anim.rotX = setupData->rotX << 8;
    obj->anim.rotY = setupData->rotY << 8;
    obj->anim.rotZ = setupData->rotZ << 8;
    flags->acceptsDamage = 1;
    state->health = 1;
    state->pathSpeed = (f32)(u32)setupData->pathSpeed * pathSpeedScale;
    state->targetPathSpeed = state->pathSpeed;
    state->rotXSpeed = setupData->rotXSpeed << 4;
    state->rotYSpeed = setupData->rotYSpeed << 4;
    state->rotZSpeed = setupData->rotZSpeed << 4;
    ObjHits_SetTargetMask(obj, 4);

    if (setupData->objectId == ARW_SQUADRON_BIGASTEROID_OBJ || setupData->objectId == ARW_SQUADRON_SMALLASTEROID_OBJ)
    {
        state->variant = ARW_SQUADRON_VARIANT_ASTEROID;
        if (setupData->objectId == ARW_SQUADRON_BIGASTEROID_OBJ)
        {
            flags->acceptsDamage = 0;
        }
        if (setupData->objectId == ARW_SQUADRON_BIGASTEROID_OBJ)
        {
            state->activationDistance = 10000.0f;
        }
        else
        {
            state->activationDistance = 5000.0f;
        }
        state->deathScore = 5;
        state->hitScore = 0;
        if (setupData->objectId == ARW_SQUADRON_BIGASTEROID_OBJ)
        {
            state->hitVolumeMode = 2;
        }
        else
        {
            state->hitVolumeMode = 1;
        }
        state->rotXSpeed = randomGetRange(-0x12c, 0x12c);
        state->rotYSpeed = randomGetRange(-0x12c, 0x12c);
        state->rotZSpeed = randomGetRange(-0x12c, 0x12c);
        flags->attackWindowOpen = 1;
    }
    else if (setupData->objectId == ARW_SQUADRON_OBJ)
    {
        state->variant = ARW_SQUADRON_VARIANT_SQUADRON;
        flags->acceptsDamage = 0;
        state->activationDistance = 10000.0f;
    }
    else
    {
        state->variant = ARW_SQUADRON_VARIANT_FIGHTER;
        state->activationDistance = 5000.0f;
        state->hitVolumeMode = 1;
        state->deathScore = 0x14;
        state->hitScore = 0;
        state->damageSmokeScale = 4.2f;
        fxScale = 4.0f;
        state->fireFxScale = fxScale;
        flags->attackWindowOpen = 1;
        switch (obj->anim.seqId)
        {
        case ARW_SQUADRON_SEQID_SHIP_TWIN:
            state->muzzleCount = 1;
            state->projectilePathCount = 2;
            state->muzzleLightRadius = 3.8f;
            state->muzzleLightIntensity = 0.3f;
            break;
        case ARW_SQUADRON_SEQID_SHIP_FLY:
            state->muzzleCount = 0;
            state->projectilePathCount = 1;
            break;
        case ARW_SQUADRON_SEQID_SHIP_ANGE:
            state->muzzleCount = 1;
            state->projectilePathCount = 1;
            state->muzzleLightRadius = fxScale;
            state->muzzleLightIntensity = 0.3f;
            break;
        default:
            state->muzzleCount = 1;
            state->projectilePathCount = 1;
            state->muzzleLightRadius = 4.0f;
            state->muzzleLightIntensity = 0.3f;
            break;
        }
    }

    state->exitDistance = (f32)(u32)setupData->exitDistance;
    if (state->exitDistance > state->activationDistance)
    {
        state->exitDistance = state->activationDistance;
    }
    obj->anim.alpha = 0;
    obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
    storeZeroToFloatParam(&state->deathTimer);

    if (setupData->pathMode != 0)
    {
        if (state->variant == ARW_SQUADRON_VARIANT_FIGHTER || state->variant == ARW_SQUADRON_VARIANT_SQUADRON)
        {
            curveMode = 0x28;
        }
        else
        {
            curveMode = 2;
        }
        if ((*gRomCurveInterface)->initCurve(&state->curve, obj, 200.0f, &curveMode, -1) == 0)
        {
            flags->followingCurve = 1;
            obj->anim.localPosX = state->curve.posX;
            obj->anim.localPosY = state->curve.posY;
            obj->anim.localPosZ = state->curve.posZ;
            arwsquadron_applyCommandParams(obj, state);
        }
    }

    state->swayPhaseX = randomGetRange(0, 0xffff);
    state->swayPhaseY = randomGetRange(0, 0xffff);
    state->swaySpeedX = randomGetRange(0xc8, 0x12c);
    state->swaySpeedY = randomGetRange(0xc8, 0x12c);
    state->rollAmplitude = (f32)(int)randomGetRange(0x3e8, 0x7d0);
    state->dialogueVariant = setupData->dialogueVariant;
}
