#include "main/dll/dll_80220608_shared.h"
#include "main/dll/dll_029B_arwingandrossstuff.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/dll/ARW/dll_02A6_arwsquadron.h"
#include "main/dll/headdisplay.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

#define ARW_SQUADRON_PARTFX_SMOKE 0x7d0 /* damage smoke effect (pfx.f8 = damageSmokeScale) */
#define ARW_SQUADRON_PARTFX_FIRE  0x7d1 /* fire effect (pfx.f8 = fireFxScale) */

#define ARWSQUADRON_HIT_VOLUME_SLOT 0x13

#define ARW_SQUADRON_STATE_WAITING  0
#define ARW_SQUADRON_STATE_ACTIVE   1
#define ARW_SQUADRON_STATE_DEAD     3
#define ARW_SQUADRON_STATE_DISABLED 4

#define ARW_SQUADRON_VARIANT_FIGHTER  1
#define ARW_SQUADRON_VARIANT_ASTEROID 2
#define ARW_SQUADRON_VARIANT_SHIP     3

#define ARWSQUADRON_CHILD_OBJ_PROJECTILE 0x6ae

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

void ARWSquadron_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E7188);
}

void ARWSquadron_hitDetect(void)
{
}

#pragma optimization_level 2
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
    ((ArwSquadronProjectileSetup*)setup)->rotZ = ((obj)->anim.rotX + 0x10000 + angle - 0x8000) >> 8;
    ((ArwSquadronProjectileSetup*)setup)->rotY = -(obj)->anim.rotY >> 8;
    ((ArwSquadronProjectileSetup*)setup)->rotX = 0;
    ((ArwSquadronProjectileSetup*)setup)->field04 = 1;
    ((ArwSquadronProjectileSetup*)setup)->field05 = 1;
    proj = (GameObject*)((int (*)(int, int))loadObjectAtObject)((int)obj, (int)setup);
    if (proj == NULL)
        return;
    if ((u8)flag != 0)
        arwprojectile_createLinkedEffect(proj, 1);
    arwprojectile_setLifetime(proj, 0x4b);
    arwprojectile_placeForward(proj, lbl_803E71A8);
    Sfx_PlayFromObjectLimited((int)proj, SFXTRIG_wp_blaserhit16, 4);
}
#pragma optimization_level reset

void ARWSquadron_init(GameObject* obj, ArwSquadronSetup* setup)
{
    SquadFlags* flags;
    ArwSquadronState* state;
    ArwSquadronSetup* setupData;
    int curveMode;
    f32 fxScale;

    curveMode = lbl_803E7160;
    state = (ArwSquadronState*)obj->extra;
    setupData = setup;
    flags = &state->flags.init;

    obj->anim.rotX = setupData->rotX << 8;
    obj->anim.rotY = setupData->rotY << 8;
    obj->anim.rotZ = setupData->rotZ << 8;
    flags->b10 = 1;
    state->health = 1;
    state->pathSpeed = (f32)(u32)setupData->pathSpeed * lbl_803E716C;
    state->targetPathSpeed = state->pathSpeed;
    state->rotXSpeed = setupData->rotXSpeed << 4;
    state->rotYSpeed = setupData->rotYSpeed << 4;
    state->rotZSpeed = setupData->rotZSpeed << 4;
    ObjHits_SetTargetMask((int)obj, 4);

    if (setupData->objectId == 0x616 || setupData->objectId == 0x617)
    {
        state->variant = ARW_SQUADRON_VARIANT_SHIP;
        if (setupData->objectId == 0x616)
        {
            flags->b10 = 0;
        }
        if (setupData->objectId == 0x616)
        {
            state->activationDistance = lbl_803E71C0;
        }
        else
        {
            state->activationDistance = lbl_803E71C4;
        }
        state->deathScore = 5;
        state->hitScore = 0;
        if (setupData->objectId == 0x616)
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
        flags->b80 = 1;
    }
    else if (setupData->objectId == 0x7f0)
    {
        state->variant = ARW_SQUADRON_VARIANT_ASTEROID;
        flags->b10 = 0;
        state->activationDistance = lbl_803E71C0;
    }
    else
    {
        state->variant = ARW_SQUADRON_VARIANT_FIGHTER;
        state->activationDistance = lbl_803E71C4;
        state->hitVolumeMode = 1;
        state->deathScore = 0x14;
        state->hitScore = 0;
        state->damageSmokeScale = lbl_803E71C8;
        fxScale = lbl_803E7170;
        state->fireFxScale = fxScale;
        flags->b80 = 1;
        switch (obj->anim.seqId)
        {
        case 0x6d6:
            state->muzzleCount = 1;
            state->projectilePathCount = 2;
            state->muzzleLightRadius = lbl_803E71CC;
            state->muzzleLightIntensity = lbl_803E71D0;
            break;
        case 0x6d5:
            state->muzzleCount = 0;
            state->projectilePathCount = 1;
            break;
        case 0x6d7:
            state->muzzleCount = 1;
            state->projectilePathCount = 1;
            state->muzzleLightRadius = fxScale;
            state->muzzleLightIntensity = lbl_803E71D0;
            break;
        default:
            state->muzzleCount = 1;
            state->projectilePathCount = 1;
            state->muzzleLightRadius = lbl_803E7170;
            state->muzzleLightIntensity = lbl_803E71D0;
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
        if (state->variant == ARW_SQUADRON_VARIANT_FIGHTER || state->variant == ARW_SQUADRON_VARIANT_ASTEROID)
        {
            curveMode = 0x28;
        }
        else
        {
            curveMode = 2;
        }
        if ((*gRomCurveInterface)->initCurve(state, obj, lbl_803E71D4, &curveMode, -1) == 0)
        {
            flags->b40 = 1;
            obj->anim.localPosX = state->curveX;
            obj->anim.localPosY = state->curveY;
            obj->anim.localPosZ = state->curveZ;
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

void arwsquadron_applyCommandParams(GameObject* obj, ArwSquadronState* state)
{
    SquadCmdFlags* flags = &state->flags.cmd;
    ArwSquadronPathCommand* cmds = state->commandData;
    int i;

    if (cmds->signature == 0x28)
    {
        for (i = 0; i < 2; i++)
        {
            int cmd;
            f32 val;
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
                state->targetPathSpeed = val * lbl_803E716C;
                break;
            case 1:
                if (!flags->f80)
                {
                    ArwSquadronSetup* setup;
                    flags->f80 = 1;
                    setup = (ArwSquadronSetup*)obj->anim.placementData;
                    if (state->variant == ARW_SQUADRON_VARIANT_FIGHTER)
                    {
                        flags->f20 = 0;
                        storeZeroToFloatParam(&state->volleyCooldownTimer);
                        s16toFloat(&state->volleyCooldownTimer, setup->volleyCooldown);
                    }
                }
                break;
            case 2:
                flags->f80 = 0;
                break;
            case 4:
                if (!flags->f08)
                {
                    flags->f08 = 1;
                    state->rotZSpeed = lbl_803E7170 * val;
                }
                break;
            case 5:
                flags->f08 = 0;
                break;
            }
        }
    }
}

void arwsquadron_followPath(GameObject* obj, ArwSquadronState* state)
{
    ObjAnimComponent* objAnim = &obj->anim;
    ArwSquadronSetup* setup = (ArwSquadronSetup*)objAnim->placementData;
    int pathResult;

    pathResult = Obj_UpdateRomCurveFollowVelocity(obj, (int)state, state->pathSpeed, lbl_803E719C,
                                                  state->pathSpeed, 1);
    if (pathResult == -1)
    {
        objAnim->flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject((int)obj);
        state->phase = ARW_SQUADRON_STATE_DISABLED;
    }
    else
    {
        if (pathResult != 0)
            arwsquadron_applyCommandParams(obj, state);
        if (setup->pathMode == 2)
        {
            if (state->variant == ARW_SQUADRON_VARIANT_ASTEROID)
                Obj_SmoothTurnAnglesTowardVelocity(obj, (int)&objAnim->velocityX, 0xf, lbl_803E71A0,
                                                   lbl_803E7188);
            else
                Obj_SmoothTurnAnglesTowardVelocity(obj, (int)&objAnim->velocityX, 0xf,
                                                   state->flags.cmd.f08 ? lbl_803E7168 : lbl_803E71A0, lbl_803E7188);
        }
        state->pathSpeed += interpolate(state->targetPathSpeed - state->pathSpeed, lbl_803E71A4, timeDelta);
        objMove((int)obj, objAnim->velocityX * timeDelta, objAnim->velocityY * timeDelta,
                objAnim->velocityZ * timeDelta);
    }
}

void arwsquadron_updateVolley(GameObject* obj, ArwSquadronState* state, ArwSquadronSetup* setup)
{
    SquadCmdFlags* flags = &state->flags.cmd;

    if (!flags->f20)
    {
        if (timerCountDown(&state->volleyCooldownTimer) != 0)
        {
            flags->f20 = 1;
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
            flags->f20 = 0;
            storeZeroToFloatParam(&state->volleyCooldownTimer);
            s16toFloat(&state->volleyCooldownTimer, setup->volleyCooldown);
        }
    }
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
        pfx.f8 = lbl_803E7168;
        ObjPath_GetPointLocalPosition(obj, 2, &pfx.fx, &pfx.fy, &pfx.fz);
        objfx_spawnLightPulse(obj, state->muzzleLightRadius, 2, 0, 0, state->muzzleLightIntensity,
                              (int)&pfx);
    }
    if (state->muzzleCount > 1 && (s8)state->health > 1)
    {
        ObjPath_GetPointLocalPosition(obj, 3, &pfx.fx, &pfx.fy, &pfx.fz);
        objfx_spawnLightPulse(obj, state->muzzleLightRadius, 2, 0, 0, state->muzzleLightIntensity,
                              (int)&pfx);
    }
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
        if (squad->hitFlashTimer <= lbl_803E7168)
            squad->hitFlashActive = 0;
        if (flags->f10)
        {
            squad->hitFadeRed = lbl_803E71AC * timeDelta + (f32) * (u16*)&squad->hitFadeRed;
            squad->hitFadeGreen = lbl_803E71B0 * timeDelta + (f32) * (u16*)&squad->hitFadeGreen;
        }
    }
    if (ObjHits_GetPriorityHit(obj, &hitObj, 0, &hitVol) != 0 ||
        ((ObjHitsPriorityState*)(obj)->anim.hitReactState)->lastHitObject != 0)
    {
        if (flags->f10)
        {
            if (squad->hitFlashActive == 0)
                Sfx_PlayFromObjectLimited((int)obj, SFXTRIG_wmap_nameoff_29e, 4);
            Obj_SetModelColorFadeRecursive((int)obj, 0xf, 0xc8, 0, 0, 1);
            squad->hitFlashTimer = lbl_803E71B4;
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
                    spawnExplosion((int)obj, lbl_803E719C, 1, 0, 1, 1, 0, 0, 0);
                    (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    ObjHits_DisableObject((int)obj);
                    squad->phase = ARW_SQUADRON_STATE_DISABLED;
                    squad->phase = ARW_SQUADRON_STATE_DEAD;
                    if (squad->dialogueVariant == 3)
                        gameTextFn_80125ba4(0xe);
                }
                else
                {
                    spawnExplosion((int)obj, lbl_803E719C, 1, 0, 0, 1, 0, 0, 3);
                    (obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    ObjHits_DisableObject((int)obj);
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
            squad->hitFlashTimer = lbl_803E71B4;
            squad->hitFlashActive = 1;
        }
    }
}

void arwsquadron_followLeader(GameObject* obj, ArwSquadronState* state)
{
    ObjAnimComponent* objAnim = &obj->anim;
    GameObject* leaderObj = (GameObject*)state->leaderObj;
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
    src.scale = lbl_803E7188;
    src.rotX = leaderAnim->rotX;
    src.rotY = leaderAnim->rotY;
    src.rotZ = leaderAnim->rotZ;
    out[0] = 15.0f * mathSinf(gArwingSquadronPi * state->swayPhaseX / gArwingSquadronSwayPhaseToAngleDiv) +
             5.0f * setup->leaderOffsetX;
    out[1] = 15.0f * mathSinf(gArwingSquadronPi * state->swayPhaseY / gArwingSquadronSwayPhaseToAngleDiv) +
             5.0f * setup->leaderOffsetY;
    out[2] = 5.0f * setup->leaderOffsetZ;
    setMatrixFromObjectTransposed(&src, mtx);
    PSMTXMultVec(mtx, out, &objAnim->localPosX);
    objAnim->velocityX = leaderAnim->velocityX;
    objAnim->velocityY = leaderAnim->velocityY;
    objAnim->velocityZ = leaderAnim->velocityZ;
    objAnim->rotX = leaderAnim->rotX;
    objAnim->rotY = leaderAnim->rotY;
    if (!state->flags.cmd.f08)
    {
        objAnim->rotZ = state->rollAmplitude *
                            mathSinf(gArwingSquadronPi * state->swayPhaseX / gArwingSquadronSwayPhaseToAngleDiv) +
                        leaderAnim->rotZ;
    }
    state->flags.cmd.f80 = leaderState->flags.cmd.f80;
    if (state->rotZSpeed > 0)
        state->flags.cmd.f08 = leaderState->flags.cmd.f08;
    if (leaderState->phase == ARW_SQUADRON_STATE_DISABLED)
    {
        objAnim->flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject((int)obj);
        state->phase = ARW_SQUADRON_STATE_DISABLED;
        state->phase = ARW_SQUADRON_STATE_DISABLED;
    }
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
        GameObject* aim = (GameObject*)getArwing();
        f32 deltaZ;
        int inRange;
        if (aim == NULL)
            aim = Obj_GetPlayerObject();
        deltaZ = ((GameObject*)obj)->anim.localPosZ - aim->anim.localPosZ;
        inRange = (deltaZ < lbl_803E71B8 && deltaZ > lbl_803E7164);
        if (inRange)
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
        int leader;
        ArwSquadronSetup* setupL = *(ArwSquadronSetup**)&((GameObject*)obj)->anim.placementData;
        int enable;
        getArwing();
        leader = obj;
        if (setupL->leaderObjectId > 0)
        {
            if ((u32)state->leaderObj == 0)
                state->leaderObj = ObjList_FindObjectById(setupL->leaderObjectId);
            leader = state->leaderObj;
        }
        if ((u32)leader == 0)
            goto enable0;
        {
            f32 thr = state->activationDistance;
            GameObject* aim = (GameObject*)getArwing();
            f32 deltaZ;
            int inRange;
            if (aim == NULL)
                aim = Obj_GetPlayerObject();
            deltaZ = ((GameObject*)leader)->anim.localPosZ - aim->anim.localPosZ;
            inRange = (deltaZ < thr && deltaZ > lbl_803E7164);
            if (!inRange)
                goto enable0;
            if (setupL->gameBit > 0)
                goto enableCheckBit;
            {
                f32 thr2 = state->exitDistance;
                GameObject* aim2 = (GameObject*)getArwing();
                f32 d2;
                int inRange2;
                if (aim2 == NULL)
                    aim2 = Obj_GetPlayerObject();
                d2 = ((GameObject*)leader)->anim.localPosZ - aim2->anim.localPosZ;
                inRange2 = (d2 < thr2 && d2 > lbl_803E7164);
                if (inRange2)
                    goto enable1;
            }
        enableCheckBit:
            if (mainGetBit(setupL->gameBit) == 0)
                goto enable0;
        }
    enable1:
        enable = 1;
        goto enableDone;
    enable0:
        enable = 0;
    enableDone:
        if (enable)
        {
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ObjHits_EnableObject(obj);
            state->phase = ARW_SQUADRON_STATE_ACTIVE;
            {
                ArwSquadronSetup* setupF = *(ArwSquadronSetup**)&((GameObject*)obj)->anim.placementData;
                if (state->variant == ARW_SQUADRON_VARIANT_FIGHTER)
                {
                    flags->f20 = 0;
                    storeZeroToFloatParam(&state->volleyCooldownTimer);
                    s16toFloat(&state->volleyCooldownTimer, setupF->volleyCooldown);
                }
            }
        }
        return;
    }
    case ARW_SQUADRON_STATE_ACTIVE:
    {
        int leader;
        ArwSquadronSetup* setupL;
        int disable;
        ((GameObject*)obj)->anim.alpha = 0xff;
        setupL = *(ArwSquadronSetup**)&((GameObject*)obj)->anim.placementData;
        getArwing();
        leader = obj;
        if ((u32)state->leaderObj != 0)
            leader = state->leaderObj;
        if ((u32)leader == 0)
            goto disable0;
        {
            f32 thr = state->activationDistance;
            GameObject* aim = (GameObject*)getArwing();
            f32 deltaZ;
            int inRange;
            if (aim == NULL)
                aim = Obj_GetPlayerObject();
            deltaZ = ((GameObject*)leader)->anim.localPosZ - aim->anim.localPosZ;
            inRange = (deltaZ < thr && deltaZ > lbl_803E7164);
            if (inRange)
                goto disable0;
            if (setupL->gameBit > 0)
                goto disableCheckBit;
            {
                f32 thr2 = state->exitDistance;
                GameObject* aim2 = (GameObject*)getArwing();
                f32 d2;
                int inRange2;
                if (aim2 == NULL)
                    aim2 = Obj_GetPlayerObject();
                d2 = ((GameObject*)leader)->anim.localPosZ - aim2->anim.localPosZ;
                inRange2 = (d2 < thr2 && d2 > lbl_803E7164);
                if (!inRange2)
                    goto disable1;
            }
        disableCheckBit:
            if (mainGetBit(setupL->gameBit) != 0)
                goto disable0;
        }
    disable1:
        disable = 1;
        goto disableDone;
    disable0:
        disable = 0;
    disableDone:
        if (disable)
        {
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_DisableObject(obj);
            state->phase = ARW_SQUADRON_STATE_DISABLED;
            return;
        }
        if (state->variant != ARW_SQUADRON_VARIANT_ASTEROID)
        {
            if (setup->pathMode != 2)
            {
                ((GameObject*)obj)->anim.rotX = state->rotXSpeed * timeDelta + (f32)((GameObject*)obj)->anim.rotX;
                ((GameObject*)obj)->anim.rotY = state->rotYSpeed * timeDelta + (f32)((GameObject*)obj)->anim.rotY;
            }
            if (flags->f08 || setup->pathMode != 2)
            {
                ((GameObject*)obj)->anim.rotZ = state->rotZSpeed * timeDelta + (f32)((GameObject*)obj)->anim.rotZ;
            }
        }
        if ((u32)state->leaderObj != 0)
        {
            arwsquadron_followLeader((GameObject*)obj, state);
        }
        else if (flags->f40)
        {
            arwsquadron_followPath((GameObject*)obj, state);
        }
        if (flags->f80)
        {
            ArwSquadronSetup* setupF = *(ArwSquadronSetup**)&((GameObject*)obj)->anim.placementData;
            ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, ARWSQUADRON_HIT_VOLUME_SLOT, state->hitVolumeMode, 0);
            if (state->variant == ARW_SQUADRON_VARIANT_FIGHTER)
                arwsquadron_updateVolley((GameObject*)obj, state, setupF);
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
        ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E71BC, timeDelta, 0);
}
