#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"


#define ARW_SQUADRON_STATE_WAITING 0
#define ARW_SQUADRON_STATE_ACTIVE 1
#define ARW_SQUADRON_STATE_DEAD 3
#define ARW_SQUADRON_STATE_DISABLED 4

#define ARW_SQUADRON_VARIANT_FIGHTER 1
#define ARW_SQUADRON_VARIANT_ASTEROID 2
#define ARW_SQUADRON_VARIANT_SHIP 3

typedef struct ArwSquadronSetup
{
    s16 objectId;
    u8 pad02[0x16];
    u8 rotX;
    u8 rotY;
    u8 rotZ;
    u8 rotXSpeed;
    u8 rotYSpeed;
    u8 rotZSpeed;
    s8 leaderOffsetZ;
    u8 pad1F;
    int leaderObjectId;
    u16 exitDistance;
    s8 leaderOffsetX;
    s8 leaderOffsetY;
    u8 pad28[2];
    u16 volleyAngleSpread;
    u8 volleyCooldown;
    u8 shotInterval;
    u8 shotsPerVolley;
    u8 pathMode;
    u8 pathSpeed;
    u8 dialogueVariant;
    s16 gameBit;
} ArwSquadronSetup;

typedef struct ArwSquadronProjectileSetup
{
    s16 objectId;
    u8 pad02[2];
    u8 field04;
    u8 field05;
    u8 pad06[2];
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad14[4];
    u8 rotX;
    u8 rotY;
    u8 rotZ;
} ArwSquadronProjectileSetup;

STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, field04) == 0x04);
STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, field05) == 0x05);
STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, posX) == 0x08);
STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, posY) == 0x0c);
STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, posZ) == 0x10);
STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, rotX) == 0x18);
STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, rotY) == 0x19);
STATIC_ASSERT(offsetof(ArwSquadronProjectileSetup, rotZ) == 0x1a);

typedef struct ArwSquadronPathCommand
{
    u8 pad00[0x18];
    u8 primaryCommand;
    s8 signature;
    s8 primaryValue;
    u8 pad1B[0x14];
    u8 secondaryCommand;
    u8 secondaryValue;
} ArwSquadronPathCommand;

/* arwsquadron_getExtraSize == 0x164 (ARWSquadron object family). */
typedef struct ArwSquadronState
{
    u8 pad000[0x68];
    f32 curveX;
    f32 curveY;
    f32 curveZ;
    u8 pad74[0x28];
    ArwSquadronPathCommand* commandData;
    u8 padA0[0x68];
    f32 pathSpeed;
    f32 targetPathSpeed;
    f32 hitFlashTimer;
    f32 muzzleLightRadius;
    f32 muzzleLightIntensity;
    f32 damageSmokeScale;
    f32 fireFxScale;
    f32 volleyCooldownTimer;
    f32 shotIntervalTimer;
    f32 deathTimer;
    f32 activationDistance;
    f32 exitDistance;
    f32 rollAmplitude;
    int leaderObj;
    s16 rotXSpeed;
    s16 rotYSpeed;
    s16 rotZSpeed;
    u16 swayPhaseX;
    u16 swayPhaseY;
    u16 swaySpeedX;
    u16 swaySpeedY;
    s16 volleyAngle;
    s16 hitFadeRed;
    s16 hitFadeGreen;
    u8 hitFlashActive;
    u8 volleyShotsRemaining;
    u8 hitVolumeMode;
    u8 deathScore;
    u8 hitScore;
    u8 phase;
    u8 muzzleCount;
    u8 projectilePathCount;
    u8 variant;
    u8 dialogueVariant;
    u8 health;
    u8 fxFrameCounter;

    union
    {
        SquadFlags init;
        SquadCmdFlags cmd;
    } flags;

    u8 pad161[3];
} ArwSquadronState;

STATIC_ASSERT(sizeof(ArwSquadronState) == 0x164);
STATIC_ASSERT(offsetof(ArwSquadronState, pathSpeed) == 0x108);
STATIC_ASSERT(offsetof(ArwSquadronState, volleyCooldownTimer) == 0x124);
STATIC_ASSERT(offsetof(ArwSquadronState, leaderObj) == 0x13c);
STATIC_ASSERT(offsetof(ArwSquadronState, flags) == 0x160);

int arwsquadron_getExtraSize(void) { return 0x164; }

int arwsquadron_getObjectTypeId(void) { return 0; }

void arwsquadron_free(void)
{
}

void arwsquadron_render(int obj, int p2, int p3, int p4, int p5)
{
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7188);
}

void arwsquadron_hitDetect(void)
{
}

#pragma optimization_level 2
void arwsquadron_spawnProjectile(int obj, int pathIdx, int angle, u8 flag)
{
    f32 pz, py, px;
    int proj;
    int setup;
    if (Obj_IsLoadingLocked() == 0)
        return;
    ObjPath_GetPointWorldPosition(obj, pathIdx, &px, &py, &pz, 0);
    setup = Obj_AllocObjectSetup(0x20, 0x6ae);
    ((ArwSquadronProjectileSetup*)setup)->posX = px;
    ((ArwSquadronProjectileSetup*)setup)->posY = py;
    ((ArwSquadronProjectileSetup*)setup)->posZ = pz;
    ((ArwSquadronProjectileSetup*)setup)->rotZ =
        (((GameObject*)obj)->anim.rotX + 0x10000 + angle - 0x8000) >> 8;
    ((ArwSquadronProjectileSetup*)setup)->rotY = -((GameObject*)obj)->anim.rotY >> 8;
    ((ArwSquadronProjectileSetup*)setup)->rotX = 0;
    ((ArwSquadronProjectileSetup*)setup)->field04 = 1;
    ((ArwSquadronProjectileSetup*)setup)->field05 = 1;
    proj = ((int (*)(int, int))loadObjectAtObject)(obj, setup);
    if ((u32)proj == 0)
        return;
    if (flag != 0)
        arwprojectile_createLinkedEffect(proj, 1);
    arwprojectile_setLifetime(proj, 0x4b);
    arwprojectile_placeForward(proj, lbl_803E71A8);
    Sfx_PlayFromObjectLimited(proj, SFXbaddie_eba_smallswipe1, 4);
}
#pragma optimization_level reset

void arwsquadron_init(int obj, int setup)
{
    SquadFlags* flags;
    ArwSquadronState* state;
    ArwSquadronSetup* setupData;
    int tmp;
    f32 fxScale;

    tmp = lbl_803E7160;
    state = *(ArwSquadronState**)&((GameObject*)obj)->extra;
    setupData = (ArwSquadronSetup*)setup;
    flags = &state->flags.init;

    ((GameObject*)obj)->anim.rotX = setupData->rotX << 8;
    ((GameObject*)obj)->anim.rotY = setupData->rotY << 8;
    ((GameObject*)obj)->anim.rotZ = setupData->rotZ << 8;
    flags->b10 = 1;
    state->health = 1;
    state->pathSpeed = (f32)(u32)
    setupData->pathSpeed * lbl_803E716C;
    state->targetPathSpeed = state->pathSpeed;
    state->rotXSpeed = setupData->rotXSpeed << 4;
    state->rotYSpeed = setupData->rotYSpeed << 4;
    state->rotZSpeed = setupData->rotZSpeed << 4;
    ObjHits_SetTargetMask(obj, 4);

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
        switch (((GameObject*)obj)->anim.seqId)
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

    state->exitDistance = (f32)(u32)
    setupData->exitDistance;
    if (state->exitDistance > state->activationDistance)
    {
        state->exitDistance = state->activationDistance;
    }
    ((GameObject*)obj)->anim.alpha = 0;
    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    storeZeroToFloatParam(&state->deathTimer);

    if (setupData->pathMode != 0)
    {
        if (state->variant == ARW_SQUADRON_VARIANT_FIGHTER || state->variant == ARW_SQUADRON_VARIANT_ASTEROID)
        {
            tmp = 0x28;
        }
        else
        {
            tmp = 2;
        }
        if ((*gRomCurveInterface)->initCurve(state, (void*)obj, lbl_803E71D4, &tmp, -1) == 0)
        {
            flags->b40 = 1;
            ((GameObject*)obj)->anim.localPosX = state->curveX;
            ((GameObject*)obj)->anim.localPosY = state->curveY;
            ((GameObject*)obj)->anim.localPosZ = state->curveZ;
            arwsquadron_applyCommandParams(obj, (int)state);
        }
    }

    state->swayPhaseX = randomGetRange(0, 0xffff);
    state->swayPhaseY = randomGetRange(0, 0xffff);
    state->swaySpeedX = randomGetRange(0xc8, 0x12c);
    state->swaySpeedY = randomGetRange(0xc8, 0x12c);
    state->rollAmplitude = (f32)(int)
    randomGetRange(0x3e8, 0x7d0);
    state->dialogueVariant = setupData->dialogueVariant;
}

void arwsquadron_applyCommandParams(int p1, int p2)
{
    GameObject* obj = (GameObject*)p1;
    ArwSquadronState* state = (ArwSquadronState*)p2;
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

void arwsquadron_followPath(int p1, int p2)
{
    GameObject* obj = (GameObject*)p1;
    ObjAnimComponent* objAnim = &obj->anim;
    ArwSquadronState* state = (ArwSquadronState*)p2;
    ArwSquadronSetup* setup = (ArwSquadronSetup*)objAnim->placementData;
    int r;

    r = Obj_UpdateRomCurveFollowVelocity(p1, p2, state->pathSpeed, lbl_803E719C, state->pathSpeed, 1);
    if (r == -1)
    {
        objAnim->flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject(p1);
        state->phase = ARW_SQUADRON_STATE_DISABLED;
    }
    else
    {
        if (r != 0)
            arwsquadron_applyCommandParams(p1, p2);
        if (setup->pathMode == 2)
        {
            if (state->variant == ARW_SQUADRON_VARIANT_ASTEROID)
                Obj_SmoothTurnAnglesTowardVelocity(p1, (int)&objAnim->velocityX, 0xf, lbl_803E71A0, lbl_803E7188);
            else
                Obj_SmoothTurnAnglesTowardVelocity(p1, (int)&objAnim->velocityX, 0xf,
                                                   state->flags.cmd.f08 ? lbl_803E7168 : lbl_803E71A0,
                                                   lbl_803E7188);
        }
        state->pathSpeed += interpolate(state->targetPathSpeed - state->pathSpeed, lbl_803E71A4, timeDelta);
        objMove(p1, objAnim->velocityX * timeDelta, objAnim->velocityY * timeDelta,
                objAnim->velocityZ * timeDelta);
    }
}

void arwsquadron_updateVolley(int p1, int p2, int p3)
{
    ArwSquadronState* state = (ArwSquadronState*)p2;
    ArwSquadronSetup* setup = (ArwSquadronSetup*)p3;
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
        extern void arwsquadron_spawnProjectile(int obj, int pathIdx, int angle, int flag);
        arwsquadron_spawnProjectile(p1, 0, state->volleyAngle,
                                    (s8)state->volleyShotsRemaining == setup->shotsPerVolley ? 1 : 0);
        if (state->projectilePathCount > 1)
            arwsquadron_spawnProjectile(p1, 1, state->volleyAngle, 0);
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

void arwsquadron_emitEffects(int p1, int p2)
{
    ArwSquadronState* state = (ArwSquadronState*)p2;
    u8 flag = 1;
    SquadPfx pfx;

    if ((s8)state->health <= 2)
    {
        if (state->fxFrameCounter++ % 2 != 0)
        {
            ObjPath_GetPointLocalPosition(p1, 4, &pfx.fx, &pfx.fy, &pfx.fz);
            pfx.f8 = state->damageSmokeScale;
            if ((s8)state->health <= 1)
                pfx.s6 = 0x61a8;
            else
                pfx.s6 = -0x63c0;
            (*gPartfxInterface)->spawnObject((void*)p1, 0x7d0, &pfx, 4, -1, &flag);
        }
    }
    if ((s8)state->health <= 1)
    {
        pfx.s6 = 0xc0a;
        ObjPath_GetPointLocalPosition(p1, 5, &pfx.fx, &pfx.fy, &pfx.fz);
        pfx.f8 = state->fireFxScale;
        (*gPartfxInterface)->spawnObject((void*)p1, 0x7d1, &pfx, 4, -1, &flag);
    }
    if (state->muzzleCount != 0 && (s8)state->health > 1)
    {
        pfx.s0 = 0;
        pfx.s2 = 0;
        pfx.s4 = 0;
        pfx.f8 = lbl_803E7168;
        ObjPath_GetPointLocalPosition(p1, 2, &pfx.fx, &pfx.fy, &pfx.fz);
        objfx_spawnLightPulse(p1, state->muzzleLightRadius, 2, 0, 0, state->muzzleLightIntensity, (int)&pfx);
    }
    if (state->muzzleCount > 1 && (s8)state->health > 1)
    {
        ObjPath_GetPointLocalPosition(p1, 3, &pfx.fx, &pfx.fy, &pfx.fz);
        objfx_spawnLightPulse(p1, state->muzzleLightRadius, 2, 0, 0, state->muzzleLightIntensity, (int)&pfx);
    }
}

void arwsquadron_handleDamage(int obj, int state)
{
    ArwSquadronState* squad = (ArwSquadronState*)state;
    SquadCmdFlags* flags = &squad->flags.cmd;
    int hitObj;
    u32 hitVol;
    int arwing;

    if (((GameObject*)obj)->anim.hitReactState == NULL)
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
        ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject != 0)
    {
        if (flags->f10)
        {
            if (squad->hitFlashActive == 0)
                Sfx_PlayFromObjectLimited(obj, SFXbaddie_mika_death, 4);
            Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
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
                    spawnExplosion(obj, lbl_803E719C, 1, 0, 1, 1, 0, 0, 0);
                    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    ObjHits_DisableObject(obj);
                    squad->phase = ARW_SQUADRON_STATE_DISABLED;
                    squad->phase = ARW_SQUADRON_STATE_DEAD;
                    if (squad->dialogueVariant == 3)
                        gameTextFn_80125ba4(0xe);
                }
                else
                {
                    spawnExplosion(obj, lbl_803E719C, 1, 0, 0, 1, 0, 0, 3);
                    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                    ObjHits_DisableObject(obj);
                    squad->phase = ARW_SQUADRON_STATE_DEAD;
                }
                arwing = getArwing();
                if ((u32)arwing != 0)
                    arwarwing_addScore(arwing, squad->deathScore);
            }
            else
            {
                arwing = getArwing();
                if ((u32)arwing != 0)
                    arwarwing_addScore(arwing, squad->hitScore);
            }
        }
        else
        {
            if (squad->hitFlashActive == 0)
                Sfx_PlayFromObjectLimited(obj, SFXbaddie_invin_hit, 4);
            squad->hitFlashTimer = lbl_803E71B4;
            squad->hitFlashActive = 1;
        }
    }
}

void arwsquadron_followLeader(int p1, int p2)
{
    GameObject* obj = (GameObject*)p1;
    ObjAnimComponent* objAnim = &obj->anim;
    ArwSquadronState* state = (ArwSquadronState*)p2;
    GameObject* leaderObj = (GameObject*)state->leaderObj;
    ObjAnimComponent* leaderAnim = &leaderObj->anim;
    ArwSquadronState* leaderState = (ArwSquadronState*)leaderObj->extra;
    ArwSquadronSetup* setup = (ArwSquadronSetup*)objAnim->placementData;
    ArwProjPosSrc src;
    f32 mtx[16];
    f32 out[3];

    *(s16*)&state->swayPhaseX = state->swaySpeedX * timeDelta + state->swayPhaseX;
    *(s16*)&state->swayPhaseY = state->swaySpeedY * timeDelta + state->swayPhaseY;
    src.pos[0] = leaderAnim->localPosX;
    src.pos[1] = leaderAnim->localPosY;
    src.pos[2] = leaderAnim->localPosZ;
    src.scale = lbl_803E7188;
    src.rot[0] = leaderAnim->rotX;
    src.rot[1] = leaderAnim->rotY;
    src.rot[2] = leaderAnim->rotZ;
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
        objAnim->rotZ =
            state->rollAmplitude *
            mathSinf(gArwingSquadronPi * state->swayPhaseX / gArwingSquadronSwayPhaseToAngleDiv) +
            leaderAnim->rotZ;
    }
    state->flags.cmd.f80 = leaderState->flags.cmd.f80;
    if (state->rotZSpeed > 0)
        state->flags.cmd.f08 = leaderState->flags.cmd.f08;
    if (leaderState->phase == ARW_SQUADRON_STATE_DISABLED)
    {
        objAnim->flags |= OBJANIM_FLAG_HIDDEN;
        ObjHits_DisableObject(p1);
        state->phase = ARW_SQUADRON_STATE_DISABLED;
        state->phase = ARW_SQUADRON_STATE_DISABLED;
    }
}

void arwsquadron_update(int obj)
{
    ArwSquadronState* state = *(ArwSquadronState**)&((GameObject*)obj)->extra;
    ArwSquadronSetup* setup = *(ArwSquadronSetup**)&((GameObject*)obj)->anim.placementData;
    SquadCmdFlags* flags = &state->flags.cmd;
    u8 phase = state->phase;

    if (phase == ARW_SQUADRON_STATE_DISABLED || phase == ARW_SQUADRON_STATE_DEAD)
        return;

    if (state->dialogueVariant == 1)
    {
        int aim = getArwing();
        f32 d;
        int inRange;
        if ((u32)aim == 0)
            aim = Obj_GetPlayerObject();
        d = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)aim)->anim.localPosZ;
        inRange = (d < lbl_803E71B8 && d > lbl_803E7164);
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
                int aim = getArwing();
                f32 d;
                int inRange;
                if ((u32)aim == 0)
                    aim = Obj_GetPlayerObject();
                d = ((GameObject*)leader)->anim.localPosZ - ((GameObject*)aim)->anim.localPosZ;
                inRange = (d < thr && d > lbl_803E7164);
                if (!inRange)
                    goto enable0;
                if (setupL->gameBit > 0)
                    goto enableCheckBit;
                {
                    f32 thr2 = state->exitDistance;
                    int aim2 = getArwing();
                    f32 d2;
                    int inRange2;
                    if ((u32)aim2 == 0)
                        aim2 = Obj_GetPlayerObject();
                    d2 = ((GameObject*)leader)->anim.localPosZ - ((GameObject*)aim2)->anim.localPosZ;
                    inRange2 = (d2 < thr2 && d2 > lbl_803E7164);
                    if (inRange2)
                        goto enable1;
                }
            enableCheckBit:
                if (GameBit_Get(setupL->gameBit) == 0)
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
                int aim = getArwing();
                f32 d;
                int inRange;
                if ((u32)aim == 0)
                    aim = Obj_GetPlayerObject();
                d = ((GameObject*)leader)->anim.localPosZ - ((GameObject*)aim)->anim.localPosZ;
                inRange = (d < thr && d > lbl_803E7164);
                if (inRange)
                    goto disable0;
                if (setupL->gameBit > 0)
                    goto disableCheckBit;
                {
                    f32 thr2 = state->exitDistance;
                    int aim2 = getArwing();
                    f32 d2;
                    int inRange2;
                    if ((u32)aim2 == 0)
                        aim2 = Obj_GetPlayerObject();
                    d2 = ((GameObject*)leader)->anim.localPosZ - ((GameObject*)aim2)->anim.localPosZ;
                    inRange2 = (d2 < thr2 && d2 > lbl_803E7164);
                    if (!inRange2)
                        goto disable1;
                }
            disableCheckBit:
                if (GameBit_Get(setupL->gameBit) != 0)
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
                    ((GameObject*)obj)->anim.rotX =
                        state->rotXSpeed * timeDelta + (f32)((GameObject*)obj)->anim.rotX;
                    ((GameObject*)obj)->anim.rotY =
                        state->rotYSpeed * timeDelta + (f32)((GameObject*)obj)->anim.rotY;
                }
                if (flags->f08 || setup->pathMode != 2)
                {
                    ((GameObject*)obj)->anim.rotZ =
                        state->rotZSpeed * timeDelta + (f32)((GameObject*)obj)->anim.rotZ;
                }
            }
            if ((u32)state->leaderObj != 0)
            {
                arwsquadron_followLeader(obj, (int)state);
            }
            else if (flags->f40)
            {
                arwsquadron_followPath(obj, (int)state);
            }
            if (flags->f80)
            {
                ArwSquadronSetup* setupF = *(ArwSquadronSetup**)&((GameObject*)obj)->anim.placementData;
                ObjHits_SetHitVolumeSlot(obj, 0x13, state->hitVolumeMode, 0);
                if (state->variant == ARW_SQUADRON_VARIANT_FIGHTER)
                    arwsquadron_updateVolley(obj, (int)state, (int)setupF);
            }
            break;
        }
    case ARW_SQUADRON_STATE_DEAD:
    case ARW_SQUADRON_STATE_DISABLED:
        return;
    default:
        break;
    }

    arwsquadron_handleDamage(obj, (int)state);
    if (state->variant == ARW_SQUADRON_VARIANT_FIGHTER)
        arwsquadron_emitEffects(obj, (int)state);
    if (((GameObject*)obj)->anim.modelInstance->flags == 0)
        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E71BC, timeDelta, 0);
}
