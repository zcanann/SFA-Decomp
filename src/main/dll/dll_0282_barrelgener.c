/*
 * barrelgener (DLL 0x282) - the barrel generator/dispenser object.
 *
 * Object-group member 0x3a. On init it joins that group and clears its
 * release state. When the player approaches within range it fires
 * trigger sequence 1 (once, gated by game bit 0xADB). A queued barrel
 * (barrelgener_queueObjectRelease, called from the gunpowder-barrel DLL)
 * is held until its release timer elapses: the dispense animation plays
 * with a PDA camera-off sfx, a compass beep fires partway through, and at
 * timer end the queued barrel is teleported to this object's position,
 * zeroed in velocity, and added to its own update group (25).
 *
 * The rest of the TU is a shared curve-following / steering / voxel
 * line-trace toolkit consumed by the Drakor-area and ArwingSquadron DLLs
 * (Obj_UpdateRomCurveFollowVelocity[Indexed], Obj_SteerVelocityTowardVector,
 * Obj_SmoothTurnAnglesTowardVelocity, the lightning-spawn helper, and the
 * voxmaps_trace* world-line wrappers).
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/barrelgener_state.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"

typedef struct ObjUpdateRomCurveFollowVelocityState
{
    u8 pad0[0x28C - 0x0];
    f32 velX;
    f32 velZ;
    u8 pad294[0x298 - 0x294];
} ObjUpdateRomCurveFollowVelocityState;

#define BARRELGENER_OBJGROUP 0x3a
#define GAMEBIT_BARRELGENER_TRIGGERED 0xadb

int barrelgener_getLinkId(int obj)
{
    BarrelGeneratorSetup* setup = (BarrelGeneratorSetup*)((GameObject*)obj)->anim.placementData;
    return setup->linkId;
}

void barrelgener_queueObjectRelease(int obj, int queuedObj, int releaseFrame)
{
    BarrelGeneratorState* state = ((GameObject*)obj)->extra;

    state->queuedObject = (GameObject*)queuedObj;
    state->releaseAnimPlaying = 0;
    storeZeroToFloatParam(&state->releaseTimer);
    s16toFloat(&state->releaseTimer, (s16)(releaseFrame - lbl_803DC398));
}

int barrelgener_getExtraSize(void) { return 0x10; }

int barrelgener_getObjectTypeId(void) { return 0; }

void barrelgener_free(int obj) { ObjGroup_RemoveObject(obj, BARRELGENER_OBJGROUP); }

void barrelgener_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E6C20);
    }
}

void barrelgener_hitDetect(void)
{
}

void barrelgener_init(int obj)
{
    BarrelGeneratorState* state = ((GameObject*)obj)->extra;

    ObjGroup_AddObject(obj, BARRELGENER_OBJGROUP);
    state->releaseAnimPlaying = 0;
    state->queuedObject = NULL;
    storeZeroToFloatParam(&state->releaseTimer);
}

void barrelgener_release(void)
{
}

void barrelgener_initialise(void)
{
}

void barrelgener_update(int obj)
{
    BarrelGeneratorState* state = ((GameObject*)obj)->extra;
    int player = Obj_GetPlayerObject();

    if ((u32)GameBit_Get(GAMEBIT_BARRELGENER_TRIGGERED) == 0)
    {
        if (Vec_distance(obj + 24, player + 24) < lbl_803E6C24)
        {
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
            GameBit_Set(GAMEBIT_BARRELGENER_TRIGGERED, 1);
        }
    }
    if (fn_80080150((int)&state->releaseTimer) != 0)
    {
        if (state->releaseTimer <= lbl_803E6C28 && state->releaseAnimPlaying == 0)
        {
            state->releaseAnimPlaying = 1;
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E6C2C, 0);
            Sfx_PlayFromObject(obj, SFXpda_fper_camoff);
            state->releaseBeepPlayed = 0;
        }
        if (timerCountDown((void*)&state->releaseTimer) != 0)
        {
            if (Obj_IsObjectAlive((int)state->queuedObject) != 0)
            {
                GameObject* releasedBarrel = state->queuedObject;
                f32 releaseVelocity;
                releasedBarrel->anim.localPosX = ((GameObject*)obj)->anim.localPosX;
                releasedBarrel->anim.localPosY = ((GameObject*)obj)->anim.localPosY;
                releasedBarrel->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ;
                releasedBarrel->anim.previousLocalPosX = releasedBarrel->anim.localPosX;
                releasedBarrel->anim.previousLocalPosY = releasedBarrel->anim.localPosY;
                releasedBarrel->anim.previousLocalPosZ = releasedBarrel->anim.localPosZ;
                releasedBarrel->anim.worldPosX = releasedBarrel->anim.localPosX;
                releasedBarrel->anim.worldPosY = releasedBarrel->anim.localPosY;
                releasedBarrel->anim.worldPosZ = releasedBarrel->anim.localPosZ;
                releaseVelocity = lbl_803E6C2C;
                releasedBarrel->anim.velocityZ = releaseVelocity;
                releasedBarrel->anim.velocityY = releaseVelocity;
                releasedBarrel->anim.velocityX = releaseVelocity;
                ObjGroup_AddObject((int)state->queuedObject, 25);
                state->queuedObject = NULL;
            }
        }
    }
    if (state->releaseAnimPlaying != 0)
    {
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E6C30)
        {
            if (state->releaseBeepPlayed == 0)
            {
                Sfx_PlayFromObject(obj, SFXpda_compassbeep);
                state->releaseBeepPlayed = 1;
            }
        }
        state->releaseAnimPlaying =
            !((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E6C34, timeDelta, 0);
    }
}

#pragma optimization_level 2
void Obj_SteerVelocityTowardVector(int out, f32* v1, f32* v2, f32 a, f32 b, f32 c)
{
    f32 mtx[12];
    f32 n1[3];
    f32 n2[3];
    f32 cross[3];
    f32 mag1, mag2, t, ang;
    int gt;
    f64 gtf;

    mag1 = PSVECMag(v1);
    if (mag1 > lbl_803E6C38)
    {
        f32 inv = lbl_803E6C6C / mag1;
        n1[0] = v1[0] * inv;
        n1[1] = v1[1] * inv;
        n1[2] = v1[2] * inv;
        PSVECNormalize(n1, n1);
    }
    else
    {
        n1[0] = lbl_803E6C38;
        n1[1] = lbl_803E6C38;
        n1[2] = lbl_803E6C38;
    }
    mag2 = PSVECMag(v2);
    if (mag2 > lbl_803E6C38)
    {
        f32 inv = lbl_803E6C6C / mag2;
        n2[0] = v2[0] * inv;
        n2[1] = v2[1] * inv;
        n2[2] = v2[2] * inv;
    }
    else
    {
        n2[0] = lbl_803E6C38;
        n2[1] = lbl_803E6C38;
        n2[2] = lbl_803E6C38;
    }
    PSVECCrossProduct(n1, n2, cross);
    if (PSVECMag(cross) > lbl_803E6C38)
    {
        ang = fn_80291FF4(PSVECDotProduct(n1, n2));
        gt = (ang > c);
        gtf = __fabs((f32)gt);
        if (gtf != lbl_803E6C38)
        {
            PSMTXRotAxisRad(mtx, cross, c * (ang > lbl_803E6C38 ? lbl_803E6C6C : lbl_803E6C70));
            PSMTXMultVecSR(mtx, n1, n2);
        }
    }
    t = mag2 * lbl_803E6C74;
    if (t > mag1 + b)
        t = mag1 + b;
    else if (t < mag1 - b)
        t = mag1 - b;
    if (t > a)
        t = a;
    ((GameObject*)out)->anim.velocityX = n2[0] * t;
    ((GameObject*)out)->anim.velocityY = n2[1] * t;
    ((GameObject*)out)->anim.velocityZ = n2[2] * t;
}
#pragma optimization_level reset

int Obj_UpdateRomCurveFollowVelocity(int obj, int routePtr, f32 a, f32 b, f32 c, int flag)
{
    int result;
    f32 d[3];
    f32 dist, ang;

    result = 0;
    d[0] = ((GameObject*)obj)->anim.localPosX - ((RomCurveWalker*)routePtr)->posX;
    d[2] = ((GameObject*)obj)->anim.localPosZ - ((RomCurveWalker*)routePtr)->posZ;
    dist = sqrtf(d[0] * d[0] + d[2] * d[2]);
    if (dist < b)
    {
        if (Curve_AdvanceAlongPath((RomCurveWalker*)routePtr, a) != 0 || ((RomCurveWalker*)routePtr)->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint((RomCurveWalker*)routePtr) != 0)
                result = -1;
            else
                result = *(s8*)((int)((RomCurveWalker*)routePtr)->node9C + 0x18);
        }
        c = lbl_803E6C78 * a;
    }
    d[0] = ((RomCurveWalker*)routePtr)->posX - ((GameObject*)obj)->anim.localPosX;
    d[1] = ((RomCurveWalker*)routePtr)->posY - ((GameObject*)obj)->anim.localPosY;
    d[2] = ((RomCurveWalker*)routePtr)->posZ - ((GameObject*)obj)->anim.localPosZ;
    if ((u8)flag == 0)
    {
        int state2 = *(int*)&((GameObject*)obj)->extra;
        s16 raw;
        d[0] = ((GameObject*)obj)->anim.localPosX - ((RomCurveWalker*)routePtr)->posX;
        d[2] = ((GameObject*)obj)->anim.localPosZ - ((RomCurveWalker*)routePtr)->posZ;
        raw = (s16)getAngle(d[0], d[2]);
        ang = gBarrelGenPi * (f32)(-raw) / gBarrelGenAngleHalfRange;
        ((ObjUpdateRomCurveFollowVelocityState*)state2)->velZ = c * -mathSinf(ang);
        ((ObjUpdateRomCurveFollowVelocityState*)state2)->velX = c * -mathCosf(ang);
    }
    else
    {
        Obj_SteerVelocityTowardVector(obj, &((GameObject*)obj)->anim.velocityX, d, c, c / lbl_803E6C7C,
                                      lbl_803E6C80);
    }
    return result;
}

int Obj_UpdateRomCurveFollowVelocityIndexed(int obj, int routePtr, f32 a, f32 b, f32 c, int flag, int* pickIdx)
{
    int result;
    f32 d[3];
    f32 dist, ang;

    result = 0;
    d[0] = ((GameObject*)obj)->anim.localPosX - ((RomCurveWalker*)routePtr)->posX;
    d[2] = ((GameObject*)obj)->anim.localPosZ - ((RomCurveWalker*)routePtr)->posZ;
    dist = sqrtf(d[0] * d[0] + d[2] * d[2]);
    if (dist < b)
    {
        if (Curve_AdvanceAlongPath((RomCurveWalker*)routePtr, a) != 0 || ((RomCurveWalker*)routePtr)->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPointIndexed((RomCurveWalker*)routePtr, *pickIdx) != 0)
                result = -1;
            else
                result = *(s8*)((int)((RomCurveWalker*)routePtr)->node9C + 0x18);
            *pickIdx = 0;
        }
        c = lbl_803E6C78 * a;
    }
    d[0] = ((RomCurveWalker*)routePtr)->posX - ((GameObject*)obj)->anim.localPosX;
    d[1] = ((RomCurveWalker*)routePtr)->posY - ((GameObject*)obj)->anim.localPosY;
    d[2] = ((RomCurveWalker*)routePtr)->posZ - ((GameObject*)obj)->anim.localPosZ;
    if ((u8)flag == 0)
    {
        int state2 = *(int*)&((GameObject*)obj)->extra;
        s16 raw;
        d[0] = ((GameObject*)obj)->anim.localPosX - ((RomCurveWalker*)routePtr)->posX;
        d[2] = ((GameObject*)obj)->anim.localPosZ - ((RomCurveWalker*)routePtr)->posZ;
        raw = (s16)getAngle(d[0], d[2]);
        ang = gBarrelGenPi * (f32)(-raw) / gBarrelGenAngleHalfRange;
        ((ObjUpdateRomCurveFollowVelocityState*)state2)->velZ = c * -mathSinf(ang);
        ((ObjUpdateRomCurveFollowVelocityState*)state2)->velX = c * -mathCosf(ang);
    }
    else
    {
        Obj_SteerVelocityTowardVector(obj, &((GameObject*)obj)->anim.velocityX, d, c, c / lbl_803E6C7C,
                                      lbl_803E6C80);
    }
    return result;
}

void Obj_SpawnHitLightAndFade(int obj, f32* p2)
{
    struct
    {
        f32 _pad[3];
        f32 vec[3];
    } s;

    s.vec[0] = p2[0] + playerMapOffsetX;
    s.vec[1] = p2[1];
    s.vec[2] = p2[2] + playerMapOffsetZ;
    objLightFn_8009a1dc((void*)obj, lbl_803E6C68, &s, 1, 0);
    Obj_SetModelColorFadeRecursive(obj, 0x5a, 0xc8, 0, 0, 1);
}

int Obj_UpdateLightningCluster(int obj, void** entries, int count, f32 intensity, void** light)
{
    int spawned;
    int i;
    f32 pos[3];

    spawned = 0;
    if (lbl_803E6C38 == intensity)
    {
        spawned = 0;
        for (i = 0; i < count; i++)
        {
            if (entries[i] != 0)
            {
                mm_free_(entries[i]);
                entries[i] = 0;
            }
        }
        if (*light != 0)
        {
            modelLightStruct_freeSlot((int)light);
        }
        return 0;
    }

    for (i = 0; i < count; i++)
    {
        if (entries[i] != 0)
        {
            lightningRender(entries[i]);
            *(u16*)((char*)entries[i] + 0x20) += framesThisStep;
            if ((f32)(u32) * (u16*)((char*)entries[i] + 0x20) > lbl_803DC3A8)
            {
                mm_free_(entries[i]);
                entries[i] = 0;
            }
        }
        else if (spawned == 0)
        {
            pos[0] = ((GameObject*)obj)->anim.localPosX;
            pos[1] = ((GameObject*)obj)->anim.localPosY;
            pos[2] = ((GameObject*)obj)->anim.localPosZ;
            pos[0] += lbl_803E6C3C * (intensity * (f32)(int)(randomGetRange(0, 0x7d0) - 0x3e8));
            pos[1] += lbl_803E6C3C * (intensity * (f32)(int)(randomGetRange(0, 0x7d0) - 0x3e8));
            pos[2] += lbl_803E6C3C * (intensity * (f32)(int)(randomGetRange(0, 0x7d0) - 0x3e8));
            entries[i] = lightningCreate((f32*)(obj + 0xc), pos, lbl_803DC3A0, lbl_803DC3A4,
                                 lbl_803DC3A8, (u8)lbl_803DC3AC, 0);
            spawned = 1;
        }
    }

    if (*light == 0)
    {
        *light = (void*)modelLightStruct_createPointLight(obj, 0x80, 0x80, 0xff, 0);
        if (*light != 0)
        {
            modelLightStruct_setPosition(*light, lbl_803E6C38, intensity * lbl_803E6C40, lbl_803E6C38);
            modelLightStruct_setDistanceAttenuation(*light, intensity, lbl_803E6C44 + intensity);
        }
    }
    return 1;
}

#pragma opt_common_subs off
void Obj_SmoothTurnAnglesTowardVelocity(int obj, int velVec, int turnFrames, f32 rollFactor, f32 pitchFactor)
{
    ObjAnimComponent* anim = &((GameObject*)obj)->anim;
    f32* vel = (f32*)velVec;
    f32 rate;
    f32 delta;
    f32 clamped;
    f32 dist;
    int rotZ;

    rate = timeDelta / (f32)(u32)(u16)turnFrames;
    if (rate > lbl_803E6C6C)
    {
        rate = lbl_803E6C6C;
    }

    delta = (f32)(int)((u16)getAngle(-vel[0], -vel[2]) - (u16)anim->rotX);
    if (delta > gBarrelGenAngleHalfRange)
    {
        delta = gBarrelGenAngleWrapNeg + delta;
    }
    if (delta < gBarrelGenAngleWrapThreshold)
    {
        delta = gBarrelGenAngleWrapPos + delta;
    }
    delta *= rate;
    clamped = (delta < gBarrelGenTurnRateClampMin)
                  ? gBarrelGenTurnRateClampMin
                  : ((delta > gBarrelGenTurnRateClampMax) ? gBarrelGenTurnRateClampMax : delta);
    anim->rotX += (int)clamped;

    if (rollFactor != lbl_803E6C38)
    {
        anim->rotZ = (s16)(lbl_803E6C98 * (f32)anim->rotZ);
        anim->rotZ = (s16)(oneOverTimeDelta * (lbl_803E6C5C * (clamped * rollFactor)) + (f32)anim->rotZ);
        rotZ = anim->rotZ;
        if (rotZ < -0x2000)
        {
            rotZ = -0x2000;
        }
        else if (rotZ > 0x2000)
        {
            rotZ = 0x2000;
        }
        anim->rotZ = rotZ;
    }

    if (lbl_803E6C38 != pitchFactor)
    {
        {
            f32 xx = vel[0] * vel[0];
            f32 zz = vel[2] * vel[2];
            dist = sqrtf(xx + zz);
        }
        delta = (f32)(int)((u16)getAngle(vel[1] * pitchFactor, dist) - (u16)anim->rotY);
        if (delta > gBarrelGenAngleHalfRange)
        {
            delta = gBarrelGenAngleWrapNeg + delta;
        }
        if (delta < gBarrelGenAngleWrapThreshold)
        {
            delta = gBarrelGenAngleWrapPos + delta;
        }
        anim->rotY += (int)(delta * rate);
    }
}
#pragma opt_common_subs reset


#pragma opt_loop_invariants off
int Obj_PredictInterceptPoint(int obj, f32 dt, int p3, int p4)
{
    f32 pos[3];
    f32 step[3];
    f32 vel[3];
    int gridOut[2];
    int gridB[2];
    int gridA[2];
    int i;

    if ((u32)obj != Obj_GetPlayerObject())
    {
        PSVECSubtract((void*)&((GameObject*)obj)->anim.localPosX, &((GameObject*)obj)->anim.previousLocalPosX,
                      vel);
    }
    else
    {
        vel[0] = ((GameObject*)obj)->anim.velocityX;
        vel[1] = ((GameObject*)obj)->anim.velocityY;
        vel[2] = ((GameObject*)obj)->anim.velocityZ;
    }
    PSVECScale(vel, vel, oneOverTimeDelta);
    pos[0] = ((GameObject*)obj)->anim.localPosX;
    pos[1] = lbl_803E6C58 + ((GameObject*)obj)->anim.localPosY;
    pos[2] = ((GameObject*)obj)->anim.localPosZ;
    for (i = 0; i < 5; i++)
    {
        PSVECScale(vel, step, PSVECDistance(pos, (void*)p3) / dt);
        PSVECAdd(obj + 0xc, (int)step, (int)pos);
    }
    *(f32*)(p4 + 0) = pos[0];
    *(f32*)(p4 + 4) = pos[1];
    *(f32*)(p4 + 8) = pos[2];
    voxmaps_worldToGrid((void*)p3, gridA);
    voxmaps_worldToGrid(pos, gridB);
    return voxmaps_traceLine(gridA, gridB, gridOut, 0, 0) != 0;
}
#pragma opt_loop_invariants reset

int voxmaps_traceWorldLine(void* p1, void* p2)
{
    int grid1[2];
    int grid2[2];
    int out[2];

    voxmaps_worldToGrid(p1, grid1);
    voxmaps_worldToGrid(p2, grid2);
    return voxmaps_traceLine(grid1, grid2, out, 0, 0);
}

void voxmaps_traceScaledVectorEnd(f32* p1, void* p2, f32* p3, f32 scale)
{
    f32 endPos[3];
    f32 scaled[3];
    int gridA[2];
    int gridB[2];
    int gridOut[2];
    int e0;
    int e1;

    PSVECNormalize(p3, p3);
    PSVECScale(p3, scaled, scale);
    PSVECAdd((int)scaled, (int)p2, (int)endPos);
    voxmaps_worldToGrid(p2, gridA);
    voxmaps_worldToGrid(endPos, gridB);
    if (voxmaps_traceLine(gridA, gridB, gridOut, 0, 0) == 0)
        voxmaps_gridToWorld(endPos, gridOut);
    *(SunVec3*)p1 = *(SunVec3*)endPos;
}
