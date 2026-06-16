#include "main/dll/dll_80220608_shared.h"
#include "main/dll/barrelgener_state.h"
#include "main/dll/curve_walker.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"

typedef struct ObjUpdateRomCurveFollowVelocityIndexedState
{
    u8 pad0[0x28C - 0x0];
    f32 unk28C;
    f32 unk290;
    u8 pad294[0x298 - 0x294];
} ObjUpdateRomCurveFollowVelocityIndexedState;


typedef struct ObjUpdateRomCurveFollowVelocityState
{
    u8 pad0[0x28C - 0x0];
    f32 unk28C;
    f32 unk290;
    u8 pad294[0x298 - 0x294];
} ObjUpdateRomCurveFollowVelocityState;

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

void barrelgener_free(int obj) { ObjGroup_RemoveObject(obj, 0x3a); }

void barrelgener_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6C20);
    }
}

void barrelgener_hitDetect(void)
{
}

void barrelgener_init(int obj)
{
    BarrelGeneratorState* state = ((GameObject*)obj)->extra;

    ObjGroup_AddObject(obj, 0x3a);
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

    if ((u32)GameBit_Get(0xadb) == 0)
    {
        if (Vec_distance(obj + 24, player + 24) < lbl_803E6C24)
        {
            (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
            GameBit_Set(0xadb, 1);
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
                f32 c2c;
                releasedBarrel->anim.localPosX = ((GameObject*)obj)->anim.localPosX;
                releasedBarrel->anim.localPosY = ((GameObject*)obj)->anim.localPosY;
                releasedBarrel->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ;
                releasedBarrel->anim.previousLocalPosX = releasedBarrel->anim.localPosX;
                releasedBarrel->anim.previousLocalPosY = releasedBarrel->anim.localPosY;
                releasedBarrel->anim.previousLocalPosZ = releasedBarrel->anim.localPosZ;
                releasedBarrel->anim.worldPosX = releasedBarrel->anim.localPosX;
                releasedBarrel->anim.worldPosY = releasedBarrel->anim.localPosY;
                releasedBarrel->anim.worldPosZ = releasedBarrel->anim.localPosZ;
                c2c = lbl_803E6C2C;
                releasedBarrel->anim.velocityZ = c2c;
                releasedBarrel->anim.velocityY = c2c;
                releasedBarrel->anim.velocityX = c2c;
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

void Obj_SteerVelocityTowardVector(int out, f32* v1, f32* v2, f32 a, f32 b, f32 c)
{
    f32 mtx[12];
    f32 n1[3];
    f32 n2[3];
    f32 cross[3];
    f32 mag1, mag2, t, ang;

    mag1 = PSVECMag(v1);
    if (mag1 > lbl_803E6C38)
    {
        t = lbl_803E6C6C / mag1;
        n1[0] = v1[0] * t;
        n1[1] = v1[1] * t;
        n1[2] = v1[2] * t;
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
        t = lbl_803E6C6C / mag2;
        n2[0] = v2[0] * t;
        n2[1] = v2[1] * t;
        n2[2] = v2[2] * t;
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
        if ((f32)(ang > c) != lbl_803E6C38)
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
    *(f32*)(out + 0x24) = n2[0] * t;
    *(f32*)(out + 0x28) = n2[1] * t;
    *(f32*)(out + 0x2c) = n2[2] * t;
}

int Obj_UpdateRomCurveFollowVelocity(int obj, int routePtr, f32 a, f32 b, f32 c, int flag)
{
    int result;

    f32 d[3];
    f32 dist, ang, scale;

    result = 0;
    scale = c;

    d[0] = ((GameObject*)obj)->anim.localPosX - ((RomCurveWalker*)routePtr)->posX;
    d[2] = ((GameObject*)obj)->anim.localPosZ - ((RomCurveWalker*)routePtr)->posZ;
    dist = sqrtf(d[0] * d[0] + d[2] * d[2]);
    if (dist < b)
    {
        if (Curve_AdvanceAlongPath(((RomCurveWalker*)routePtr), a) != 0 || ((RomCurveWalker*)routePtr)->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint(((RomCurveWalker*)routePtr)) != 0)
                result = -1;
            else
                result = (s8) * (u8*)((int)((RomCurveWalker*)routePtr)->node9C + 0x18);
        }
        scale = lbl_803E6C78 * a;
    }
    d[0] = ((RomCurveWalker*)routePtr)->posX - ((GameObject*)obj)->anim.localPosX;
    d[1] = ((RomCurveWalker*)routePtr)->posY - ((GameObject*)obj)->anim.localPosY;
    d[2] = ((RomCurveWalker*)routePtr)->posZ - ((GameObject*)obj)->anim.localPosZ;
    if ((u8)flag == 0)
    {
        int state2 = *(int*)&((GameObject*)obj)->extra;
        d[0] = ((GameObject*)obj)->anim.localPosX - ((RomCurveWalker*)routePtr)->posX;
        d[2] = ((GameObject*)obj)->anim.localPosZ - ((RomCurveWalker*)routePtr)->posZ;
        ang = lbl_803E6C60 * (f32)(-(s16)getAngle(d[0], d[2])) / lbl_803E6C64;
        ((ObjUpdateRomCurveFollowVelocityState*)state2)->unk290 = scale * -mathSinf(ang);
        ((ObjUpdateRomCurveFollowVelocityState*)state2)->unk28C = scale * -mathCosf(ang);
    }
    else
    {
        Obj_SteerVelocityTowardVector(obj, &((GameObject*)obj)->anim.velocityX, d, scale, scale / lbl_803E6C7C,
                                      lbl_803E6C80);
    }
    return result;
}

int Obj_UpdateRomCurveFollowVelocityIndexed(int obj, int routePtr, f32 a, f32 b, f32 c, int flag, int* pickIdx)
{
    RomCurveWalker* route;
    f32 d[3];
    f32 dist, ang, scale;
    int result;

    result = 0;
    scale = c;
    route = (RomCurveWalker*)routePtr;
    d[0] = ((GameObject*)obj)->anim.localPosX - route->posX;
    d[2] = ((GameObject*)obj)->anim.localPosZ - route->posZ;
    dist = sqrtf(d[0] * d[0] + d[2] * d[2]);
    if (dist < b)
    {
        if (Curve_AdvanceAlongPath(route, a) != 0 || route->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPointIndexed(route, *pickIdx) != 0)
                result = -1;
            else
                result = (s8) * (u8*)((int)route->node9C + 0x18);
            *pickIdx = 0;
        }
        scale = lbl_803E6C78 * a;
    }
    d[0] = route->posX - ((GameObject*)obj)->anim.localPosX;
    d[1] = route->posY - ((GameObject*)obj)->anim.localPosY;
    d[2] = route->posZ - ((GameObject*)obj)->anim.localPosZ;
    if ((u8)flag == 0)
    {
        int state2 = *(int*)&((GameObject*)obj)->extra;
        d[0] = ((GameObject*)obj)->anim.localPosX - route->posX;
        d[2] = ((GameObject*)obj)->anim.localPosZ - route->posZ;
        ang = lbl_803E6C60 * (f32)(-(s16)getAngle(d[0], d[2])) / lbl_803E6C64;
        ((ObjUpdateRomCurveFollowVelocityIndexedState*)state2)->unk290 = scale * -mathSinf(ang);
        ((ObjUpdateRomCurveFollowVelocityIndexedState*)state2)->unk28C = scale * -mathCosf(ang);
    }
    else
    {
        Obj_SteerVelocityTowardVector(obj, &((GameObject*)obj)->anim.velocityX, d, scale, scale / lbl_803E6C7C,
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

int fn_80221978(int obj, void** entries, int count, void** light, f32 intensity)
{
    int i;
    int spawned;
    void** p;
    f32 pos[3];

    spawned = 0;
    if (lbl_803E6C38 == intensity)
    {
        spawned = 0;
        for (i = 0, p = entries; i < count; p++, i++)
        {
            if (*p != 0)
            {
                mm_free_(*p);
                *p = 0;
            }
        }
        if (*light != 0)
        {
            modelLightStruct_freeSlot((int)light);
        }
        return 0;
    }

    for (i = 0, p = entries; i < count; p++, i++)
    {
        if (*p != 0)
        {
            lightningRender(*p);
            *(u16*)((char*)*p + 0x20) += framesThisStep;
            if ((f32)(u32) * (u16*)((char*)*p + 0x20) > lbl_803DC3A8)
            {
                mm_free_(*p);
                *p = 0;
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
            *p = lightningCreate((f32*)(obj + 0xc), pos, lbl_803DC3A0, lbl_803DC3A4,
                                 (int)lbl_803DC3A8, (u8)lbl_803DC3AC, 0);
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

void Obj_SmoothTurnAnglesTowardVelocity(int a, int b, int c, f32 d, f32 e)
{
    f32 rate;
    f32 delta;
    f32 clamped;
    f32 dist;
    int tmp;

    rate = timeDelta / (f32)(u32)(u16)
    c;
    if (rate > lbl_803E6C6C)
    {
        rate = lbl_803E6C6C;
    }

    delta = (f32)(int)((u16)getAngle(-*(f32*)(b + 0), -*(f32*)(b + 8)) - (u16) * (s16*)(a + 0));
    if (delta > lbl_803E6C64)
    {
        delta = lbl_803E6C84 + delta;
    }
    if (delta < lbl_803E6C8C)
    {
        delta = lbl_803E6C88 + delta;
    }
    delta *= rate;
    if (delta < lbl_803E6C90)
    {
        clamped = lbl_803E6C90;
    }
    else if (delta > lbl_803E6C94)
    {
        clamped = lbl_803E6C94;
    }
    else
    {
        clamped = delta;
    }
    *(s16*)(a + 0) = *(s16*)(a + 0) + (int)clamped;

    if (d != lbl_803E6C38)
    {
        *(s16*)(a + 4) = (s16)(lbl_803E6C98 * (f32) * (s16*)(a + 4));
        *(s16*)(a + 4) = (s16)(oneOverTimeDelta * (lbl_803E6C5C * (clamped * d)) + (f32) * (s16*)(a + 4));
        tmp = *(s16*)(a + 4);
        if (tmp < -0x2000)
        {
            tmp = -0x2000;
        }
        else if (tmp > 0x2000)
        {
            tmp = 0x2000;
        }
        *(s16*)(a + 4) = (s16)tmp;
    }

    if (lbl_803E6C38 != e)
    {
        dist = sqrtf(*(f32*)(b + 0) * *(f32*)(b + 0) + *(f32*)(b + 8) * *(f32*)(b + 8));
        delta = (f32)(int)((u16)getAngle(*(f32*)(b + 4) * e, dist) - (u16) * (s16*)(a + 2));
        if (delta > lbl_803E6C64)
        {
            delta = lbl_803E6C84 + delta;
        }
        if (delta < lbl_803E6C8C)
        {
            delta = lbl_803E6C88 + delta;
        }
        *(s16*)(a + 2) = *(s16*)(a + 2) + (int)(delta * rate);
    }
}

#pragma opt_loop_invariants off
int fn_80221C18(int obj, f32 dt, int p3, int p4)
{
    f32 pos[3];
    f32 step[3];
    f32 vel[3];
    int gridOut[2];
    int gridB[2];
    int gridA[2];
    int i;

    if ((u32)obj != (u32)Obj_GetPlayerObject())
    {
        PSVECSubtract((void*)&((GameObject*)obj)->anim.localPosX, (void*)&((GameObject*)obj)->anim.previousLocalPosX,
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
