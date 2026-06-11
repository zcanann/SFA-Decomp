#include "main/audio/sfx_ids.h"
#include "main/camera_interface.h"
#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/dll/IM/IMspacecraft.h"

/* SDK / engine externs */
extern int Obj_GetPlayerObject(void);
extern f32 Vec_distance(f32 * a, f32 * b);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern u32 randomGetRange(int min, int max);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_PlayFromObjectLimited(int obj, int sfxId, int p3);
extern void Sfx_KeepAliveLoopedObjectSound(int obj, int sfxId);
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);

extern int modelLightStruct_createPointLight(int obj, int a, int b, int c, int d);
extern void modelLightStruct_freeSlot(void* p);
extern void modelLightStruct_setDistanceAttenuation(void* p, f32 a, f32 b);
extern f32 Curve_AdvanceAlongPath(void* state, f32 t);
extern s16 getAngle(f32 dx, f32 dz);

extern void ObjHitbox_SetSphereRadius(int obj, int r);
extern void ObjHits_SetHitVolumeSlot(int obj, u8 slot, int a, int b);
extern void ObjHits_DisableObject(int obj);
extern void ObjHits_EnableObject(int obj);
extern int ObjHits_GetPriorityHit(int obj, int* outHitObj, int* outB, u32* outC);
extern int* ObjGroup_GetObjects(int groupId, int* outCount);
extern void ObjGroup_RemoveObject(int obj, int groupId);
extern void ObjGroup_AddObject(int obj, int groupId);
extern int* objFindTexture(int obj, int a, int b);
extern void Obj_TransformLocalVectorByWorldMatrix(int obj, f32* in, f32* out);
extern void PSVECAdd(f32 * a, f32 * b, f32 * out);
extern void Obj_FreeObject(int obj);

extern void spawnExplosion(int obj, int p2, int p3, int p4, int p5, int p6, int p7, int p8, f32 size);
extern void CameraShake_Start(int obj, f32 a, f32 b, f32 c);
extern void doRumble(f32 v);

extern void objRenderFn_8003b8f4(f32 v);
extern void Music_Trigger(int id, int p2);
extern int getSaveGameLoadStatus(void);
extern int getEnvfxAct(int obj, int player, int id, int p);
extern void MMP_levelcontrol_update(int obj);

extern ObjectTriggerInterface** gObjectTriggerInterface;

extern f32 timeDelta;
extern u8 framesThisStep;
extern int lbl_802C22F8[4];
extern s16 lbl_803DBED0;
extern s32 lbl_803DBED4;
extern s32 lbl_803DBED8;
extern s16 lbl_803DDB20;

extern f32 lbl_803E4430;
extern f32 lbl_803E4440;
extern f32 lbl_803E4444;
extern f32 lbl_803E4448;
extern f32 lbl_803E444C;
extern f32 lbl_803E4450;
extern f32 lbl_803E4454;
extern f32 lbl_803E4458;
extern int lbl_803E4460;
extern int lbl_803E4464;
extern f32 lbl_803E4468;
extern f32 lbl_803E446C;
extern f32 lbl_803E4470;
extern f32 lbl_803E4474;
extern f32 lbl_803E4478;
extern f32 lbl_803E447C;
extern f32 lbl_803E4480;
extern f32 lbl_803E4484;
extern f32 lbl_803E4494;
extern f32 lbl_803E4498;
extern f32 lbl_803E449C;
extern f32 lbl_803E44A0;
extern f32 lbl_803E44A4;
extern f32 lbl_803E44A8;
extern f32 lbl_803E44AC;
extern f32 lbl_803E44B0;
extern f32 lbl_803E44B4;
extern f32 lbl_803E44B8;
extern f32 lbl_803E44C0;
extern f32 lbl_803E44C4;

extern f32 lbl_803DDB28;
extern int lbl_803DDB2C;

/* Trivial 4b 0-arg blr leaves. */
void SpiritDoorLock_hitDetect(void)
{
}

void SpiritDoorLock_release(void)
{
}

void SpiritDoorLock_initialise(void)
{
}

void RollingBarrel_hitDetect(void)
{
}

void RollingBarrel_release(void)
{
}

void MMP_levelcontrol_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int SpiritDoorLock_getExtraSize(void) { return SPIRITDOORLOCK_EXTRA_SIZE; }
int SpiritDoorLock_getObjectTypeId(void) { return 0x0; }
int RollingBarrel_getExtraSize(void) { return ROLLINGBARREL_EXTRA_SIZE; }
int RollingBarrel_getObjectTypeId(void) { return 0x0; }
int MMP_levelcontrol_getExtraSize(void) { return 0x0; }
int MMP_levelcontrol_getObjectTypeId(void) { return 0x0; }

/* Pattern wrappers. */
void RollingBarrel_initialise(void) { lbl_803DDB20 = 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
void SpiritDoorLock_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4440);
}

void MMP_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E44C4);
}

void RollingBarrel_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    RollingBarrelState* state = ((GameObject*)obj)->extra;
    if (visible != 0 && state->state < ROLLINGBARREL_STATE_EXPLODED_WAIT)
    {
        ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E4474);
    }
}

void SpiritDoorLock_free(int obj)
{
    SpiritDoorLockState* state = ((GameObject*)obj)->extra;
    if ((void*)state->light != NULL)
    {
        modelLightStruct_freeSlot(state);
    }
}

void MMP_levelcontrol_free(int obj)
{
    lbl_803DDB28 = lbl_803E44C0;
    lbl_803DDB2C = 0;
    Music_Trigger(0xd5, 0);
}

void RollingBarrel_free(int obj)
{
    RollingBarrelState* state = ((GameObject*)obj)->extra;
    int count;
    int* arr = ObjGroup_GetObjects(ROLLINGBARREL_GROUP_ID, &count);
    int i;
    u32 a;
    for (i = 0; i < count; i++)
    {
        a = (u32)arr[i];
        if (a == (u32)obj)
        {
            ObjGroup_RemoveObject(obj, ROLLINGBARREL_GROUP_ID);
            break;
        }
    }
    if (state->state == ROLLINGBARREL_STATE_EXPLODED_WAIT)
    {
        lbl_803DDB20 -= 1;
    }
}

void RollingBarrel_init(int obj, RollingBarrelMapData* params)
{
    RollingBarrelState* state = ((GameObject*)obj)->extra;
    int tmp[2];

    tmp[0] = lbl_803E4460;
    tmp[1] = lbl_803E4464;
    params->respawnParam = -1;
    ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN);
    ((GameObject*)obj)->anim.rotZ = 0x4000;

    ((GameObject*)obj)->anim.localPosX = params->x;
    ((GameObject*)obj)->anim.worldPosX = params->x;
    ((GameObject*)obj)->anim.localPosY = params->y;
    ((GameObject*)obj)->anim.worldPosY = params->y;
    ((GameObject*)obj)->anim.localPosZ = params->z;
    ((GameObject*)obj)->anim.worldPosZ = params->z;

    state->verticalSpeed = (f32)params->verticalSpeed / lbl_803E447C;
    state->curveSpeed = (f32)params->curveSpeed / lbl_803E447C;
    state->state = ROLLINGBARREL_STATE_ROLLING;
    state->pitchRising = 1;
    state->timer = lbl_803E4468;

    (*gRomCurveInterface)->initCurve(state, (void*)obj, lbl_803E44B8, tmp, -1);
}

void SpiritDoorLock_init(int obj, SpiritDoorLockMapData* params, int mode)
{
    SpiritDoorLockState* state = ((GameObject*)obj)->extra;
    f32 mult;

    *(s16*)obj = (s16)(params->yaw << 8);
    state->orbitCount = params->orbitCount;
    state->active = 0;

    mult = (f32)params->scale * lbl_803E4448;
    if (mult < lbl_803E4430)
    {
        mult = lbl_803E4440;
    }
    ((GameObject*)obj)->anim.rootMotionScale = (*(f32**)&((GameObject*)obj)->anim.modelInstance)[1] * mult;
    state->spinAngle = 0;

    ObjHits_DisableObject(obj);
    state->flags &= ~0x80;

    if (mode == 0)
    {
        ((GameObject*)obj)->anim.alpha = 0;
        state->light = modelLightStruct_createPointLight(obj, 255, 0, 77, 0);
    }
}

void SpiritDoorLock_update(int obj)
{
    SpiritDoorLockState* state;
    SpiritDoorLockMapData* descriptor;
    int player;
    int local_68;
    f32 local_58[3];
    f32 local_5c[3];

    ((int*)local_58)[0] = lbl_802C22F8[0];
    ((int*)local_58)[1] = lbl_802C22F8[1];
    ((int*)local_58)[2] = lbl_802C22F8[2];

    state = ((GameObject*)obj)->extra;
    descriptor = *(SpiritDoorLockMapData**)&((GameObject*)obj)->anim.placementData;

    player = Obj_GetPlayerObject();

    if (GameBit_Get(SPIRITDOORLOCK_GAMEBIT_PLAYER_APPROACHED) == 0)
    {
        if (Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX) < lbl_803E4444)
        {
            if (state->active != 0)
            {
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            }
            GameBit_Set(SPIRITDOORLOCK_GAMEBIT_PLAYER_APPROACHED, 1);
        }
    }

    if (state->active == 0)
    {
        if (GameBit_Get(descriptor->doneGameBit) == 0)
        {
            state->active = GameBit_Get(descriptor->activeGameBit);
            if (state->active != 0)
            {
                ((GameObject*)obj)->anim.rootMotionScale =
                    (*(f32**)&((GameObject*)obj)->anim.modelInstance)[1] *
                    (f32)(int)
                descriptor->scale *
                    lbl_803E4448;
                if (state->light == 0)
                {
                    state->light = modelLightStruct_createPointLight(obj, 0xff, 0, 0x4d, 0);
                }
            }
        }
        else
        {
            if ((s8)((GameObject*)obj)->anim.alpha == -1)
            {
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
            }
            if (((GameObject*)obj)->anim.alpha == 0)
            {
                if (state->light != 0)
                {
                    modelLightStruct_freeSlot(state);
                }
            }
            else
            {
                ((GameObject*)obj)->anim.alpha -= 1;
                if (state->light != 0)
                {
                    u32 b = ((GameObject*)obj)->anim.alpha >> 2;
                    modelLightStruct_setDistanceAttenuation((void*)state->light, (f32)(int)b,
                                                            (f32)(int)(b + 10));
                }
                ((GameObject*)obj)->anim.rootMotionScale *= lbl_803E444C;
                ((GameObject*)obj)->anim.rotZ =
                    (s16)(s32)((f32)(int)((GameObject*)obj)->anim.rotZ - lbl_803E4450 * timeDelta);
            }
        }
    }
    else
    {
        int cam_state;
        int* list_ptr;
        int* piTex;
        int i;
        s16 angle;
        s16 stride;
        f32 max_dist;
        cam_state = (*gCameraInterface)->getMode();
        if (cam_state != 0x51)
        {
            Sfx_KeepAliveLoopedObjectSound(obj, SPIRITDOORLOCK_LOOP_SFX);
        }
        list_ptr = ObjGroup_GetObjects(SPIRITDOORLOCK_ORBIT_OBJECT_GROUP, &local_68);
        stride = (s16)(0x10000 / state->orbitCount);
        angle = (s16)state->spinAngle;
        local_58[1] = lbl_803E4454;
        max_dist = lbl_803E4458;
        for (i = 0; i < local_68; i++)
        {
            if (Vec_distance(&((GameObject*)obj)->anim.worldPosX, (f32*)((char*)list_ptr[i] + 0x18)) <= max_dist)
            {
                ((GameObject*)obj)->anim.rotZ = angle;
                Obj_TransformLocalVectorByWorldMatrix(obj, local_58, local_5c);
                PSVECAdd(&((GameObject*)obj)->anim.localPosX, local_5c, (f32*)((char*)list_ptr[i] + 0xc));
                *(s16*)list_ptr[i] = *(s16*)obj;
                *(s16*)((char*)list_ptr[i] + 4) = (s16)(angle + 0x8000);
                *(f32*)((char*)list_ptr[i] + 8) = ((GameObject*)obj)->anim.rootMotionScale;
                angle = (s16)(angle + stride);
            }
        }
        state->spinAngle += (int)lbl_803DBED0;
        ((GameObject*)obj)->anim.rotZ = 0;
        if (local_68 == 0)
        {
            state->active = 0;
            GameBit_Set(descriptor->doneGameBit, 1);
            ObjHits_DisableObject(obj);
        }
        piTex = objFindTexture(obj, 0, 0);
        if (piTex != NULL)
        {
            *(s16*)((char*)piTex + 0xa) = (s16)(*(s16*)((char*)piTex + 0xa) + lbl_803DBED4 * (s32)framesThisStep);
            *(s16*)((char*)piTex + 0x8) = (s16)(*(s16*)((char*)piTex + 0x8) + lbl_803DBED4 * (s32)framesThisStep);
            if ((s32) * (s16*)((char*)piTex + 0xa) > (s32)(lbl_803DBED8 << 8))
            {
                *(s16*)((char*)piTex + 0xa) = (s16)(*(s16*)((char*)piTex + 0xa) - (lbl_803DBED8 << 8));
            }
            if ((s32) * (s16*)((char*)piTex + 0x8) > (s32)(lbl_803DBED8 << 8))
            {
                *(s16*)((char*)piTex + 0x8) = (s16)(*(s16*)((char*)piTex + 0x8) - (lbl_803DBED8 << 8));
            }
        }
        if (((GameObject*)obj)->anim.alpha < 0xff)
        {
            ((GameObject*)obj)->anim.alpha += 1;
        }
    }
}

#pragma peephole on
void RollingBarrel_update(int obj)
{
    RollingBarrelState* state;
    RollingBarrelMapData* descriptor;
    f32 floor_y;
    f32 dist_sq;
    int blocked;
    int hitInfo;
    int hitB;
    u32 hitC;
    int hitResult;
    u32 r;
    u8 bVar1;

    state = ((GameObject*)obj)->extra;
    hitInfo = 0;
    descriptor = *(RollingBarrelMapData**)&((GameObject*)obj)->anim.placementData;
    blocked = 0;
    dist_sq = lbl_803E4468;
    bVar1 = state->state;

    if (bVar1 == ROLLINGBARREL_STATE_RESPAWN_WAIT)
    {
        state->timer += timeDelta;
        if (state->timer >= lbl_803E44B0)
        {
            state->hitVolumeSlot = 0;
            state->state = ROLLINGBARREL_STATE_CLEANUP;
            state->timer -= lbl_803E44B0;
            ObjGroup_AddObject(obj, ROLLINGBARREL_GROUP_ID);
            lbl_803DDB20 -= 1;
        }
    }
    else if (bVar1 < ROLLINGBARREL_STATE_RESPAWN_WAIT)
    {
        if (bVar1 == ROLLINGBARREL_STATE_ROLLING)
        {
            if (descriptor->objectDefId == ROLLINGBARREL_SPECIAL_DESCRIPTOR_TYPE)
            {
                f32 vmax = lbl_803E446C;
                while (blocked == 0 && dist_sq < vmax * timeDelta)
                {
                    blocked = (int)Curve_AdvanceAlongPath(state, state->curveSpeed);
                    if (blocked == 0 && state->curve.atSegmentEnd != 0)
                    {
                        (*gRomCurveInterface)->goNextPoint(state);
                    }
                    {
                        f32 dx = state->curve.posX - ((GameObject*)obj)->anim.previousLocalPosX;
                        f32 dz = state->curve.posZ - ((GameObject*)obj)->anim.previousLocalPosZ;
                        dist_sq = dx * dx + dz * dz;
                    }
                }
            }
            else
            {
                blocked = (int)Curve_AdvanceAlongPath(state, state->curveSpeed);
                if (blocked == 0 && state->curve.atSegmentEnd != 0)
                {
                    (*gRomCurveInterface)->goNextPoint(state);
                }
            }

            state->hitVolumeSlot = 10;
            ObjHitbox_SetSphereRadius(obj, *(u8*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x62));

            if (descriptor->objectDefId == ROLLINGBARREL_SPECIAL_DESCRIPTOR_TYPE)
            {
                floor_y = lbl_803E4478 + state->curve.posY;
            }
            else
            {
                floor_y = state->curve.posY;
            }

            state->verticalSpeed = lbl_803E4498 * timeDelta + state->verticalSpeed;
            ((GameObject*)obj)->anim.localPosY =
                state->verticalSpeed * timeDelta + ((GameObject*)obj)->anim.localPosY;

            if (((GameObject*)obj)->anim.localPosY < floor_y)
            {
                if (descriptor->objectDefId == ROLLINGBARREL_SPECIAL_DESCRIPTOR_TYPE &&
                    ((GameObject*)obj)->anim.localPosY < lbl_803E449C)
                {
                    blocked = 1;
                }
                if (blocked == 0 &&
                    state->verticalSpeed * state->verticalSpeed > lbl_803E446C)
                {
                    Sfx_PlayFromObjectLimited(obj, 0x41e, 6);
                }
                state->verticalSpeed *= lbl_803E44A0;
                ((GameObject*)obj)->anim.localPosY = lbl_803E44A4 * floor_y - ((GameObject*)obj)->anim.localPosY;
            }
            ((GameObject*)obj)->anim.localPosX = state->curve.posX;
            ((GameObject*)obj)->anim.localPosZ = state->curve.posZ;
            *(s16*)obj = (s16)getAngle(state->curve.tangentX, state->curve.tangentZ);

            if (state->pitchRising != 0)
            {
                ((GameObject*)obj)->anim.rotZ =
                    (s16)(s32)(lbl_803E44A8 * timeDelta + (f32)(int)((GameObject*)obj)->anim.rotZ);
                if (((GameObject*)obj)->anim.rotZ > 0x5000)
                {
                    state->pitchRising = 0;
                }
            }
            else
            {
                ((GameObject*)obj)->anim.rotZ =
                    (s16)(s32) - (lbl_803E44A8 * timeDelta - (f32)(int)((GameObject*)obj)->anim.rotZ);
                if (((GameObject*)obj)->anim.rotZ < 0x3a00)
                {
                    state->pitchRising = 1;
                }
            }

            ((GameObject*)obj)->anim.rotY =
                (s16)(s32)(lbl_803E44AC * timeDelta * state->curveSpeed +
                    (f32)(int)((GameObject*)obj)->anim.rotY);
            hitResult = ObjHits_GetPriorityHit(obj, &hitInfo, &hitB, &hitC);

            if (blocked != 0 || hitInfo == Obj_GetPlayerObject() || (u32)(hitResult - 0xe) <= 1u ||
                hitResult == 0x13)
            {
                if (blocked == 0)
                {
                    state->hitVolumeSlot = 0;
                }
                else
                {
                    state->hitVolumeSlot = 5;
                }
                r = randomGetRange(0, 2);
                fn_801A5D88(obj, (int)r);
            }
        }
        else
        {
            state->timer += timeDelta;
            if (state->timer >= lbl_803E44B0)
            {
                state->state = ROLLINGBARREL_STATE_RESPAWN_WAIT;
                state->timer -= lbl_803E44B0;
            }
        }
    }
    else if (bVar1 < 4)
    {
        state->timer += timeDelta;
        if (state->timer >= lbl_803E44B4)
        {
            Obj_FreeObject(obj);
            return;
        }
    }

    if (state->hitVolumeSlot != 0)
    {
        ObjHits_EnableObject(obj);
        ObjHits_SetHitVolumeSlot(obj, state->hitVolumeSlot, 1, 0);
    }
    else
    {
        ObjHits_DisableObject(obj);
        ObjHits_SetHitVolumeSlot(obj, state->hitVolumeSlot, 0, 0);
    }
}

#pragma peephole off
int MMP_LevelControl_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int player;
    int i;

    player = Obj_GetPlayerObject();
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 v = animUpdate->eventIds[i];
        switch (v)
        {
        case 1:
            getEnvfxAct(obj, player, 315, 0);
            break;
        case 2:
            getEnvfxAct(obj, player, 312, 0);
            break;
        }
    }
    MMP_levelcontrol_update(obj);
    return 0;
}

void fn_801A5D88(int obj, int explosionVariant)
{
    RollingBarrelState* state = ((GameObject*)obj)->extra;
    u32 r;
    u32 r2;
    int player;
    f32 dist;
    f32 falloff;
    lbl_803DDB20 += 1;
    Sfx_PlayFromObject(obj, SFXsp_lf_mutter1);
    if (lbl_803DDB20 > 1)
    {
        f32 size;
        r = randomGetRange(0, 1) & 0xff;
        r2 = randomGetRange(0x32, 0x3c);
        size = (f32)(int)
        r2;
        spawnExplosion(obj, 1, 1, 0, (int)r, 0, 0, 0, size);
    }
    else
    {
        f32 size;
        r = randomGetRange(0, 1) & 0xff;
        r2 = randomGetRange(0x32, 0x3c);
        size = (f32)(int)
        r2;
        spawnExplosion(obj, 1, 1, 0, (int)r, 0, 1, 0, size);
    }
    state->state = ROLLINGBARREL_STATE_EXPLODED_WAIT;
    state->timer = lbl_803E4468;
    ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
    ObjHitbox_SetSphereRadius(obj,
                              (s32)(lbl_803E446C * (f32)(u32) * (u8*)(*(int*)&((GameObject*)obj)->anim.modelInstance +
                                  0x62)));
    player = (int)Obj_GetPlayerObject();
    if ((((GameObject*)player)->objectFlags & 0x1000) == 0)
    {
        dist = Vec_distance(&((GameObject*)obj)->anim.worldPosX, &((GameObject*)player)->anim.worldPosX);
        if (dist <= lbl_803E4470)
        {
            falloff = lbl_803E4474 - dist / lbl_803E4470;
            CameraShake_Start(obj, lbl_803E4478 * falloff, lbl_803E447C * falloff, lbl_803E4480);
            doRumble(lbl_803E4484 * falloff);
        }
    }
}
