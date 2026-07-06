/* proximitymine_update - ProximityMine object update/render handlers [8021122C-802113F8) */
#include "main/proximitymine.h"
#include "main/audio/sfx.h"
#include "main/objlib.h"
#include "main/effect_interfaces.h"
#include "main/objtexture.h"
#include "main/engine_shared.h"
#include "main/audio/sfx_trigger_ids.h"
extern void modelLightStruct_freeSlot(void* handle);
extern void objRenderModelAndHitVolumes(void* obj, u32 fwdArg2, u32 fwdArg3, u32 fwdArg4,
                                 u32 fwdArg5, double scale);
extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z);
extern void queueGlowRender(void* effect);
extern int fn_80080150(f32* p);
extern void storeZeroToFloatParam(f32* p);
extern void s16toFloat(f32* p, s16 val);
extern f32 lbl_803E6768;
extern f32 lbl_803E6778;
extern void modelLightStruct_updateGlowAlpha(void* light);
extern int timerCountDown(f32* p);
extern int objUpdateOpacity(char* obj);
extern int hitDetectFn_800658a4(void* obj, f32 x, f32 y, f32 z, f32* out, int flag);
extern ProximityMineEffect* modelLightStruct_createPointLight(void* obj, int r, int g, int b, int a);
extern void modelLightStruct_setupGlow(void* light, int a, int b, int c, int d, u8 e, f32 f);
extern void modelLightStruct_setPosition(void* light, f32 x, f32 y, f32 z);

extern f32 Vec_distance(f32* a, f32* b);
extern f32 Vec_xzDistance(f32* a, f32* b);

extern void vecRotateZXY(void* params, f32* vec);
extern void Obj_FreeObject(void* obj);
extern f32 lbl_803DC234;
extern u8 lbl_803DC238;
extern f32 lbl_803DC23C;
extern u8 lbl_803DC240;
extern f32 lbl_803DC244;
extern f32 lbl_803DC248;
extern f32 lbl_803E677C;
extern f32 lbl_803E6780;
extern f32 gProximityMineMinVelocityY;
extern f32 gProximityMineGravityAccel;
extern void Obj_SetActiveModelIndex(void* obj, int modelIndex);
extern s32 lbl_803DC230;
extern f32 lbl_803E6774;
extern f32 gProximityMineHeightScale;
extern f32 lbl_803E679C;

int proximitymine_getExtraSize(void)
{
    return sizeof(ProximityMineState);
}

int proximitymine_getObjectTypeId(void)
{
    return 0;
}

void proximitymine_free(ProximityMineObject* obj)
{
    ProximityMineState* state;

    state = obj->state;
    if (state->effectHandle != NULL)
    {
        modelLightStruct_freeSlot(&state->effectHandle);
    }
    return;
}

void proximitymine_render(ProximityMineObject* obj, u32 p2, u32 p3,
                          u32 p4, u32 p5)
{
    int mapBlock;
    ProximityMineEffect* effect;
    ProximityMineState* state;

    state = obj->state;
    if (obj->pendingTarget != NULL)
    {
        state->targetObj = obj->pendingTarget;
        obj->pendingTarget = NULL;
    }
    if (fn_80080150(&state->renderTimer) != 0 ||
        (mapBlock = objPosToMapBlockIdx((double)obj->posX, (double)obj->posY,
                                        (double)obj->posZ)) == -1)
    {
        return;
    }
    effect = state->effectHandle;
    if ((effect != NULL) && (effect->active != 0) && (effect->visible != 0))
    {
        queueGlowRender(effect);
    }
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E6778);
    return;
}

void proximitymine_hitDetect(ProximityMineObject* obj)
{
    f32 zeroVelocity;
    int hit;
    int hitFlag;
    ProximityMineCollider* collider;
    ProximityMineState* state;

    if (fn_80080150(&obj->state->renderTimer) == 0)
    {
        hit = ObjHits_GetPriorityHit((int)obj, 0, 0, 0);
        collider = obj->collider;
        hitFlag = collider->hitFlag;
        if ((hitFlag != 0) || (hit != 0) || (collider->hitObj != NULL))
        {
            state = obj->state;
            zeroVelocity = lbl_803E6768;
            obj->velocityY = zeroVelocity;
            obj->velocityX = zeroVelocity;
            obj->velocityZ = zeroVelocity;
            state->mode = PROXIMITYMINE_MODE_EXPIRED;
            storeZeroToFloatParam(&state->resetTimer);
            s16toFloat(&state->resetTimer, 1);
            s16toFloat(&state->renderTimer, 10);
        }
    }
    return;
}

typedef struct MineLaunchParams
{
    s16 rotX;
    s16 rotY;
    s16 rotZ;
    f32 scale;
    f32 x;
    f32 y;
    f32 z;
} MineLaunchParams;

void proximitymine_update(ProximityMineObject* obj)
{
    f32 groundY;
    MineLaunchParams params;
    ProximityMineState* state;

    state = obj->state;
    if (state->effectHandle != NULL)
    {
        modelLightStruct_updateGlowAlpha(state->effectHandle);
    }
    if (obj->pendingTarget != NULL)
    {
        state->targetObj = obj->pendingTarget;
        obj->pendingTarget = NULL;
    }
    if (fn_80080150(&state->lifespanTimer) != 0)
    {
        obj->height += state->verticalStep * timeDelta;
        if (state->targetObj != NULL)
        {
            if (objUpdateOpacity(state->targetObj) != 0)
            {
                ObjPath_GetPointWorldPosition((int)state->targetObj, obj->pathIndex, &obj->posX,
                                              &obj->posY, &obj->posZ, 0);
            }
            else
            {
                obj->posX = ((ProximityMineObject*)state->targetObj)->posX;
                obj->posY = ((ProximityMineObject*)state->targetObj)->posY;
                obj->posZ = ((ProximityMineObject*)state->targetObj)->posZ;
            }
        }
        if (timerCountDown(&state->lifespanTimer) != 0)
        {
            if (state->mode == PROXIMITYMINE_MODE_ARMED)
            {
                hitDetectFn_800658a4(obj, obj->posX, obj->posY, obj->posZ, &groundY, 0);
                obj->posY -= groundY;
                Sfx_PlayFromObject((u32)obj, 0x2e6);
                Sfx_PlayFromObject((u32)obj, 0x2e8);
            }
            else
            {
                Sfx_PlayFromObject((u32)obj, 0x2e7);
                Sfx_PlayFromObject((u32)obj, 0x2e9);
            }
        }
        if (state->effectHandle == NULL)
        {
            int brightness;
            ObjTextureRuntimeSlot* tex;

            state->effectHandle = modelLightStruct_createPointLight(obj, 0xff, 0, 0, 0);
            tex = objFindTexture(obj, 0, 0);
            if (tex != NULL)
            {
                tex->textureId = (tex->textureId + 0x10) % 512;
                brightness = tex->textureId >> 8;
            }
            else
            {
                brightness = 0;
            }
            if (state->effectHandle != NULL)
            {
                state->effectHandle->visible = brightness;
                modelLightStruct_setupGlow(state->effectHandle, 0, 0xff, 0, 0, lbl_803DC238, lbl_803DC234);
                {
                    ProximityMineEffect* fx = state->effectHandle;
                    modelLightStruct_setPosition(fx, lbl_803E6768, obj->lightPosY, *(f32*)&lbl_803E6768);
                }
            }
        }
    }
    else
    {
        if (fn_80080150(&state->resetTimer) != 0)
        {
            Sfx_PlayFromObject((u32)obj, 0xef);
            if (state->effectHandle == NULL)
            {
                state->effectHandle = modelLightStruct_createPointLight(obj, 0xff, 0, 0, 0);
                if (state->effectHandle != NULL)
                {
                    modelLightStruct_setupGlow(state->effectHandle, 0, 0xff, 0, 0, lbl_803DC240, lbl_803DC23C);
                    {
                        ProximityMineEffect* fx = state->effectHandle;
                        modelLightStruct_setPosition(fx, lbl_803E6768, obj->lightPosY, *(f32*)&lbl_803E6768);
                    }
                }
            }
            if (timerCountDown(&state->resetTimer) != 0)
            {
                proximitymine_resetToIdle(obj);
                return;
            }
        }
        switch (state->mode)
        {
        case PROXIMITYMINE_MODE_WAITING:
            {
                f32 trigger;
                ProximityMineObject* player;

                trigger = obj->def->parameter;
                player = Obj_GetPlayerObject();
                if (Vec_distance(&obj->prevX, &player->prevX) < trigger)
                {
                    state->mode = PROXIMITYMINE_MODE_ARMED;
                    s16toFloat(&state->resetTimer, 0x78);
                }
                break;
            }
        case PROXIMITYMINE_MODE_EXPIRED:
            Sfx_StopObjectChannel((u32)obj, 0x40);
            if (timerCountDown(&state->renderTimer) != 0)
            {
                Obj_FreeObject(obj);
                return;
            }
            break;
        case PROXIMITYMINE_MODE_LAUNCHING:
            {
                f32 dist;
                f32 zero;
                ProximityMineObject* player;

                player = Obj_GetPlayerObject();
                dist = Vec_xzDistance(&obj->prevX, &player->prevX);
                state->mode = PROXIMITYMINE_MODE_FLIGHT;
                obj->velocityX = lbl_803E6768;
                obj->velocityY = sqrtf(dist) / lbl_803DC244 + lbl_803E677C * lbl_803DC248;
                obj->velocityZ = lbl_803E6780 * lbl_803DC248 - sqrtf(dist) / lbl_803DC244;
                zero = lbl_803E6768;
                params.x = zero;
                params.y = zero;
                params.z = zero;
                params.scale = lbl_803E6778;
                params.rotZ = 0;
                params.rotY = 0;
                params.rotX = obj->angle;
                vecRotateZXY(&params, &obj->velocityX);
                Sfx_PlayFromObject((u32)obj, 0xf0);
            }
        case PROXIMITYMINE_MODE_FLIGHT:
            if (timerCountDown(&state->launchTimer) != 0)
            {
                f32 zero;

                state = obj->state;
                zero = lbl_803E6768;
                obj->velocityY = zero;
                obj->velocityX = zero;
                obj->velocityZ = zero;
                state->mode = PROXIMITYMINE_MODE_EXPIRED;
                storeZeroToFloatParam(&state->resetTimer);
                s16toFloat(&state->resetTimer, 1);
                s16toFloat(&state->renderTimer, 10);
                return;
            }
            if (obj->velocityY > gProximityMineMinVelocityY)
            {
                obj->velocityY += gProximityMineGravityAccel * timeDelta;
            }
            obj->angle += framesThisStep << 10;
            obj->angle2 += framesThisStep * 0x700;
            obj->posX += obj->velocityX * timeDelta;
            obj->posY += obj->velocityY * timeDelta;
            obj->posZ += obj->velocityZ * timeDelta;
            obj->prevX = obj->posX;
            obj->prevY = obj->posY;
            obj->prevZ = obj->posZ;
        case PROXIMITYMINE_MODE_ARMED:
            (*gPartfxInterface)->spawnObject(obj, 0x51c, NULL, 1, -1, NULL);
            if (timerCountDown(&state->bounceTimer) != 0)
            {
                ObjHits_EnableObject((u32)obj);
            }
            ObjHits_SetHitVolumeSlot((u32)obj, 13, 1, 0);
            if (state->effectHandle != NULL)
            {
                if ((state->effectHandle->visible != 0) && (state->effectVisible == 0))
                {
                    Sfx_PlayFromObject((u32)obj, SFXTRIG_gal_prophitbird);
                }
                state->effectVisible = state->effectHandle->visible;
            }
            else
            {
                state->effectVisible = 0;
            }
            break;
        }
        if (fn_80080150(&state->renderTimer) == 0)
        {
            if (objPosToMapBlockIdx((double)obj->posX, (double)obj->posY, (double)obj->posZ) == -1)
            {
                f32 zero;

                state = obj->state;
                zero = lbl_803E6768;
                obj->velocityY = zero;
                obj->velocityX = zero;
                obj->velocityZ = zero;
                state->mode = PROXIMITYMINE_MODE_EXPIRED;
                storeZeroToFloatParam(&state->resetTimer);
                s16toFloat(&state->resetTimer, 1);
                s16toFloat(&state->renderTimer, 10);
            }
        }
    }
}

void proximitymine_init(ProximityMineObject* obj, ProximityMineDef* def)
{
    s8 mode;
    ProximityMineState* state;

    state = obj->state;
    if (obj->objId == 0x789)
    {
        def->mode = PROXIMITYMINE_SPAWN_PROXIMITY;
    }
    obj->angle = 0;
    ObjHits_DisableObject((u32)obj);
    state->mode = PROXIMITYMINE_MODE_EXPIRED;
    storeZeroToFloatParam(&state->renderTimer);
    storeZeroToFloatParam(&state->resetTimer);
    storeZeroToFloatParam(&state->bounceTimer);
    s16toFloat(&state->bounceTimer, 0x14);
    storeZeroToFloatParam(&state->launchTimer);
    storeZeroToFloatParam(&state->initTimer);
    s16toFloat(&state->initTimer, 5);
    obj->angle = def->angleSeed << 8;
    storeZeroToFloatParam(&state->lifespanTimer);
    s16toFloat(&state->lifespanTimer, (s16)lbl_803DC230);
    state->flashMode = 0;
    state->triggerDistance = lbl_803E6774;
    state->effectVisible = 0;
    mode = def->mode;
    switch (mode)
    {
    case PROXIMITYMINE_SPAWN_TIMED:
        s16toFloat(&state->resetTimer, def->parameter);
        state->mode = PROXIMITYMINE_MODE_ARMED;
        Obj_SetActiveModelIndex(obj, 1);
        obj->height *= gProximityMineHeightScale;
        break;
    case PROXIMITYMINE_SPAWN_LAUNCHED:
        s16toFloat(&state->launchTimer, 800);
        s16toFloat(&state->resetTimer, 800);
        obj->angle = def->parameter;
        state->mode = PROXIMITYMINE_MODE_LAUNCHING;
        obj->height *= gProximityMineHeightScale;
        break;
    case PROXIMITYMINE_SPAWN_PROXIMITY:
        storeZeroToFloatParam(&state->lifespanTimer);
        state->mode = PROXIMITYMINE_MODE_WAITING;
        ObjHits_EnableObject((u32)obj);
        state->triggerDistance = (f32)(s32)
        def->parameter;
        storeZeroToFloatParam(&state->bounceTimer);
        break;
    }
    state->verticalStep =
        (lbl_803E679C * obj->height) / lbl_803DC230;
    state->targetObj = NULL;
    state->effectHandle = NULL;
    return;
}

void proximitymine_release(void)
{
    return;
}

void proximitymine_initialise(void)
{
    return;
}
