/*
 * dimbossgut2 (DLL 0x1E3) - DIM boss gut-spike / tendril objects (the
 * glowing green projectile stalks that track the player around the gut cavity).
 * Each instance follows a ROM curve path while locked on, emits particle
 * breath fx, and hosts a green point light.  Hit-detection uses a sphere
 * hitbox that resets after each contact burst.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/object_render.h"
#include "main/obj_group.h"
#include "main/obj_message.h"
#include "main/model_light.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/track_dolphin_api.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/mmsh_waterspike.h"
#include "main/objhits.h"
#include "main/lightmap_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/DIM/dll_01E3_dimbossgut2.h"
#include "main/curve.h"
#include "main/dll/baddie_control_interface.h"

#define DIMBOSSGUT2_OBJGROUP 3
#define DIMBOSSGUT2_PARTFX   0x32b


void dimbossgut2_updateTracking(GameObject* obj, Dimbossgut2State* state)
{
    Dimbossgut2Curve* curve;
    RomCurveWalker* pathWalker;
    s16 delta;
    s16 angle;
    int angleMag;
    f32 angleScale;
    int player;
    int rel;

    curve = state->curveData;
    pathWalker = state->curvePath;
    if ((state->flags400 & 8) != 0)
    {
        if ((Curve_AdvanceAlongPath(&pathWalker->curve, curve->pathSpeed) != 0) || pathWalker->atSegmentEnd != 0)
        {
            if ((*gRomCurveInterface)->goNextPoint((void*)pathWalker) != 0)
            {
                state->flags400 &= ~0x8;
            }
        }
        angle = (s16)(getAngle(pathWalker->tangentX, pathWalker->tangentZ) + 0x8000);
        delta = (s16)(angle - (u16)(obj)->anim.rotX);
        if (delta > 0x8000)
        {
            delta = (s16)(delta - 0xffff);
        }
        if (delta < -0x8000)
        {
            delta = (s16)(delta + 0xffff);
        }
        (obj)->anim.rotX = angle;
        curve->leanAngle = curve->leanAngle + (f32)(delta >> 4);
        if (curve->pathSpeed < 0.15f)
        {
            curve->pathSpeed += 0.002f;
        }
        angleMag = delta / 0xb6;
        if (angleMag < 0)
        {
            angleMag = -angleMag;
        }
        angleScale = (f32)(s32)angleMag;
        angleScale = angleScale * 0.25f;
        if (angleScale > 1.0f)
        {
            curve->pathSpeed = curve->pathSpeed / angleScale;
            curve->turnWobble += 0.01f;
        }
        if (curve->turnWobble > 0.0f)
        {
            curve->turnWobble = curve->turnWobble / 1.04f;
        }
        (obj)->anim.localPosX = pathWalker->posX;
        (obj)->anim.localPosZ = pathWalker->posZ;
    }
    else
    {
        player = (int)Obj_GetPlayerObject();
        rel = (int)(u16)getAngle(-(((GameObject*)player)->anim.worldPosX - (obj)->anim.worldPosX),
                                 -(((GameObject*)player)->anim.worldPosZ - (obj)->anim.worldPosZ)) -
              (int)(u16)(obj)->anim.rotX;
        if (rel > 0x8000)
        {
            rel = rel - 0xffff;
        }
        if (rel < -0x8000)
        {
            rel = rel + 0xffff;
        }
        (obj)->anim.rotX = (s16)(*(s16*)(long)obj + rel * framesThisStep / 3);
    }
    return;
}

void DIM_BossGut2_func0B(void)
{
}

int DIM_BossGut2_setScale(void)
{
    return 0x0;
}
int DIM_BossGut2_getExtraSize(void)
{
    return 0x42c;
}
int DIM_BossGut2_getObjectTypeId(void)
{
    return 0x49;
}

void DIM_BossGut2_free(int objArg)
{
    int obj = objArg;
    ModelLightStruct* handle;
    int state;
    GameObject* childObj;

    state = *(int*)&((GameObject*)obj)->extra;
    handle = ((Dimbossgut2Curve*)((Dimbossgut2State*)state)->curveData)->light;
    if (handle != 0)
    {
        ModelLightStruct_free(handle);
    }
    ObjGroup_RemoveObject((int)obj, DIMBOSSGUT2_OBJGROUP);
    childObj = ((GameObject*)obj)->childObjs[0];
    if (childObj != 0)
    {
        Obj_FreeObject(childObj);
        ((GameObject*)obj)->childObjs[0] = NULL;
    }
    ((BaddieControlInterface*)*gBaddieControlInterface)->releaseState((GameObject*)obj, (void*)state, 0);
    return;
}

void DIM_BossGut2_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8* light;

    light = ((GameObject*)obj)->extra;
    if (visible != 0)
    {
        objRenderModelAndHitVolumes((GameObject*)obj, p2, p3, p4, p5, 1.0f);
        light = (u8*)((Dimbossgut2Curve*)((Dimbossgut2State*)light)->curveData)->light;
        if (((light != 0) && (light[0x2f8] != 0)) && (light[0x4c] != 0))
        {
            queueGlowRender((ModelLightStruct*)light);
        }
    }
    return;
}

void DIM_BossGut2_hitDetect(void)
{
}

void DIM_BossGut2_update(GameObject* obj)
{
    Dimbossgut2State* state;
    int result;
    u32 randomThreshold;
    u32 brightness;
    Dimbossgut2Curve* posData;
    Dimbossgut2Curve* val;
    f32 heightDiff;
    f32 xyScale;
    u8* curveLight;
    u32 msgB;
    u32 msgA;
    u32 msgC;
    struct
    {
        u8 pad[8];
        f32 f54;
        f32 f50;
        f32 f4c;
        f32 f48;
    } stk;

    state = obj->extra;
    if (((obj)->userData1 == 0) &&
        (((obj)->anim.parent != NULL ||
          (result = objPosToMapBlockIdx((obj)->anim.localPosX, (obj)->anim.localPosY, (obj)->anim.localPosZ),
           result >= 0))))
    {
        msgC = 0;
        do
        {
            result = ObjMsg_Pop(obj, (u32*)&msgA, (u32*)&msgB, (u32*)&msgC);
        } while (result != 0);
        posData = state->curveData;
        if ((posData->f0 < -0.025f) && (posData->pathSpeed < 0.25f))
        {
            heightDiff = posData->lavaSurfaceY - (obj)->anim.localPosY;
            if (heightDiff < 0.0f)
            {
                heightDiff = -heightDiff;
            }
            if ((heightDiff < 14.0f) && (stk.f4c = posData->lavaSurfaceY, randomThreshold = randomGetRange(0x1e, 0x3c),
                                                (int)(u32)posData->breathFxTimer > (int)randomThreshold))
            {
                xyScale = 20.0f * posData->pathSpeed;
                stk.f50 = (obj)->anim.localPosX -
                          xyScale * mathSinf(3.1415927f * (f32)(obj)->anim.rotX / 32768.0f);
                stk.f48 = (obj)->anim.localPosZ -
                          xyScale * mathCosf(3.1415927f * (f32)(obj)->anim.rotX / 32768.0f);
                stk.f54 = 0.65f * (1.0f - heightDiff / 14.0f);
                (*gPartfxInterface)->spawnObject((void*)obj, DIMBOSSGUT2_PARTFX, &stk, 1, -1, NULL);
                posData->breathFxTimer = 0;
            }
        }
        posData->breathFxTimer += framesThisStep;
        fn_801BEEA0((s16*)obj, (u8*)state);
        dimbossgut2_updateTracking(obj, state);
        ObjAnim_AdvanceCurrentMove((int)obj, 0.015f, timeDelta, NULL);
        ((ObjHitsPriorityState*)*(int*)&(obj)->anim.hitReactState)->hitVolumePriority = 9;
        ((ObjHitsPriorityState*)*(int*)&(obj)->anim.hitReactState)->hitVolumeId = 1;
        ObjHits_RegisterActiveHitVolumeObject(obj);
        val = state->curveData;
        curveLight = (u8*)val->light;
        if ((curveLight != NULL) && (curveLight[0x2f8] != 0) && (curveLight[0x4c] != 0))
        {
            brightness = (curveLight[0x2f9] + *(s8*)(curveLight + 0x2fa)) & 0xffff;
            if (0xc < brightness)
            {
                brightness = (brightness + randomGetRange(-12, 12)) & 0xffff;
                if (0xff < brightness)
                {
                    brightness = 0xff;
                    *(u8*)((u8*)val->light + 0x2fa) = 0;
                }
            }
            *(u8*)((u8*)val->light + 0x2f9) = brightness;
        }
    }
    return;
}

void DIM_BossGut2_init(GameObject* obj, int def, int p3)
{
    Dimbossgut2State* state;
    Dimbossgut2Curve* curve;
    int count;
    int i;
    TrackGroundHit** list;
    u8 flags;
    f32 z;

    state = obj->extra;
    flags = 0x16;
    if (p3 != 0)
    {
        flags |= 1;
    }
    ((BaddieControlInterface*)*gBaddieControlInterface)
        ->initGroundBaddie(obj, (u8*)def, (u8*)state, 0, 0, 0x102, flags, 20.0f);
    (obj)->animEventCallback = NULL;
    curve = state->curveData;
    z = 0.0f;
    curve->f0 = z;
    curve->leanAngle = z;
    curve->randomPhase = randomGetRange(-0x7fff, 0x7fff);
    z = 0.0f;
    curve->turnWobble = z;
    curve->breathFxTimer = 0;
    curve->pathSpeed = z;
    count = hitDetectFn_80065e50(obj, (obj)->anim.localPosX, (obj)->anim.localPosY, (obj)->anim.localPosZ, &list,
                                 0, 0);
    curve->lavaSurfaceY = 0.0f;
    if (count != 0)
    {
        curve->lavaSurfaceY = -9999.0f;
        for (i = 0; i < count; i++)
        {
            f32 d = list[i]->height - (obj)->anim.localPosY;
            if ((s8)list[i]->surfaceType == 0xe)
            {
                if (d > curve->lavaSurfaceY)
                {
                    curve->lavaSurfaceY = d;
                }
            }
        }
    }
    curve->lavaSurfaceY += (obj)->anim.localPosY;
    ObjAnim_SetCurrentMove((int)obj, 0, (f32)(int)randomGetRange(0, 0x63) / 100.0f, 0);
    ObjAnim_AdvanceCurrentMove((int)obj, 0.015f, timeDelta, NULL);
    curve->light = objCreateLight(obj, 1);
    if (curve->light != NULL)
    {
        modelLightStruct_setLightKind(curve->light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(curve->light, 0, 255, 0, 0);
        lightSetFieldBC_8001db14(curve->light, 1);
        modelLightStruct_setDistanceAttenuation(curve->light, 10.0f, 20.0f);
        modelLightStruct_setupGlow(curve->light, 0, 0, 255, 0, 127, 15.0f);
        modelLightStruct_setGlowProjectionRadius(curve->light, 50.0f);
    }
}

void DIM_BossGut2_release(void)
{
}

void DIM_BossGut2_initialise(void)
{
}

ObjectDescriptor12 gDIM_BossGut2ObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)DIM_BossGut2_initialise,
    (ObjectDescriptorCallback)DIM_BossGut2_release,
    0,
    (ObjectDescriptorCallback)DIM_BossGut2_init,
    (ObjectDescriptorCallback)DIM_BossGut2_update,
    (ObjectDescriptorCallback)DIM_BossGut2_hitDetect,
    (ObjectDescriptorCallback)DIM_BossGut2_render,
    (ObjectDescriptorCallback)DIM_BossGut2_free,
    (ObjectDescriptorCallback)DIM_BossGut2_getObjectTypeId,
    DIM_BossGut2_getExtraSize,
    (ObjectDescriptorCallback)DIM_BossGut2_setScale,
    (ObjectDescriptorCallback)DIM_BossGut2_func0B,
};
