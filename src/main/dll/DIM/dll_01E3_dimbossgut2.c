/*
 * dimbossgut2 (DLL 0x1E3) - DIM boss gut-spike / tendril objects (the
 * glowing green projectile stalks that track the player around the gut cavity).
 * Each instance follows a ROM curve path while locked on, emits particle
 * breath fx, and hosts a green point light.  Hit-detection uses a sphere
 * hitbox that resets after each contact burst.
 */
#include "main/dll_000A_expgfx.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/mmsh_waterspike.h"
#include "main/objhits.h"
#include "main/lightmap.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/DIM/dll_01E3_dimbossgut2.h"

#define DIMBOSSGUT2_OBJGROUP 3
#define DIMBOSSGUT2_PARTFX   0x32b

#define MODEL_LIGHT_KIND_POINT 2

extern u32* gBaddieControlInterface;
extern f32 lbl_803E4CF0;
extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803E4CD0;
extern f32 lbl_803E4CD4;
extern f32 lbl_803E4CD8;
extern f32 lbl_803E4CDC;
extern f32 lbl_803E4CE0;
extern f32 gDimBossGut2Pi;
extern f32 gDimBossGut2AngleUnitToRadians;
extern f32 lbl_803E4CEC;
extern f32 lbl_803E4D20;
extern f32 lbl_803E4D10;
extern f32 lbl_803E4D14;
extern f32 lbl_803E4D18;
extern f32 lbl_803E4D1C;
extern f32 lbl_803E4D24;
extern f32 lbl_803E4D28;
extern f32 lbl_803E4D2C;
extern f32 lbl_803E4D30;
extern f32 lbl_803E4D04;

extern void ModelLightStruct_free(void* light);
extern void Obj_FreeObject(int obj);
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern int ObjMsg_Pop();
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void queueGlowRender(void* light);
extern int Curve_AdvanceAlongPath(int a, f32 f);
extern int getAngle(float y, float x);
extern int hitDetectFn_80065e50(int a, f32 b, f32 c, f32 d, void* out, int e, int f);
extern void lightSetFieldBC_8001db14(int light, int v);
extern void* objCreateLight(int arg, u8 addToList);
extern void modelLightStruct_setLightKind(int light, int v);
extern void modelLightStruct_setDiffuseColor(int light, int a, int b, int c, int d);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 a, f32 b);
extern void modelLightStruct_setupGlow(int light, int a, int b, int c, int d, int e, f32 f);
extern void modelLightStruct_setGlowProjectionRadius(int light, f32 f);

void dimbossgut2_updateTracking(GameObject* obj, int state)
{
    int curve;
    int pathWalker;
    s16 delta;
    s16 angle;
    int angleMag;
    f32 angleScale;
    int player;
    int rel;

    curve = ((Dimbossgut2State*)state)->curveData;
    pathWalker = ((Dimbossgut2State*)state)->curvePath;
    if ((((Dimbossgut2State*)state)->flags400 & 8) != 0)
    {
        if ((Curve_AdvanceAlongPath(pathWalker, ((Dimbossgut2Curve*)curve)->f10) != 0) ||
            (*(int*)(pathWalker + 0x10) != 0))
        {
            if ((*gRomCurveInterface)->goNextPoint((void*)pathWalker) != 0)
            {
                ((Dimbossgut2State*)state)->flags400 = ((Dimbossgut2State*)state)->flags400 & ~0x8;
            }
        }
        angle = (s16)(getAngle(*(f32*)(pathWalker + 0x74), *(f32*)(pathWalker + 0x7c)) + 0x8000);
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
        ((Dimbossgut2Curve*)curve)->f4 = ((Dimbossgut2Curve*)curve)->f4 + (f32)(delta >> 4);
        if (((Dimbossgut2Curve*)curve)->f10 < lbl_803E4D14)
        {
            ((Dimbossgut2Curve*)curve)->f10 = ((Dimbossgut2Curve*)curve)->f10 + lbl_803E4D18;
        }
        angleMag = delta / 0xb6;
        if (angleMag < 0)
        {
            angleMag = -angleMag;
        }
        angleScale = (f32)(s32)angleMag * lbl_803E4CD4;
        if (angleScale > lbl_803E4CF0)
        {
            ((Dimbossgut2Curve*)curve)->f10 = ((Dimbossgut2Curve*)curve)->f10 / angleScale;
            ((Dimbossgut2Curve*)curve)->f8 = ((Dimbossgut2Curve*)curve)->f8 + lbl_803E4D1C;
        }
        if (((Dimbossgut2Curve*)curve)->f8 > lbl_803E4CD8)
        {
            ((Dimbossgut2Curve*)curve)->f8 = ((Dimbossgut2Curve*)curve)->f8 / lbl_803E4D10;
        }
        (obj)->anim.localPosX = *(f32*)(pathWalker + 0x68);
        (obj)->anim.localPosZ = *(f32*)(pathWalker + 0x70);
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
    u32 handle;
    int state;
    void* childObj;

    state = *(int*)&((GameObject*)obj)->extra;
    handle = ((Dimbossgut2Curve*)((Dimbossgut2State*)state)->curveData)->light;
    if (handle != 0)
    {
        ModelLightStruct_free((void*)handle);
    }
    ObjGroup_RemoveObject(obj, DIMBOSSGUT2_OBJGROUP);
    childObj = ((GameObject*)obj)->childObjs[0];
    if (childObj != 0)
    {
        Obj_FreeObject((int)childObj);
        *(u32*)(obj + 200) = 0;
    }
    (*(void (*)(int, int, int))(*(int*)(*gBaddieControlInterface + 0x40)))(obj, state, 0);
    return;
}

void DIM_BossGut2_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8* light;

    light = ((GameObject*)obj)->extra;
    if (visible != 0)
    {
        ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E4CF0);
        light = (u8*)((Dimbossgut2Curve*)((Dimbossgut2State*)light)->curveData)->light;
        if (((light != 0) && (light[0x2f8] != 0)) && (light[0x4c] != 0))
        {
            queueGlowRender(light);
        }
    }
    return;
}

void DIM_BossGut2_hitDetect(void)
{
}

void DIM_BossGut2_update(GameObject* obj)
{
    int state;
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

    state = *(int*)&(obj)->extra;
    if (((obj)->unkF4 == 0) &&
        (((obj)->anim.parent != NULL ||
          (result = objPosToMapBlockIdx((obj)->anim.localPosX, (obj)->anim.localPosY, (obj)->anim.localPosZ),
           result >= 0))))
    {
        msgC = 0;
        do
        {
            result = ObjMsg_Pop(obj, &msgA, &msgB, &msgC);
        } while (result != 0);
        posData = (Dimbossgut2Curve*)((Dimbossgut2State*)state)->curveData;
        if ((posData->f0 < lbl_803E4CD0) && (posData->f10 < lbl_803E4CD4))
        {
            heightDiff = posData->fC - (obj)->anim.localPosY;
            if (heightDiff < lbl_803E4CD8)
            {
                heightDiff = -heightDiff;
            }
            if ((heightDiff < lbl_803E4CDC) && (stk.f4c = posData->fC, randomThreshold = randomGetRange(0x1e, 0x3c),
                                                (int)(u32)posData->timer16 > (int)randomThreshold))
            {
                xyScale = lbl_803E4CE0 * posData->f10;
                stk.f50 = (obj)->anim.localPosX -
                          xyScale * mathSinf(gDimBossGut2Pi * (f32)(obj)->anim.rotX / gDimBossGut2AngleUnitToRadians);
                stk.f48 = (obj)->anim.localPosZ -
                          xyScale * mathCosf(gDimBossGut2Pi * (f32)(obj)->anim.rotX / gDimBossGut2AngleUnitToRadians);
                stk.f54 = lbl_803E4CEC * (lbl_803E4CF0 - heightDiff / lbl_803E4CDC);
                (*gPartfxInterface)->spawnObject((void*)obj, DIMBOSSGUT2_PARTFX, &stk, 1, -1, NULL);
                posData->timer16 = 0;
            }
        }
        posData->timer16 += framesThisStep;
        fn_801BEEA0((s16*)obj, (u8*)state);
        dimbossgut2_updateTracking(obj, state);
        ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E4D20, timeDelta, NULL);
        ((ObjHitsPriorityState*)*(int*)&(obj)->anim.hitReactState)->hitVolumePriority = 9;
        ((ObjHitsPriorityState*)*(int*)&(obj)->anim.hitReactState)->hitVolumeId = 1;
        ObjHits_RegisterActiveHitVolumeObject((int)obj);
        val = (Dimbossgut2Curve*)((Dimbossgut2State*)state)->curveData;
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
                    *(u8*)(val->light + 0x2fa) = 0;
                }
            }
            *(u8*)(val->light + 0x2f9) = brightness;
        }
    }
    return;
}

void DIM_BossGut2_init(GameObject* obj, int def, int p3)
{
    int state;
    int curve;
    int count;
    int i;
    int* list;
    u8 flags;
    f32 z;

    state = *(int*)&(obj)->extra;
    flags = 0x16;
    if (p3 != 0)
    {
        flags |= 1;
    }
    (*(void (*)(int, int, int, int, int, int, u8, f32))(*(int*)(*gBaddieControlInterface + 0x58)))(
        (int)obj, def, state, 0, 0, 0x102, flags, lbl_803E4CE0);
    (obj)->animEventCallback = NULL;
    curve = ((Dimbossgut2State*)state)->curveData;
    z = lbl_803E4CD8;
    ((Dimbossgut2Curve*)curve)->f0 = z;
    ((Dimbossgut2Curve*)curve)->f4 = z;
    ((Dimbossgut2Curve*)curve)->s14 = randomGetRange(-0x7fff, 0x7fff);
    z = lbl_803E4CD8;
    ((Dimbossgut2Curve*)curve)->f8 = z;
    ((Dimbossgut2Curve*)curve)->timer16 = 0;
    ((Dimbossgut2Curve*)curve)->f10 = z;
    count = hitDetectFn_80065e50((int)obj, (obj)->anim.localPosX, (obj)->anim.localPosY, (obj)->anim.localPosZ, &list,
                                 0, 0);
    ((Dimbossgut2Curve*)curve)->fC = lbl_803E4CD8;
    if (count != 0)
    {
        ((Dimbossgut2Curve*)curve)->fC = lbl_803E4D24;
        for (i = 0; i < count; i++)
        {
            f32 d = *(f32*)list[i] - (obj)->anim.localPosY;
            if (*(s8*)(list[i] + 0x14) == 0xe)
            {
                if (d > ((Dimbossgut2Curve*)curve)->fC)
                {
                    ((Dimbossgut2Curve*)curve)->fC = d;
                }
            }
        }
    }
    ((Dimbossgut2Curve*)curve)->fC += (obj)->anim.localPosY;
    ObjAnim_SetCurrentMove((int)obj, 0, (f32)(int)randomGetRange(0, 0x63) / lbl_803E4D28, 0);
    ObjAnim_AdvanceCurrentMove((int)obj, lbl_803E4D20, timeDelta, NULL);
    ((Dimbossgut2Curve*)curve)->light = (int)objCreateLight((int)obj, 1);
    if ((void*)((Dimbossgut2Curve*)curve)->light != NULL)
    {
        modelLightStruct_setLightKind(((Dimbossgut2Curve*)curve)->light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(((Dimbossgut2Curve*)curve)->light, 0, 255, 0, 0);
        lightSetFieldBC_8001db14(((Dimbossgut2Curve*)curve)->light, 1);
        modelLightStruct_setDistanceAttenuation(((Dimbossgut2Curve*)curve)->light, lbl_803E4D2C, lbl_803E4CE0);
        modelLightStruct_setupGlow(((Dimbossgut2Curve*)curve)->light, 0, 0, 255, 0, 127, lbl_803E4D30);
        modelLightStruct_setGlowProjectionRadius(((Dimbossgut2Curve*)curve)->light, lbl_803E4D04);
    }
}

void DIM_BossGut2_release(void)
{
}

void DIM_BossGut2_initialise(void)
{
}
