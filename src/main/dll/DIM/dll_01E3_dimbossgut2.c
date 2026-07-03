/*
 * dimbossgut2 (DLL 0x1E3) - DIM boss gut-spike / tendril objects (the
 * glowing green projectile stalks that track the player around the gut cavity).
 * Each instance follows a ROM curve path while locked on, emits particle
 * breath fx, and hosts a green point light.  Hit-detection uses a sphere
 * hitbox that resets after each contact burst.
 */
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/mmsh_waterspike.h"
#include "main/objhits.h"
#include "main/sfa_shared_decls.h"

#define MODEL_LIGHT_KIND_POINT 2

typedef struct Dimbossgut2State
{
    u8 pad0[0x4 - 0x0];
    s32 unk4;
    u8 pad8[0x3DC - 0x8];
    s32 curvePath; /* 0x3DC rom-curve path walker (Curve_AdvanceAlongPath/goNextPoint) */
    u8 pad3E0[0x400 - 0x3E0];
    u16 flags400; /* 0x400 bit3 = advancing along path */
    u8 pad402[0x40C - 0x402];
    s32 curveData; /* 0x40C Dimbossgut2Curve definition pointer */
    u8 pad410[0x42C - 0x410];
} Dimbossgut2State;

typedef struct Dimbossgut2Curve
{
    f32 f0;
    f32 f4;
    f32 f8;
    f32 fC;
    f32 f10;
    s16 s14;
    u16 timer16;
    s32 light;
} Dimbossgut2Curve;

STATIC_ASSERT(offsetof(Dimbossgut2Curve, f0) == 0x0);
STATIC_ASSERT(offsetof(Dimbossgut2Curve, f4) == 0x4);
STATIC_ASSERT(offsetof(Dimbossgut2Curve, f8) == 0x8);
STATIC_ASSERT(offsetof(Dimbossgut2Curve, fC) == 0xC);
STATIC_ASSERT(offsetof(Dimbossgut2Curve, f10) == 0x10);
STATIC_ASSERT(offsetof(Dimbossgut2Curve, s14) == 0x14);
STATIC_ASSERT(offsetof(Dimbossgut2Curve, timer16) == 0x16);
STATIC_ASSERT(offsetof(Dimbossgut2Curve, light) == 0x18);

extern void ModelLightStruct_free(void* light);
extern int randomGetRange(int lo, int hi);
extern void Obj_FreeObject(int obj);
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern int ObjMsg_Pop();
extern void objRenderFn_8003b8f4(int* obj);
extern void queueGlowRender(void* light);
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
extern int Curve_AdvanceAlongPath(int a, f32 f);
extern int getAngle(float y, float x);
extern int Obj_GetPlayerObject(void);
extern f32 lbl_803E4D10;
extern f32 lbl_803E4D14;
extern f32 lbl_803E4D18;
extern f32 lbl_803E4D1C;
extern int hitDetectFn_80065e50(int a, f32 b, f32 c, f32 d, void* out, int e, int f);
extern void lightSetFieldBC_8001db14(int light, int v);
extern void* objCreateLight(int arg, u8 addToList);
extern void modelLightStruct_setLightKind(int light, int v);
extern void modelLightStruct_setDiffuseColor(int light, int a, int b, int c, int d);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 a, f32 b);
extern void modelLightStruct_setupGlow(int light, int a, int b, int c, int d, int e, f32 f);
extern void modelLightStruct_setGlowProjectionRadius(int light, f32 f);
extern f32 lbl_803E4D24;
extern f32 lbl_803E4D28;
extern f32 lbl_803E4D2C;
extern f32 lbl_803E4D30;
extern f32 lbl_803E4D04;

void dimbossgut2_updateTracking(int obj, int state)
{
    int curve;
    int r30v;
    s16 delta;
    s16 angle;
    int q;
    f32 fv;
    int player;
    int rel;

    curve = ((Dimbossgut2State*)state)->curveData;
    r30v = ((Dimbossgut2State*)state)->curvePath;
    if ((((Dimbossgut2State*)state)->flags400 & 8) != 0)
    {
        if ((Curve_AdvanceAlongPath(r30v, ((Dimbossgut2Curve*)curve)->f10) != 0) || (*(int*)(r30v + 0x10) != 0))
        {
            if ((*gRomCurveInterface)->goNextPoint((void*)r30v) != 0)
            {
                ((Dimbossgut2State*)state)->flags400 = ((Dimbossgut2State*)state)->flags400 & ~0x8;
            }
        }
        angle = (s16)(getAngle(*(f32*)(r30v + 0x74), *(f32*)(r30v + 0x7c)) + 0x8000);
        delta = (s16)(angle - (u16)((GameObject*)obj)->anim.rotX);
        if (delta > 0x8000)
        {
            delta = (s16)(delta - 0xffff);
        }
        if (delta < -0x8000)
        {
            delta = (s16)(delta + 0xffff);
        }
        ((GameObject*)obj)->anim.rotX = angle;
        ((Dimbossgut2Curve*)curve)->f4 = ((Dimbossgut2Curve*)curve)->f4 + (f32)(delta >> 4);
        if (((Dimbossgut2Curve*)curve)->f10 < lbl_803E4D14)
        {
            ((Dimbossgut2Curve*)curve)->f10 = ((Dimbossgut2Curve*)curve)->f10 + lbl_803E4D18;
        }
        q = delta / 0xb6;
        if (q < 0)
        {
            q = -q;
        }
        fv = (f32)(s32)
        q * lbl_803E4CD4;
        if (fv > lbl_803E4CF0)
        {
            ((Dimbossgut2Curve*)curve)->f10 = ((Dimbossgut2Curve*)curve)->f10 / fv;
            ((Dimbossgut2Curve*)curve)->f8 = ((Dimbossgut2Curve*)curve)->f8 + lbl_803E4D1C;
        }
        if (((Dimbossgut2Curve*)curve)->f8 > lbl_803E4CD8)
        {
            ((Dimbossgut2Curve*)curve)->f8 = ((Dimbossgut2Curve*)curve)->f8 / lbl_803E4D10;
        }
        ((GameObject*)obj)->anim.localPosX = *(f32*)(r30v + 0x68);
        ((GameObject*)obj)->anim.localPosZ = *(f32*)(r30v + 0x70);
    }
    else
    {
        player = Obj_GetPlayerObject();
        rel = (int)(u16)getAngle(-(((GameObject*)player)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX),
                                 -(((GameObject*)player)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ)) -
            (int)(u16)((GameObject*)obj)->anim.rotX;
        if (rel > 0x8000)
        {
            rel = rel - 0xffff;
        }
        if (rel < -0x8000)
        {
            rel = rel + 0xffff;
        }
        ((GameObject*)obj)->anim.rotX = (s16)(*(s16*)(long)obj + rel * framesThisStep / 3);
    }
    return;
}

void dimbossgut2_free(int arg9)
{
    int obj = arg9;
    u32 handle;
    int state;
    void* childObj;

    state = *(int*)&((GameObject*)obj)->extra;
    handle = ((Dimbossgut2Curve*)((Dimbossgut2State*)state)->curveData)->light;
    if (handle != 0)
    {
        ModelLightStruct_free((void*)handle);
    }
    ObjGroup_RemoveObject(obj, 3);
    childObj = ((GameObject*)obj)->childObjs[0];
    if (childObj != 0)
    {
        Obj_FreeObject((int)childObj);
        *(u32*)(obj + 200) = 0;
    }
    (*(void (*)(int, int, int))(*(int*)(*gBaddieControlInterface + 0x40)))(obj, state, 0);
    return;
}

void dimbossgut2_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8* light;

    light = ((GameObject*)obj)->extra;
    if (visible != 0)
    {
        ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5,
                                                                      lbl_803E4CF0);
        light = (u8*)((Dimbossgut2Curve*)((Dimbossgut2State*)light)->curveData)->light;
        if (((light != 0) && (light[0x2f8] != 0)) && (light[0x4c] != 0))
        {
            queueGlowRender(light);
        }
    }
    return;
}

void dimbossgut2_update(int obj)
{
    int state;
    int tmpVar;
    u32 randomThreshold;
    u32 n;
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

    state = *(int*)&((GameObject*)obj)->extra;
    if ((((GameObject*)obj)->unkF4 == 0) &&
        ((((GameObject*)obj)->anim.parent != NULL ||
            (tmpVar = objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                        ((GameObject*)obj)->anim.localPosZ),
                tmpVar >= 0))))
    {
        msgC = 0;
        do
        {
            tmpVar = ObjMsg_Pop(obj, &msgA, &msgB, &msgC);
        }
        while (tmpVar != 0);
        posData = (Dimbossgut2Curve*)((Dimbossgut2State*)state)->curveData;
        if ((posData->f0 < lbl_803E4CD0) && (posData->f10 < lbl_803E4CD4))
        {
            heightDiff = posData->fC - ((GameObject*)obj)->anim.localPosY;
            if (heightDiff < lbl_803E4CD8)
            {
                heightDiff = -heightDiff;
            }
            if ((heightDiff < lbl_803E4CDC) &&
                (stk.f4c = posData->fC, randomThreshold = randomGetRange(0x1e, 0x3c),
                    (int)(u32)posData->timer16 > (int)randomThreshold))
            {
                xyScale = lbl_803E4CE0 * posData->f10;
                stk.f50 = ((GameObject*)obj)->anim.localPosX -
                    xyScale * mathSinf(gDimBossGut2Pi * (f32)((GameObject*)obj)->anim.rotX / gDimBossGut2AngleUnitToRadians);
                stk.f48 = ((GameObject*)obj)->anim.localPosZ -
                    xyScale * mathCosf(gDimBossGut2Pi * (f32)((GameObject*)obj)->anim.rotX / gDimBossGut2AngleUnitToRadians);
                stk.f54 = lbl_803E4CEC * (lbl_803E4CF0 - heightDiff / lbl_803E4CDC);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x32b, &stk, 1, -1,
                                                 NULL);
                posData->timer16 = 0;
            }
        }
        posData->timer16 += framesThisStep;
        fn_801BEEA0((s16*)obj, (u8*)state);
        dimbossgut2_updateTracking(obj, state);
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E4D20, timeDelta, NULL);
        ((ObjHitsPriorityState*)*(int*)&((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 9;
        ((ObjHitsPriorityState*)*(int*)&((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 1;
        ObjHits_RegisterActiveHitVolumeObject(obj);
        val = (Dimbossgut2Curve*)((Dimbossgut2State*)state)->curveData;
        curveLight = (u8*)val->light;
        if ((curveLight != NULL) && (curveLight[0x2f8] != 0) && (curveLight[0x4c] != 0))
        {
            n = (curveLight[0x2f9] + *(s8*)(curveLight + 0x2fa)) & 0xffff;
            if (0xc < n)
            {
                n = (n + randomGetRange(-12, 12)) & 0xffff;
                if (0xff < n)
                {
                    n = 0xff;
                    *(u8*)(val->light + 0x2fa) = 0;
                }
            }
            *(u8*)(val->light + 0x2f9) = n;
        }
    }
    return;
}

void dimbossgut2_init(int obj, int def, int p3)
{
    int state;
    int p;
    int count;
    int i;
    int* list;
    u8 flags;
    f32 z;

    state = *(int*)&((GameObject*)obj)->extra;
    flags = 0x16;
    if (p3 != 0)
    {
        flags |= 1;
    }
    (*(void (*)(int, int, int, int, int, int, u8, f32))(*(int*)(*gBaddieControlInterface + 0x58)))(
        obj, def, state, 0, 0, 0x102, flags, lbl_803E4CE0);
    ((GameObject*)obj)->animEventCallback = NULL;
    p = ((Dimbossgut2State*)state)->curveData;
    z = lbl_803E4CD8;
    ((Dimbossgut2Curve*)p)->f0 = z;
    ((Dimbossgut2Curve*)p)->f4 = z;
    ((Dimbossgut2Curve*)p)->s14 = randomGetRange(-0x7fff, 0x7fff);
    z = lbl_803E4CD8;
    ((Dimbossgut2Curve*)p)->f8 = z;
    ((Dimbossgut2Curve*)p)->timer16 = 0;
    ((Dimbossgut2Curve*)p)->f10 = z;
    count = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                 ((GameObject*)obj)->anim.localPosZ, &list, 0, 0);
    ((Dimbossgut2Curve*)p)->fC = lbl_803E4CD8;
    if (count != 0)
    {
        ((Dimbossgut2Curve*)p)->fC = lbl_803E4D24;
        for (i = 0; i < count; i++)
        {
            f32 d = *(f32*)list[i] - ((GameObject*)obj)->anim.localPosY;
            if (*(s8*)(list[i] + 0x14) == 0xe)
            {
                if (d > ((Dimbossgut2Curve*)p)->fC)
                {
                    ((Dimbossgut2Curve*)p)->fC = d;
                }
            }
        }
    }
    ((Dimbossgut2Curve*)p)->fC += ((GameObject*)obj)->anim.localPosY;
    ObjAnim_SetCurrentMove(obj, 0, (f32)(int)randomGetRange(0, 0x63) / lbl_803E4D28, 0);
    ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)(obj, lbl_803E4D20, timeDelta, NULL);
    ((Dimbossgut2Curve*)p)->light = (int)objCreateLight(obj, 1);
    if ((void*)((Dimbossgut2Curve*)p)->light != NULL)
    {
        modelLightStruct_setLightKind(((Dimbossgut2Curve*)p)->light, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setDiffuseColor(((Dimbossgut2Curve*)p)->light, 0, 255, 0, 0);
        lightSetFieldBC_8001db14(((Dimbossgut2Curve*)p)->light, 1);
        modelLightStruct_setDistanceAttenuation(((Dimbossgut2Curve*)p)->light, lbl_803E4D2C, lbl_803E4CE0);
        modelLightStruct_setupGlow(((Dimbossgut2Curve*)p)->light, 0, 0, 255, 0, 127, lbl_803E4D30);
        modelLightStruct_setGlowProjectionRadius(((Dimbossgut2Curve*)p)->light, lbl_803E4D04);
    }
}

void dimbossgut2_func11(void)
{
}

void dimbossgut2_hitDetect(void)
{
}

void dimbossgut2_release(void)
{
}

void dimbossgut2_initialise(void)
{
}


int dimbossgut2_setScale(void) { return 0x0; }
int dimbossgut2_getExtraSize(void) { return 0x42c; }
int dimbossgut2_getObjectTypeId(void) { return 0x49; }
