#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/objtexture.h"
#include "main/screen_transition.h"
#include "main/worldobj.h"
#include "dolphin/gx/GXCull.h"
#include "main/objlib.h"
#include "main/camera.h"

typedef struct
{
    f32 f0;
    f32 f4;
    f32 f8;
    f32 fc;
    u8 f10;
    u8 f11;
    u8 pad12[2];
} GreatFoxFxEntry;

extern void ModelLightStruct_free(int model);
extern void objRenderFn_8003b8f4(f32 e);
extern f32 lbl_803E6678;
extern int randomGetRange(int lo, int hi);
extern void Camera_ApplyCurrentViewport(int cam);
extern int gWorldObjEffectRenderDelay;
extern int modelLightStruct_getActiveState(int model);
extern void queueGlowRender(int model);
extern void vecRotateZXY(void* in, void* out);
extern int ObjList_FindObjectById(int id);
extern f32 Vec_distance(f32* a, f32* b);
extern int objCreateLight(int obj, int arg);
extern void modelLightStruct_setLightKind(int light, int v);
extern void modelLightStruct_setPosition(int light, f32 a, f32 b, f32 c);
extern void modelLightStruct_setDiffuseColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 a, f32 b);
extern void modelLightStruct_setupGlow(int light, int a, int r, int g, int b, int e, f32 f);
extern void modelLightStruct_setGlowProjectionRadius(int light, f32 a);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void* Obj_SetupObject(int a, int b, int c, int d, int e);
extern u8 gWorldObjVariantAlphaTable[8];
extern int gWorldObjEffectTargetObj;
extern f32 lbl_803E6668;
extern f32 lbl_803E66B4;
extern f32 lbl_803E66C8;
extern f32 lbl_803E66CC;
extern f32 lbl_803E66D0;
extern f32 lbl_803E66D4;
extern f32 lbl_803E66A0;
extern f32 lbl_803E66AC;
extern f32 lbl_803E66D8;
extern f32 lbl_803E665C;
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int extraSize, int id);
#define GREAT_FOX_EFFECT_COUNT 10
extern GreatFoxFxEntry gGreatFoxEffects[GREAT_FOX_EFFECT_COUNT];
extern f32 lbl_803E6640;
extern f32 lbl_803E6644;
extern f32 lbl_803E6648;
extern f32 lbl_803E664C;
extern f32 lbl_803E6650;
extern f32 lbl_803E6654;
extern f32 lbl_803E6658;
extern f32 lbl_803E6660;
extern f32 lbl_803E6664;
extern f32 lbl_803E666C;
extern void objfx_spawnMaskedHitEffect(int obj, f32 scale, int a, int b, int c, void* params);
extern void objfx_spawnLightPulse(int obj, f32 scale, int a, int b, int c, f32 arg2, void* params);

int worldobj_getExtraSize(void);
void worldobj_hitDetect(void);
void worldobj_release(void);
void worldobj_initialise(void);
int worldobj_getObjectTypeId(int* obj);
void worldobj_free(int obj);
void worldobj_init(int obj, int arg);
void worldobj_spawnGreatFoxEffects(int obj);
void worldobj_spawnAsteroidBatch(int obj, int xMin, int xMax, int yMin, int yMax, int count, int dispatchId);
void worldobj_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

extern float mathCosf(float x);
extern f32 sqrtf(f32 x);
extern float mathSinf(float x);
extern int getAngle(float y, float x);
extern f32 timeDelta;
extern f32 oneOverTimeDelta;
extern int gAudioStreamCurrentId;
extern void Obj_FreeObject(int obj);
extern void modelLightStruct_setEnabled(int light, int a, f32 b);
extern void modelLightStruct_updateGlowAlpha(int light);
extern void modelLightStruct_setDiffuseTargetColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_startColorFade(int light, int a, int b);
extern void modelLightStruct_setDirection(int light, f32 a, f32 b, f32 c);
extern void objfx_spawnFlaggedTrailBurst(int obj, f32 scale, int a, int b, int c, void* vec);
extern f32 gWorldObjAdvanceMoveTable[];
extern f32 lbl_803E667C;
extern f32 gWorldObjPi;
extern f32 gWorldObjAngleHalfCircle;
extern f32 lbl_803E6688;
extern f32 lbl_803E668C;
extern f32 lbl_803E6690;
extern f32 lbl_803E6694;
extern f32 lbl_803E6698;
extern f32 lbl_803E669C;
extern f32 lbl_803E66A4;
extern f32 lbl_803E66A8;
extern f32 lbl_803E66B0;
extern f32 lbl_803E66B8;

int worldobj_getExtraSize(void) { return 0x284; }

void worldobj_hitDetect(void)
{
}

void worldobj_release(void)
{
}

void worldobj_initialise(void)
{
}

int worldobj_getObjectTypeId(int* obj)
{
    if (((WorldObjSetup*)((GameObject*)obj)->anim.placementData)->objectId != 0x5e3)
    {
        return 0x0;
    }
    return 0x8;
}

void worldobj_free(int obj)
{
    WorldObjState* state = ((GameObject*)obj)->extra;
    if (*(void**)&state->light != NULL)
    {
        ModelLightStruct_free(state->light);
        state->light = 0;
    }
    (*gExpgfxInterface)->freeSource(obj);
}

void worldobj_init(int obj, int arg)
{
    WorldObjState* state = ((GameObject*)obj)->extra;
    WorldObjSetup* setup = (WorldObjSetup*)arg;
    int objA, objB;
    int sub;
    int idx;
    u8 i;
    f32 base;
    f32 d;

    switch (setup->objectId)
    {
    case 0x5dd:
    case 0x5ed:
    case 0x5ee:
    case 0x5ef:
    case 0x5f0:
    case 0x5f1:
    case 0x5f2:
    case 0x5f3:
        state->effectState = 0;
        break;
    case 0x80f:
        objA = ObjList_FindObjectById(0x42fe7);
        objB = ObjList_FindObjectById(0x4305a);
        base = ((GameObject*)objB)->anim.localPosY - ((GameObject*)objA)->anim.localPosY;
        state->orbitStartY = (((GameObject*)objA)->anim.localPosY - base) + (f32)(int)
        randomGetRange(-0x3e8, 0x3e8);
        state->orbitEndY = ((GameObject*)objB)->anim.localPosY + (f32)(int)
        randomGetRange(-5, 5);
        state->scale = lbl_803E6668 * ((f32)(int)
        randomGetRange(0, 0x64) / lbl_803E66B4
        )
        +*(f32*)&lbl_803E6668;
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.rootMotionScale * state->scale;
        state->spinXStep = randomGetRange(0xa, 0x19);
        if (randomGetRange(0, 1) != 0)
        {
            state->spinXStep = (s8)(-state->spinXStep);
            state->orbitAngle = 0x8000;
        }
        base = (f32)(int)
        randomGetRange(0xc8, 0x190);
        d = Vec_distance(&((GameObject*)objB)->anim.worldPosX, &((GameObject*)objA)->anim.worldPosX);
        state->orbitRadiusZ = lbl_803E66C8 * d + base;
        state->orbitRadiusX = state->orbitRadiusZ * (lbl_803E66CC * ((f32)(int)
        randomGetRange(0, 0x64) / lbl_803E66B4
        )
        +*(f32*)&lbl_803E66CC
        )
        ;
        state->light = objCreateLight(obj, 1);
        if (*(void**)&state->light != NULL)
        {
            modelLightStruct_setLightKind(state->light, 2);
            modelLightStruct_setPosition(state->light, lbl_803E665C, lbl_803E665C, lbl_803E665C);
            modelLightStruct_setDiffuseColor(state->light, 0xff, 0xff, 0xff, 0);
            modelLightStruct_setDistanceAttenuation(state->light, lbl_803E66AC, lbl_803E66D0);
            modelLightStruct_setupGlow(state->light, 0, 0xff, 0xff, 0xff, 0x82, lbl_803E66D4 * state->scale);
            modelLightStruct_setGlowProjectionRadius(state->light, lbl_803E66A0);
        }
        break;
    case 0x5f5:
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E66D8;
        break;
    case 0x5e3:
        state->controlByte = 0;
        state->spinZStep = 0;
        break;
    case 0x5dc:
        break;
    case 0x5f4:
        break;
    case 0x5e2:
        idx = setup->variant;
        Obj_SetActiveModelIndex(obj, idx);
        ((GameObject*)obj)->anim.alpha = gWorldObjVariantAlphaTable[idx];
        for (i = 0; i < 0xb; i++)
        {
            sub = *(int*)&((GameObject*)obj)->anim.placementData;
            if (Obj_IsLoadingLocked() != 0)
            {
                int o2 = Obj_AllocObjectSetup(0x20, 0x5da);
                *(u8*)(o2 + 4) = *(u8*)(sub + 4);
                *(u8*)(o2 + 6) = *(u8*)(sub + 6);
                *(u8*)(o2 + 5) = *(u8*)(sub + 5);
                *(u8*)(o2 + 7) = *(u8*)(sub + 7);
                *(f32*)(o2 + 8) = ((GameObject*)obj)->anim.localPosX;
                *(f32*)(o2 + 0xc) = ((GameObject*)obj)->anim.localPosY;
                *(f32*)(o2 + 0x10) = ((GameObject*)obj)->anim.localPosZ;
                Obj_SetupObject(o2, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
            }
        }
        break;
    case 0x5da:
        ((GameObject*)obj)->anim.rotZ = randomGetRange(0, 0xffff);
        ((GameObject*)obj)->anim.rotY = randomGetRange(0, 0xffff);
        ((GameObject*)obj)->anim.rotX = randomGetRange(0, 0xffff);
        state->controlByte = randomGetRange(0, 0xff);
        state->spinZStep = randomGetRange(-0xa, 0xa);
        state->spinYStep = randomGetRange(-0xa, 0xa);
        state->spinXStep = randomGetRange(-0xa, 0xa);
        break;
    case 0x61e:
        state->controlByte = 0;
        break;
    case 0x740:
        state->effectState = 0;
        gWorldObjEffectTargetObj = obj;
        break;
    case 0x5d5:
        state->lookAtTargetRef = 0x4aaf7;
        state->attachChildObjectId = 0x4ab08;
        break;
    case 0x5d6:
        state->lookAtTargetRef = 0x4ab03;
        state->attachChildObjectId = 0x4ab09;
        break;
    case 0x5d9:
        state->lookAtTargetRef = 0x4ab04;
        state->attachChildObjectId = 0x4ab0a;
        break;
    case 0x5d7:
        state->lookAtTargetRef = 0x4ab05;
        state->attachChildObjectId = 0x4ab0b;
        break;
    }
}

void worldobj_update(int obj)
{
    s16 rot[3];
    f32 vec[10];
    WorldObjEffectParams params;
    WorldObjState* state;
    WorldObjSetup* setup;
    int objA;
    int objB;
    int tmp;
    u8 i;
    int child;
    ObjTextureRuntimeSlot* tex;
    u8* view;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 dist;
    f32 sv;

    state = ((GameObject*)obj)->extra;
    setup = (WorldObjSetup*)((GameObject*)obj)->anim.placementData;

    switch (setup->objectId)
    {
    case 0x80f:
        if (state->orbitAngle > 0x8000 || state->orbitAngle < 0)
        {
            if (*(void**)&state->light != NULL)
            {
                modelLightStruct_setEnabled(state->light, 0, lbl_803E6678);
            }
            tmp = (int)((f32)((GameObject*)obj)->anim.alpha - lbl_803E667C * timeDelta);
            if (tmp < 0)
            {
                tmp = 0;
            }
            ((GameObject*)obj)->anim.alpha = tmp;
            if (((GameObject*)obj)->anim.alpha == 0)
            {
                Obj_FreeObject(obj);
            }
        }
        else
        {
            objA = ObjList_FindObjectById(0x42fe7);
            objB = ObjList_FindObjectById(0x4305a);
            if ((void*)objA != NULL && (void*)objB != NULL)
            {
                state->orbitAngle =
                    (int)((f32)state->spinXStep * timeDelta + state->orbitAngle);
                vec[0] = state->orbitRadiusX *
                    mathCosf(gWorldObjPi * state->orbitAngle / gWorldObjAngleHalfCircle);
                vec[1] = lbl_803E665C;
                vec[2] = state->orbitRadiusZ *
                    mathSinf(gWorldObjPi * state->orbitAngle / gWorldObjAngleHalfCircle);
                dx = ((GameObject*)objB)->anim.localPosX - ((GameObject*)objA)->anim.localPosX;
                dz = ((GameObject*)objB)->anim.localPosZ - ((GameObject*)objA)->anim.localPosZ;
                rot[0] = getAngle(dx, dz);
                rot[1] = 0;
                rot[2] = 0;
                vecRotateZXY(rot, vec);
                ((GameObject*)obj)->anim.localPosX = vec[0] + (((GameObject*)objA)->anim.localPosX - dx);
                ((GameObject*)obj)->anim.localPosY =
                    state->orbitStartY +
                    state->orbitAngle *
                    (state->orbitEndY - state->orbitStartY) / lbl_803E6688;
                ((GameObject*)obj)->anim.localPosZ = vec[2] + (((GameObject*)objA)->anim.localPosZ - dz);
            }
            ((GameObject*)obj)->anim.velocityX = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosX - ((GameObject*)
                obj)->anim.previousLocalPosX);
            ((GameObject*)obj)->anim.velocityZ = oneOverTimeDelta * (((GameObject*)obj)->anim.localPosZ - ((GameObject*)
                obj)->anim.previousLocalPosZ);
            vec[0] = ((GameObject*)obj)->anim.velocityX;
            vec[1] = lbl_803E665C;
            vec[2] = ((GameObject*)obj)->anim.velocityZ;
            objfx_spawnFlaggedTrailBurst(obj, lbl_803E6668 * state->scale, 2, 0xdf,
                                         8, vec);
            ((GameObject*)obj)->anim.rotX = lbl_803E668C * timeDelta + (f32)((GameObject*)obj)->anim.rotX;
            ((GameObject*)obj)->anim.rotY = lbl_803E6690 * timeDelta + (f32)((GameObject*)obj)->anim.rotY;
            if (*(void**)&state->light != NULL && modelLightStruct_getActiveState(state->light) != 0)
            {
                modelLightStruct_updateGlowAlpha(state->light);
            }
        }
        break;
    case 0x740:
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
            (obj, lbl_803E6694, timeDelta, NULL);
        ((GameObject*)obj)->anim.rotX = lbl_803E668C * timeDelta + (f32)((GameObject*)obj)->anim.rotX;
        break;
    case 0x5dc:
        if (((GameObject*)obj)->unkF4 == 0)
        {
            ((GameObject*)obj)->unkF4 = ObjList_FindObjectById(0x431dc);
            ObjLink_AttachChild(obj, ((GameObject*)obj)->unkF4, 0);
        }
        if (((GameObject*)obj)->unkF8 == 0)
        {
            ((GameObject*)obj)->unkF8 = ObjList_FindObjectById(0x4325b);
            ObjLink_AttachChild(obj, ((GameObject*)obj)->unkF8, 0);
        }
        tex = objFindTexture((void*)obj, 0, 0);
        if (tex != NULL)
        {
            tmp = (s16)-tex->offsetS;
            tmp -= 2;
            if ((s16)tmp < 0)
            {
                tmp += 0x2710;
            }
            tex->offsetS = (s16)-tmp;
        }
        break;
    case 0x5dd:
    case 0x5ed:
    case 0x5ee:
    case 0x5ef:
    case 0x5f0:
    case 0x5f1:
    case 0x5f2:
    case 0x5f3:
        if (state->effectState == 2)
        {
            for (i = 0; i < 0x16; i++)
            {
                char* pathPoint = WorldObj_GetPathPointWork(state, i);
                ObjPath_GetPointWorldPosition(obj, i, (f32*)(pathPoint + 0x10), (f32*)(pathPoint + 0x14),
                                              (f32*)(pathPoint + 0x18), 0);
            }
        }
        break;
    case 0x5e2:
        switch (setup->variant)
        {
        case 0:
            ((GameObject*)obj)->anim.rotX += 0x64;
            break;
        case 1:
            ((GameObject*)obj)->anim.rotY += 0x64;
            break;
        case 2:
            ((GameObject*)obj)->anim.rotZ += 0x64;
            break;
        }
        break;
    case 0x5da:
        ((GameObject*)obj)->anim.rotX += state->spinXStep;
        ((GameObject*)obj)->anim.rotY += state->spinYStep;
        ((GameObject*)obj)->anim.rotZ += state->spinZStep;
        state->controlByte += 2;
        sv = mathCosf(gWorldObjPi * (f32)(s16)(state->controlByte << 8) / gWorldObjAngleHalfCircle);
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E669C * (lbl_803E6678 + sv) + lbl_803E6698;
        break;
    case 0x5db:
        ((GameObject*)obj)->anim.rotX = 0x21a8;
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E66A0;
        break;
    case 0x5f5:
        ((GameObject*)obj)->anim.rotX += 1;
        break;
    case 0x602:
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
            (obj, lbl_803E66A4, timeDelta, (ObjAnimEventList*)&vec[3]);
        break;
    case 0x5e3:
        if (state->controlByte != ((ObjAnimComponent*)obj)->bankIndex)
        {
            Obj_SetActiveModelIndex(obj, state->controlByte);
        }
        if (state->spinZStep != (gAudioStreamCurrentId != 0))
        {
            if (gAudioStreamCurrentId != 0)
            {
                ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
                    (obj, 1, lbl_803E665C, 0);
            }
            else
            {
                ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
                    (obj, 0, lbl_803E665C, 0);
            }
        }
        state->spinZStep = gAudioStreamCurrentId != 0;
        ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
        (obj, gWorldObjAdvanceMoveTable[state->controlByte], timeDelta,
         (ObjAnimEventList*)&vec[3]);
        if (state->effectState == 0 && *(void**)&state->light != NULL)
        {
            ModelLightStruct_free(state->light);
            state->light = 0;
        }
        break;
    case 0x5df:
        worldobj_spawnGreatFoxEffects(obj);
    case 0x5d5:
    case 0x5d6:
    case 0x5d7:
    case 0x5d8:
        if (((GameObject*)obj)->unkF8 == 0)
        {
            child = ObjList_FindObjectById(state->attachChildObjectId);
            if ((void*)child != NULL)
            {
                ((GameObject*)child)->anim.rootMotionScale *= lbl_803E6668;
                ((GameObject*)child)->anim.alpha = 0x96;
                ((GameObject*)child)->anim.flags |= 0x4000;
                ObjLink_AttachChild(obj, child, 0);
                ((GameObject*)obj)->unkF8 = 1;
            }
        }
        if (((GameObject*)obj)->unkF4 != 0 && *(void**)&state->lookAtTargetRef != NULL)
        {
            view = Camera_GetCurrentViewSlot();
            dx = *(f32*)(view + 0xc) - ((GameObject*)obj)->anim.localPosX;
            dy = *(f32*)(view + 0x10) - ((GameObject*)obj)->anim.localPosY;
            dz = *(f32*)(view + 0x14) - ((GameObject*)obj)->anim.localPosZ;
            dist = sqrtf(dx * dx + dy * dy + dz * dz);
            if (dist > lbl_803E665C)
            {
                dx /= dist;
                dy /= dist;
                dz /= dist;
            }
            sv = lbl_803E66A8;
            ((GameObject*)state->lookAtTargetRef)->anim.localPosX = sv * dx + ((GameObject*)obj)->anim.localPosX;
            ((GameObject*)state->lookAtTargetRef)->anim.localPosY = sv * dy + ((GameObject*)obj)->anim.localPosY;
            ((GameObject*)state->lookAtTargetRef)->anim.localPosZ = sv * dz + ((GameObject*)obj)->anim.localPosZ;
        }
        if (state->effectState != 0)
        {
            if ((u8)fn_8012DDAC() == 0 &&
                (*gScreenTransitionInterface)->isFinished() != 0 &&
                gWorldObjEffectRenderDelay == 0)
            {
                if (*(void**)&state->light == NULL)
                {
                    state->light = objCreateLight(obj, 1);
                    if (*(void**)&state->light != NULL)
                    {
                        modelLightStruct_setLightKind(state->light, 2);
                        modelLightStruct_setPosition(state->light, lbl_803E665C, lbl_803E66AC,
                                                     *(f32*)&lbl_803E665C);
                        modelLightStruct_setDiffuseColor(state->light, 0xff, 0, 0, 0xff);
                        modelLightStruct_setDiffuseTargetColor(state->light, 0, 0, 0, 0xff);
                        modelLightStruct_setEnabled(state->light, 1, lbl_803E665C);
                        modelLightStruct_setDistanceAttenuation(state->light, lbl_803E66B0, lbl_803E66B4);
                        modelLightStruct_startColorFade(state->light, 2, 0x3c);
                        modelLightStruct_setDirection(state->light, lbl_803E665C, lbl_803E6644,
                                                      *(f32*)&lbl_803E665C);
                    }
                }
            }
            else if (*(void**)&state->light != NULL)
            {
                ModelLightStruct_free(state->light);
                state->light = 0;
            }
            ((WorldObjState*)((GameObject*)gWorldObjEffectTargetObj)->extra)->effectState = 1;
            ((GameObject*)gWorldObjEffectTargetObj)->anim.localPosX = ((GameObject*)obj)->anim.localPosX;
            ((GameObject*)gWorldObjEffectTargetObj)->anim.localPosY = lbl_803E66B8 + ((GameObject*)obj)->anim.localPosY;
            ((GameObject*)gWorldObjEffectTargetObj)->anim.localPosZ = ((GameObject*)obj)->anim.localPosZ;
            objA = ObjList_FindObjectById(0x4300c);
            if ((void*)objA != NULL && (((GameObject*)objA)->anim.flags & OBJANIM_FLAG_HIDDEN))
            {
                Obj_SetActiveModelIndex(gWorldObjEffectTargetObj, 1);
            }
            else
            {
                Obj_SetActiveModelIndex(gWorldObjEffectTargetObj, 0);
            }
        }
        else if (*(void**)&state->light != NULL)
        {
            ModelLightStruct_free(state->light);
            state->light = 0;
        }
        break;
    case 0x61e:
        ((GameObject*)obj)->anim.rotY = 0x3448;
        ((GameObject*)obj)->anim.rotX = 0x4000;
        switch (setup->variant)
        {
        case 0:
            ((GameObject*)obj)->anim.rotZ -= 0xe;
            break;
        case 1:
            ((GameObject*)obj)->anim.rotZ -= 0x10;
            break;
        case 2:
            ((GameObject*)obj)->anim.rotZ -= 0x13;
            break;
        }
        if (state->controlByte == 0)
        {
            switch (setup->variant)
            {
            case 0:
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x5, 0x5, 0x4b, 0x6f3);
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x7, 0x7, 0x4b, 0x6f4);
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x5, 0x5, 0x4b, 0x6f5);
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x7, 0x7, 0x32, 0x6f6);
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x5, 0x5, 0x4b, 0x6f7);
                worldobj_spawnAsteroidBatch(obj, 0xfa, 0x113, -0x7, 0x7, 0x32, 0x6f8);
                break;
            case 1:
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0x8, 0x8, 0x4b, 0x6f3);
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0xa, 0xa, 0x4b, 0x6f4);
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0x8, 0x8, 0x4b, 0x6f5);
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0xa, 0xa, 0x32, 0x6f6);
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0x8, 0x8, 0x4b, 0x6f7);
                worldobj_spawnAsteroidBatch(obj, 0xa5, 0xbe, -0xa, 0xa, 0x32, 0x6f8);
                break;
            case 2:
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x5, 0x5, 0x32, 0x6f3);
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x7, 0x7, 0x32, 0x6f4);
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x5, 0x5, 0x32, 0x6f5);
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x7, 0x7, 0x19, 0x6f6);
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x5, 0x5, 0x32, 0x6f7);
                worldobj_spawnAsteroidBatch(obj, 0x78, 0x91, -0x7, 0x7, 0x19, 0x6f8);
                break;
            }
            state->controlByte = 1;
        }
        break;
    }
}

void worldobj_spawnGreatFoxEffects(int obj)
{
    WorldObjEffectParams params;
    u8 i;
    f32 s;
    f32 k;

    for (i = 0, k = lbl_803E6640; i < GREAT_FOX_EFFECT_COUNT; i++)
    {
        GreatFoxFxEntry* e;
        s = ((GameObject*)obj)->anim.rootMotionScale;
        e = &gGreatFoxEffects[i];
        params.offsetX = k * (s * e->f0);
        params.offsetY = k * (s * e->f4);
        params.offsetZ = k * (s * e->f8);
        objfx_spawnMaskedHitEffect(obj, s * e->fc, 3, e->f10, e->f11, &params);
    }
    params.effectScale = lbl_803E6644;
    params.offsetX = lbl_803E6640 * (lbl_803E6648 * ((GameObject*)obj)->anim.rootMotionScale);
    params.offsetY = lbl_803E6640 * (lbl_803E664C * ((GameObject*)obj)->anim.rootMotionScale);
    params.offsetZ = lbl_803E6640 * (lbl_803E6650 * ((GameObject*)obj)->anim.rootMotionScale);
    objfx_spawnLightPulse(obj, lbl_803E6654 * ((GameObject*)obj)->anim.rootMotionScale, 1, 0, 6, lbl_803E6658, &params);
    params.offsetX = lbl_803E665C;
    params.offsetY = lbl_803E6640 * (lbl_803E6660 * ((GameObject*)obj)->anim.rootMotionScale);
    params.offsetZ = lbl_803E6640 * (lbl_803E6664 * ((GameObject*)obj)->anim.rootMotionScale);
    objfx_spawnLightPulse(obj, lbl_803E6654 * ((GameObject*)obj)->anim.rootMotionScale, 1, 0, 6, lbl_803E6668, &params);
    params.offsetX = lbl_803E6640 * (lbl_803E666C * ((GameObject*)obj)->anim.rootMotionScale);
    params.offsetY = lbl_803E6640 * (lbl_803E664C * ((GameObject*)obj)->anim.rootMotionScale);
    params.offsetZ = lbl_803E6640 * (lbl_803E6650 * ((GameObject*)obj)->anim.rootMotionScale);
    objfx_spawnLightPulse(obj, lbl_803E6654 * ((GameObject*)obj)->anim.rootMotionScale, 1, 0, 6, lbl_803E6658, &params);
}

void worldobj_spawnAsteroidBatch(int obj, int xMin, int xMax, int yMin, int yMax, int count, int dispatchId)
{
    s16 rot[3];
    f32 vec[3];
    WorldObjEffectParams params;
    int i;
    f32 base;

    for (i = 0, base = lbl_803E665C; i < count; i++)
    {
        vec[0] = base;
        vec[1] = (f32)(int)
        randomGetRange(xMin, xMax);
        vec[2] = (f32)(int)
        randomGetRange(yMin, yMax);
        rot[0] = 0;
        rot[1] = 0;
        rot[2] = randomGetRange(-0x7fff, 0x7fff);
        vecRotateZXY(rot, vec);
        params.offsetX = vec[0];
        params.offsetY = vec[1];
        params.offsetZ = vec[2];
        params.dispatchTimer = 0x64;
        (*gPartfxInterface)->spawnObject((void*)obj, dispatchId, &params, 2,
                                         -1, NULL);
    }
}

void worldobj_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    WorldObjState* state = ((GameObject*)p1)->extra;
    int modelId = ((WorldObjSetup*)((GameObject*)p1)->anim.placementData)->objectId;

    if (modelId == 0x5f5)
    {
        objRenderFn_8003b8f4(lbl_803E6678);
        return;
    }
    if (visible == 0)
    {
        return;
    }
    switch (modelId)
    {
    case 0x61e:
        break;
    case 0x5de:
        if (state->effectState == 0)
        {
            objRenderFn_8003b8f4(lbl_803E6678);
        }
        break;
    case 0x5e3:
        if (randomGetRange(0, 0x19) != 0 && state->effectState != 0)
        {
            GXSetScissor(0x1e0, 0x32, 0x82, 0x96);
            ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E6678);
            Camera_ApplyCurrentViewport(p2);
        }
        break;
    case 0x740:
        if (state->effectState != 0 && (u8)fn_8012DDAC() == 0 &&
            (*gScreenTransitionInterface)->isFinished() != 0)
        {
            if (gWorldObjEffectRenderDelay != 0)
            {
                gWorldObjEffectRenderDelay = gWorldObjEffectRenderDelay - 1;
            }
            else
            {
                ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E6678);
            }
        }
        else
        {
            gWorldObjEffectRenderDelay = 2;
        }
        break;
    case 0x80f:
        if (*(void**)&state->light != NULL && modelLightStruct_getActiveState(state->light) != 0)
        {
            queueGlowRender(state->light);
        }
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E6678);
        break;
    case 0x5da:
    case 0x5dc:
    default:
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E6678);
        break;
    }
}
