/*
 * DLL 0xE3 - fireball object (a homing magic projectile).
 *
 * The fireball spawns a model light (objCreateLight) tinted per colorIndex
 * from lbl_80320978 (owned by the staff TU), flies for flightDuration
 * computed from its launch velocity, optionally homes onto a target
 * hit-volume (fn_8016F260) on a spiral (spiralPhase), runs ground collision
 * when stateFlags bit 4 is set, and on contact plays an impact SFX /
 * particle burst, frees its light and fades out. seqId 2110 hides the
 * object; seqId 0x6e8 contact recolors it from the combat source palette.
 * stateFlags: bit0 = launch position latched, bit1 = (unused here),
 * bit3 = disabled/no-update, bit4 = affected by gravity+ground snap.
 */
#include "main/dll/xyzanimator.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/game_object.h"
#include "main/audio/sfx.h"
#include "main/objhits.h"
#include "main/dll/genprops.h"
#include "main/dll_000A_expgfx.h"
#include "main/vecmath.h"
#include "main/dll/dll_00E3_fireball.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#define FIREBALL_HIT_VOLUME_SLOT 14

/* object group this object joins while active */
#define FIREBALL_OBJGROUP 2

#define MODEL_LIGHT_KIND_POINT 2

#define FIREBALL_ROT_COUNT 5

extern void modelLightStruct_setLightKind(int light, int value);
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setupGlow(int light, int a, int r, int g, int b, int alpha, f32 radius);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far);
extern void lightSetField4D(int light, int v);
extern void modelLightStruct_setEnabled(int light, int enabled, f32 scale);

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);

extern int getAngle(float y, float x);

typedef struct FireballPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s16 unk18;
    s16 startupDelayEnabled; /* 0x1A nonzero (and seqId != 2110) => arms FireballState.startupDelay */
    s16 startDisabled;       /* 0x1C nonzero => fireball starts with FIREBALL_FLAG_DISABLED */
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x2C - 0x22];
    s16 unk2C;
    u8 pad2E[0x30 - 0x2E];
} FireballPlacement;

typedef struct FireballState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    f32 unkC;
    s32 unk10;
    u8 pad14[0x18 - 0x14];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 posX;
    f32 posY;
    f32 posZ;
    f32 flightDuration;
    f32 elapsedTime;
    f32 fadeoutTimer;
    f32 startupDelay;
    s16 unk40;
    s16 unk42;
    u8 pad44[0x46 - 0x44];
    u16 spiralPhase;
    u16 rotZBase[FIREBALL_ROT_COUNT];  /* 0x48 */
    u16 rotZDelta[FIREBALL_ROT_COUNT]; /* 0x52 */
    u16 rotYBase[FIREBALL_ROT_COUNT];  /* 0x5C */
    u16 rotYDelta[FIREBALL_ROT_COUNT]; /* 0x66 */
    u8 stateFlags;
    u8 colorIndex;
    u8 pad72[0x94 - 0x72];
    s32 unk94;
    s32 unk98;
    u8 pad9C[0xAA - 0x9C];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xE8 - 0xB2];
    s32 unkE8;
    u8 padEC[0x114 - 0xEC];
    s16 unk114;
    s16 unk116;
} FireballState;

/* FireballState.stateFlags bits (see file header comment) */
#define FIREBALL_FLAG_POS_LATCHED 0x1 /* launch position has been latched into posX/Y/Z */
#define FIREBALL_FLAG_GRAVITY     0x4 /* affected by gravity + ground snap */
#define FIREBALL_FLAG_DISABLED    0x8 /* disabled / no-update */

#define FIREBALL_OBJFLAG_FREED 0x40

/* anim.seqId of the invisible variant (docblock: "seqId 2110 hides the object"). */
#define FIREBALL_SEQID_HIDDEN 0x83e
/* anim.seqId of the hit object that triggers combat-source recolor. */
#define FIREBALL_SEQID_CMBSRC_RECOLOR 0x6e8

extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void ObjGroup_AddObject(u32 obj, int group);
extern void ModelLightStruct_free(void* p);
extern int* Obj_GetActiveModel(int obj);
extern const f32 lbl_803E3330;
extern int cmbsrc_getColorIndex(int* p);
extern void projectileParticleFxFn_80099660(int* obj, f32 v, int kind);
extern const f32 lbl_803E3354;
extern const f32 lbl_803E3358;
extern void lightSetFieldBC_8001db14(int light, int v);
extern void modelLightStruct_setGlowProjectionRadius(int light, f32 a);
extern const f32 lbl_803E3378;
extern const f32 lbl_803E337C;
extern const f32 lbl_803E3380;
extern int hitDetectFn_800658a4(int* obj, f32 x, f32 y, f32 z, f32* out, int flag);
void fn_8016F260(int* obj, int* state, int* other);
extern const f32 gFireballSpiralAmplitude;
extern const f32 gFireballPi;
extern const f32 gFireballAngleScale;
extern const f32 lbl_803E335C;
extern const f32 lbl_803E3360;
extern const f32 lbl_803E3364;
extern const f32 lbl_803E3368;
extern const f32 lbl_803E336C;
extern u8 gFireballColorIndexTable[8];
extern void queueGlowRender(int light);
extern const f32 lbl_803E3350;
extern const f32 lbl_803E3340;
extern void modelLightStruct_setDiffuseColor(int* light, int r, int g, int b, int a);
extern int objCreateLight(int* obj, int arg);
extern void Obj_FreeObject(int* obj);

/* fireball light tint per colorIndex; lives in the staff TU's data (0x80320978) */
extern u32 lbl_80320978[];

int Fireball_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);

u8 fn_8016F16C(int* obj)
{
    return ((FireballState*)((GameObject*)obj)->extra)->colorIndex;
}

int Fireball_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int i;
    int* state = ((GameObject*)obj)->extra;
    if (((FireballState*)state)->stateFlags & FIREBALL_FLAG_DISABLED)
    {
        return 0;
    }
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 cmd = animUpdate->eventIds[i];
        if (cmd == 1)
        {
            if (*(void**)state != NULL)
            {
                modelLightStruct_setEnabled(*(int*)state, 1, lbl_803E3330);
            }
            ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        }
        else if (cmd == 2)
        {
            if (*(void**)state != NULL)
            {
                modelLightStruct_setEnabled(*(int*)state, 0, lbl_803E3330);
            }
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        }
    }
    return 0;
}

void fn_8016F260(int* obj, int* state, int* other)
{
    ObjHitVolumeRuntimeTransform* hitVolume =
        &((GameObject*)other)->anim.hitVolumeTransforms[((GameObject*)other)->hitVolumeIndex];
    if (hitVolume != NULL)
    {
        f32 dx = hitVolume->jointX - ((FireballState*)state)->posX;
        f32 dy = hitVolume->jointY - gFireballSpiralAmplitude - ((FireballState*)state)->posY;
        f32 dz = hitVolume->jointZ - ((FireballState*)state)->posZ;
        s16 angY;
        s16 angP;
        s16 difY;
        s16 difP;
        s16 targY;
        s16 targP;
        f32 t1;
        f32 t2;
        f32 c;

        angY = getAngle(((GameObject*)obj)->anim.velocityX, ((GameObject*)obj)->anim.velocityZ);
        t1 = ((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX;
        t2 = ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ;
        angP = getAngle(((GameObject*)obj)->anim.velocityY, sqrtf(t1 + t2));
        targY = getAngle(dx, dz);
        targP = getAngle(dy, sqrtf(dx * dx + dz * dz));

        difY = targY - (u16)angY;
        if (difY > 0x8000)
        {
            difY = (difY - 0x10000) + 1;
        }
        if (difY < -0x8000)
        {
            difY += 0xffff;
        }
        difP = targP - (u16)angP;
        if (difP > 0x8000)
        {
            difP = (difP - 0x10000) + 1;
        }
        if (difP < -0x8000)
        {
            difP += 0xffff;
        }
        difY >>= 5;
        if (difY > 364)
        {
            difY = 364;
        }
        if (difY < -364)
        {
            difY = -364;
        }
        difP >>= 4;
        if (difP > 728)
        {
            difP = 728;
        }
        if (difP < -728)
        {
            difP = -728;
        }
        angY += framesThisStep * difY;
        angP += framesThisStep * difP;

        dx = gFireballPi * angY / gFireballAngleScale;
        ((GameObject*)obj)->anim.velocityX = mathSinf(dx);
        ((GameObject*)obj)->anim.velocityZ = mathCosf(dx);
        dx = gFireballPi * angP / gFireballAngleScale;
        c = mathSinf(dx);
        {
            f32 cosP = mathCosf(dx);
            if (lbl_803E3330 != cosP)
            {
                c = c / cosP;
            }
        }
        ((GameObject*)obj)->anim.velocityY = c;

        c = lbl_803E3340 / sqrtf(((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ +
                                 (((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
                                  ((GameObject*)obj)->anim.velocityY * ((GameObject*)obj)->anim.velocityY));
        ((GameObject*)obj)->anim.velocityX *= c;
        ((GameObject*)obj)->anim.velocityY *= c;
        ((GameObject*)obj)->anim.velocityZ *= c;
    }
}

int Fireball_getExtraSize(void)
{
    return 0x74;
}
int Fireball_getObjectTypeId(void)
{
    return 0x0;
}

void Fireball_free(int* obj)
{
    int* inner = (int*)((GameObject*)obj)->extra;
    void* ptr = *(void**)inner;
    if (ptr != NULL)
    {
        ModelLightStruct_free(ptr);
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
    ObjGroup_RemoveObject((int)obj, FIREBALL_OBJGROUP);
}

void Fireball_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int* model;
    u8* state = ((GameObject*)obj)->extra;
    u16 savedRot4;
    u16 savedRot2;
    u8 i;
    f32 savedF8;
    if (visible == 0 || (((FireballState*)state)->stateFlags & FIREBALL_FLAG_DISABLED) != 0 ||
        ((FireballState*)state)->startupDelay != lbl_803E3330)
    {
        return;
    }
    ((ObjAnimComponent*)obj)->bankIndex = 1;
    model = Obj_GetActiveModel(obj);
    *(u8*)((char*)*(int**)((char*)model + 0x34) + 8) = gFireballColorIndexTable[((FireballState*)state)->colorIndex];
    savedRot4 = ((GameObject*)obj)->anim.rotZ;
    savedRot2 = ((GameObject*)obj)->anim.rotY;
    savedF8 = ((GameObject*)obj)->anim.rootMotionScale;
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3350;
    for (i = 0; i < FIREBALL_ROT_COUNT; i++)
    {
        FireballState* fs = (FireballState*)(state + i * 2);
        fs->rotZBase[0] += fs->rotZDelta[0];
        fs->rotYBase[0] += fs->rotYDelta[0];
        ((GameObject*)obj)->anim.rotZ = (s16)fs->rotZBase[0];
        ((GameObject*)obj)->anim.rotY = (s16)fs->rotYBase[0];
        *(u16*)((char*)model + 0x18) &= ~0x8;
        ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E3354);
    }
    ((GameObject*)obj)->anim.rotZ = savedRot4;
    ((GameObject*)obj)->anim.rotY = savedRot2;
    ((GameObject*)obj)->anim.rootMotionScale = savedF8;
    ((ObjAnimComponent*)obj)->bankIndex = 0;
    model = Obj_GetActiveModel(obj);
    *(u8*)((char*)*(int**)((char*)model + 0x34) + 8) = gFireballColorIndexTable[((FireballState*)state)->colorIndex];
    ((void (*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E3354);
    if (*(int**)state != NULL)
    {
        if (*(u8*)((char*)*(int**)state + 0x2f8) != 0 && *(u8*)((char*)*(int**)state + 0x4c) != 0)
        {
            u16 sum = *(u8*)((char*)*(int**)state + 0x2f9) + *(s8*)((char*)*(int**)state + 0x2fa);
            if (sum > 12)
            {
                sum += randomGetRange(-12, 12);
                if (sum > 255)
                {
                    sum = 255;
                    *(u8*)((char*)*(int**)state + 0x2fa) = 0;
                }
            }
            *(u8*)((char*)*(int**)state + 0x2f9) = sum;
        }
        if (*(u8*)((char*)*(int**)state + 0x2f8) != 0 && *(u8*)((char*)*(int**)state + 0x4c) != 0)
        {
            queueGlowRender(*(int*)state);
        }
    }
}

void Fireball_hitDetect(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    int* target;
    if (((GameObject*)obj)->anim.seqId == FIREBALL_SEQID_HIDDEN)
        return;
    switch (((FireballState*)state)->stateFlags & FIREBALL_FLAG_DISABLED)
    {
    case 0:
        break;
    default:
        return;
    }
    target = (int*)((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject;
    if (target == NULL)
        return;
    if (((GameObject*)target)->anim.seqId == FIREBALL_SEQID_CMBSRC_RECOLOR)
    {
        int idx = cmbsrc_getColorIndex(target);
        if ((s8)idx != -1)
        {
            ((FireballState*)state)->colorIndex = idx;
            if (*(void**)state != NULL)
            {
                int paletteBase = ((FireballState*)state)->colorIndex * 3;
                u8* pal = (u8*)lbl_80320978;
                modelLightStruct_setDiffuseColor(*(int**)state, pal[paletteBase], pal[paletteBase + 1],
                                                 pal[paletteBase + 2], 0);
            }
        }
        ObjHits_EnableObject(obj);
    }
    else
    {
        u8 colorIndex;
        ((FireballState*)state)->fadeoutTimer = lbl_803E3358;
        colorIndex = ((FireballState*)state)->colorIndex;
        if (colorIndex == 0)
        {
            projectileParticleFxFn_80099660(obj, lbl_803E3354, 3);
        }
        else if (colorIndex == 1)
        {
            projectileParticleFxFn_80099660(obj, lbl_803E3354, 0);
        }
        else
        {
            projectileParticleFxFn_80099660(obj, lbl_803E3354, 6);
        }
        ((GameObject*)obj)->anim.alpha = 0;
        if (*(void**)state != NULL)
        {
            ModelLightStruct_free(*(void**)state);
            *(void**)state = NULL;
        }
    }
    ObjGroup_RemoveObject((int)obj, FIREBALL_OBJGROUP);
}

void Fireball_update(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
#define hitState ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)
    int* other = *(int**)&((GameObject*)obj)->unkF8;
    int* params = *(int**)&((GameObject*)obj)->anim.placementData;

    if ((((FireballState*)state)->stateFlags & FIREBALL_FLAG_DISABLED) != 0)
    {
        return;
    }
    ((FireballState*)state)->startupDelay -= timeDelta;
    if (((FireballState*)state)->startupDelay < *(f32*)&lbl_803E3330)
    {
        ((FireballState*)state)->startupDelay = lbl_803E3330;
    }
    if (((GameObject*)obj)->anim.seqId == FIREBALL_SEQID_HIDDEN)
    {
        if (*(void**)state != NULL)
        {
            modelLightStruct_setEnabled(*(int*)state, 0, lbl_803E3330);
        }
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        return;
    }
    if (lbl_803E3330 == ((FireballState*)state)->elapsedTime)
    {
        ((FireballState*)state)->flightDuration = lbl_803E335C / Vec3_Length(&((GameObject*)obj)->anim.velocityX);
    }
    ((FireballState*)state)->elapsedTime += timeDelta;
    if (((FireballState*)state)->elapsedTime > ((FireballState*)state)->flightDuration)
    {
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, FIREBALL_HIT_VOLUME_SLOT, *(s8*)((char*)params + 0x19) != 0 ? 3 : 1, 0);
    }
    if ((((FireballState*)state)->stateFlags & FIREBALL_FLAG_POS_LATCHED) == 0)
    {
        ((FireballState*)state)->posX = ((GameObject*)obj)->anim.localPosX;
        ((FireballState*)state)->posY = ((GameObject*)obj)->anim.localPosY;
        ((FireballState*)state)->posZ = ((GameObject*)obj)->anim.localPosZ;
        ((FireballState*)state)->stateFlags |= FIREBALL_FLAG_POS_LATCHED;
    }
    {
        if (hitState->contactFlags != 0)
        {
            if (hitState->contactHitVolume != 14)
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_npu_216);
            }
            else
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_foot_water_walk_1);
                (*gWaterfxInterface)
                    ->spawnSplashBurst(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                       ((GameObject*)obj)->anim.localPosZ, lbl_803E3360);
                ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
                    ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ, *(s16*)obj, lbl_803E3330, 2);
            }
            {
                u8 v = ((FireballState*)state)->colorIndex;
                if (v == 0)
                {
                    projectileParticleFxFn_80099660(obj, lbl_803E3354, 3);
                }
                else if (v == 1)
                {
                    projectileParticleFxFn_80099660(obj, lbl_803E3354, 0);
                }
                else
                {
                    projectileParticleFxFn_80099660(obj, lbl_803E3354, 6);
                }
            }
            ((FireballState*)state)->fadeoutTimer = lbl_803E3358;
            ((GameObject*)obj)->anim.alpha = 0;
            if (*(void**)state != NULL)
            {
                ModelLightStruct_free(*(void**)state);
                *(int*)state = 0;
            }
            ObjGroup_RemoveObject((int)obj, FIREBALL_OBJGROUP);
            ObjHits_DisableObject(obj);
        }
    }
    if (((FireballState*)state)->fadeoutTimer != *(f32*)&lbl_803E3330)
    {
        ((GameObject*)obj)->anim.velocityX = lbl_803E3330;
        ((GameObject*)obj)->anim.velocityY = lbl_803E3330;
        ((GameObject*)obj)->anim.velocityZ = lbl_803E3330;
        ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
        ((FireballState*)state)->fadeoutTimer -= timeDelta;
        if (((FireballState*)state)->fadeoutTimer <= lbl_803E3330)
        {
            Obj_FreeObject(obj);
        }
    }
    else
    {
        ((GameObject*)obj)->anim.previousLocalPosX = ((GameObject*)obj)->anim.localPosX;
        ((GameObject*)obj)->anim.previousLocalPosY = ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)obj)->anim.previousLocalPosZ = ((GameObject*)obj)->anim.localPosZ;
        if (other != NULL)
        {
            if ((((GameObject*)other)->objectFlags & FIREBALL_OBJFLAG_FREED) != 0)
            {
                ((GameObject*)obj)->unkF8 = 0;
            }
            else
            {
                fn_8016F260(obj, state, other);
            }
        }
        ((FireballState*)state)->posX += ((GameObject*)obj)->anim.velocityX * timeDelta;
        ((FireballState*)state)->posY += ((GameObject*)obj)->anim.velocityY * timeDelta;
        ((FireballState*)state)->posZ += ((GameObject*)obj)->anim.velocityZ * timeDelta;
        ((FireballState*)state)->spiralPhase += framesThisStep * 1500;
        if ((((FireballState*)state)->stateFlags & FIREBALL_FLAG_GRAVITY) != 0)
        {
            f32 ground;
            ((FireballState*)state)->posY -= lbl_803E3364 * timeDelta;
            if (hitDetectFn_800658a4(obj, ((FireballState*)state)->posX, ((FireballState*)state)->posY,
                                     ((FireballState*)state)->posZ, &ground, 0) == 0)
            {
                ground -= lbl_803E3368;
                if (ground < lbl_803E3330 && ground > lbl_803E336C)
                {
                    ((FireballState*)state)->posY -= ground;
                }
            }
        }
        ((GameObject*)obj)->anim.localPosX = ((FireballState*)state)->posX;
        ((GameObject*)obj)->anim.localPosY = ((FireballState*)state)->posY;
        ((GameObject*)obj)->anim.localPosZ = ((FireballState*)state)->posZ;
        if (other != NULL)
        {
            ((GameObject*)obj)->anim.localPosX +=
                gFireballSpiralAmplitude *
                mathSinf(gFireballPi * (f32)((FireballState*)state)->spiralPhase / gFireballAngleScale);
            ((GameObject*)obj)->anim.localPosZ +=
                gFireballSpiralAmplitude *
                mathCosf(gFireballPi * (f32)((FireballState*)state)->spiralPhase / gFireballAngleScale);
        }
        if ((((GameObject*)obj)->unkF4 -= framesThisStep) < 0)
        {
            Obj_FreeObject(obj);
        }
    }
#undef hitState
}

#pragma opt_common_subs off
void Fireball_init(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    int* params = *(int**)&((GameObject*)obj)->anim.placementData;

    if (((FireballPlacement*)params)->startDisabled != 0)
    {
        ((FireballState*)state)->stateFlags |= FIREBALL_FLAG_DISABLED;
    }
    else
    {
        FireballState* fs;
        int i;
        ((FireballState*)state)->unk40 = randomGetRange(600, 900);
        ((FireballState*)state)->unk42 = randomGetRange(-600, 600);
        ((FireballState*)state)->colorIndex = 0;
        {
            ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
            if (hitState != NULL)
            {
                hitState->trackContactMask = 257;
            }
        }
        if (*(void**)state == NULL)
        {
            *(int*)state = objCreateLight(obj, 1);
            if (*(void**)state != NULL)
            {
                int c;
                u8* base1;
                u8* base2;
                modelLightStruct_setLightKind(*(int*)state, MODEL_LIGHT_KIND_POINT);
                lightSetField4D(*(int*)state, 0);
                modelLightStruct_setPosition(*(int*)state, lbl_803E3330, lbl_803E3330, lbl_803E3330);
                lightSetFieldBC_8001db14(*(int*)state, 1);
                c = ((FireballState*)state)->colorIndex * 3;
                modelLightStruct_setDiffuseColor(
                    *(int**)state, ((u8*)lbl_80320978)[c],
                    (base1 = (u8*)lbl_80320978 + 1)[((FireballState*)state)->colorIndex * 3],
                    (base2 = (u8*)lbl_80320978 + 2)[((FireballState*)state)->colorIndex * 3], 0);
                modelLightStruct_setDistanceAttenuation(*(int*)state, lbl_803E3358, lbl_803E3378);
                c = ((FireballState*)state)->colorIndex * 3;
                modelLightStruct_setupGlow(*(int*)state, 0, ((u8*)lbl_80320978)[c], base1[c], base2[c], 32,
                                           lbl_803E337C);
                modelLightStruct_setGlowProjectionRadius(*(int*)state, lbl_803E337C);
            }
        }
        ((GameObject*)obj)->anim.alpha = 200;
        for (i = 0, fs = (FireballState*)state; i < FIREBALL_ROT_COUNT; i++)
        {
            fs->rotZBase[0] = randomGetRange(-32767, 32767);
            fs->rotZDelta[0] = randomGetRange(-1024, 1024);
            fs->rotYBase[0] = randomGetRange(-32767, 32767);
            fs->rotYDelta[0] = randomGetRange(-1024, 1024);
            fs = (FireballState*)((char*)fs + 2);
        }
        ((GameObject*)obj)->animEventCallback = Fireball_SeqFn;
        ObjGroup_AddObject((int)obj, FIREBALL_OBJGROUP);
        if (((GameObject*)obj)->anim.seqId != FIREBALL_SEQID_HIDDEN &&
            ((FireballPlacement*)params)->startupDelayEnabled != 0)
        {
            ((FireballState*)state)->startupDelay = lbl_803E3380;
        }
    }
}
#pragma opt_common_subs reset

void Fireball_release(void)
{
}

void Fireball_initialise(void)
{
}

ObjectDescriptor10WithPadding gFireballObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)Fireball_initialise,
        (ObjectDescriptorCallback)Fireball_release,
        0,
        (ObjectDescriptorCallback)Fireball_init,
        (ObjectDescriptorCallback)Fireball_update,
        (ObjectDescriptorCallback)Fireball_hitDetect,
        (ObjectDescriptorCallback)Fireball_render,
        (ObjectDescriptorCallback)Fireball_free,
        (ObjectDescriptorCallback)Fireball_getObjectTypeId,
        Fireball_getExtraSize,
    },
    0,
};
