/*
 * wmsun (DLL 0x20E) - the finale sky/crystal objects at Krazoa Palace
 * (map 'warlock' = Dinosaur Planet's Warlock Mountain, hence the WM dll
 * prefix). One DLL serves two retail object defs, neither placed by any
 * romlist on the 124 retail maps - instances are spawned at runtime:
 *  - def 922 'WM_Crystal' (romlist type 0x262): Krystal's crystal
 *    prison above the palace. Each returned Krazoa spirit (game bits
 *    0x21B/0x21C/0x21D/0x21F/0x221/0x222) raises its rise threshold
 *    (100..6400); while below it the crystal grows, climbs and spins
 *    faster, rumbling the camera (bit 0x370) past 0x960. Once the
 *    last spirit is in it sets bit 0x38D, clears 0x370 and frees
 *    itself.
 *  - def 907 'WM_sun' (romlist type 0x2BD): despite the retail name
 *    there is no sun in the finale's storm sky - three additive layers
 *    (alpha 0xFF/0x55/0x19 by placement bank) that spawn INVISIBLE and
 *    spin until the crystal sets bit 0x38D; bank 0 then runs the finale
 *    countdowns in gWmSunQuakeTimer..B0 (armed to 800 at init): quakes, a
 *    ONE-SHOT envfx 0x30/0x34 burst, and finally bit 0x38F, after which
 *    every bank fades in and bank 0 flickers the view-dependent glare
 *    (wmsun_updateGlare, intensity/damping state in gWmSunGlareIntensity/A4).
 *    The on-screen visual is unconfirmed - plausibly the bright energy
 *    mass in the storm sky where the released spirits converge. The
 *    repeated explosion flashes over the crystal during the shake come
 *    from elsewhere (the wmnewcrystal detonations are three one-shots;
 *    this unit's envfx fires once).
 * A third variant (type 0x2C2, mapped to no def by the retail
 * OBJINDEX, so unreachable in retail) allocates the WmSunGlareParams
 * flicker table and scroll-fades a texture once bit 0x38F is set.
 */
#include "main/audio/sfx_ids.h"
#include "main/frame_timing.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/render_envfx_api.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/WM/dll_020E_wmsun.h"
#include "main/object_render.h"
#include "main/lightmap_api.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/objtexture.h"
#include "main/mm.h"
#include "main/gamebits.h"
#include "main/mapEventTypes.h"
#include "main/vecmath.h"
#include "main/camera.h"
#include "main/camera_shake_api.h"
#include "main/object_descriptor.h"

/* romlist object-def variants driving this DLL's seqId branches (see
   docblock): def 922 'WM_Crystal' (0x262) and def 907 'WM_sun' (0x2BD). */
#define WMSUN_SEQID_CRYSTAL 0x262
#define WMSUN_SEQID_SUN     0x2bd

/* Env-fx ids co-activated when the envfx timer expires (getEnvfxAct 3rd arg) */
#define WMSUN_ENVFX_A 0x30
#define WMSUN_ENVFX_B 0x34

#pragma force_active on
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E5F20 = 0.0f;
#pragma explicit_zero_data off
__declspec(section ".sdata2") f32 lbl_803E5F24 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E5F28 = 0.5f;
__declspec(section ".sdata2") f32 lbl_803E5F2C = 20.0f;
__declspec(section ".sdata2") f32 gWmSunPi = 3.1415927f;
__declspec(section ".sdata2") f32 lbl_803E5F34 = 32767.0f;
__declspec(section ".sdata2") f32 lbl_803E5F38 = 32768.0f;
__declspec(section ".sdata2") f32 lbl_803E5F3C = 0.1f;
__declspec(section ".sdata2") f32 lbl_803E5F40 = -0.1f;
__declspec(section ".sdata2") f32 lbl_803E5F44 = 0.2f;
__declspec(section ".sdata2") f32 lbl_803E5F48 = 100.0f;
__declspec(section ".sdata2") f32 lbl_803E5F4C = 4.0f;
__declspec(section ".sdata2") f32 lbl_803E5F50 = 0.0005f;
__declspec(section ".sdata2") f32 lbl_803E5F54 = 0.0002f;
__declspec(section ".sdata2") f32 lbl_803E5F58 = 0.05f;
__declspec(section ".sdata2") f32 lbl_803E5F5C = 65535.0f;
__declspec(section ".sdata2") f32 lbl_803E5F60 = 0.001f;
__declspec(section ".sdata2") f32 lbl_803E5F64 = -0.001f;
__declspec(section ".sdata2") f32 lbl_803E5F68 = 0.01f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E5F6C = 0.0f;
#pragma explicit_zero_data off
#pragma force_active reset
const WmSunVec3 gWmSunGlareDir = {0.0f, 0.0f, -1.0f};
const WmSunVec3 gWmSunGlareSun = {0.0f, 0.0f, -1.0f};

int wmsun_animEventCallback(GameObject* obj, int unused, ObjAnimUpdateState* actor)
{
    actor->hitVolumePair = -1;
    actor->sequenceEventActive = 0;
    return 0;
}

/* The sun-glare flicker: measures the angle between the camera->sun
   ray and the camera facing; staring near the sun (cos > 0.5) ramps
   the flicker intensity (sin curve + random jitter, damped through
   gWmSunGlareDamping), looking away decays it. */
void wmsun_updateGlare(GameObject* obj)
{
    WmSunVec3 dir;
    WmSunVec3 sun;
    WmSunGlare g;
    CameraViewSlot* cam;
    f32 dx, dy, dz, len;
    f32 dot, prod, denom;
    f32 hy, hz, cosang, hlen;
    f32 f;
    f32 cz;

    dir = gWmSunGlareDir;
    sun = gWmSunGlareSun;
    obj->anim.rotX += 400;
    g.vx = lbl_803E5F20;
    g.vy = lbl_803E5F20;
    g.vz = lbl_803E5F20;
    g.intensity = lbl_803E5F24;
    g.ang[2] = 0;
    g.ang[1] = 0;
    g.ang[0] = obj->anim.rotX;
    cam = Camera_GetCurrentViewSlot();
    if (cam != NULL)
    {
        g.ang[0] = 0x8000 - cam->yaw;
        vecRotateZXY(g.ang, &sun.x);
        dx = obj->anim.localPosX - cam->x;
        dy = obj->anim.localPosY - cam->y;
        dz = obj->anim.localPosZ - cam->z;
        len = sqrtf(dz * dz + (dx * dx + dy * dy));
        if (*(f32*)&lbl_803E5F20 != len)
        {
            dx = dx / len;
            dy = dy / len;
            dz = dz / len;
        }
        dot = dz * sun.z + (dx * sun.x + dy * sun.y);
        prod = (dz * dz + (dx * dx + dy * dy)) * (denom = sun.z * sun.z + (sun.x * sun.x + sun.y * sun.y));
        if (prod != lbl_803E5F20)
        {
            denom = sqrtf(prod);
        }
        cz = lbl_803E5F20;
        if (denom != cz)
        {
            cosang = dot / denom;
        }
        else
        {
            cosang = cz;
        }
        hy = *(f32*)&lbl_803E5F20;
        if (cosang > hy)
        {
            dot = obj->anim.localPosX - cam->x;
            hz = obj->anim.localPosZ - cam->z;
            hlen = sqrtf(hz * hz + (dot * dot + hy));
            if (*(f32*)&lbl_803E5F20 != hlen)
            {
                dot = dot / hlen;
                hy = hy / hlen;
                hz = hz / hlen;
            }
            len = dir.y;
            f = dir.z;
            prod = f * f + (dir.x * dir.x + len * len);
            prod = prod * (hz * hz + (dot * dot + hy * hy));
            if (prod != lbl_803E5F20)
            {
                sqrtf(prod);
            }
            if (cosang > lbl_803E5F28)
            {
                g.vx = lbl_803E5F2C * dot;
                g.vy = lbl_803E5F20;
                g.vz = lbl_803E5F2C * hz;
                f = mathSinf(gWmSunPi * (lbl_803E5F34 * (cosang - lbl_803E5F28)) / lbl_803E5F38) - gWmSunGlareIntensity;
                if (f > lbl_803E5F3C || f < lbl_803E5F40)
                {
                    gWmSunGlareIntensity = gWmSunGlareIntensity + f / timeDelta;
                }
                g.intensity = gWmSunGlareIntensity;
                if (gWmSunGlareIntensity > *(f32*)&lbl_803E5F44)
                {
                    if (gWmSunGlareDamping < lbl_803E5F4C)
                    {
                        gWmSunGlareDamping = gWmSunGlareDamping + (gWmSunGlareIntensity - lbl_803E5F44) / lbl_803E5F48;
                    }
                    f = g.intensity - gWmSunGlareDamping;
                    g.intensity = f;
                    if (f < *(f32*)&lbl_803E5F44)
                    {
                        g.intensity = *(f32*)&lbl_803E5F44;
                    }
                }
                else
                {
                    gWmSunGlareDamping = gWmSunGlareDamping - (gWmSunGlareIntensity - lbl_803E5F44) / lbl_803E5F2C;
                }
                g.intensity = lbl_803E5F50 * (f32)(int)randomGetRange(0, 0x1e) + g.intensity;
                if (gWmSunGlareIntensity > lbl_803E5F58)
                {
                    gWmSunGlareIntensity = gWmSunGlareIntensity - lbl_803E5F54;
                }
                g.ang[2] = 0;
                g.ang[1] = 0;
                g.ang[0] = lbl_803E5F5C * cosang;
            }
            else
            {
                f = lbl_803E5F20 - gWmSunGlareIntensity;
                if (f > lbl_803E5F60)
                {
                    gWmSunGlareIntensity = oneOverTimeDelta * f + gWmSunGlareIntensity;
                }
                else if (f < lbl_803E5F64)
                {
                    gWmSunGlareIntensity = oneOverTimeDelta * f + gWmSunGlareIntensity;
                }
                if (gWmSunGlareDamping > *(f32*)&lbl_803E5F20)
                {
                    gWmSunGlareDamping = -(lbl_803E5F68 * timeDelta - gWmSunGlareDamping);
                    if (gWmSunGlareDamping < *(f32*)&lbl_803E5F20)
                    {
                        gWmSunGlareDamping = *(f32*)&lbl_803E5F20;
                    }
                }
            }
        }
        else
        {
            if (gWmSunGlareDamping > hy)
            {
                gWmSunGlareDamping = -(lbl_803E5F68 * timeDelta - gWmSunGlareDamping);
                if (gWmSunGlareDamping < hy)
                {
                    gWmSunGlareDamping = hy;
                }
            }
        }
    }
}

int wmsun_getExtraSize(void)
{
    return 0x10;
}

int wmsun_getObjectTypeId(void)
{
    return 0x0;
}

void wmsun_free(GameObject* obj)
{
    WmSunState* state = obj->extra;
    if (state->glareParams != NULL)
    {
        mm_free(state->glareParams);
    }
    state->glareParams = NULL;
}

void wmsun_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 vis)
{
    WmSunState* state = (obj)->extra;
    if (vis != 0 && state->renderEnabled != 0)
    {
        doNothing_8005D148Legacy(p2, 0x10000);
        objRenderModelAndHitVolumesFwdLegacy(obj, p2, p3, p4, p5, lbl_803E5F24); /* 1.0f */
        doNothing_8005D14CLegacy(p2, 0x10000);
    }
}

void wmsun_hitDetect(void)
{
}

void wmsun_update(GameObject* obj)
{
    ObjAnimComponent* objAnim;
    WmSunState* state = (obj)->extra;
    s16 thresh;
    s16 mult;
    f32 spd;
    ObjTextureRuntimeSlot* t;
    s8 bank;
    u8 curAlpha;
    s16 newAlpha;

    objAnim = (ObjAnimComponent*)obj;
    thresh = 0;
    mult = 1;
    spd = lbl_803E5F20;
    if ((obj)->anim.seqId == WMSUN_SEQID_CRYSTAL) /* WM_Crystal */
    {
        if (mainGetBit(0x38f) != 0)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            t = objFindTexture(obj, 1, 0);
            if (t != NULL)
            {
                t->offsetT -= 0x10;
                if (t->offsetT < -0x3e0)
                {
                    t->offsetT = 0;
                }
            }
            if (mainGetBit(0x21b) != 0)
            {
                thresh = 100;
            }
            if (mainGetBit(0x21c) != 0)
            {
                thresh = 200;
            }
            if (mainGetBit(GAMEBIT_WM_SpiritHead1Fired) != 0)
            {
                thresh = 400;
            }
            if (mainGetBit(0x21f) != 0)
            {
                thresh = 800;
            }
            if (mainGetBit(0x221) != 0)
            {
                thresh = 0x640;
            }
            if (mainGetBit(0x222) != 0)
            {
                thresh = 0x1900;
                mult = 3;
                spd = lbl_803E5F78;
            }
            if (state->riseStep < thresh)
            {
                state->riseStep = state->riseStep + framesThisStep * mult;
                (obj)->anim.rootMotionScale = -(spd * timeDelta - (obj)->anim.rootMotionScale);
                (obj)->anim.localPosY = lbl_803E5F7C * (spd * timeDelta) + (obj)->anim.localPosY;
            }
            else if (mainGetBit(0x222) != 0 && mainGetBit(GAMEBIT_WM_FinaleQuakeActive) == 0)
            {
                mainSetBits(GAMEBIT_WM_FinaleQuakeActive, 1);
                mainSetBits(0x370, 0);
                state->renderEnabled = 0;
            }
            if (mainGetBit(GAMEBIT_WM_FinaleQuakeActive) == 0 && state->riseStep > 0x960 &&
                (int)randomGetRange(0, 100) == 0)
            {
                CameraShake_SetAllMagnitudes(lbl_803E5F80 * ((f32)(state->riseStep - 0x960) / lbl_803E5F84));
                mainSetBits(0x370, 1);
            }
            (obj)->anim.rotX += state->riseStep;
            if (state->renderEnabled == 0)
            {
                Obj_FreeObject(obj);
            }
        }
        return;
    }
    if ((obj)->anim.seqId == 0x2c2) /* unreachable in retail */
    {
        if (mainGetBit(0x38f) != 0)
        {
            /* v is only set when b < 0xfa - retail-faithful shape (at
               b >= 0xfa the clamp-and-store is effectively a no-op);
               same pattern in the fades below. Do not "fix". */
            curAlpha = objAnim->alpha;
            if (curAlpha < 0xfa)
            {
                newAlpha = curAlpha + framesThisStep;
            }
            if (newAlpha > 0xfa)
            {
                newAlpha = 0xfa;
            }
            objAnim->alpha = newAlpha;
            t = objFindTexture(obj, 0, 0);
            if (t != NULL)
            {
                t->offsetS = t->offsetS - framesThisStep * 8;
                if (t->offsetS < -0x3e0)
                {
                    t->offsetS = 0;
                }
            }
        }
        return;
    }
    if (mainGetBit(0x38f) != 0)
    {
        bank = objAnim->bankIndex;
        if (bank == 0 && (curAlpha = objAnim->alpha) != 0xff)
        {
            if (curAlpha < 0xff)
            {
                newAlpha = curAlpha + framesThisStep;
            }
            if (newAlpha > 0xff)
            {
                newAlpha = 0xff;
            }
            objAnim->alpha = newAlpha;
        }
        else if (bank == 1 && (curAlpha = objAnim->alpha) != 0x55)
        {
            if (curAlpha < 0x55)
            {
                newAlpha = curAlpha + framesThisStep;
            }
            if (newAlpha > 0x55)
            {
                newAlpha = 0x55;
            }
            objAnim->alpha = newAlpha;
        }
        else if (bank == 2 && (curAlpha = objAnim->alpha) != 0x19)
        {
            if (curAlpha < 0x19)
            {
                newAlpha = curAlpha + framesThisStep;
            }
            if (newAlpha > 0x19)
            {
                newAlpha = 0x19;
            }
            objAnim->alpha = newAlpha;
        }
        if (objAnim->bankIndex == 0)
        {
            if ((int)randomGetRange(0, 0x96) == 0)
            {
                randomGetRange(0, 0xffff);
                randomGetRange(0, 0xffff);
                randomGetRange(0, 0xffff);
                Sfx_PlayFromObject((int)obj, SFXTRIG_en_icecrk16);
            }
            wmsun_updateGlare(obj);
        }
    }
    else
    {
        (obj)->anim.rotZ += state->spinStep;
        (obj)->anim.rotX += state->riseStep;
        if (mainGetBit(GAMEBIT_WM_FinaleQuakeActive) != 0 && objAnim->bankIndex == 0)
        {
            if (lbl_803DDCAA == 0)
            {
                if (gWmSunQuakeTimer > 600 && (int)randomGetRange(0, 10) == 0)
                {
                    CameraShake_SetAllMagnitudes(lbl_803E5F88); /* 2.8f */
                }
                if (gWmSunQuakeTimer > 0)
                {
                    gWmSunQuakeTimer -= framesThisStep;
                    if (gWmSunQuakeTimer <= 0)
                    {
                        gWmSunQuakeTimer = 0;
                        mainSetBits(GAMEBIT_WM_FinaleQuakeActive, 0);
                        mainSetBits(0x38f, 1);
                    }
                }
            }
            if (gWmSunEnvfxTimer == 0)
            {
                if (lbl_803DDCAE > 0)
                {
                    lbl_803DDCAE -= framesThisStep;
                    if (lbl_803DDCAE < 0)
                    {
                        lbl_803DDCAE = 0;
                    }
                }
            }
            else
            {
                if (gWmSunEnvfxTimer > 0)
                {
                    gWmSunEnvfxTimer -= framesThisStep;
                    if (gWmSunEnvfxTimer <= 0)
                    {
                        gWmSunEnvfxTimer = 0;
                        getEnvfxActVoid((int)obj, (int)obj, WMSUN_ENVFX_A, 0);
                        getEnvfxActVoid((int)obj, (int)obj, WMSUN_ENVFX_B, 0);
                    }
                }
                if ((int)randomGetRange(0, 8) == 0)
                {
                    CameraShake_SetAllMagnitudes(lbl_803E5F88);
                }
            }
        }
    }
}

void wmsun_init(GameObject* obj, WmSunMapData* mapData)
{
    ObjAnimComponent* objAnim;
    WmSunState* state = obj->extra;
    u8 mapAct;
    int bank;
    int j;
    s16 i;
    s16 mode;

    objAnim = (ObjAnimComponent*)obj;
    obj->animEventCallback = wmsun_animEventCallback;
    mapAct = (*gMapEventInterface)->getMapAct((int)obj->anim.mapEventSlot);
    if (mapAct == 3 && mainGetBit(0x21b) == 0)
    {
        mainSetBits(0x21b, 1);
    }
    state->glareParams = NULL;
    state->renderEnabled = 1;
    mode = obj->anim.seqId;
    if (mode == WMSUN_SEQID_CRYSTAL) /* WM_Crystal */
    {
        obj->anim.rotX = (s16)(mapData->rotXByte << 8);
        state->riseStep = 100;
        if (mapData->rootMotionScaleParam >= 1000)
        {
            obj->anim.rootMotionScale = mapData->rootMotionScaleParam / lbl_803E5F8C;
        }
        else
        {
            obj->anim.rootMotionScale = lbl_803E5F24; /* 1.0f */
        }
    }
    else if (mode == WMSUN_SEQID_SUN) /* WM_sun */
    {
        gWmSunEnvfxTimer = 800;
        lbl_803DDCAE = 800;
        lbl_803DDCAC = 800;
        lbl_803DDCAA = 800;
        gWmSunQuakeTimer = 800;
        obj->anim.rotX = (s16)(mapData->rotXByte << 8);
        if (mapData->rootMotionScaleParam >= 0)
        {
            obj->anim.rootMotionScale = mapData->rootMotionScaleParam / lbl_803E5F8C;
        }
        else
        {
            obj->anim.rootMotionScale = lbl_803E5F24;
        }
        *(u8*)&objAnim->bankIndex = mapData->bankIndex;
        bank = objAnim->bankIndex;
        if (bank == 0)
        {
            state->riseStep = randomGetRange(300, 600);
            state->spinStep = randomGetRange(300, 600);
        }
        else if (bank == 1)
        {
            state->riseStep = randomGetRange(500, 800);
            state->spinStep = randomGetRange(500, 800);
        }
        else if (bank == 2)
        {
            state->riseStep = randomGetRange(700, 1000);
            state->spinStep = randomGetRange(700, 1000);
        }
        objAnim->alpha = 0;
    }
    else if (mode == 0x2c2) /* unreachable in retail (no OBJINDEX entry) */
    {
        state->glareParams = (WmSunGlareParams*)mmAlloc(sizeof(WmSunGlareParams), 0xe, 0);
        i = 0x14;
        j = 0x28;
        while (i != 0)
        {
            j -= 2;
            i--;
            *(s16*)((u8*)state->glareParams + j + 0x28) = 0;
            *(s16*)((u8*)state->glareParams + j + 0x50) = randomGetRange(10, 0x14);
            *(s16*)((u8*)state->glareParams + j + 0x78) = randomGetRange(0x50, 0xff);
        }
        objAnim->alpha = 0;
        if (mapData->rootMotionScaleParam != 0)
        {
            obj->anim.rootMotionScale = lbl_803E5F24 / ((f32)mapData->rootMotionScaleParam / lbl_803E5F8C);
        }
    }
}

void wmsun_release(void)
{
}

void wmsun_initialise(void)
{
}

ObjectDescriptor gWM_sunObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wmsun_initialise,
    (ObjectDescriptorCallback)wmsun_release,
    0,
    (ObjectDescriptorCallback)wmsun_init,
    (ObjectDescriptorCallback)wmsun_update,
    (ObjectDescriptorCallback)wmsun_hitDetect,
    (ObjectDescriptorCallback)wmsun_render,
    (ObjectDescriptorCallback)wmsun_free,
    (ObjectDescriptorCallback)wmsun_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)wmsun_getExtraSize,
};

#pragma force_active on
__declspec(section ".sdata2") f32 lbl_803E5F78 = 0.00375f;
__declspec(section ".sdata2") f32 lbl_803E5F7C = 50.0f;
__declspec(section ".sdata2") f32 lbl_803E5F80 = 0.8f;
__declspec(section ".sdata2") f32 lbl_803E5F84 = 2400.0f;
__declspec(section ".sdata2") f32 lbl_803E5F88 = 2.8f;
__declspec(section ".sdata2") f32 lbl_803E5F8C = 1000.0f;
#pragma force_active reset
