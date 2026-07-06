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
#include "main/dll/WM/wm_shared.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/obj_placement.h"
#include "main/objtexture.h"
#include "main/mm.h"

#define WM_SUN_GLARE_COUNT 20

/* per-glare-sprite flicker table; filled at init by the unreachable
   0x2C2 variant and never read back by this TU */
typedef struct WmSunGlareParams
{
    s16 unk00[WM_SUN_GLARE_COUNT];         /* 0x00: never written */
    s16 angleOffsets[WM_SUN_GLARE_COUNT];  /* 0x28: cleared at init */
    s16 flickerTimers[WM_SUN_GLARE_COUNT]; /* 0x50: random 10..20 */
    s16 alphaValues[WM_SUN_GLARE_COUNT];   /* 0x78: random 0x50..0xFF */
} WmSunGlareParams;

typedef struct WmSunMapData
{
    ObjPlacement base;
    s8 rotXByte;              /* 0x18: rotX in 1/256 turns */
    u8 bankIndex;             /* 0x19: sun layer / model bank (0..2) */
    s16 unused1A;
    s16 rootMotionScaleParam; /* 0x1C: model scale * 1000 */
    u8 pad1E[2];
} WmSunMapData;

typedef struct WmSunState
{
    s16 pad00;
    s16 riseStep;                  /* 0x02: rotX advance per frame; the crystal's rise progress */
    s16 spinStep;                  /* 0x04: sun rotZ advance per frame */
    u8 pad06[2];
    WmSunGlareParams* glareParams; /* 0x08: 0x2C2 variant only, else NULL */
    u8 pad0C;
    u8 renderEnabled;              /* 0x0D: cleared to hide + free the crystal */
    u8 pad0E[2];
} WmSunState;

STATIC_ASSERT(offsetof(WmSunGlareParams, angleOffsets) == 0x28);
STATIC_ASSERT(offsetof(WmSunGlareParams, flickerTimers) == 0x50);
STATIC_ASSERT(offsetof(WmSunGlareParams, alphaValues) == 0x78);
STATIC_ASSERT(sizeof(WmSunGlareParams) == 0xA0);
STATIC_ASSERT(offsetof(WmSunMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(WmSunMapData, bankIndex) == 0x19);
STATIC_ASSERT(offsetof(WmSunMapData, rootMotionScaleParam) == 0x1C);
STATIC_ASSERT(sizeof(WmSunMapData) == 0x20);
STATIC_ASSERT(offsetof(WmSunState, riseStep) == 0x02);
STATIC_ASSERT(offsetof(WmSunState, spinStep) == 0x04);
STATIC_ASSERT(offsetof(WmSunState, glareParams) == 0x08);
STATIC_ASSERT(offsetof(WmSunState, renderEnabled) == 0x0D);
STATIC_ASSERT(sizeof(WmSunState) == 0x10);

extern f32 lbl_803E5F8C;  /* 1000.0f */
extern s16 gWmSunQuakeTimer;  /* finale countdowns, see file-top comment */
extern s16 lbl_803DDCAA;
extern s16 lbl_803DDCAC;
extern s16 lbl_803DDCAE;
extern s16 gWmSunEnvfxTimer;
extern void CameraShake_SetAllMagnitudes(f32 magnitude);
extern f32 lbl_803E5F20; /* 0.0f */
extern f32 lbl_803E5F78; /* 0.00375f */
extern f32 lbl_803E5F7C; /* 50.0f */
extern f32 lbl_803E5F80; /* 0.8f */
extern f32 lbl_803E5F84; /* 2400.0f */
extern f32 lbl_803E5F88; /* 2.8f */

typedef struct
{
    f32 x, y, z;
} WmSunVec3;

/* glare work record; only ang feeds vecRotateZXY - the intensity/v*
   results are computed and discarded (the struct's address escapes
   through the g.ang call arg, which keeps the stores live; likely a
   remnant of the Dinosaur Planet-era glare renderer) */
typedef struct
{
    s16 ang[3];
    f32 intensity;
    f32 vx;
    f32 vy;
    f32 vz;
} WmSunGlare;

extern WmSunVec3 gWmSunGlareDir; /* (0, 0, -1) */
extern WmSunVec3 gWmSunGlareSun; /* (0, 0, -1) */
extern f32 gWmSunGlareIntensity;       /* glare intensity */
extern f32 gWmSunGlareDamping;       /* glare damping accumulator */
extern f32 oneOverTimeDelta;
extern f32 lbl_803E5F28; /* 0.5f */
extern f32 lbl_803E5F2C; /* 20.0f */
extern f32 gWmSunPi; /* 3.1415927f */
extern f32 lbl_803E5F34; /* 32767.0f */
extern f32 lbl_803E5F38; /* 32768.0f */
extern f32 lbl_803E5F3C; /* 0.1f */
extern f32 lbl_803E5F40; /* -0.1f */
extern f32 lbl_803E5F44; /* 0.2f */
extern f32 lbl_803E5F48; /* 100.0f */
extern f32 lbl_803E5F4C; /* 4.0f */
extern f32 lbl_803E5F50; /* 0.0005f */
extern f32 lbl_803E5F54; /* 0.0002f */
extern f32 lbl_803E5F58; /* 0.05f */
extern f32 lbl_803E5F5C; /* 65535.0f */
extern f32 lbl_803E5F60; /* 0.001f */
extern f32 lbl_803E5F64; /* -0.001f */
extern f32 lbl_803E5F68; /* 0.01f */
extern f32 sqrtf(f32 x);
extern float mathSinf(float x);
extern int Camera_GetCurrentViewSlot(void);
extern void vecRotateZXY(s16 * ang, WmSunVec3 * vec);

int wmsun_SeqFn(int p1, int p2, ObjAnimUpdateState* actor)
{
    actor->hitVolumePair = -1;
    actor->sequenceEventActive = 0;
    return 0;
}

/* The sun-glare flicker: measures the angle between the camera->sun
   ray and the camera facing; staring near the sun (cos > 0.5) ramps
   the flicker intensity (sin curve + random jitter, damped through
   gWmSunGlareDamping), looking away decays it. */
void wmsun_updateGlare(int obj)
{
    WmSunVec3 dir;
    WmSunVec3 sun;
    WmSunGlare g;
    int cam;
    f32 dx, dy, dz, len;
    f32 dot, prod, denom;
    f32 hy, hz, cosang, hlen;
    f32 f;
    f32 cz;

    dir = gWmSunGlareDir;
    sun = gWmSunGlareSun;
    ((GameObject*)obj)->anim.rotX += 400;
    g.vx = lbl_803E5F20;
    g.vy = lbl_803E5F20;
    g.vz = lbl_803E5F20;
    g.intensity = lbl_803E5F24;
    g.ang[2] = 0;
    g.ang[1] = 0;
    g.ang[0] = ((GameObject*)obj)->anim.rotX;
    cam = Camera_GetCurrentViewSlot();
    if ((void*)cam != NULL)
    {
        g.ang[0] = 0x8000 - *(s16*)cam;
        vecRotateZXY(g.ang, &sun);
        dx = ((GameObject*)obj)->anim.localPosX - *(f32*)(cam + 0xc);
        dy = ((GameObject*)obj)->anim.localPosY - *(f32*)(cam + 0x10);
        dz = ((GameObject*)obj)->anim.localPosZ - *(f32*)(cam + 0x14);
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
            dot = ((GameObject*)obj)->anim.localPosX - *(f32*)(cam + 0xc);
            hz = ((GameObject*)obj)->anim.localPosZ - *(f32*)(cam + 0x14);
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

int wmsun_getExtraSize(void) { return 0x10; }

int wmsun_getObjectTypeId(void) { return 0x0; }

void wmsun_free(int obj)
{
    WmSunState* state = ((GameObject*)obj)->extra;
    if (state->glareParams != NULL)
    {
        mm_free(state->glareParams);
    }
    state->glareParams = NULL;
}

void wmsun_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    WmSunState* state = ((GameObject*)p1)->extra;
    if (vis != 0 && state->renderEnabled != 0)
    {
        doNothing_8005D148(p2, 0x10000);
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E5F24); /* 1.0f */
        doNothing_8005D14C(p2, 0x10000);
    }
}

void wmsun_hitDetect(void)
{
}

void wmsun_update(int obj)
{
    ObjAnimComponent* objAnim;
    WmSunState* state = ((GameObject*)obj)->extra;
    s16 thresh;
    s16 mult;
    f32 spd;
    ObjTextureRuntimeSlot* t;
    s8 c;
    u8 b;
    s16 v;

    objAnim = (ObjAnimComponent*)obj;
    thresh = 0;
    mult = 1;
    spd = lbl_803E5F20;
    if (((GameObject*)obj)->anim.seqId == 0x262) /* WM_Crystal */
    {
        if (GameBit_Get(0x38f) != 0)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            t = objFindTexture((void*)obj, 1, 0);
            if (t != NULL)
            {
                t->offsetT -= 0x10;
                if (t->offsetT < -0x3e0)
                {
                    t->offsetT = 0;
                }
            }
            if (GameBit_Get(0x21b) != 0)
            {
                thresh = 100;
            }
            if (GameBit_Get(0x21c) != 0)
            {
                thresh = 200;
            }
            if (GameBit_Get(0x21d) != 0)
            {
                thresh = 400;
            }
            if (GameBit_Get(0x21f) != 0)
            {
                thresh = 800;
            }
            if (GameBit_Get(0x221) != 0)
            {
                thresh = 0x640;
            }
            if (GameBit_Get(0x222) != 0)
            {
                thresh = 0x1900;
                mult = 3;
                spd = lbl_803E5F78;
            }
            if (state->riseStep < thresh)
            {
                state->riseStep = state->riseStep + framesThisStep * mult;
                ((GameObject*)obj)->anim.rootMotionScale = -(spd * timeDelta - ((GameObject*)obj)->anim.
                    rootMotionScale);
                ((GameObject*)obj)->anim.localPosY = lbl_803E5F7C * (spd * timeDelta) + ((GameObject*)obj)->anim.
                    localPosY;
            }
            else if (GameBit_Get(0x222) != 0 && GameBit_Get(0x38d) == 0)
            {
                GameBit_Set(0x38d, 1);
                GameBit_Set(0x370, 0);
                state->renderEnabled = 0;
            }
            if (GameBit_Get(0x38d) == 0 && state->riseStep > 0x960 && (int)randomGetRange(0, 100) == 0)
            {
                CameraShake_SetAllMagnitudes(lbl_803E5F80 * ((f32)(state->riseStep - 0x960) / lbl_803E5F84));
                GameBit_Set(0x370, 1);
            }
            ((GameObject*)obj)->anim.rotX += state->riseStep;
            if (state->renderEnabled == 0)
            {
                Obj_FreeObject(obj);
            }
        }
        return;
    }
    if (((GameObject*)obj)->anim.seqId == 0x2c2) /* unreachable in retail */
    {
        if (GameBit_Get(0x38f) != 0)
        {
            /* v is only set when b < 0xfa - retail-faithful shape (at
               b >= 0xfa the clamp-and-store is effectively a no-op);
               same pattern in the fades below. Do not "fix". */
            b = objAnim->alpha;
            if (b < 0xfa)
            {
                v = b + framesThisStep;
            }
            if (v > 0xfa)
            {
                v = 0xfa;
            }
            objAnim->alpha = v;
            t = objFindTexture((void*)obj, 0, 0);
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
    if (GameBit_Get(0x38f) != 0)
    {
        c = objAnim->bankIndex;
        if (c == 0 && (b = objAnim->alpha) != 0xff)
        {
            if (b < 0xff)
            {
                v = b + framesThisStep;
            }
            if (v > 0xff)
            {
                v = 0xff;
            }
            objAnim->alpha = v;
        }
        else if (c == 1 && (b = objAnim->alpha) != 0x55)
        {
            if (b < 0x55)
            {
                v = b + framesThisStep;
            }
            if (v > 0x55)
            {
                v = 0x55;
            }
            objAnim->alpha = v;
        }
        else if (c == 2 && (b = objAnim->alpha) != 0x19)
        {
            if (b < 0x19)
            {
                v = b + framesThisStep;
            }
            if (v > 0x19)
            {
                v = 0x19;
            }
            objAnim->alpha = v;
        }
        if (objAnim->bankIndex == 0)
        {
            if ((int)randomGetRange(0, 0x96) == 0)
            {
                randomGetRange(0, 0xffff);
                randomGetRange(0, 0xffff);
                randomGetRange(0, 0xffff);
                Sfx_PlayFromObject(obj, SFXmn_sml_trex_snap2);
            }
            wmsun_updateGlare(obj);
        }
    }
    else
    {
        ((GameObject*)obj)->anim.rotZ += state->spinStep;
        ((GameObject*)obj)->anim.rotX += state->riseStep;
        if (GameBit_Get(0x38d) != 0 && objAnim->bankIndex == 0)
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
                        GameBit_Set(0x38d, 0);
                        GameBit_Set(0x38f, 1);
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
                        getEnvfxAct(obj, obj, 0x30, 0);
                        getEnvfxAct(obj, obj, 0x34, 0);
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

void wmsun_init(int obj, int params)
{
    ObjAnimComponent* objAnim;
    WmSunState* state = ((GameObject*)obj)->extra;
    WmSunMapData* mapData;
    u8 c;
    int c2;
    int j;
    s16 i;
    s16 mode;

    objAnim = (ObjAnimComponent*)obj;
    mapData = (WmSunMapData*)params;
    ((GameObject*)obj)->animEventCallback = wmsun_SeqFn;
    c = (*gMapEventInterface)->getMapAct((int)((GameObject*)obj)->anim.mapEventSlot);
    if (c == 3 && GameBit_Get(0x21b) == 0)
    {
        GameBit_Set(0x21b, 1);
    }
    state->glareParams = NULL;
    state->renderEnabled = 1;
    mode = ((GameObject*)obj)->anim.seqId;
    if (mode == 0x262) /* WM_Crystal */
    {
        ((GameObject*)obj)->anim.rotX = (s16)(mapData->rotXByte << 8);
        state->riseStep = 100;
        if (mapData->rootMotionScaleParam >= 1000)
        {
            ((GameObject*)obj)->anim.rootMotionScale = mapData->rootMotionScaleParam / lbl_803E5F8C;
        }
        else
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E5F24; /* 1.0f */
        }
    }
    else if (mode == 0x2bd) /* WM_sun */
    {
        gWmSunEnvfxTimer = 800;
        lbl_803DDCAE = 800;
        lbl_803DDCAC = 800;
        lbl_803DDCAA = 800;
        gWmSunQuakeTimer = 800;
        ((GameObject*)obj)->anim.rotX = (s16)(mapData->rotXByte << 8);
        if (mapData->rootMotionScaleParam >= 0)
        {
            ((GameObject*)obj)->anim.rootMotionScale = mapData->rootMotionScaleParam / lbl_803E5F8C;
        }
        else
        {
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E5F24;
        }
        *(u8*)&objAnim->bankIndex = mapData->bankIndex;
        c2 = objAnim->bankIndex;
        if (c2 == 0)
        {
            state->riseStep = randomGetRange(300, 600);
            state->spinStep = randomGetRange(300, 600);
        }
        else if (c2 == 1)
        {
            state->riseStep = randomGetRange(500, 800);
            state->spinStep = randomGetRange(500, 800);
        }
        else if (c2 == 2)
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
            ((GameObject*)obj)->anim.rootMotionScale = lbl_803E5F24 / ((f32)mapData->rootMotionScaleParam /
                lbl_803E5F8C);
        }
    }
}

void wmsun_release(void)
{
}

void wmsun_initialise(void)
{
}
