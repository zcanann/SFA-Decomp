#include "main/sky_state.h"
#include "main/dll/savegame_env_api.h"
#include "main/render_envfx_api.h"
#include "main/sky_interface.h"
#include "string.h"
#include "sys/objects.h"
#include "main/curve_eval.h"
#include "main/frame_timing.h"
#include "main/camera.h"
#include "main/mm.h"
#include "main/model.h"
#include "main/model_light.h"
#include "main/texture.h"
#include "main/textrender_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/sky.h"
#include "main/sky_api.h"
#include "main/lightmap_api.h"
#include "dlls/object_descriptor.h"
#include "track/intersect_api.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "main/lightmap.h"
#include "main/track_dolphin_shadow_api.h"
#include "main/vecmath.h"

u8* gSky2States[2];
s8 gSky2DrawMode;

s8 gSky2TintDisabled = 1;
int gSky2EnvfxFirstTime = 1;
u8 gSky2RunFirstTime = 1;

/* gSkyEnvFxFlags: per-group env-FX trigger enables + update state */
#define SKY_ENVFX_GROUP_C        0x01 /* gSkyEnvFxGroupCTable group (GameBit 0x3ab) */
#define SKY_ENVFX_GROUP_A        0x02 /* gSkyEnvFxGroupATable group (GameBit 0x3ac) */
#define SKY_ENVFX_GROUP_B        0x04 /* gSkyEnvFxGroupBTable group */
#define SKY_ENVFX_GROUP_D        0x08 /* gSkyEnvFxGroupDTable group (weather) */
#define SKY_ENVFX_UPDATE_PENDING 0x10 /* sun position changed; process this frame */
#define SKY_ENVFX_IMMEDIATE      0x20 /* fire acts immediately vs deferred */
/* env-effect ids activated together when the GROUP_D (weather) flag is clear
   (index-style; roles opaque) */
#define SKY_ENVFX_ID_A         0x136
#define SKY_ENVFX_ID_B         0x137
#define SKY_ENVFX_ID_C         0x143
#define SKY_CONFIG_FIELD_COUNT 0xb
#define SKY_CHILD_OBJ_SUN      0x62b /* spawned into gSkySunObject */
#define SKY_CHILD_OBJ_MOON     0x62c /* spawned into gSkyMoonObject */
#define SKY_TEXTURE_SKY        0x5fa /* gSkySkyTexture */
extern u8 gSkyConfigFieldIndices[];
STATIC_ASSERT(sizeof(Vec) == 0xC);
extern u16 lbl_803E8460;
extern u8 lbl_803E8462;
extern f32 lbl_8039A7B8[];
const Vec sSky2BestWeightsInit = {-1000.0f, -1000.0f, -1000.0f};

void skyGetCurrentAmbientAndLightColors(u8* ambientRed, u8* ambientGreen, u8* ambientBlue, u8* lightRed, u8* lightGreen,
                                        u8* lightBlue);

void skySetLightSlot(int slot, f32 x, f32 y, f32 z, int red, int green, int blue, int ambientIntensity,
                     int lightIntensity, u8 blendAlpha);

void sky2GetFogRange(int* fogNear, int* fogFar) {
    SkySlotAnim* state;
    f32 value;

    state = (SkySlotAnim*)gSky2States[0];
    if (state != NULL) {
        value = state->fogNear;
        *fogNear = value;
        value = ((SkySlotAnim*)gSky2States[0])->fogFar;
        *fogFar = value;
    }
}

void sky2GetTargetColor(int* red, int* green, int* blue, f32* blend) {
    SkySlotAnim* state;

    state = (SkySlotAnim*)gSky2States[0];
    if (state == NULL) {
        return;
    }
    *red = state->colorR;
    *green = ((SkySlotAnim*)gSky2States[0])->colorG;
    *blue = ((SkySlotAnim*)gSky2States[0])->colorB;
    *blend = ((SkySlotAnim*)gSky2States[0])->prevT;
}

void sky2ResetStateFromConfig(u8* cfg, u8 flags) {
    int i;
    int idx;

    if (((Sky2Config*)cfg)->flags & 0x80) {
        idx = 1;
    } else {
        idx = 0;
    }
    ((SkySlotAnim*)gSky2States[idx])->unk00 = 0;
    ((SkySlotAnim*)gSky2States[idx])->b317 = 1;
    for (i = 0; i < 0x21; i++) {
        ((SkySlotAnim*)gSky2States[idx])->vel[i] = 0.0f;
    }
    for (i = 0; i < 0x21; i++) {
        ((SkySlotAnim*)gSky2States[idx])->cur[i] = 0.0f;
    }
    for (i = 0; i < 0x16; i++) {
        ((SkySlotAnim*)gSky2States[idx])->vel2[i] = 0.0f;
    }
    for (i = 0; i < SKY_CONFIG_FIELD_COUNT; i++) {
        ((SkySlotAnim*)gSky2States[idx])->cur2[i] = 1400.0f;
        ((SkySlotAnim*)gSky2States[idx])->cur2[i + 0xb] = 1600.0f;
    }
    for (i = 0; i < SKY_CONFIG_FIELD_COUNT; i++) {
        ((SkySlotAnim*)gSky2States[idx])->target[i] = (f32)(u32)((Sky2Config*)cfg)->redKeys[gSkyConfigFieldIndices[i]];
        ((SkySlotAnim*)gSky2States[idx])->target[i + 0xb] =
            (f32)(u32)((Sky2Config*)cfg)->greenKeys[gSkyConfigFieldIndices[i]];
        ((SkySlotAnim*)gSky2States[idx])->target[i + 0x16] =
            (f32)(u32)((Sky2Config*)cfg)->blueKeys[gSkyConfigFieldIndices[i]];
        ((SkySlotAnim*)gSky2States[idx])->target2[i] =
            (f32)(u32)((Sky2Config*)cfg)->fogNearKeys[gSkyConfigFieldIndices[i]];
        ((SkySlotAnim*)gSky2States[idx])->target2[i + 0xb] =
            (f32)(u32)((Sky2Config*)cfg)->fogFarKeys[gSkyConfigFieldIndices[i]];
    }
    ((SkySlotAnim*)gSky2States[idx])->flags4 = cfg[0x58];
    ((SkySlotAnim*)gSky2States[idx])->flags6 = ((Sky2Config*)cfg)->flags2;
    ((SkySlotAnim*)gSky2States[idx])->wobbleStep = 0.0f;
    ((SkySlotAnim*)gSky2States[idx])->wobbleAmp = 0.0f;
    ((SkySlotAnim*)gSky2States[idx])->b314 = -1;
    ((SkySlotAnim*)gSky2States[idx])->wobbleOffset = 0.0f;
    if (((Sky2Config*)cfg)->fadeDurationA == 0) {
        ((Sky2Config*)cfg)->fadeDurationA = 1;
    }
    if (((Sky2Config*)cfg)->fadeDurationA != 0) {
        ((SkySlotAnim*)gSky2States[idx])->fadeDurationA = ((Sky2Config*)cfg)->fadeDurationA;
        ((SkySlotAnim*)gSky2States[idx])->unk48 = 1;
        ((SkySlotAnim*)gSky2States[idx])->unk08 = ((Sky2Config*)cfg)->skyTexId0;
        ((SkySlotAnim*)gSky2States[idx])->unk5C = 1.0f / (f32)(u32)((Sky2Config*)cfg)->fadeDurationA;
    } else {
        ((SkySlotAnim*)gSky2States[idx])->fadeDurationA = 0;
        ((SkySlotAnim*)gSky2States[idx])->unk5C = 1.0f;
    }
    if (((Sky2Config*)cfg)->fadeDurationB == 0) {
        ((Sky2Config*)cfg)->fadeDurationB = 1;
    }
    if (((Sky2Config*)cfg)->fadeDurationB != 0) {
        ((SkySlotAnim*)gSky2States[idx])->fadeDurationB = ((Sky2Config*)cfg)->fadeDurationB;
        ((SkySlotAnim*)gSky2States[idx])->fadeRate =
            255.0f / (60.0f * ((f32)(u32)((Sky2Config*)cfg)->fadeDurationB / 10.0f));
        ((SkySlotAnim*)gSky2States[idx])->unk0C = 0x5dc;
        ((SkySlotAnim*)gSky2States[idx])->unk60 = 1.0f / (f32)(u32)((Sky2Config*)cfg)->fadeDurationB;
    } else {
        ((SkySlotAnim*)gSky2States[idx])->fadeDurationB = 0;
        ((SkySlotAnim*)gSky2States[idx])->unk60 = 1.0f;
    }
    ((SkySlotAnim*)gSky2States[idx])->unk44 = 0;
}

void sky2StepSlotAnim(int slot) {
    SkySlotAnim* anim;
    f32 dur;
    f32 zero;
    f32 len;
    f32 spd;
    f32 bv;
    int i;
    u16 flags;
    int flag1;

    anim = (SkySlotAnim*)gSky2States[slot];
    if (anim->t >= (dur = 1.0f)) {
        anim->flags4 &= ~0x100;
        zero = 0.0f;
        ((SkySlotAnim*)gSky2States[slot])->step = zero;
        ((SkySlotAnim*)gSky2States[slot])->t = zero;
        ((SkySlotAnim*)gSky2States[slot])->prevT = dur;
        anim = (SkySlotAnim*)gSky2States[slot];
        if (anim->b316 != 0 && (anim->flags6 & 0x40) == 0) {
            anim->b316 = 0;
        }
        for (i = 0; i < 0x21; i++) {
            ((SkySlotAnim*)gSky2States[slot])->cur[i] = ((SkySlotAnim*)gSky2States[slot])->target[i];
        }
        for (i = 0; i < 0x16; i++) {
            ((SkySlotAnim*)gSky2States[slot])->cur2[i] = ((SkySlotAnim*)gSky2States[slot])->target2[i];
        }
    } else {
        if (anim->b315 != 0) {
            len = 60.0f * ((f32)anim->fadeDurationA / 10.0f);
            if (0.0f == len) {
                len = dur;
            }
            anim->step = 1.0f / len;
            for (i = 0; i < 0x21; i++) {
                ((SkySlotAnim*)gSky2States[slot])->vel[i] =
                    (((SkySlotAnim*)gSky2States[slot])->target[i] - ((SkySlotAnim*)gSky2States[slot])->cur[i]) / len;
            }
            for (i = 0; i < 0x16; i++) {
                ((SkySlotAnim*)gSky2States[slot])->vel2[i] =
                    (((SkySlotAnim*)gSky2States[slot])->target2[i] - ((SkySlotAnim*)gSky2States[slot])->cur2[i]) / len;
            }
            ((SkySlotAnim*)gSky2States[slot])->b315 = 0;
        }
        for (i = 0; i < 0x21; i++) {
            ((SkySlotAnim*)gSky2States[slot])->cur[i] += timeDelta * ((SkySlotAnim*)gSky2States[slot])->vel[i];
        }
        for (i = 0; i < 0x16; i++) {
            ((SkySlotAnim*)gSky2States[slot])->cur2[i] += timeDelta * ((SkySlotAnim*)gSky2States[slot])->vel2[i];
        }
        ((SkySlotAnim*)gSky2States[slot])->t += timeDelta * ((SkySlotAnim*)gSky2States[slot])->step;
        anim = (SkySlotAnim*)gSky2States[slot];
        flags = anim->flags4;
        flag1 = flags & 1;
        if (flag1 != 0 && (bv = anim->blend) > (zero = 0.0f)) {
            anim->blend = -(255.0f * anim->t - bv);
            if (((SkySlotAnim*)gSky2States[slot])->blend < zero) {
                ((SkySlotAnim*)gSky2States[slot])->blend = zero;
                gSky2TintDisabled = 1;
            }
        } else if ((flags & 4) != 0 && anim->blend < (spd = 255.0f)) {
            anim->blend = spd * anim->t;
            if (((SkySlotAnim*)gSky2States[slot])->blend > spd) {
                ((SkySlotAnim*)gSky2States[slot])->blend = spd;
            }
        } else if (flag1 == 0 && anim->blend < (spd = 255.0f)) {
            anim->blend = spd * anim->t;
            if (((SkySlotAnim*)gSky2States[slot])->blend > spd) {
                ((SkySlotAnim*)gSky2States[slot])->blend = spd;
            }
        }
        ((SkySlotAnim*)gSky2States[slot])->prevT = ((SkySlotAnim*)gSky2States[slot])->t;
    }
}

int sky2GetFogFadeAlpha(void) {
    SkySlotAnim* state;
    f32 y;
    int alpha;

    state = (SkySlotAnim*)gSky2States[0];
    if (state == NULL) {
        return 0xff;
    }
    y = state->fogNear;
    if (y < 950.0f) {
        alpha = 0;
    } else if (y > 1210.0f) {
        alpha = 0xff;
    } else {
        alpha = (int)(255.0f * ((y - 950.0f) / 200.0f));
    }
    return alpha;
}

void dll_06_func0C_nop(void) {
}

void sky2BlendTowardTargetColor(s32* red, s32* green, s32* blue) {
    SkySlotAnim* state;
    s32 targetR;
    s32 targetG;
    s32 targetB;
    s32 oldR;
    s32 oldG;
    s32 oldB;
    f32 blend;
    f32 fy;
    f32 fz;

    blend = 0.0f;
    state = (SkySlotAnim*)gSky2States[0];
    if (state == NULL) {
        return;
    }
    if (state != NULL && state->b316 == 0) {
        return;
    }

    oldR = *red;
    oldG = *green;
    oldB = *blue;
    if (state != NULL) {
        targetR = state->colorR;
        targetG = state->colorG;
        targetB = state->colorB;
        blend = state->prevT;
    }

    fy = (f32)(targetG - oldG);
    fz = (f32)(targetB - oldB);
    *red = (s32)((f32)(targetR - oldR) * (blend = 0.25f * blend) + oldR);
    *green = (s32)(fy * blend + oldG);
    *blue = (s32)(fz * blend + oldB);
}

void sky2SetDrawMode1(void) {
    if (gSky2States[0] == NULL) {
        return;
    }
    if (gSky2DrawMode != 1) {
        gSky2DrawMode = 1;
    }
}

void sky2SetDrawMode2(void) {
    if (gSky2States[0] == NULL) {
        return;
    }
    if (gSky2DrawMode != 2) {
        gSky2DrawMode = 2;
    }
}

void sky2ApplyModelTint(GameObject* obj) {
    SkySlotAnim* s;
    f32 v;
    int alpha;

    if (gSky2States[0] == NULL) {
        Obj_SetModelColorOverrideRecursive(obj, 0, 0, 0, 0, 0);
    }
    if (gSky2TintDisabled == 0 && ((s = (SkySlotAnim*)gSky2States[0])->flags4 & 1) == 0) {
        v = s->fogNear;
        if (v < 0.0f) {
            alpha = 255;
        } else if (v > 15.0f) {
            alpha = 0;
        } else {
            alpha = (int)(255.0f - 255.0f * (v / 15.0f));
        }
        Obj_SetModelColorOverrideRecursive(obj, (u8)s->colorR, (u8)s->colorG, (u8)s->colorB, (u8)alpha, 1);
    } else {
        Obj_SetModelColorOverrideRecursive(obj, 0, 0, 0, 0, 0);
    }
}

void sky2ApplyTextColor(void* context) {
    SkySlotAnim* s = (SkySlotAnim*)gSky2States[0];
    f32 v;
    int alpha;

    if (s != NULL) {
        if (gSky2TintDisabled == 0 && (s->flags4 & 1) == 0) {
            v = s->fogNear;
            if (v < 0.0f) {
                alpha = 255;
            } else if (v > 15.0f) {
                alpha = 0;
            } else {
                alpha = (int)(255.0f - 255.0f * (v / 15.0f));
            }
            setTextColor(context, (u8)s->colorR, (u8)s->colorG, (u8)s->colorB, (u8)alpha);
        } else {
            setTextColor(context, 255, 255, 255, 0);
        }
    }
}

int dll_06_func07_ret_0(void) {
    return 0x0;
}

void sky2ApplyFog(int obj) {
    SkySlotAnim* s = (SkySlotAnim*)gSky2States[0];

    if (s != NULL) {
        gSky2DrawMode = 2;
        setFogColorCallback(obj, (u8)s->colorR, (u8)s->colorG, (u8)s->colorB, 55);
        s = (SkySlotAnim*)gSky2States[0];
        if (s->fogNear == s->fogFar) {
            s->fogNear = s->fogNear - 20.0f;
        }
        s = (SkySlotAnim*)gSky2States[0];
        if (s->fogNear > s->fogFar) {
            s->fogNear = s->fogFar - 20.0f;
        }
        s = (SkySlotAnim*)gSky2States[0];
        fogSetRange(s->fogNear, s->fogFar);
    }
}

void sky2_run(void) {
    SkyRotQ q;
    f32 vec[3];
    Vec best;
    f32 height;
    SkyBestIdx idx;
    u8 red;
    u8 green;
    u8 blue;
    Camera* cam;
    u8** pp;
    int i;
    SkySlotAnim* p;
    f32* dst;
    f32* knot;
    f32* sampleBase;
    f32 colorMax;
    int k;
    int d;
    int sampleIndex;
    u16 angle;
    int range;
    int redInt;
    int greenInt;
    int blueInt;
    u16 flags;
    f32 r;
    f32 g;
    f32 b;
    f32 sa;
    f32 sb;
    f32 step;
    f32 t;
    f32 u;
    f32 directionWeight;
    f32 weight;
    f32 zero;
    f32 c158;
    f32 c154;
    f32 c150;
    f32 one;
    f32 z;
    f32 zv;
    f32 spd;
    f32 value;
    f32 offset;
    f32 wobbleRange;
    f32 half;
    f32 ambientScale;

    best = sSky2BestWeightsInit;
    r = 0.0f;
    g = r;
    b = r;
    sa = r;
    sb = r;
    height = r;
    *(u16*)&idx = lbl_803E8460;
    idx.pad = lbl_803E8462;
    skyGetSunColor(0, &red, &green, &blue);
    if (gSky2RunFirstTime != 0) {
        z = 0.0f;
        dst = lbl_8039A7B8;
        dst[0] = z;
        dst[1] = z;
        one = 1.0f;
        dst[2] = one;
        c150 = -0.707f;
        dst[3] = c150;
        dst[4] = z;
        c154 = 0.707f;
        dst[5] = c154;
        c158 = (-1.0f);
        dst[6] = c158;
        dst[7] = z;
        dst[8] = z;
        dst[9] = c150;
        dst[10] = z;
        dst[11] = c150;
        dst[12] = z;
        dst[13] = z;
        dst[14] = c158;
        dst[15] = c154;
        dst[16] = z;
        dst[17] = c150;
        dst[18] = one;
        dst[19] = z;
        dst[20] = z;
        dst[21] = c154;
        dst[22] = z;
        dst[23] = c154;
        gSky2RunFirstTime = 0;
    }
    cam = Camera_GetCurrent();
    zv = 0.0f;
    vec[0] = zv;
    vec[1] = zv;
    vec[2] = (-1.0f);
    q.x = zv;
    q.y = zv;
    q.z = zv;
    q.w = 1.0f;
    q.rx = -cam->yaw;
    q.rz = 0;
    q.ry = 0;
    vecRotateZXY(&q.rx, vec);
    i = 0;
    pp = gSky2States;
    do {
        if (*pp != NULL && ((SkySlotAnim*)*pp)->b317 != 0) {
            gSky2TintDisabled = 0;
            p = (SkySlotAnim*)*pp;
            if (p->unk48 != 0) {
                if ((p->flags4 & 1) == 0) {
                    spd = 255.0f;
                    p->blend = spd * p->prevT;
                    if (((SkySlotAnim*)*pp)->blend > spd) {
                        ((SkySlotAnim*)*pp)->blend = spd;
                    }
                }
            } else if (p->unk44 != 0) {
                p->prevT = p->blend / 255.0f;
                p = (SkySlotAnim*)*pp;
                if ((p->flags4 & 1) == 0) {
                    p->blend = -(timeDelta * p->fadeRate - p->blend);
                    value = ((SkySlotAnim*)*pp)->blend;
                    if (value < 0.0f) {
                        ((SkySlotAnim*)*pp)->blend = 0.0f;
                    }
                }
            }
            if ((((SkySlotAnim*)*pp)->flags4 & 0x100) != 0) {
                sky2StepSlotAnim(i);
            }
            p = (SkySlotAnim*)*pp;
            if ((p->flags4 & 0x10) != 0) {
                r = p->cur[0];
                g = p->cur[0xb];
                b = p->cur[0x16];
                sa = p->cur2[0];
                sb = p->cur2[0xb];
            } else if ((p->flags6 & 0x20) != 0) {
                (*gSkyInterface)->getTimeOfDay(&height);
                if ((t = height / 86400.0f) < 0.0f) {
                    t = 0.0f;
                }
                if (t > 1.0f) {
                    t = 1.0f;
                }
                step = 0.125f;
                if (t <= step) {
                    u = t / step;
                    k = 0;
                } else if (t <= 0.25f) {
                    u = (t - step) / step;
                    k = 1;
                } else if (t <= 0.375f) {
                    u = (t - 0.25f) / step;
                    k = 2;
                } else if (t <= 0.5f) {
                    u = (t - 0.375f) / step;
                    k = 3;
                } else if (t <= 0.625f) {
                    u = (t - 0.5f) / step;
                    k = 4;
                } else if (t <= 0.75f) {
                    u = (t - 0.625f) / step;
                    k = 5;
                } else if (t <= 0.875f) {
                    u = (t - 0.75f) / step;
                    k = 6;
                } else {
                    u = (t - 0.875f) / step;
                    k = 7;
                }
                r = Curve_EvalCatmullRom(&((SkySlotAnim*)*pp)->cur[k], u, 0);
                g = Curve_EvalCatmullRom(&((SkySlotAnim*)*pp)->cur[k + 0xb], u, 0);
                b = Curve_EvalCatmullRom(&((SkySlotAnim*)*pp)->cur[k + 0x16], u, 0);
                sa = Curve_EvalCatmullRom(&((SkySlotAnim*)*pp)->cur2[k], u, 0);
                sb = Curve_EvalCatmullRom(&((SkySlotAnim*)*pp)->cur2[k + 0xb], u, 0);
            } else {
                k = 0;
                do {
                    angle = getAngle(lbl_8039A7B8[k * 3], lbl_8039A7B8[k * 3 + 2]);
                    d = angle - (u16)getAngle(vec[0], vec[2]);
                    if (d < 0) {
                        d *= -1;
                    }
                    if (d > 0x7fff) {
                        d = 0xffff - d;
                    }
                    directionWeight = (32767.0f - d) / 32767.0f;
                    directionWeight -= 0.75f;
                    directionWeight /= 0.25f;
                    if (directionWeight > best.x) {
                        if (best.x > best.y) {
                            best.y = best.x;
                            idx.second = idx.best;
                        }
                        best.x = directionWeight;
                        idx.best = k;
                    } else if (directionWeight > best.y) {
                        best.y = directionWeight;
                        idx.second = k;
                    }
                    k++;
                } while (k < 8);
                zero = 0.0f;
                for (k = 0; k < 2; k++) {
                    weight = (&best.x)[k];
                    if (weight > zero) {
                        sampleBase = (f32*)*pp;
                        p = (SkySlotAnim*)(sampleBase + (sampleIndex = (&idx.best)[k]));
                        r = p->cur[0] * weight + r;
                        g = p->cur[0xb] * weight + g;
                        b = p->cur[0x16] * weight + b;
                        knot = (f32*)((u8*)(sampleBase + sampleIndex) + offsetof(SkySlotAnim, cur2));
                        sa = *knot * weight + sa;
                        sb = p->cur2[0xb] * weight + sb;
                    }
                }
            }
            if (r > 255.0f) {
                r = 255.0f;
            } else if (r < 0.0f) {
                r = 0.0f;
            }
            colorMax = 255.0f;
            if (g > 255.0f) {
                g = colorMax;
            } else if (g < 0.0f) {
                g = 0.0f;
            }
            if (b > 255.0f) {
                b = colorMax;
            } else if (b < 0.0f) {
                b = 0.0f;
            }
            p = (SkySlotAnim*)*pp;
            if ((p->flags6 & 0x40) != 0) {
                if (p->b314 == -1) {
                    p->b314 = 1;
                    value = 0.0f;
                    ((SkySlotAnim*)*pp)->wobbleOffset = value;
                    wobbleRange = sb - sa;
                    half = 0.5f;
                    ((SkySlotAnim*)*pp)->wobbleAmp =
                        randomGetRange((int)(-wobbleRange * half), (int)(wobbleRange * half));
                    ((SkySlotAnim*)*pp)->wobbleStep = 0.05f * randomGetRange(1, 10);
                } else if (p->b314 == 1) {
                    offset = p->wobbleOffset;
                    sa = sa + offset;
                    p->wobbleOffset = offset + p->wobbleStep;
                    p = (SkySlotAnim*)*pp;
                    if (p->wobbleOffset > p->wobbleAmp) {
                        p->b314 = (s8)(1 - p->b314);
                    }
                } else {
                    offset = p->wobbleOffset;
                    sa = sa + offset;
                    p->wobbleOffset = offset - p->wobbleStep;
                    p = (SkySlotAnim*)*pp;
                    value = p->wobbleOffset;
                    if (value < 0.0f) {
                        p->b314 = (s8)(1 - p->b314);
                        ((SkySlotAnim*)*pp)->wobbleOffset = 0.0f;
                        range = (s16)(int)(sb - sa);
                        ((SkySlotAnim*)*pp)->wobbleAmp = randomGetRange(-range / 2, range / 2);
                        ((SkySlotAnim*)*pp)->wobbleStep = 0.05f * randomGetRange(1, 10);
                    }
                }
            }
            if (sb > 2000.0f) {
                sb = 2000.0f;
            }
            if (sa > sb) {
                sa = sb - 1.0f;
            }
            if (sa <= 0.0f) {
                setStarsHidden(1);
            } else {
                setStarsHidden(0);
            }
            p = (SkySlotAnim*)*pp;
            flags = p->flags4;
            if ((flags & 8) == 0) {
                ambientScale = (f32)(red + green + blue) / 765.0f;
                r *= ambientScale;
                g *= ambientScale;
                b *= ambientScale;
            }
            if ((flags & 1) != 0) {
                p->colorR = r;
                ((SkySlotAnim*)*pp)->colorG = g;
                ((SkySlotAnim*)*pp)->colorB = b;
                ((SkySlotAnim*)*pp)->fogNear = sa;
                ((SkySlotAnim*)*pp)->fogFar = sb;
                if ((((SkySlotAnim*)*pp)->flags4 & 0x80) == 0) {
                    ((SkySlotAnim*)*pp)->colorR2 = 0xff;
                    ((SkySlotAnim*)*pp)->colorG2 = 0xff;
                    ((SkySlotAnim*)*pp)->colorB2 = 0xff;
                    ((SkySlotAnim*)*pp)->fogNear2 = 1950.0f;
                    ((SkySlotAnim*)*pp)->fogFar2 = 2005.0f;
                }
            } else if ((flags & 4) != 0) {
                p->colorR2 = r;
                ((SkySlotAnim*)*pp)->colorG2 = g;
                ((SkySlotAnim*)*pp)->colorB2 = b;
                ((SkySlotAnim*)*pp)->fogNear2 = sa;
                ((SkySlotAnim*)*pp)->fogFar2 = sb;
                if ((((SkySlotAnim*)*pp)->flags4 & 0x80) == 0) {
                    ((SkySlotAnim*)*pp)->colorR = 0xff;
                    ((SkySlotAnim*)*pp)->colorG = 0xff;
                    ((SkySlotAnim*)*pp)->colorB = 0xff;
                    ((SkySlotAnim*)*pp)->fogNear = 1950.0f;
                    ((SkySlotAnim*)*pp)->fogFar = 2005.0f;
                }
            } else {
                redInt = r;
                p->colorR = redInt;
                greenInt = g;
                ((SkySlotAnim*)*pp)->colorG = greenInt;
                blueInt = b;
                ((SkySlotAnim*)*pp)->colorB = blueInt;
                ((SkySlotAnim*)*pp)->fogNear = sa;
                ((SkySlotAnim*)*pp)->fogFar = sb;
                ((SkySlotAnim*)*pp)->colorR2 = redInt;
                ((SkySlotAnim*)*pp)->colorG2 = greenInt;
                ((SkySlotAnim*)*pp)->colorB2 = blueInt;
                ((SkySlotAnim*)*pp)->fogNear2 = sa;
                ((SkySlotAnim*)*pp)->fogFar2 = sb;
            }
        }
        pp++;
        i++;
    } while (i < 2);
}

void sky2_onMapSetup(void) {
    void** slot;
    int i;
    f32 b;
    f32 a;

    gSky2EnvfxActIndex = -1;
    (&gSky2EnvfxActIndex)[1] = -1;
    i = 0;
    slot = (void**)gSky2States;
    a = 1150.0f;
    b = 1205.0f;
    for (; i < 2; i++) {
        if (*slot == NULL) {
            *slot = mmAlloc(792, 23, 0);
        }
        memset(*slot, 0, 792);
        ((SkySlotAnim*)*slot)->colorR = 255;
        ((SkySlotAnim*)*slot)->colorG = 255;
        ((SkySlotAnim*)*slot)->colorB = 255;
        ((SkySlotAnim*)*slot)->fogNear = a;
        ((SkySlotAnim*)*slot)->fogFar = b;
        ((SkySlotAnim*)*slot)->colorR2 = 255;
        ((SkySlotAnim*)*slot)->colorG2 = 255;
        ((SkySlotAnim*)*slot)->colorB2 = 255;
        ((SkySlotAnim*)*slot)->fogNear2 = a;
        ((SkySlotAnim*)*slot)->fogFar2 = b;
        if (gSky2EnvfxFirstTime != 0) {
            getEnvfxAct(NULL, NULL, 9, 0);
            gSky2EnvfxFirstTime = 0;
        }
        slot++;
    }
}

void sky2_update(int a, int b, u8* cfg) {
    SaveGameEnvState* env;
    u16 bits;
    SkySlotAnim* st;
    int m40;
    u8 flags;
    u8 flags58;
    u8 b1;
    u8 i;

    flags = 0;
    env = saveGameGetEnvState();
    if (cfg != NULL) {
        (&gSky2EnvfxActIndex)[1] = gSky2EnvfxActIndex = (s16)((Sky2Config*)cfg)->envfxActId - 1;
        env->sky2EnvfxActId = (s16)((Sky2Config*)cfg)->envfxActId - 1;
        flags58 = ((Sky2Config*)cfg)->flags;
        b1 = (flags58 & 0x80) ? 1 : 0;
        if (((SkySlotAnim*)gSky2States[b1])->b317 == 0) {
            if ((flags58 & 0x40) != 0) {
                flags |= 0x40;
            }
            sky2ResetStateFromConfig(cfg, flags);
            if ((((Sky2Config*)cfg)->flags & 0x40) != 0) {
                ((SkySlotAnim*)gSky2States[b1])->b316 = 1;
            }
            ((SkySlotAnim*)gSky2States[b1])->flags4 = ((Sky2Config*)cfg)->flags | 0x100;
            ((SkySlotAnim*)gSky2States[b1])->b315 = 1;
            ((SkySlotAnim*)gSky2States[b1])->t = 0.0f;
        } else if ((flags58 & 0x20) != 0) {
            getEnvfxAct(0, 0, 9, 0);
        } else {
            ((SkySlotAnim*)gSky2States[b1])->flags4 = ((Sky2Config*)cfg)->flags | 0x100;
            ((SkySlotAnim*)gSky2States[b1])->b315 = 1;
            ((SkySlotAnim*)gSky2States[b1])->t = 0.0f;
            for (i = 0; i < SKY_CONFIG_FIELD_COUNT; i++) {
                ((SkySlotAnim*)gSky2States[b1])->target[i] =
                    (f32)(u32)((Sky2Config*)cfg)->redKeys[gSkyConfigFieldIndices[i]];
                ((SkySlotAnim*)gSky2States[b1])->target[i + 0xb] =
                    (f32)(u32)((Sky2Config*)cfg)->greenKeys[gSkyConfigFieldIndices[i]];
                ((SkySlotAnim*)gSky2States[b1])->target[i + 0x16] =
                    (f32)(u32)((Sky2Config*)cfg)->blueKeys[gSkyConfigFieldIndices[i]];
                ((SkySlotAnim*)gSky2States[b1])->target2[i] =
                    (f32)(u32)((Sky2Config*)cfg)->fogNearKeys[gSkyConfigFieldIndices[i]];
                ((SkySlotAnim*)gSky2States[b1])->target2[i + 0xb] =
                    (f32)(u32)((Sky2Config*)cfg)->fogFarKeys[gSkyConfigFieldIndices[i]];
            }
            ((SkySlotAnim*)gSky2States[b1])->fadeDurationA = ((Sky2Config*)cfg)->fadeDurationA;
            ((SkySlotAnim*)gSky2States[b1])->fadeDurationB = ((Sky2Config*)cfg)->fadeDurationB;
            ((SkySlotAnim*)gSky2States[b1])->b314 = -1;
            if ((((Sky2Config*)cfg)->flags2 & 0x20) != 0) {
                st = (SkySlotAnim*)gSky2States[b1];
                bits = st->flags6;
                if ((bits & 0x20) == 0) {
                    st->flags6 = bits | 0x20;
                }
            }
            if ((((Sky2Config*)cfg)->flags2 & 0x20) == 0) {
                st = (SkySlotAnim*)gSky2States[b1];
                bits = st->flags6;
                if ((bits & 0x20) != 0) {
                    st->flags6 = bits ^ 0x20;
                }
            }
            if ((((Sky2Config*)cfg)->flags & 0x40) != 0) {
                ((SkySlotAnim*)gSky2States[b1])->flags6 |= 0x40;
                ((SkySlotAnim*)gSky2States[b1])->b316 = 1;
            } else {
                st = (SkySlotAnim*)gSky2States[b1];
                bits = st->flags6;
                if ((bits & 0x40) != 0) {
                    st->flags6 = bits ^ 0x40;
                }
            }
            m40 = ((Sky2Config*)cfg)->flags2 & 0x40;
            if (m40 != 0) {
                st = (SkySlotAnim*)gSky2States[b1];
                bits = st->flags6;
                if ((bits & 0x40) == 0) {
                    st->flags6 = bits | 0x40;
                    return;
                }
            }
            if (m40 == 0) {
                st = (SkySlotAnim*)gSky2States[b1];
                bits = st->flags6;
                if ((bits & 0x40) != 0) {
                    st->flags6 = bits ^ 0x40;
                }
            }
        }
    }
}

void sky2_release(void) {
}

void sky2_initialise(void) {
    u8* state;

    gSky2EnvfxActIndex = -1;
    (&gSky2EnvfxActIndex)[1] = -1;
    if (gSky2States[0] != NULL) {
        mm_free(gSky2States[0]);
    }
    state = gSky2States[1];
    if (state != NULL) {
        mm_free(state);
    }
    gSky2States[0] = NULL;
    gSky2States[1] = NULL;
}

u8 gSkyConfigFieldIndices[] = {0, 0, 1, 2, 3, 4, 5, 6, 7, 0, 0, 0};

typedef struct Sky2DllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback update;
    ObjectDescriptorCallback onMapSetup;
    ObjectDescriptorCallback run;
    ObjectDescriptorCallback applyFog;
    ObjectDescriptorCallback slot07;
    ObjectDescriptorCallback applyTextColor;
    ObjectDescriptorCallback blendTowardTargetColor;
    ObjectDescriptorCallback getTargetColor;
    ObjectDescriptorCallback getFogRange;
    ObjectDescriptorCallback slot0C;
    ObjectDescriptorCallback setDrawMode2;
    ObjectDescriptorCallback setDrawMode1;
    ObjectDescriptorCallback getFogFadeAlpha;
    u32 padding;
} Sky2DllInterface;

Sky2DllInterface sky2_funcs = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_16_SLOTS,
    (ObjectDescriptorCallback)sky2_initialise,
    (ObjectDescriptorCallback)sky2_release,
    0,
    (ObjectDescriptorCallback)sky2_update,
    (ObjectDescriptorCallback)sky2_onMapSetup,
    (ObjectDescriptorCallback)sky2_run,
    (ObjectDescriptorCallback)sky2ApplyFog,
    (ObjectDescriptorCallback)dll_06_func07_ret_0,
    (ObjectDescriptorCallback)sky2ApplyTextColor,
    (ObjectDescriptorCallback)sky2BlendTowardTargetColor,
    (ObjectDescriptorCallback)sky2GetTargetColor,
    (ObjectDescriptorCallback)sky2GetFogRange,
    (ObjectDescriptorCallback)dll_06_func0C_nop,
    (ObjectDescriptorCallback)sky2SetDrawMode2,
    (ObjectDescriptorCallback)sky2SetDrawMode1,
    (ObjectDescriptorCallback)sky2GetFogFadeAlpha,
    0,
};

f32 lbl_8039A7B8[0x18];
