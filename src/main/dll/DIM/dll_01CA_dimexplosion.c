/*
 * explosion (DLL 0x1CA) - the generic explosion/fireball effect object.
 *
 * The extra block (explosion_getExtraSize == 0xA60, ExplosionState) holds a
 * flame pool (50 x ExplosionDebris, 0x30 each, from offset 0) and a gravity
 * debris pool (6 x 0x24 records, from 0x964). Functions are kept in binary
 * (address) order:
 *   explosion_spawnFlame   - seed one flame slot (speed/colour/spin/sfx)
 *   explosion_computeColor - age/lifetime -> RGB ramp via per-channel expf
 *   explosion_render       - draw each live flame as a billboarded quad
 *                            through the GX FIFO
 *   explosion_update       - age the flames, integrate the gravity debris,
 *                            spawn particle fx, fade the light
 *   explosion_init         - seed flames/debris/light from placement flags
 *   explosion_initialise   - precompute the expf falloff scales
 */
#include "main/dll/explosiondebris_struct.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/shader_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/dll/fbtextbl_struct.h"
#include "main/dll/fbwgpipe_struct.h"
#include "main/dll/explosionpartfxsource_struct.h"
#include "main/dll/explosion_state.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/modellight_api.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/gameplay_runtime.h"
#include "main/camera.h"
#include "string.h"
#include "main/audio/sfx.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXTransform.h"
#include "main/camera.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/DIM/dll_01CA_dimexplosion.h"

typedef void (*ExplosionSpawnFlameSpdFirst)(int obj, f32 spd, int gen, f32 x, f32 y, f32 z);
typedef int (*HitDetectFloatsFirst)(int obj, f32 x, f32 y, f32 z, int out, int p3);

typedef struct ExplosionPlacement
{
    u8 pad00[0x1a];
    s16 scaleParam;
    s16 configFlags;
} ExplosionPlacement;

STATIC_ASSERT(sizeof(ExplosionPartfxSource) == 0x38);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, rootMotionScale) == 0x08);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, localPosX) == 0x0C);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, worldPosX) == 0x18);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, velocityX) == 0x24);

STATIC_ASSERT(sizeof(ExplosionState) == 0xA60);
STATIC_ASSERT(offsetof(ExplosionState, driftYSpeed) == 0xA3C);
STATIC_ASSERT(sizeof(GravityDebris) == 0x24);
STATIC_ASSERT(offsetof(ExplosionState, debris) == 0x964);
STATIC_ASSERT(offsetof(GravityDebris, active) == 0x20);

#define DIMEXPLOSION_OBJFLAG_HITDETECT_DISABLED 0x2000
#define MODEL_LIGHT_KIND_POINT                  2
#define DIMEXPLOSION_PARTFX                     0x5e

#define GEXPLOSION_TEXTURE_COUNT 4

#define GX_PNMTX0  0 /* GXPosNrmMtx (GXEnum.h): GX_PNMTX0=0 */
#define GX_VA_POS  9
#define GX_VA_TEX0 13
#define GX_DIRECT  1
#define GX_QUADS   0x80
#define GX_VTXFMT2 2

extern int gExplosionTextures[GEXPLOSION_TEXTURE_COUNT];
extern f32 lbl_803E492C;
extern f32 lbl_803E4930;
extern f32 lbl_803E4934;
extern f32 lbl_803E4938;
extern f32 lbl_803E493C;
extern f32 lbl_803E4940;
extern f32 lbl_803E4950;
extern f32 lbl_803E4954;
extern f32 lbl_803E4958;
extern f32 lbl_803E495C;
extern f32 lbl_803E4960;
extern f64 lbl_803E4968;
extern f32 lbl_803E4970;
extern f32 lbl_803E4974;
extern f32 lbl_803E4998;
extern f32 lbl_803E499C;
extern f32 lbl_803E49A0;
extern f32 lbl_803E49A4;
extern f32 lbl_803E49A8;
extern f32 lbl_803E49AC;
extern f32 lbl_803E49B0;
extern f32 lbl_803E49B4;
extern f32 lbl_803E49B8;
extern f32 lbl_803E49BC;
extern f32 lbl_803E49C0;
extern f32 lbl_803E49C4;
extern f32 lbl_803E49C8;
extern f32 lbl_803E49CC;
extern int lbl_803E4928;
extern int lbl_803E8468;
extern u8 gExplosionUpdateTick;
extern f32 gExplosionFalloffScaleBlue;
extern f32 gExplosionFalloffScaleGreen;
extern f32 gExplosionFalloffScaleRed;
extern f32 gExplosionDebrisColorScale;
extern f32 gExplosionDebrisAlphaScale;
extern f32 gExplosionDebrisSpeedScale;
extern f32 gExplosionSpreadDirs[];
extern FbTexTbl gExplosionTexTable;

extern void textureFree(int tex);
extern void ModelLightStruct_free(void*);
extern f32 expf(f32 x);
extern void GXSetCurrentMtx(u32 id);
extern void fn_80073AAC(void* tex, u32* a, u32* b, int k);
extern int textureLoadAsset(int id);
extern int hitDetectFn_800658a4(int a, f32 b, f32 val, f32 d, f32* out, int e);
extern int objCreateLight(int a, int b);
extern void modelLightStruct_setLightKind(int h, int v);
extern void modelLightStruct_setPosition(int h, f32 x, f32 y, f32 z);
extern void modelLightStruct_setEnabled(int h, int n, f32 v);
extern void modelLightStruct_setDistanceAttenuation(int h, f32 a, f32 b);
extern void modelLightStruct_setDiffuseColor(int h, int r, int g, int b, int a);

volatile FbWGPipe GXWGFifo : (0xCC008000);

void explosion_spawnFlame(GameObject* obj, u8 gen, f32 spd, f32 x, f32 y, f32 z);
void explosion_computeColor(f32 age, f32 lifetime, u8 mode, u8* out);

#pragma scheduling off
#pragma peephole off
#pragma opt_propagation off
void explosion_spawnFlame(GameObject* obj, u8 gen, f32 spd, f32 x, f32 y, f32 z)
{
    s16* placement = (obj)->anim.placementData;
    ExplosionState* state = (obj)->extra;
    ExplosionDebris* flames = (ExplosionDebris*)state->flames;
    int idx = state->flameCount++;
    flames[idx].posX = x;
    flames[idx].posY = y;
    flames[idx].posZ = z;
    flames[idx].baseScale = lbl_803E492C;
    flames[idx].scale = flames[0].baseScale;
    flames[idx].speed = spd;
    flames[idx].generation = gen;
    flames[idx].age = 0;
    flames[idx].lifetime = (int)(lbl_803E4930 * sqrtf(spd));
    {
        int life = flames[idx].lifetime;
        if (life < 0)
        {
            life = 0;
        }
        else if (life > 0x3c)
        {
            life = 0x3c;
        }
        flames[idx].lifetime = life;
    }
    if (flames[idx].generation < 1)
    {
        s8 c = *(s8*)((char*)placement + 0x19);
        if (c != 0)
        {
            if (c == 2)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_wp_sexpl2_c_4bf);
            }
            else if (c == 3)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_wp_sexpl2_c_4c2);
            }
            else
            {
                s8 m = (obj)->anim.mapEventSlot;
                if (m < 0x3a)
                {
                    if (m == 0x2c)
                    {
                        goto playLimited;
                    }
                }
                else if (m < 0x3f)
                {
                playLimited:
                    Sfx_PlayFromObjectLimited((int)obj, SFXTRIG_wp_sexpl2_c_4b8, 2);
                    goto done;
                }
                Sfx_PlayFromObject((int)obj, SFXTRIG_sexpl2_c);
            done:;
            }
        }
    }
    flames[idx].spinAngle = randomGetRange(0, 0xffff);
    flames[idx].spinSpeed = randomGetRange(0xc8, 0x12c);
    if ((int)randomGetRange(0, 1) != 0)
    {
        flames[idx].spinSpeed = -flames[idx].spinSpeed;
    }
    flames[idx].texVariant = randomGetRange(0, 3);
    {
        f32 sp = flames[idx].speed;
        f32 ev = expf((lbl_803E4934 * ((f32)flames[idx].lifetime - (f32)flames[idx].age)) / (f32)flames[idx].lifetime);
        f32 d = sp - flames[idx].baseScale;
        f32 t = d * ev;
        flames[idx].scale = sp - gExplosionDebrisSpeedScale * t;
        ev = expf((lbl_803E493C * (f32)flames[idx].age) / (f32)flames[idx].lifetime);
        t = lbl_803E4938 * ev;
        flames[idx].alpha = lbl_803E4938 - gExplosionDebrisAlphaScale * t;
        flames[idx].spawnTimer = lbl_803E4940;
        flames[idx].spawnInterval = flames[idx].spawnTimer;
        flames[idx].active = 1;
    }
}
#pragma opt_propagation on
#pragma dont_inline on
void explosion_computeColor(f32 age, f32 lifetime, u8 mode, u8* out)
{
    s16 r;
    s16 g;
    s16 b;
    s16 rawR;
    s16 rawG;
    s16 rawB;
    rawR = 0xff - (u8)(int)(gExplosionFalloffScaleRed * (lbl_803E4938 * expf((lbl_803E4950 * age) / lifetime)));
    rawG = 0xff - (u8)(int)(gExplosionFalloffScaleGreen * (lbl_803E4938 * expf((lbl_803E4954 * age) / lifetime)));
    rawB = 0xff - (u8)(int)(gExplosionFalloffScaleBlue * (lbl_803E4938 * expf(age / lifetime)));
    r = (rawR < 1) ? 1 : ((rawR > 0xff) ? 0xff : rawR);
    g = (rawG < 1) ? 1 : ((rawG > 0xff) ? 0xff : rawG);
    b = (rawB < 1) ? 1 : ((rawB > 0xff) ? 0xff : rawB);
    switch (mode)
    {
    case 0:
        out[0] = r;
        out[1] = g;
        out[2] = b;
        break;
    case 1:
        out[0] = r;
        out[1] = b;
        out[2] = b;
        break;
    case 2:
        out[0] = b;
        out[1] = r;
        out[2] = b;
        break;
    case 3:
        out[0] = b;
        out[1] = b;
        out[2] = r;
        break;
    }
}
#pragma dont_inline reset

#pragma scheduling on
#pragma peephole on
int explosion_getExtraSize(void)
{
    return sizeof(ExplosionState);
}

#pragma scheduling off
int explosion_getObjectTypeId(GameObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int idx = (int)*(short*)(*(int*)&obj->anim.placementData + 0x1c) & 3;
    if (idx >= objAnim->modelInstance->modelCount)
    {
        idx = 0;
    }
    return (idx << 11) | 0x400;
}

#pragma scheduling on
void explosion_free(GameObject* obj)
{
    void* light = *(void**)(*(int*)&obj->extra + 0xa40);
    if (light != NULL)
    {
        ModelLightStruct_free(light);
    }
}

#pragma scheduling off
#pragma peephole off
void explosion_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u32 colA;
    u32 colB;
    u32 colA2;
    u32 colB2;
    f32 mE[12];
    f32 m4[12];
    f32 m3[12];
    f32 m2[12];
    f32 m1[12];
    int state;
    int model;
    int i;
    int cursor;
    colA = lbl_803E4928;
    colB = lbl_803E8468;
    state = *(int*)&obj->extra;
    model = (int)Obj_GetActiveModel(obj);
    cursor = state;
    if (visible != 0)
    {
        GXClearVtxDesc();
        GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
        GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
        GXSetCurrentMtx(GX_PNMTX0);
        for (i = 0, cursor = state; i < ((ExplosionState*)state)->flameCount; i++)
        {
            if (((ExplosionDebris*)cursor)->active != 0)
            {
                void** tex;
                int k;
                u8 cv;
                Obj_BuildWorldTransformMatrix(obj, mE, 0);
                PSMTXRotRad(m1, 0x7a, (f32)((6.2832 * (f64)(int)((ExplosionDebris*)cursor)->spinAngle) / 65536.0));
                PSMTXRotRad(m3, 0x78, (f32)((6.2832 * ((f64)(u32)(fn_8000FA70() & 0xffff) - 0.0)) / 65536.0));
                PSMTXConcat(m3, m1, m3);
                PSMTXRotRad(m2, 0x79, (f32)((6.2832 * (f64)(int)(0x10000 - (fn_8000FA90() & 0xffff))) / 65536.0));
                PSMTXConcat(m2, m3, m2);
                PSMTXScale(m4, ((ExplosionDebris*)cursor)->scale, ((ExplosionDebris*)cursor)->scale,
                           ((ExplosionDebris*)cursor)->scale);
                PSMTXConcat(m4, m2, m4);
                PSMTXTrans(mE, ((ExplosionDebris*)cursor)->posX - playerMapOffsetX, ((ExplosionDebris*)cursor)->posY,
                           ((ExplosionDebris*)cursor)->posZ - playerMapOffsetZ);
                PSMTXConcat(mE, m4, mE);
                PSMTXConcat(Camera_GetViewMatrix(), mE, mE);
    GXLoadPosMtxImm((const f32(*)[4])mE, GX_PNMTX0);
                ((u8*)&colA)[3] = ((ExplosionDebris*)cursor)->alpha;
                cv = gExplosionDebrisColorScale *
                     (255.0f *
                      expf((3.0f * ((f32)((ExplosionDebris*)cursor)->lifetime - (f32)((ExplosionDebris*)cursor)->age)) /
                           (f32)((ExplosionDebris*)cursor)->lifetime));
                ((u8*)&colB)[0] = cv;
                ((u8*)&colB)[1] = cv;
                ((u8*)&colB)[2] = cv;
                ((u8*)&colB)[3] = cv;
                explosion_computeColor((f32)((ExplosionDebris*)cursor)->age, (f32)((ExplosionDebris*)cursor)->lifetime,
                                       ((ExplosionState*)state)->modelKind, (u8*)&colA);
                tex = (void**)((int*)gExplosionTextures)[((ExplosionState*)state)->modelKind];
                for (k = 0; k < ((ExplosionDebris*)cursor)->texVariant; k++)
                {
                    tex = (void**)*tex;
                }
                colB2 = colB;
                colA2 = colA;
                fn_80073AAC(tex, &colA2, &colB2, k);
                GXBegin(GX_QUADS, GX_VTXFMT2, 4);
                {
                    f32 fc = 1.0f;
                    f32 fb = 0.0f;
                    f32 fa = -1.0f;
                    GXWGFifo.f32 = fa;
                    GXWGFifo.f32 = fa;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fa;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fa;
                    GXWGFifo.f32 = fc;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fb;
                    GXWGFifo.f32 = fc;
                }
            }
            cursor += 0x30;
        }
        if (((ExplosionState*)state)->frameCounter < ((ExplosionState*)state)->lifeFrames &&
            *(u8*)&((ExplosionState*)state)->rayMode != 0)
        {
            for (i = 0, cursor = state; i < ((ExplosionState*)state)->rayMode; cursor += 4, i++)
            {
                obj->anim.rotY = (s16) * (u16*)&((ExplosionState*)cursor)->rayYawA;
                obj->anim.rotX = (s16) * (u16*)&((ExplosionState*)cursor)->rayPitchA;
                ((void (*)(void*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, visible);
                if (i < ((ExplosionState*)state)->rayMode - 1)
                {
                    *(u16*)((char*)model + 0x18) &= ~8;
                }
            }
        }
    }
    renderResetFn_8003fc60();
}

#pragma scheduling on
#pragma peephole on
void explosion_hitDetect(void)
{
}

#pragma scheduling off
#pragma peephole off
#pragma opt_propagation off
void explosion_update(GameObject* obj)
{
    ExplosionPartfxSource fake;
    u16 ang[6];
    f32 vpos[3];
    f32 m[12];
    u8 rgb[3];
    int state = *(int*)&(obj)->extra;
    int i;
    int cursor;
    gExplosionUpdateTick += 1;
    cursor = state;
    ((ExplosionState*)state)->frameCounter += framesThisStep;
    for (i = 0, cursor = state; i < ((ExplosionState*)state)->flameCount; i++)
    {
        ((ExplosionDebris*)cursor)->age += framesThisStep;
        if (((ExplosionDebris*)cursor)->active != 0)
        {
            f32 sp = ((ExplosionDebris*)cursor)->speed;
            f32 ev = expf(
                (lbl_803E4934 * ((f32)((ExplosionDebris*)cursor)->lifetime - (f32)((ExplosionDebris*)cursor)->age)) /
                (f32)(int)((ExplosionDebris*)cursor)->lifetime);
            f32 d = sp - ((ExplosionDebris*)cursor)->baseScale;
            f32 t = d * ev;
            ((ExplosionDebris*)cursor)->scale = sp - gExplosionDebrisSpeedScale * t;
            ev =
                expf((lbl_803E493C * (f32)((ExplosionDebris*)cursor)->age) / (f32)((ExplosionDebris*)cursor)->lifetime);
            t = lbl_803E4938 * ev;
            *(s8*)&((ExplosionDebris*)cursor)->alpha = lbl_803E4938 - gExplosionDebrisAlphaScale * t;
            if (((ExplosionDebris*)cursor)->age >= ((ExplosionDebris*)cursor)->lifetime)
            {
                ((ExplosionDebris*)cursor)->active = 0;
            }
            else
            {
                *(s16*)&((ExplosionDebris*)cursor)->spinAngle +=
                    framesThisStep * *(s16*)&((ExplosionDebris*)cursor)->spinSpeed;
                if (((ExplosionDebris*)cursor)->texVariant >= 4)
                {
                    ((ExplosionDebris*)cursor)->texVariant -= 4;
                }
                if (((ExplosionDebris*)cursor)->generation < 5)
                {
                    if ((f32)((ExplosionDebris*)cursor)->age / (f32)((ExplosionDebris*)cursor)->lifetime <
                            lbl_803E4998 &&
                        (((ExplosionDebris*)cursor)->spawnTimer -= framesThisStep,
                         ((ExplosionDebris*)cursor)->spawnTimer <= 0))
                    {
                        int st2;
                        u8 gen;
                        f32 sp2;
                        f32 sv;
                        gen = ((ExplosionDebris*)cursor)->generation;
                        sp2 = ((ExplosionDebris*)cursor)->speed;
                        st2 = *(int*)&(obj)->extra;
                        vpos[0] = ((ExplosionDebris*)cursor)->scale *
                                  (lbl_803E495C * (f32)(int)randomGetRange(-5, 3) + lbl_803E492C);
                        vpos[1] = lbl_803E4960;
                        vpos[2] = lbl_803E4960;
                        PSMTXRotRad(m, 0x7a,
                                    (f32)(lbl_803E4968 * (f64)((f32)(int)randomGetRange(0, 0xffff) / lbl_803E4970)));
                        PSMTXConcat(Camera_GetInverseViewRotationMatrix(), m, m);
                        PSMTXMultVecSR(m, vpos, vpos);
                        vpos[0] += ((ExplosionDebris*)cursor)->posX;
                        vpos[1] += ((ExplosionDebris*)cursor)->posY;
                        vpos[2] += ((ExplosionDebris*)cursor)->posZ;
                        sv = sp2 * (f32)(int)randomGetRange(0xc0, 0x100);
                        sv = sv * lbl_803E4974;
                        if (((ExplosionState*)st2)->flameCount < 0x32)
                        {
                            explosion_spawnFlame(obj, (u8)(gen + 1), sv, vpos[0], vpos[1], vpos[2]);
                        }
                        ((ExplosionDebris*)cursor)->spawnTimer = ((ExplosionDebris*)cursor)->spawnInterval;
                    }
                }
            }
        }
        cursor += 0x30;
    }
    memcpy(&fake, (void*)obj, sizeof(fake));
    fake.rootMotionScale = lbl_803E492C;
    fake.velocityX = lbl_803E4960;
    fake.velocityY = lbl_803E4960;
    fake.velocityZ = lbl_803E4960;
    for (i = 0, cursor = state; i < ((ExplosionState*)state)->debrisCount; i++)
    {
        GravityDebris* d = (GravityDebris*)((char*)cursor + 0x964);
        if (d->active != 0)
        {
            d->age += framesThisStep;
            if (d->age >= d->lifetime)
            {
                d->active = 0;
            }
            else
            {
                f32 grav = ((ExplosionState*)state)->driftYSpeed;
                u32 ft = framesThisStep;
                f32 n974 = -(grav * (f32)(u32)ft - d->velY);
                d->posY = -(lbl_803E499C * (grav * (f32)(int)(ft * ft)) - (d->velY * (f32)(u32)ft + d->posY));
                d->velY = n974;
                d->posX += d->velX * (f32)(u32)framesThisStep;
                d->posZ += d->velZ * (f32)(u32)framesThisStep;
                if (((ExplosionState*)state)->nearGround != 0 && d->posY < ((ExplosionState*)state)->groundY &&
                    d->velY < lbl_803E4960)
                {
                    d->velY = lbl_803E49A0 * -d->velY;
                }
                fake.localPosX = d->posX;
                fake.localPosY = d->posY;
                fake.localPosZ = d->posZ;
                fake.worldPosX = fake.localPosX;
                fake.worldPosY = fake.localPosY;
                fake.worldPosZ = fake.localPosZ;
                if (gExplosionUpdateTick & 1)
                {
                    int t = d->age;
                    if (t < 0x40)
                    {
                        int v = t << 6;
                        ang[0] = 0xffff - v;
                        ang[1] = ang[0];
                        ang[2] = 0x8000;
                        ang[3] = 0xc000 - v;
                        ang[4] = 0xa000 - v;
                        ang[5] = 0;
                    }
                    else if (t < 0x80)
                    {
                        int v = t << 6;
                        ang[0] = 0xc000 - v;
                        ang[1] = 0xa000 - v;
                        ang[2] = 0;
                        ang[3] = 0x8000;
                        ang[4] = 0;
                        ang[5] = 0;
                    }
                    else
                    {
                        ang[0] = 0xa000;
                        ang[1] = 0;
                        ang[2] = 0;
                        ang[3] = 0;
                        ang[4] = 0;
                        ang[5] = 0;
                    }
                    {
                        u8 md;
                        md = ((ExplosionState*)state)->modelKind;
                        switch (md)
                        {
                        case 0:
                            break;
                        case 1:
                            ang[1] = ang[2];
                            ang[4] = ang[5];
                            break;
                        case 2:
                            ang[1] = ang[0];
                            ang[4] = ang[3];
                            ang[0] = ang[2];
                            ang[3] = ang[5];
                            break;
                        case 3:
                        {
                            u16 sv5;
                            u16 sv = ang[2];
                            ang[1] = sv;
                            sv5 = ang[5];
                            ang[4] = sv5;
                            ang[2] = ang[0];
                            ang[5] = ang[3];
                            ang[0] = sv;
                            ang[3] = sv5;
                        }
                        break;
                        }
                    }
                    (*gPartfxInterface)->spawnObject((void*)obj, DIMEXPLOSION_PARTFX, &fake, 0x200001, -1, ang);
                }
            }
        }
        cursor += 0x24;
    }
    {
        int e = ((ExplosionState*)state)->frameCounter;
        int d = ((ExplosionState*)state)->lifeFrames;
        if (e > d << 1)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            if (e > d)
            {
                if (*(void**)&((ExplosionState*)state)->light != NULL)
                {
                    modelLightStruct_setEnabled(((ExplosionState*)state)->light, 0, lbl_803E4960);
                }
            }
            else
            {
                explosion_computeColor((f32)e, (f32)d, ((ExplosionState*)state)->modelKind, rgb);
                if (*(void**)&((ExplosionState*)state)->light != NULL)
                {
                    modelLightStruct_setDiffuseColor(((ExplosionState*)state)->light, rgb[0], rgb[1], rgb[2], 0xff);
                }
            }
            {
                f32 frac = (f32)((ExplosionState*)state)->frameCounter / (f32)((ExplosionState*)state)->lifeFrames;
                (obj)->anim.rootMotionScale = lbl_803E49A4 * (frac * ((ExplosionState*)state)->scale);
                (obj)->anim.alpha = lbl_803E4938 - lbl_803E4938 * frac;
            }
            if (((ExplosionState*)state)->halfLifeFired == 0 &&
                ((ExplosionState*)state)->frameCounter >= (((ExplosionState*)state)->lifeFrames >> 1))
            {
                u32 k;
                u16 r0v = randomGetRange(0x1000, 0x6000);
                ang[0] = r0v;
                ang[1] = r0v;
                ang[2] = r0v;
                ang[3] = *(int*)((char*)state + 0x14);
                k = 0;
                while ((f32)(int)k < ((ExplosionState*)state)->scale)
                {
                    k++;
                }
                ((ExplosionState*)state)->halfLifeFired = 1;
            }
        }
    }
}

#pragma opt_propagation on
void explosion_init(GameObject* obj, int def)
{
    f32 vsp[3];
    f32 mB[12];
    f32 mA[12];
    int cursor;
    int state = *(int*)&obj->extra;
    f32 scale;
    int i;
    int debrisCount;
    ((ExplosionState*)state)->flameCount = 0;
    if (((ExplosionPlacement*)def)->scaleParam == 0)
    {
        scale = lbl_803E49A8;
    }
    else
    {
        scale = (f32)(int)((ExplosionPlacement*)def)->scaleParam * lbl_803E4974;
        if (scale > lbl_803E49A8)
        {
            scale = lbl_803E49A8;
        }
    }
    ((ExplosionSpawnFlameSpdFirst)explosion_spawnFlame)((int)obj, lbl_803E49AC * scale, 0, obj->anim.localPosX,
                                                        obj->anim.localPosY, obj->anim.localPosZ);
    obj->objectFlags |= DIMEXPLOSION_OBJFLAG_HITDETECT_DISABLED;
    ((ExplosionState*)state)->modelKind = ((ExplosionPlacement*)def)->configFlags & 3;
    Obj_SetActiveModelIndex(obj, ((ExplosionState*)state)->modelKind);
    if (((ExplosionPlacement*)def)->configFlags & 4)
    {
        ((ExplosionState*)state)->driftYSpeed = lbl_803E49A4;
    }
    else
    {
        ((ExplosionState*)state)->driftYSpeed = lbl_803E4960;
    }
    ((ExplosionState*)state)->nearGround = 0;
    if (((HitDetectFloatsFirst)hitDetectFn_800658a4)((int)obj, obj->anim.localPosX,
                                                     lbl_803E49B0 + obj->anim.localPosY, obj->anim.localPosZ,
                                                     state + 0x960, 0) == 0)
    {
        if (((ExplosionState*)state)->groundY < lbl_803E49B4)
        {
            ((ExplosionState*)state)->nearGround = 1;
        }
        ((ExplosionState*)state)->groundY = obj->anim.localPosY - ((ExplosionState*)state)->groundY;
    }
    else
    {
        ((ExplosionState*)state)->groundY = obj->anim.localPosY;
    }
    if (((ExplosionPlacement*)def)->configFlags & 0x10)
    {
        debrisCount = (int)((f32)(lbl_803E49B8 * scale) / lbl_803E49A8);
        for (i = 0, cursor = state; i < debrisCount; i++)
        {
            if (((ExplosionState*)state)->nearGround != 0)
            {
                f32 mag = (f32)(int)randomGetRange(0x14, 0x28) * lbl_803E49C0;
                mag = lbl_803E49BC * mag + lbl_803E49BC;
                vsp[0] = mag;
                vsp[1] = lbl_803E4960;
                vsp[2] = lbl_803E4960;
                PSMTXRotRad(mB, 0x7a,
                            (f32)(lbl_803E4968 * (f64)((f32)(int)randomGetRange(0x2000, 0x6000) / lbl_803E49C4)));
                PSMTXRotRad(mA, 0x79, (f32)(lbl_803E4968 * (f64)((f32)(int)randomGetRange(0, 0xffff) / lbl_803E4970)));
                PSMTXConcat(mA, mB, mB);
                PSMTXMultVecSR(mB, vsp, vsp);
            }
            else
            {
                f32 mag = (f32)(int)randomGetRange(0x14, 0x28) * lbl_803E49C0;
                u8 idx = i % 4;
                mag = lbl_803E49BC * mag + lbl_803E49BC;
                vsp[0] = mag * gExplosionSpreadDirs[idx * 3];
                vsp[1] = mag * gExplosionSpreadDirs[idx * 3 + 1];
                vsp[2] = mag * gExplosionSpreadDirs[idx * 3 + 2];
                PSMTXRotRad(
                    mB, 0x7a,
                    (f32)(lbl_803E4968 * (f64)(((f32)(int)randomGetRange(0, 0x8000) - lbl_803E49C8) / lbl_803E49C4)));
                PSMTXRotRad(
                    mA, 0x78,
                    (f32)(lbl_803E4968 * (f64)(((f32)(int)randomGetRange(0, 0x8000) - lbl_803E49C8) / lbl_803E49C4)));
                PSMTXConcat(mA, mB, mB);
                PSMTXMultVecSR(mB, vsp, vsp);
            }
            {
                GravityDebris* d = (GravityDebris*)((char*)cursor + 0x964);
                d->posX = obj->anim.localPosX;
                d->posY = obj->anim.localPosY;
                d->posZ = obj->anim.localPosZ;
                d->velX = vsp[0];
                d->velY = vsp[1];
                d->velZ = vsp[2];
                d->age = 0;
                d->lifetime = randomGetRange(0x28, 0x32);
                d->active = 1;
            }
            cursor += 0x24;
        }
        ((ExplosionState*)state)->debrisCount = i;
    }
    else
    {
        ((ExplosionState*)state)->debrisCount = 0;
    }
    ((ExplosionState*)state)->light = 0;
    if (((ExplosionPlacement*)def)->configFlags & 0x20)
    {
        ((ExplosionState*)state)->light = objCreateLight(0, 1);
        if (*(void**)&((ExplosionState*)state)->light != NULL)
        {
            modelLightStruct_setLightKind(((ExplosionState*)state)->light, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setPosition(((ExplosionState*)state)->light, obj->anim.worldPosX, obj->anim.worldPosY,
                                         obj->anim.worldPosZ);
            modelLightStruct_setAffectsAabbLightSelection((ModelLightStruct*)((ExplosionState*)state)->light, 1);
            modelLightStruct_setEnabled(((ExplosionState*)state)->light, 1, lbl_803E4960);
            modelLightStruct_setDistanceAttenuation(((ExplosionState*)state)->light, (f32)(lbl_803E49CC * scale),
                                                    (f32)(lbl_803E4958 * scale));
            modelLightStruct_setDiffuseColor(((ExplosionState*)state)->light, 0xff, 0xeb, 0xa0, 0xff);
        }
    }
    obj->anim.alpha = 0xff;
    if (((ExplosionPlacement*)def)->configFlags & 8)
    {
        if (((ExplosionState*)state)->nearGround == 0)
        {
            ((ExplosionState*)state)->rayMode = 2;
            *(u16*)&((ExplosionState*)state)->rayYawA = randomGetRange(0, 0x4000);
            *(u16*)&((ExplosionState*)state)->rayPitchA = randomGetRange(0, 0x8000);
            *(u16*)&((ExplosionState*)state)->rayYawB = *(u16*)&((ExplosionState*)state)->rayYawA + 0x4000;
            *(u16*)&((ExplosionState*)state)->rayPitchB = *(u16*)&((ExplosionState*)state)->rayPitchA;
        }
        else
        {
            ((ExplosionState*)state)->rayMode = 1;
            ((ExplosionState*)state)->rayYawA = 0;
            ((ExplosionState*)state)->rayPitchA = 0;
        }
    }
    else
    {
        ((ExplosionState*)state)->rayMode = 0;
    }
    ((ExplosionState*)state)->halfLifeFired = 0;
    ((ExplosionState*)state)->frameCounter = 0;
    ((ExplosionState*)state)->lifeFrames = (int)(lbl_803E4930 * sqrtf(scale));
    {
        int v = ((ExplosionState*)state)->lifeFrames;
        if (v < 0)
        {
            v = 0;
        }
        else if (v > 0x3c)
        {
            v = 0x3c;
        }
        ((ExplosionState*)state)->lifeFrames = v;
    }
    ((ExplosionState*)state)->scale = scale;
    obj->anim.rootMotionScale = lbl_803E4960;
}

void explosion_release(u32 obj)
{
    int i;

    for (i = 0; i < GEXPLOSION_TEXTURE_COUNT; i++)
    {
        if (((int**)gExplosionTextures)[i] != NULL)
        {
            textureFree((int)((int**)gExplosionTextures)[i]);
            ((int**)gExplosionTextures)[i] = NULL;
        }
    }
}

void explosion_initialise(void)
{
    FbTexTbl t;
    int i;
    t = gExplosionTexTable;
    gExplosionDebrisSpeedScale = lbl_803E492C / expf(lbl_803E4934);
    gExplosionDebrisAlphaScale = lbl_803E492C / expf(lbl_803E493C);
    gExplosionDebrisColorScale = lbl_803E492C / expf(lbl_803E4958);
    gExplosionFalloffScaleRed = lbl_803E492C / expf(lbl_803E4950);
    gExplosionFalloffScaleGreen = lbl_803E492C / expf(lbl_803E4954);
    gExplosionFalloffScaleBlue = lbl_803E492C / expf(lbl_803E492C);
    for (i = 0; i < GEXPLOSION_TEXTURE_COUNT; i++)
    {
        gExplosionTextures[i] = textureLoadAsset(t.v[i]);
    }
}

#pragma scheduling on
#pragma peephole on

f32 gExplosionSpreadDirs[] = {
    1.0f, 0.0f, 0.0f, 0.0f, 1.0f, 0.0f, -1.0f, 0.0f, 0.0f, 0.0f, -1.0f, 0.0f,
};

#include "main/dll/DIM/dll_01CB_dimwooddoor2.h"

/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* gExplosionObjDescriptor[14] = {(void*)0x00000000,         (void*)0x00000000,     (void*)0x00000000,
                                     (void*)0x00090000,         explosion_initialise,  explosion_release,
                                     (void*)0x00000000,         explosion_init,        explosion_update,
                                     explosion_hitDetect,       explosion_render,      explosion_free,
                                     explosion_getObjectTypeId, explosion_getExtraSize};
void* gDIMWoodDoor2ObjDescriptor[14] = {(void*)0x00000000,
                                        (void*)0x00000000,
                                        (void*)0x00000000,
                                        (void*)0x00090000,
                                        dimwooddoor2_initialise,
                                        dimwooddoor2_release,
                                        (void*)0x00000000,
                                        dimwooddoor2_init,
                                        dimwooddoor2_update,
                                        dimwooddoor2_hitDetect,
                                        dimwooddoor2_render,
                                        dimwooddoor2_free,
                                        dimwooddoor2_getObjectTypeId,
                                        dimwooddoor2_getExtraSize};
