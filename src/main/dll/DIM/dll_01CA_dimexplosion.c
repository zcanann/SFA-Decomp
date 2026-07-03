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
#include "main/dll/fbtextbl_struct.h"
#include "main/dll/fbwgpipe_struct.h"
#include "main/dll/explosionpartfxsource_struct.h"
#include "main/dll/explosion_state.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "main/camera.h"
#include "string.h"
#include "main/audio/sfx.h"
#include "sfa_light_decls.h"
#include "main/audio/sfx_trigger_ids.h"

#define DIMEXPLOSION_OBJFLAG_HITDETECT_DISABLED 0x2000
#define MODEL_LIGHT_KIND_POINT 2

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

#define GEXPLOSION_TEXTURE_COUNT 4

extern void textureFree(int tex);
extern int gExplosionTextures[GEXPLOSION_TEXTURE_COUNT];
extern int Obj_GetActiveModel(int obj);
extern void ModelLightStruct_free(void*);
extern u8 framesThisStep;

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
extern f64 lbl_803E4978;
extern f64 lbl_803E4980;
extern f32 lbl_803E4988;
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
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 gExplosionSpreadDirs[];
extern FbTexTbl gExplosionTexTable;
extern f32 expf(f32 x);
extern f32 sqrtf(f32 x);


extern void GXSetVtxDesc(int attr, int type);
extern void GXSetCurrentMtx(u32 id);
extern void GXLoadPosMtxImm(f32* m, int id);
extern void GXBegin(int prim, int fmt, int n);

#define GX_VA_POS 9
#define GX_VA_TEX0 13
#define GX_DIRECT 1
#define GX_QUADS 0x80
#define GX_VTXFMT2 2
extern void PSMTXRotRad(f32* m, int axis, f32 rad);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * out);
extern void PSMTXScale(f32* m, f32 x, f32 y, f32 z);
extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);
extern void PSMTXMultVecSR(f32 * m, f32 * in, f32 * out);

extern int fn_8000FA70(void);
extern int fn_8000FA90(void);
extern void fn_80073AAC(void* tex, u32* a, u32* b, int k);
extern void Obj_BuildWorldTransformMatrix(int obj, f32* m, int p3);
extern int textureLoadAsset(int id);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern int hitDetectFn_800658a4(int a, f32 b, f32 val, f32 d, f32* out, int e);
extern int objCreateLight(int a, int b);
extern void modelLightStruct_setLightKind(int h, int v);
extern void modelLightStruct_setPosition(int h, f32 x, f32 y, f32 z);
extern void modelLightStruct_setAffectsAabbLightSelection(int h, int v);
extern void modelLightStruct_setEnabled(int h, int n, f32 v);
extern void modelLightStruct_setDistanceAttenuation(int h, f32 a, f32 b);
extern void modelLightStruct_setDiffuseColor(int h, int r, int g, int b, int a);
extern void Obj_FreeObject(int obj);

volatile FbWGPipe GXWGFifo : (0xCC008000);

void explosion_spawnFlame(int obj, u8 gen, f32 spd, f32 x, f32 y, f32 z);
void explosion_computeColor(f32 age, f32 lifetime, u8 mode, u8* out);
typedef void (*ExplosionSpawnFlameSpdFirst)(int obj, f32 spd, int gen, f32 x, f32 y, f32 z);
typedef int (*HitDetectFloatsFirst)(int obj, f32 x, f32 y, f32 z, int out, int p3);

#pragma scheduling off
#pragma peephole off
#pragma opt_propagation off
void explosion_spawnFlame(int obj, u8 gen, f32 spd, f32 x, f32 y, f32 z)
{
    s16* placement = ((GameObject*)obj)->anim.placementData;
    ExplosionState* state = ((GameObject*)obj)->extra;
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
                Sfx_PlayFromObject(obj, SFXTRIG_wp_sexpl2_c_4bf);
            }
            else if (c == 3)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_wp_sexpl2_c_4c2);
            }
            else
            {
                s8 m = ((GameObject*)obj)->anim.mapEventSlot;
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
                    Sfx_PlayFromObjectLimited(obj, SFXTRIG_wp_sexpl2_c_4b8, 2);
                    goto done;
                }
                Sfx_PlayFromObject(obj, SFXTRIG_sexpl2_c);
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
int explosion_getExtraSize(void) { return sizeof(ExplosionState); }

#pragma scheduling off
int explosion_getObjectTypeId(int obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int idx = (int)*(short*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x1c) & 3;
    if (idx >= objAnim->modelInstance->modelCount)
    {
        idx = 0;
    }
    return (idx << 11) | 0x400;
}

#pragma scheduling on
void explosion_free(int obj)
{
    void* p = *(void**)(*(int*)&((GameObject*)obj)->extra + 0xa40);
    if (p != NULL)
    {
        ModelLightStruct_free(p);
    }
}

#pragma scheduling off
#pragma peephole off
void explosion_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
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
    int p;
    colA = lbl_803E4928;
    colB = lbl_803E8468;
    state = *(int*)&((GameObject*)obj)->extra;
    model = Obj_GetActiveModel(obj);
    p = state;
    if (visible != 0)
    {
        GXClearVtxDesc();
        GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
        GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
        GXSetCurrentMtx(0);
        for (i = 0, p = state; i < ((ExplosionState*)state)->flameCount; i++)
        {
            if (((ExplosionDebris*)p)->active != 0)
            {
                void** tex;
                int k;
                u8 cv;
                Obj_BuildWorldTransformMatrix(obj, mE, 0);
                PSMTXRotRad(
                    m1, 0x7a, (f32)((6.2832 * (f64)(int) * &((ExplosionDebris*)p)->spinAngle) / 65536.0));
                PSMTXRotRad(
                    m3, 0x78, (f32)((6.2832 * ((f64)(u32)(fn_8000FA70() & 0xffff) - 0.0)) / 65536.0));
                PSMTXConcat(m3, m1, m3);
                PSMTXRotRad(
                    m2, 0x79, (f32)((6.2832 * (f64)(int)(0x10000 - (fn_8000FA90() & 0xffff))) / 65536.0));
                PSMTXConcat(m2, m3, m2);
                PSMTXScale(m4, ((ExplosionDebris*)p)->scale, ((ExplosionDebris*)p)->scale, ((ExplosionDebris*)p)->scale);
                PSMTXConcat(m4, m2, m4);
                PSMTXTrans(mE, ((ExplosionDebris*)p)->posX - playerMapOffsetX, ((ExplosionDebris*)p)->posY,
                           ((ExplosionDebris*)p)->posZ - playerMapOffsetZ);
                PSMTXConcat(mE, m4, mE);
                PSMTXConcat(Camera_GetViewMatrix(), mE, mE);
                GXLoadPosMtxImm(mE, 0);
                ((u8*)&colA)[3] = ((ExplosionDebris*)p)->alpha;
                cv = gExplosionDebrisColorScale * (255.0f * expf(
                    (3.0f * ((f32)((ExplosionDebris*)p)->lifetime - (f32)((ExplosionDebris*)p)->age)) /
                    (f32)((ExplosionDebris*)p)->lifetime));
                ((u8*)&colB)[0] = cv;
                ((u8*)&colB)[1] = cv;
                ((u8*)&colB)[2] = cv;
                ((u8*)&colB)[3] = cv;
                explosion_computeColor((f32)((ExplosionDebris*)p)->age,
                            (f32)((ExplosionDebris*)p)->lifetime,
                            ((ExplosionState*)state)->modelKind, (u8*)&colA);
                tex = (void**)((int*)gExplosionTextures)[((ExplosionState*)state)->modelKind];
                for (k = 0; k < ((ExplosionDebris*)p)->texVariant; k++)
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
            p += 0x30;
        }
        if (((ExplosionState*)state)->frameCounter < ((ExplosionState*)state)->lifeFrames && *(u8*)&((ExplosionState*)
            state)->rayMode != 0)
        {
            for (i = 0, p = state; i < ((ExplosionState*)state)->rayMode; p += 4, i++)
            {
                ((GameObject*)obj)->anim.rotY = (s16)*(u16*)&((ExplosionState*)p)->rayYawA;
                ((GameObject*)obj)->anim.rotX = (s16)*(u16*)&((ExplosionState*)p)->rayPitchA;
                objRenderFn_8003b8f4(obj, p2, p3, p4, p5, visible);
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
void explosion_update(int obj)
{
    ExplosionPartfxSource fake;
    u16 ang[6];
    f32 vpos[3];
    f32 m[12];
    u8 rgb[3];
    int state = *(int*)&((GameObject*)obj)->extra;
    int i;
    int p;
    gExplosionUpdateTick += 1;
    p = state;
    ((ExplosionState*)state)->frameCounter += framesThisStep;
    for (i = 0, p = state; i < ((ExplosionState*)state)->flameCount; i++)
    {
        ((ExplosionDebris*)p)->age += framesThisStep;
        if (((ExplosionDebris*)p)->active != 0)
        {
            f32 sp = ((ExplosionDebris*)p)->speed;
            f32 ev = expf(
                (lbl_803E4934 * ((f32)((ExplosionDebris*)p)->lifetime - (f32)((ExplosionDebris*)p)->age)) / (
                    f32)(int)((ExplosionDebris*)p)->lifetime);
            f32 d = sp - ((ExplosionDebris*)p)->baseScale;
            f32 t = d * ev;
            ((ExplosionDebris*)p)->scale = sp - gExplosionDebrisSpeedScale * t;
            ev = expf((lbl_803E493C * (f32)((ExplosionDebris*)p)->age) / (f32)((ExplosionDebris*)p)->lifetime);
            t = lbl_803E4938 * ev;
            *(s8*)&((ExplosionDebris*)p)->alpha = lbl_803E4938 - gExplosionDebrisAlphaScale * t;
            if (((ExplosionDebris*)p)->age >= ((ExplosionDebris*)p)->lifetime)
            {
                ((ExplosionDebris*)p)->active = 0;
            }
            else
            {
                *(s16*)&((ExplosionDebris*)p)->spinAngle += framesThisStep * *(s16*)&((ExplosionDebris*)p)->spinSpeed;
                if (((ExplosionDebris*)p)->texVariant >= 4)
                {
                    ((ExplosionDebris*)p)->texVariant -= 4;
                }
                if (((ExplosionDebris*)p)->generation < 5)
                {
                    if ((f32)((ExplosionDebris*)p)->age / (f32)((ExplosionDebris*)p)->lifetime < lbl_803E4998
                        &&
                        (((ExplosionDebris*)p)->spawnTimer -= framesThisStep, ((ExplosionDebris*)p)->spawnTimer <= 0))
                    {
                        int st2;
                        u8 c;
                        f32 sp2;
                        f32 sv;
                        c = ((ExplosionDebris*)p)->generation;
                        sp2 = ((ExplosionDebris*)p)->speed;
                        st2 = *(int*)&((GameObject*)obj)->extra;
                        vpos[0] = ((ExplosionDebris*)p)->scale * (lbl_803E495C * (f32)(int)randomGetRange(-5, 3) + lbl_803E492C);
                        vpos[1] = lbl_803E4960;
                        vpos[2] = lbl_803E4960;
                        PSMTXRotRad(
                            m, 0x7a, (f32)(lbl_803E4968 * (f64)((f32)(int)randomGetRange(0, 0xffff) / lbl_803E4970)));
                        PSMTXConcat(Camera_GetInverseViewRotationMatrix(), m, m);
                        PSMTXMultVecSR(m, vpos, vpos);
                        vpos[0] += ((ExplosionDebris*)p)->posX;
                        vpos[1] += ((ExplosionDebris*)p)->posY;
                        vpos[2] += ((ExplosionDebris*)p)->posZ;
                        sv = sp2 * (f32)(int)randomGetRange(0xc0, 0x100);
                        sv = sv * lbl_803E4974;
                        if (((ExplosionState*)st2)->flameCount < 0x32)
                        {
                            explosion_spawnFlame(obj, (u8)(c + 1), sv, vpos[0], vpos[1], vpos[2]);
                        }
                        ((ExplosionDebris*)p)->spawnTimer = ((ExplosionDebris*)p)->spawnInterval;
                    }
                }
            }
        }
        p += 0x30;
    }
    memcpy(&fake, (void*)obj, sizeof(fake));
    fake.rootMotionScale = lbl_803E492C;
    fake.velocityX = lbl_803E4960;
    fake.velocityY = lbl_803E4960;
    fake.velocityZ = lbl_803E4960;
    for (i = 0, p = state; i < ((ExplosionState*)state)->debrisCount; i++)
    {
        GravityDebris* d = (GravityDebris*)((char*)p + 0x964);
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
                d->posY = -(lbl_803E499C * (grav * (f32)(int)(ft * ft))
                                       - (d->velY * (f32)(u32)ft + d->posY));
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
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x5e, &fake, 0x200001, -1, ang);
                }
            }
        }
        p += 0x24;
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
                ((GameObject*)obj)->anim.rootMotionScale = lbl_803E49A4 * (frac * ((ExplosionState*)state)->scale);
                ((GameObject*)obj)->anim.alpha = lbl_803E4938 - lbl_803E4938 * frac;
            }
            if (((ExplosionState*)state)->halfLifeFired == 0 && ((ExplosionState*)state)->frameCounter >= (((ExplosionState*)state)->lifeFrames >> 1))
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
void explosion_init(int obj, int p2)
{
    f32 vsp[3];
    f32 mB[12];
    f32 mA[12];
    int p;
    int state = *(int*)&((GameObject*)obj)->extra;
    f32 scale;
    int i;
    int n;
    ((ExplosionState*)state)->flameCount = 0;
    if (*(s16*)((char*)p2 + 0x1a) == 0)
    {
        scale = lbl_803E49A8;
    }
    else
    {
        scale = (f32)(int) * (s16*)((char*)p2 + 0x1a) * lbl_803E4974;
        if (scale > lbl_803E49A8)
        {
            scale = lbl_803E49A8;
        }
    }
    ((ExplosionSpawnFlameSpdFirst)explosion_spawnFlame)(obj, lbl_803E49AC * scale, 0, ((GameObject*)obj)->anim.localPosX,
                                      ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ);
    ((GameObject*)obj)->objectFlags |= DIMEXPLOSION_OBJFLAG_HITDETECT_DISABLED;
    ((ExplosionState*)state)->modelKind = *(s16*)((char*)p2 + 0x1c) & 3;
    Obj_SetActiveModelIndex(obj, ((ExplosionState*)state)->modelKind);
    if (*(s16*)((char*)p2 + 0x1c) & 4)
    {
        ((ExplosionState*)state)->driftYSpeed = lbl_803E49A4;
    }
    else
    {
        ((ExplosionState*)state)->driftYSpeed = lbl_803E4960;
    }
    ((ExplosionState*)state)->nearGround = 0;
    if (((HitDetectFloatsFirst)hitDetectFn_800658a4)(obj, ((GameObject*)obj)->anim.localPosX,
                             lbl_803E49B0 + ((GameObject*)obj)->anim.localPosY,
                             ((GameObject*)obj)->anim.localPosZ, state + 0x960, 0) == 0)
    {
        if (((ExplosionState*)state)->groundY < lbl_803E49B4)
        {
            ((ExplosionState*)state)->nearGround = 1;
        }
        ((ExplosionState*)state)->groundY = ((GameObject*)obj)->anim.localPosY - ((ExplosionState*)state)->groundY;
    }
    else
    {
        ((ExplosionState*)state)->groundY = ((GameObject*)obj)->anim.localPosY;
    }
    if (*(s16*)((char*)p2 + 0x1c) & 0x10)
    {
        n = (int)((f32)(lbl_803E49B8 * scale) / lbl_803E49A8);
        for (i = 0, p = state; i < n; i++)
        {
            if (((ExplosionState*)state)->nearGround != 0)
            {
                f32 mag = (f32)(int)randomGetRange(0x14, 0x28) *lbl_803E49C0;
                mag = lbl_803E49BC * mag + lbl_803E49BC;
                vsp[0] = mag;
                vsp[1] = lbl_803E4960;
                vsp[2] = lbl_803E4960;
                PSMTXRotRad(
                    mB, 0x7a, (f32)(lbl_803E4968 * (f64)((f32)(int)randomGetRange(0x2000, 0x6000) / lbl_803E49C4)));
                PSMTXRotRad(mA, 0x79, (f32)(lbl_803E4968 * (f64)((f32)(int)randomGetRange(0, 0xffff) / lbl_803E4970)));
                PSMTXConcat(mA, mB, mB);
                PSMTXMultVecSR(mB, vsp, vsp);
            }
            else
            {
                f32 mag = (f32)(int)randomGetRange(0x14, 0x28) *lbl_803E49C0;
                u8 idx = i % 4;
                mag = lbl_803E49BC * mag + lbl_803E49BC;
                vsp[0] = mag * gExplosionSpreadDirs[idx * 3];
                vsp[1] = mag * gExplosionSpreadDirs[idx * 3 + 1];
                vsp[2] = mag * gExplosionSpreadDirs[idx * 3 + 2];
                PSMTXRotRad(mB, 0x7a,
                            (f32)(lbl_803E4968 * (f64)(((f32)(int)randomGetRange(0, 0x8000) - lbl_803E49C8) / lbl_803E49C4)));
                PSMTXRotRad(mA, 0x78,
                            (f32)(lbl_803E4968 * (f64)(((f32)(int)randomGetRange(0, 0x8000) - lbl_803E49C8) / lbl_803E49C4)));
                PSMTXConcat(mA, mB, mB);
                PSMTXMultVecSR(mB, vsp, vsp);
            }
            {
                GravityDebris* d = (GravityDebris*)((char*)p + 0x964);
                d->posX = ((GameObject*)obj)->anim.localPosX;
                d->posY = ((GameObject*)obj)->anim.localPosY;
                d->posZ = ((GameObject*)obj)->anim.localPosZ;
                d->velX = vsp[0];
                d->velY = vsp[1];
                d->velZ = vsp[2];
                d->age = 0;
                d->lifetime = randomGetRange(0x28, 0x32);
                d->active = 1;
            }
            p += 0x24;
        }
        ((ExplosionState*)state)->debrisCount = i;
    }
    else
    {
        ((ExplosionState*)state)->debrisCount = 0;
    }
    ((ExplosionState*)state)->light = 0;
    if (*(s16*)((char*)p2 + 0x1c) & 0x20)
    {
        ((ExplosionState*)state)->light = objCreateLight(0, 1);
        if (*(void**)&((ExplosionState*)state)->light != NULL)
        {
            modelLightStruct_setLightKind(((ExplosionState*)state)->light, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setPosition(((ExplosionState*)state)->light, ((GameObject*)obj)->anim.worldPosX,
                                         ((GameObject*)obj)->anim.worldPosY, ((GameObject*)obj)->anim.worldPosZ);
            modelLightStruct_setAffectsAabbLightSelection(((ExplosionState*)state)->light, 1);
            modelLightStruct_setEnabled(((ExplosionState*)state)->light, 1, lbl_803E4960);
            modelLightStruct_setDistanceAttenuation(((ExplosionState*)state)->light, (f32)(lbl_803E49CC * scale),
                                                    (f32)(lbl_803E4958 * scale));
            modelLightStruct_setDiffuseColor(((ExplosionState*)state)->light, 0xff, 0xeb, 0xa0, 0xff);
        }
    }
    ((GameObject*)obj)->anim.alpha = 0xff;
    if (*(s16*)((char*)p2 + 0x1c) & 8)
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
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E4960;
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
    1.0f, 0.0f, 0.0f,
    0.0f, 1.0f, 0.0f,
    -1.0f, 0.0f, 0.0f,
    0.0f, -1.0f, 0.0f,
};
