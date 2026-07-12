/*
 * DLL 0x00E5 - the player's energy-shield object.
 *
 * The shield (seqId 0x836 uses staff-mode 5, otherwise mode 7) is
 * a four-segment ring driven by staffFn_80170380: each mode sets the
 * per-segment fade/scale targets in ShieldState, drives a point light
 * (modelLightStruct_*) and the 0x42C/0x42D loop sfx, and seeds the
 * fcos16 wobble for the four segments. Shield_update advances the fade
 * toward its target, modulates alpha from a random flicker, and updates
 * the segment cosine; Shield_render re-renders the four segments with
 * per-segment rotation and (off-HUD) spawns particle fx 2028 at the
 * staff tips.
 *
 * staffFn_80170380 (vtbl/cmd dispatch 0..7) is shared with the staff
 * object; its per-segment scale table (lbl_80320A28) and switch
 * jumptable (jumptable_80320AA0) live in the shared descriptor-catalogue
 * data split out of this TU by the retail layout.
 *
 * TU: 0x8016B230-0x8016B2E0.
 */
#include "main/dll/xyzanimator.h"
#include "main/vecmath.h"
#include "main/dll/player_objects.h"
#include "main/game_object.h"
#include "main/modellight_api.h"
#include "main/model.h"
#include "main/object_api.h"
#include "main/obj_placement.h"
#include "main/dll/genprops.h"
#include "main/dll_000A_expgfx.h"
#include "main/objprint.h"
#include "main/objlib.h"
#include "main/dll/dll_00E5_shield.h"
#include "main/dll/dll_00E2_staff.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"

extern void modelLightStruct_setLightKind(int light, int value);
#define MODEL_LIGHT_KIND_POINT 2
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setSpecularColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far);
extern void modelLightStruct_setEnabled(int light, int enabled, f32 scale);
extern void modelLightStruct_startColorFade(int light, int a, int b);

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);


/* anim.seqId of the staff-mode-5 shield variant (docblock: "seqId 0x836 uses
 * staff-mode 5, otherwise mode 7"). */
#define SHIELD_SEQID_STAFF_MODE5 0x836
/* shield-ring particle spawned around the object in the deflect loop */
#define SHIELD_PARTFX 2028

typedef struct ShieldState
{
    u8 pad0[0x4 - 0x0];
    f32 fadeValue;  /* 0x4: current shield fade, advanced toward fadeTarget by fadeRate*dt */
    f32 fadeTarget; /* 0x8 */
    f32 fadeRate;   /* 0xC */
    s32 fadeMax;    /* 0x10: divisor for alpha (fadeValue/fadeMax) */
    /* Per-segment parameters for the four ring segments, laid out
     * structure-of-arrays (each array indexed by segment 0..3). */
    f32 segScale[4]; /* 0x14: per-segment scale (feeds anim.rootMotionScale) */
    f32 segAlpha[4]; /* 0x24: per-segment alpha factor (feeds anim.alpha) */
    s16 segPhase[4]; /* 0x34: fcos16 wobble phase, advanced by segRate*dt */
    s16 segSeed[4];  /* 0x3C: random per-segment cosine seed */
    s16 segRotX[4];  /* 0x44: per-segment X rotation */
    s16 segRotY[4];  /* 0x4C: per-segment Y rotation */
    s16 segRotZ[4];  /* 0x54: per-segment Z rotation */
    u8 flags0;       /* 0x5C: segment-0 "fully faded" bit0 */
    u8 flags1;       /* 0x5D */
    u8 flags2;       /* 0x5E */
    u8 flags3;       /* 0x5F */
    u8 pad60[0x6A - 0x60];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 unk70;
    u8 pad71[0x94 - 0x71];
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
} ShieldState;

STATIC_ASSERT(offsetof(ShieldState, fadeValue) == 0x04);
STATIC_ASSERT(offsetof(ShieldState, fadeMax) == 0x10);
STATIC_ASSERT(offsetof(ShieldState, segScale) == 0x14);
STATIC_ASSERT(offsetof(ShieldState, segAlpha) == 0x24);
STATIC_ASSERT(offsetof(ShieldState, segPhase) == 0x34);
STATIC_ASSERT(offsetof(ShieldState, segSeed) == 0x3C);
STATIC_ASSERT(offsetof(ShieldState, segRotX) == 0x44);
STATIC_ASSERT(offsetof(ShieldState, segRotY) == 0x4C);
STATIC_ASSERT(offsetof(ShieldState, segRotZ) == 0x54);
STATIC_ASSERT(offsetof(ShieldState, flags0) == 0x5C);

extern int* Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, void* parent);
extern void* Obj_AllocObjectSetup(int size, int b);
extern void ModelLightStruct_free(void* p);
extern int Sfx_StopFromObject(int obj, int sfxId);
extern void postRenderSetAlphaBlendState(void);
extern int getHudHiddenFrameCount(void);
extern void vecRotateZXY(int* obj, f32* p);
extern f32 fcos16(u16 angle);
extern void Sfx_SetObjectSfxVolume(s16* obj, int sfx, int vol, f32 ratio);
extern f32 lbl_803E33A8;
extern f32 lbl_803E33AC;
extern f32 lbl_803E33C4;
extern f32 lbl_803E33E8;
extern f32 lbl_803E33EC;
extern s16 lbl_803DBD70[4];
extern s16 lbl_803DBD78[4];
extern s16 lbl_803DBD80[4];
extern s16 lbl_803DBD88[4];
extern f32 lbl_803E33D8;
extern f32 lbl_803E33DC;
extern f32 lbl_803E33B0;
extern f32 lbl_803E33B4;
extern f32 lbl_803E33B8;
extern f32 lbl_803E33BC;
extern f32 lbl_803E33C0;
extern const f32 lbl_803E33C8;
extern f32 lbl_803E33CC;

/* staff/shield per-segment scale table; lives in the shared
 * descriptor-catalogue data (0x80320A28), split out of this TU */
extern f32 lbl_80320A28[];


void Shield_hitDetect(void);
void Shield_release(void);
void Shield_initialise(void);
void Shield_init(int* obj, void* initData);
void Shield_update(int* obj);
void Shield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
void Shield_free(GameObject* obj);
int Shield_getExtraSize(void);
int Shield_getObjectTypeId(void);
void staffFn_80170380(int* obj, int cmd);

int* fn_801702D4(int* obj, f32 fv)
{
    void* alloc;
    int* new_obj;
    if ((u8)Obj_IsLoadingLocked() == 0)
        return NULL;
    alloc = Obj_AllocObjectSetup(36, 2102);
    ((ObjPlacement*)alloc)->posX = ((GameObject*)obj)->anim.worldPosX;
    ((ObjPlacement*)alloc)->posY = ((GameObject*)obj)->anim.worldPosY;
    ((ObjPlacement*)alloc)->posZ = ((GameObject*)obj)->anim.worldPosZ;
    ((ObjPlacement*)alloc)->color[0] = 1;
    ((ObjPlacement*)alloc)->color[1] = 1;
    ((ObjPlacement*)alloc)->color[3] = 255;
    new_obj = Obj_SetupObject(alloc, 5, -1, -1, 0);
    if (new_obj != NULL)
    {
        ((GameObject*)new_obj)->anim.rootMotionScale = fv;
    }
    return new_obj;
}

ObjectDescriptor gShieldObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)Shield_initialise,
    (ObjectDescriptorCallback)Shield_release,
    0,
    (ObjectDescriptorCallback)Shield_init,
    (ObjectDescriptorCallback)Shield_update,
    (ObjectDescriptorCallback)Shield_hitDetect,
    (ObjectDescriptorCallback)Shield_render,
    (ObjectDescriptorCallback)Shield_free,
    (ObjectDescriptorCallback)Shield_getObjectTypeId,
    Shield_getExtraSize,
};

#pragma opt_common_subs off
void staffFn_80170380(int* obj, int cmd)
{
    extern int objCreateLight(int* obj, int arg);
    extern void modelLightStruct_setDiffuseColor(int* light, int r, int g, int b, int a);
    extern void Sfx_PlayFromObject(int* obj, int sfx);
    f32* tbl[1];
    u8* state;
    GameObject* glow;
    GameObject* player;
    tbl[0] = lbl_80320A28;
    state = ((GameObject*)obj)->extra;
    player = Obj_GetPlayerObject();
    glow = NULL;
    if (player != NULL)
    {
        glow = Player_GetStaffObject(player);
    }
    switch ((u8)cmd)
    {
    case 7:
        if (glow != NULL)
        {
            staffSetGlow(glow, 7, 0);
        }
        if (*(int**)state != NULL)
        {
            modelLightStruct_setEnabled(*(int*)state, 0, lbl_803E33A8);
        }
        {
            f32 fade = lbl_803E33AC;
            ((ShieldState*)state)->fadeTarget = fade;
            ((ShieldState*)state)->fadeRate = fade;
            *(f32*)&((ShieldState*)state)->fadeMax = fade;
            ((ShieldState*)state)->fadeValue = fade;
        }
        ((ShieldState*)state)->flags0 |= 1;
        ((ShieldState*)state)->flags1 |= 1;
        ((ShieldState*)state)->flags2 |= 1;
        ((ShieldState*)state)->flags3 |= 1;
        break;
    case 0:
        if (*(int**)state != NULL)
        {
            modelLightStruct_setEnabled(*(int*)state, 0, lbl_803E33A8);
        }
        if (lbl_803E33AC != ((ShieldState*)state)->fadeTarget)
        {
            f32 fade = lbl_803E33B0;
            *(f32*)&((ShieldState*)state)->fadeMax = fade;
            ((ShieldState*)state)->fadeValue = fade;
            if (glow != NULL)
            {
                staffSetGlow(glow, 7, 0);
            }
        }
        ((ShieldState*)state)->fadeTarget = lbl_803E33AC;
        ((ShieldState*)state)->fadeRate = lbl_803E33B4;
        Sfx_StopFromObject((int)obj, SFXTRIG_lrope_powerup);
        Sfx_StopFromObject((int)obj, SFXTRIG_lockon3_on);
        break;
    case 1:
        if (lbl_803E33AC == ((ShieldState*)state)->fadeTarget)
        {
            if (glow != NULL)
            {
                staffSetGlow(glow, 7, 8);
            }
            if (*(int**)state == NULL)
            {
                *(int*)state = objCreateLight(0, 1);
            }
            if (*(int**)state != NULL)
            {
                modelLightStruct_setLightKind(*(int*)state, MODEL_LIGHT_KIND_POINT);
                modelLightStruct_setPosition(*(int*)state, ((GameObject*)obj)->anim.localPosX,
                                             ((GameObject*)obj)->anim.localPosY - lbl_803E33B8,
                                             ((GameObject*)obj)->anim.localPosZ);
                modelLightStruct_setDiffuseColor(*(int**)state, 0, 255, 255, 255);
                modelLightStruct_setSpecularColor(*(int*)state, 0, 255, 255, 255);
                modelLightStruct_setDistanceAttenuation(*(int*)state, lbl_803E33BC, lbl_803E33C0);
                lightSetField4D((ModelLightStruct*)*(int*)state, 1);
                modelLightStruct_setEnabled(*(int*)state, 1, lbl_803E33AC);
                modelLightStruct_startColorFade(*(int*)state, 0, 0);
                modelLightStruct_setAffectsAabbLightSelection((ModelLightStruct*)*(int*)state, 1);
            }
            {
                f32 fade = lbl_803E33AC;
                if (fade == ((ShieldState*)state)->fadeTarget)
                {
                    *(f32*)&((ShieldState*)state)->fadeMax = lbl_803E33B0;
                    ((ShieldState*)state)->fadeValue = fade;
                }
            }
            ((ShieldState*)state)->fadeTarget = lbl_803E33B0;
            {
                f32 amp = lbl_803E33C4;
                u8* hw;
                u8* w;
                f32* t1;
                int i;
                f32 k;
                ((ShieldState*)state)->fadeRate = amp;
                i = 0;
                hw = state;
                w = state;
                t1 = (f32*)((char*)tbl[0] + 0x10);
                k = lbl_803E33A8;
                for (; i < 4; i++)
                {
                    f32 wave;
                    f32 sum;
                    *(s16*)(hw + 0x34) = -0x4000;
                    wave = fcos16((u16) * (s16*)(hw + 0x34));
                    sum = amp + wave;
                    wave = sum * k;
                    *(f32*)(w + 0x24) = *tbl[0] * wave;
                    *(f32*)(w + 0x14) = *t1;
                    *(s16*)(hw + 0x3c) = (f32)(int)(i * randomGetRange(0x78, 0x7f)) + lbl_803E33C8;
                    hw += 2;
                    tbl[0] += 1;
                    w += 4;
                    t1 += 1;
                }
            }
            Sfx_PlayFromObject(obj, SFXTRIG_lrope_powerup);
            Sfx_PlayFromObject(obj, SFXTRIG_lockon3_on);
        }
        break;
    case 2:
        if (glow != NULL)
        {
            staffSetGlow(glow, 7, 0);
        }
        if (lbl_803E33AC != ((ShieldState*)state)->fadeTarget)
        {
            *(f32*)&((ShieldState*)state)->fadeMax = lbl_803E33CC;
        }
        ((ShieldState*)state)->fadeTarget = lbl_803E33AC;
        ((ShieldState*)state)->fadeRate = lbl_803E33B4;
        if (*(int**)state != NULL)
        {
            modelLightStruct_setEnabled(*(int*)state, 0, lbl_803E33A8);
        }
        Sfx_StopFromObject((int)obj, SFXTRIG_lrope_powerup);
        Sfx_StopFromObject((int)obj, SFXTRIG_lockon3_on);
        break;
    case 3:
        if (glow != NULL)
        {
            staffSetGlow(glow, 7, 8);
        }
        if (*(int**)state == NULL)
        {
            *(int*)state = objCreateLight(0, 1);
        }
        if (*(int**)state != NULL)
        {
            modelLightStruct_setLightKind(*(int*)state, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setPosition(*(int*)state, ((GameObject*)obj)->anim.localPosX,
                                         ((GameObject*)obj)->anim.localPosY - lbl_803E33B8,
                                         ((GameObject*)obj)->anim.localPosZ);
            modelLightStruct_setDiffuseColor(*(int**)state, 0, 255, 255, 255);
            modelLightStruct_setSpecularColor(*(int*)state, 0, 255, 255, 255);
            modelLightStruct_setDistanceAttenuation(*(int*)state, lbl_803E33BC, lbl_803E33C0);
            lightSetField4D((ModelLightStruct*)*(int*)state, 1);
            modelLightStruct_setEnabled(*(int*)state, 1, lbl_803E33AC);
            modelLightStruct_startColorFade(*(int*)state, 0, 0);
            modelLightStruct_setAffectsAabbLightSelection((ModelLightStruct*)*(int*)state, 1);
        }
        if (lbl_803E33AC == ((ShieldState*)state)->fadeTarget)
        {
            *(f32*)&((ShieldState*)state)->fadeMax = lbl_803E33CC;
        }
        ((ShieldState*)state)->fadeTarget = lbl_803E33CC;
        {
            f32 amp = lbl_803E33C4;
            int i;
            u8* hw;
            u8* w;
            f32* t0;
            f32* t1;
            f32 k;
            ((ShieldState*)state)->fadeRate = amp;
            i = 0;
            hw = state;
            w = state;
            t1 = (f32*)((char*)tbl[0] + 0x10);
            k = lbl_803E33A8;
            for (; i < 4; i++)
            {
                f32 wave;
                f32 sum;
                *(s16*)(hw + 0x34) = 0;
                wave = fcos16((u16) * (s16*)(hw + 0x34));
                sum = amp + wave;
                wave = sum * k;
                *(f32*)(w + 0x24) = *tbl[0] * wave;
                *(f32*)(w + 0x14) = *t1;
                hw += 2;
                tbl[0] += 1;
                w += 4;
                t1 += 1;
            }
        }
        Sfx_PlayFromObject(obj, SFXTRIG_lockon3_on);
        Sfx_PlayFromObject(obj, SFXTRIG_lrope_powerup);
        break;
    case 5:
        ((ShieldState*)state)->fadeTarget = lbl_803E33AC;
        ((ShieldState*)state)->fadeRate = lbl_803E33B4;
        *(f32*)&((ShieldState*)state)->fadeMax = lbl_803E33CC;
        Sfx_StopFromObject((int)obj, SFXTRIG_lrope_powerup);
        Sfx_StopFromObject((int)obj, SFXTRIG_lockon3_on);
        break;
    case 4:
    {
        f32 fade = lbl_803E33CC;
        f32 amp;
        ((ShieldState*)state)->fadeTarget = fade;
        amp = lbl_803E33C4;
        ((ShieldState*)state)->fadeRate = amp;
        *(f32*)&((ShieldState*)state)->fadeMax = fade;
        {
            int i;
            u8* hw;
            f32* t0;
            u8* w;
            f32* t1;
            f32 k;
            i = 0;
            hw = state;
            t0 = (f32*)((char*)tbl[0] + 0x20);
            w = state;
            t1 = (f32*)((char*)tbl[0] + 0x30);
            k = lbl_803E33A8;
            for (; i < 4; i++)
            {
                f32 wave;
                f32 sum;
                *(s16*)(hw + 0x34) = -0x4000;
                wave = fcos16((u16) * (s16*)(hw + 0x34));
                sum = amp + wave;
                wave = sum * k;
                *(f32*)(w + 0x24) = *t0 * wave;
                *(f32*)(w + 0x14) = *t1;
                *(s16*)(hw + 0x3c) = (f32)(int)(i * randomGetRange(0x78, 0x7f)) + lbl_803E33C8;
                hw += 2;
                t0 += 1;
                w += 4;
                t1 += 1;
            }
        }
        Sfx_PlayFromObject(obj, SFXTRIG_lockon3_on);
        Sfx_PlayFromObject(obj, SFXTRIG_lrope_powerup);
        break;
    }
    case 6:
    {
        int i;
        u8* hw;
        f32* t0;
        u8* w;
        f32* t1;
        f32 amp;
        f32 k;
        i = 0;
        hw = state;
        t0 = (f32*)((char*)tbl[0] + 0x20);
        w = state;
        t1 = (f32*)((char*)tbl[0] + 0x30);
        amp = lbl_803E33C4;
        k = lbl_803E33A8;
        for (; i < 4; i++)
        {
            f32 wave;
            f32 sum;
            *(s16*)(hw + 0x34) = 0x4000;
            wave = fcos16((u16) * (s16*)(hw + 0x34));
            sum = amp + wave;
            wave = sum * k;
            *(f32*)(w + 0x24) = *t0 * wave;
            *(f32*)(w + 0x14) = *t1;
            hw += 2;
            t0 += 1;
            w += 4;
            t1 += 1;
        }
        break;
    }
    }
}
#pragma opt_common_subs reset

int Shield_getExtraSize(void)
{
    return 0x60;
}
int Shield_getObjectTypeId(void)
{
    return 0x0;
}

void Shield_free(GameObject* obj)
{
    void** state = (obj)->extra;
    if (state[0] != NULL)
    {
        ModelLightStruct_free(state[0]);
        state[0] = NULL;
    }
    Sfx_StopFromObject((int)obj, SFXTRIG_lrope_powerup);
    Sfx_StopFromObject((int)obj, SFXTRIG_lockon3_on);
}

typedef struct ShieldFxVec
{
    u8 pad[8];
    f32 alpha;
    f32 pos[3];
} ShieldFxVec;

void Shield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8* state = ((GameObject*)obj)->extra;
    s32 isVisible = visible;
    if (isVisible != 0)
    {
        u8 i;
        u8 j;
        s16 saved0;
        f32 savedF8;
        s16 saved2;
        s16 saved4;
        u8 hud;
        int* model;
        f32 dt;
        ShieldFxVec s;
        u8 savedB36;
        model = (int*)Obj_GetActiveModel((GameObject*)obj);
        savedF8 = ((GameObject*)obj)->anim.rootMotionScale;
        savedB36 = ((GameObject*)obj)->anim.alpha;
        saved0 = ((GameObject*)obj)->anim.rotX;
        saved2 = ((GameObject*)obj)->anim.rotY;
        saved4 = ((GameObject*)obj)->anim.rotZ;
        hud = getHudHiddenFrameCount();
        if (hud != 0)
        {
            dt = lbl_803E33AC;
        }
        else
        {
            dt = timeDelta;
        }
        if (((GameObject*)obj)->anim.seqId == SHIELD_SEQID_STAFF_MODE5)
        {
            for (i = 0; i < 4; i++)
            {
                if ((state[i + 0x5c] & 1) == 0)
                {
                    u32 k = i;
                    u32 off = k * 2;
                    ((GameObject*)obj)->anim.rotX = *(s16*)(state + off + 0x44);
                    ((GameObject*)obj)->anim.rotY = *(s16*)(state + off + 0x4c);
                    ((GameObject*)obj)->anim.rotZ = *(s16*)(state + off + 0x54);
                    *(s16*)(state + off + 0x44) = dt * lbl_803DBD78[k] + (f32) * (s16*)(state + off + 0x44);
                    *(s16*)(state + off + 0x4c) = dt * lbl_803DBD80[k] + (f32) * (s16*)(state + off + 0x4c);
                    *(s16*)(state + off + 0x54) = dt * lbl_803DBD88[k] + (f32) * (s16*)(state + off + 0x54);
                    {
                        u8* r = state + k * 4;
                        ((GameObject*)obj)->anim.rootMotionScale =
                            *(f32*)(r + 0x24) * savedF8 *
                            (((ShieldState*)state)->fadeValue / *(f32*)&((ShieldState*)state)->fadeMax);
                        *(u8*)((char*)obj + 0x37) = *(f32*)(r + 0x14) * savedB36;
                    }
                    *(u16*)((char*)model + 0x18) &= ~0x8;
                    ((void (*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5,
                                                                                           lbl_803E33C4);
                }
            }
        }
        else
        {
            i = 0;
            for (; i < 4; i++)
            {
                if ((state[i + 0x5c] & 1) == 0)
                {
                    u32 k = i;
                    u32 off = k * 2 + 0x44;
                    ((GameObject*)obj)->anim.rotX = *(s16*)(state + off);
                    *(s16*)(state + off) = dt * lbl_803DBD70[k] + (f32) * (s16*)(state + off);
                    {
                        u8* r = state + k * 4;
                        ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(r + 0x24) * savedF8;
                        *(u8*)((char*)obj + 0x37) = *(f32*)(r + 0x14) * savedB36;
                    }
                    *(u16*)((char*)model + 0x18) &= ~0x8;
                    ((void (*)(int*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5,
                                                                                           lbl_803E33C4);
                    if (hud == 0)
                    {
                        f32 cD;
                        f32 cC;
                        f32 cB;
                        f32 cA;
                        j = 0;
                        cA = lbl_803E33D8;
                        cB = lbl_803E33DC;
                        cC = lbl_803E33AC;
                        cD = lbl_803E33C4;
                        for (; j < 2; j++)
                        {
                            f32 f8v = ((GameObject*)obj)->anim.rootMotionScale;
                            s.pos[0] = cA * f8v;
                            s.pos[1] = cB * f8v;
                            s.pos[2] = cC;
                            ((GameObject*)obj)->anim.rotX += 32767;
                            vecRotateZXY(obj, s.pos);
                            s.pos[0] += ((GameObject*)obj)->anim.localPosX;
                            s.pos[1] += ((GameObject*)obj)->anim.localPosY;
                            s.pos[2] += ((GameObject*)obj)->anim.localPosZ;
                            s.alpha = cD;
                            (*gPartfxInterface)->spawnObject(obj, SHIELD_PARTFX, &s, 0x200001, -1, NULL);
                        }
                    }
                }
            }
        }
        ((GameObject*)obj)->anim.rootMotionScale = savedF8;
        ((GameObject*)obj)->anim.alpha = savedB36;
        ((GameObject*)obj)->anim.rotX = saved0;
        ((GameObject*)obj)->anim.rotY = saved2;
        ((GameObject*)obj)->anim.rotZ = saved4;
    }
}

void Shield_hitDetect(void)
{
}

void Shield_update(int* obj)
{
    f32* tbl[1];
    f32* state;

    tbl[0] = lbl_80320A28;
    state = ((GameObject*)obj)->extra;

    if (state[1] != state[2])
    {
        state[1] = state[3] * timeDelta + state[1];
        if (state[3] > lbl_803E33AC)
        {
            if (state[1] >= state[2])
            {
                state[1] = state[2];
            }
            ((ShieldState*)state)->flags0 &= ~1;
            ((ShieldState*)state)->flags1 &= ~1;
            ((ShieldState*)state)->flags2 &= ~1;
            ((ShieldState*)state)->flags3 &= ~1;
        }
        else
        {
            if (state[1] <= state[2])
            {
                state[1] = state[2];
                ((ShieldState*)state)->flags0 |= 1;
                ((ShieldState*)state)->flags1 |= 1;
                ((ShieldState*)state)->flags2 |= 1;
                ((ShieldState*)state)->flags3 |= 1;
            }
        }
    }
    if (((GameObject*)obj)->anim.seqId == SHIELD_SEQID_STAFF_MODE5)
    {
        ((GameObject*)obj)->anim.alpha = state[1] / state[4] * (f32)(s32)randomGetRange(96, 127);
    }
    else
    {
        ((GameObject*)obj)->anim.alpha = state[1] / state[4] * (f32)(s32)randomGetRange(192, 255);
    }
    Sfx_SetObjectSfxVolume((s16*)obj, SFXTRIG_lockon3_on, (s32)(lbl_803E33E8 * (state[1] / state[4])), lbl_803E33A8);
    if (((GameObject*)obj)->anim.alpha != 0)
    {
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    {
        s16* ps;
        f32* t8;
        f32* pf;
        f32* t12;
        f32* t4;
        int i;
        i = 0;
        ps = (s16*)state;
        t8 = tbl[0] + 8;
        pf = state;
        t12 = tbl[0] + 12;
        t4 = tbl[0] + 4;
        for (; i < 4; i++)
        {
            ps[26] = (f32)ps[30] * timeDelta + ps[26];
            if (((GameObject*)obj)->anim.seqId == SHIELD_SEQID_STAFF_MODE5)
            {
                f32 c = fcos16(ps[26]);
                c = c * lbl_803E33EC + lbl_803E33C4;
                pf[9] = *t8 * c;
                pf[5] = *t12;
            }
            else
            {
                f32 c = fcos16(ps[26]);
                f32 sum = lbl_803E33C4 + c;
                c = sum * lbl_803E33A8;
                pf[9] = *tbl[0] * c;
                pf[5] = *t4;
            }
            ps++;
            t8++;
            pf++;
            t12++;
            tbl[0]++;
            t4++;
        }
    }
}

void Shield_init(int* obj, void* initData)
{
    int* model = (int*)Obj_GetActiveModel((GameObject*)obj);
    ObjModel_SetPostRenderCallback((ObjModel*)model, postRenderSetAlphaBlendState);
    if (((GameObject*)obj)->anim.seqId == SHIELD_SEQID_STAFF_MODE5)
    {
        staffFn_80170380(obj, 5);
    }
    else
    {
        staffFn_80170380(obj, 7);
    }
}

void Shield_release(void)
{
}

void Shield_initialise(void)
{
}
