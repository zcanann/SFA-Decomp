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
#include "main/dll/partfx_interface.h"
#include "main/hud_visibility_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_object_volume_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/object_render.h"
#include "main/vecmath.h"
#include "main/dll/player_objects.h"
#include "main/game_object.h"
#include "main/model_light.h"
#include "main/model.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/obj_placement.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/dll_00E5_shield.h"
#include "main/dll/dll_00E2_staff_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/trig.h"

s16 lbl_803DBD70[4] = {-1024, -512, 512, 1024};
s16 lbl_803DBD78[4] = {-500, 50, 50, 200};
s16 lbl_803DBD80[4] = {50, -512, 50, 100};
s16 lbl_803DBD88[4] = {50, 50, 512, 512};

#define MODEL_LIGHT_KIND_POINT 2

/* anim.seqId of the omni_shield variant (retail OBJECTS.bin name; DLL 0xE5
 * also hosts 0x773 "fox_shield"); this variant uses staff-mode 5, otherwise
 * mode 7. */
#define SHIELD_SEQID_OMNI_SHIELD 0x836
/* shield-ring particle spawned around the object in the deflect loop */
#define SHIELD_PARTFX 2028

typedef struct ShieldState
{
    ModelLightStruct* light;
    f32 fadeValue;  /* 0x4: current shield fade, advanced toward fadeTarget by fadeRate*dt */
    f32 fadeTarget; /* 0x8 */
    f32 fadeRate;   /* 0xC */
    f32 fadeMax;    /* 0x10: divisor for alpha (fadeValue/fadeMax) */
    /* Per-segment parameters for the four ring segments, laid out
     * structure-of-arrays (each array indexed by segment 0..3). */
    f32 segScale[4]; /* 0x14: per-segment scale (feeds anim.rootMotionScale) */
    f32 segAlpha[4]; /* 0x24: per-segment alpha factor (feeds anim.alpha) */
    s16 segPhase[4]; /* 0x34: fcos16 wobble phase, advanced by segRate*dt */
    s16 segSeed[4];  /* 0x3C: random per-segment cosine seed */
    s16 segRotX[4];  /* 0x44: per-segment X rotation */
    s16 segRotY[4];  /* 0x4C: per-segment Y rotation */
    s16 segRotZ[4];  /* 0x54: per-segment Z rotation */
    u8 segmentFlags[4]; /* 0x5C: bit0 marks a fully faded segment */
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
STATIC_ASSERT(offsetof(ShieldState, segmentFlags) == 0x5C);
STATIC_ASSERT(sizeof(ShieldState) == 0x60);

extern f32 lbl_803E33A8;
extern f32 lbl_803E33AC;
extern f32 lbl_803E33E8;
extern f32 lbl_803E33EC;
extern f32 lbl_803E33D8;
extern f32 lbl_803E33DC;

f32 lbl_80320A28[] = {
    0.5f,
    0.55f,
    0.65f,
    0.7f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.3f,
    0.3f,
    0.3f,
    0.3f,
};

GameObject* shield_spawnOmniShield(GameObject* obj, f32 fv)
{
    void* alloc;
    GameObject* new_obj;
    if ((u8)Obj_IsLoadingLocked() == 0)
        return NULL;
    alloc = (void*)Obj_AllocObjectSetup(36, SHIELD_SEQID_OMNI_SHIELD);
    ((ObjPlacement*)alloc)->posX = obj->anim.worldPosX;
    ((ObjPlacement*)alloc)->posY = obj->anim.worldPosY;
    ((ObjPlacement*)alloc)->posZ = obj->anim.worldPosZ;
    ((ObjPlacement*)alloc)->color[0] = 1;
    ((ObjPlacement*)alloc)->color[1] = 1;
    ((ObjPlacement*)alloc)->color[3] = 255;
    new_obj = Obj_SetupObject((ObjPlacement*)alloc, 5, -1, -1, 0);
    if (new_obj != NULL)
    {
        new_obj->anim.rootMotionScale = fv;
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

void staffFn_80170380(GameObject* obj, u8 cmd)
{
    f32* segmentTable[1];
    ShieldState* state;
    void* segmentData;
    GameObject* player;
    GameObject* glow;
    segmentTable[0] = lbl_80320A28;
    state = obj->extra;
    segmentData = state;
    player = Obj_GetPlayerObject();
    glow = NULL;
    if (player != NULL)
    {
        glow = Player_GetStaffObject(player);
    }
    switch (cmd)
    {
    case 7:
        if (glow != NULL)
        {
            staffSetGlow(glow, 7, 0);
        }
        if (state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 0, 0.5f);
        }
        {
            f32 fade = 0.0f;
            state->fadeTarget = fade;
            state->fadeRate = fade;
            state->fadeMax = fade;
            state->fadeValue = fade;
        }
        state->segmentFlags[0] |= 1;
        state->segmentFlags[1] |= 1;
        state->segmentFlags[2] |= 1;
        state->segmentFlags[3] |= 1;
        break;
    case 0:
        if (state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 0, 0.5f);
        }
        if (state->fadeTarget != 0.0f)
        {
            f32 fade = 2.0f;
            state->fadeMax = fade;
            state->fadeValue = fade;
            if (glow != NULL)
            {
                staffSetGlow(glow, 7, 0);
            }
        }
        state->fadeTarget = 0.0f;
        state->fadeRate = -1.0f;
        Sfx_StopFromObject((u32)obj, SFXTRIG_lrope_powerup);
        Sfx_StopFromObject((u32)obj, SFXTRIG_lockon3_on);
        break;
    case 1:
        if (state->fadeTarget == 0.0f)
        {
            if (glow != NULL)
            {
                staffSetGlow(glow, 7, 8);
            }
            if (state->light == NULL)
            {
                state->light = objCreateLight(NULL, 1);
            }
            if (state->light != NULL)
            {
                modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
                modelLightStruct_setPosition(state->light, obj->anim.localPosX,
                                             obj->anim.localPosY - 15.0f,
                                             obj->anim.localPosZ);
                modelLightStruct_setDiffuseColor(state->light, 0, 255, 255, 255);
                modelLightStruct_setSpecularColor(state->light, 0, 255, 255, 255);
                modelLightStruct_setDistanceAttenuation(state->light, 40.0f, 55.0f);
                lightSetField4D(state->light, 1);
                modelLightStruct_setEnabled(state->light, 1, 0.0f);
                modelLightStruct_startColorFade(state->light, 0, 0);
                modelLightStruct_setAffectsAabbLightSelection(state->light, 1);
            }
            {
                f32 fade = 0.0f;
                if (fade == state->fadeTarget)
                {
                    state->fadeMax = 2.0f;
                    state->fadeValue = fade;
                }
            }
            state->fadeTarget = 2.0f;
            {
                f32 amp;
                f32 k;
                s16* phaseCursor;
                f32* valueCursor;
                f32* segmentScaleCursor;
                int i;
                amp = 1.0f;
                state->fadeRate = amp;
                i = 0;
                phaseCursor = segmentData;
                valueCursor = segmentData;
                segmentScaleCursor = segmentTable[0] + 4;
                k = 0.5f;
                for (; i < 4; i++)
                {
                    f32 wave;
                    f32 sum;
                    phaseCursor[0x1A] = -0x4000;
                    wave = fcos16((u16)phaseCursor[0x1A]);
                    sum = amp + wave;
                    wave = sum * k;
                    valueCursor[9] = *segmentTable[0] * wave;
                    valueCursor[5] = *segmentScaleCursor;
                    phaseCursor[0x1E] = (f32)(int)(i * randomGetRange(0x78, 0x7f)) + 136.0f;
                    phaseCursor += 1;
                    segmentTable[0] += 1;
                    valueCursor += 1;
                    segmentScaleCursor += 1;
                }
            }
        Sfx_PlayFromObject((u32)obj, SFXTRIG_lrope_powerup);
        Sfx_PlayFromObject((u32)obj, SFXTRIG_lockon3_on);
        }
        break;
    case 2:
        if (glow != NULL)
        {
            staffSetGlow(glow, 7, 0);
        }
        if (state->fadeTarget != 0.0f)
        {
            state->fadeMax = 60.0f;
        }
        state->fadeTarget = 0.0f;
        state->fadeRate = -1.0f;
        if (state->light != NULL)
        {
            modelLightStruct_setEnabled(state->light, 0, 0.5f);
        }
        Sfx_StopFromObject((u32)obj, SFXTRIG_lrope_powerup);
        Sfx_StopFromObject((u32)obj, SFXTRIG_lockon3_on);
        break;
    case 3:
        if (glow != NULL)
        {
            staffSetGlow(glow, 7, 8);
        }
        if (state->light == NULL)
        {
            state->light = objCreateLight(NULL, 1);
        }
        if (state->light != NULL)
        {
            modelLightStruct_setLightKind(state->light, MODEL_LIGHT_KIND_POINT);
            modelLightStruct_setPosition(state->light, obj->anim.localPosX,
                                         obj->anim.localPosY - 15.0f,
                                         obj->anim.localPosZ);
            modelLightStruct_setDiffuseColor(state->light, 0, 255, 255, 255);
            modelLightStruct_setSpecularColor(state->light, 0, 255, 255, 255);
            modelLightStruct_setDistanceAttenuation(state->light, 40.0f, 55.0f);
            lightSetField4D(state->light, 1);
            modelLightStruct_setEnabled(state->light, 1, 0.0f);
            modelLightStruct_startColorFade(state->light, 0, 0);
            modelLightStruct_setAffectsAabbLightSelection(state->light, 1);
        }
        if (state->fadeTarget == 0.0f)
        {
            state->fadeMax = 60.0f;
        }
        state->fadeTarget = 60.0f;
        {
            int i;
            s16* phaseCursor;
            f32* valueCursor;
            f32* segmentScaleCursor;
            f32 k;
            f32 amp;
            amp = 1.0f;
            state->fadeRate = amp;
            i = 0;
            phaseCursor = segmentData;
            valueCursor = segmentData;
            segmentScaleCursor = segmentTable[0] + 4;
            k = 0.5f;
            for (; i < 4; i++)
            {
                f32 wave;
                f32 sum;
                phaseCursor[0x1A] = 0;
                wave = fcos16((u16)phaseCursor[0x1A]);
                sum = amp + wave;
                wave = sum * k;
                valueCursor[9] = *segmentTable[0] * wave;
                valueCursor[5] = *segmentScaleCursor;
                phaseCursor += 1;
                segmentTable[0] += 1;
                valueCursor += 1;
                segmentScaleCursor += 1;
            }
        }
        Sfx_PlayFromObject((u32)obj, SFXTRIG_lockon3_on);
        Sfx_PlayFromObject((u32)obj, SFXTRIG_lrope_powerup);
        break;
    case 5:
        state->fadeTarget = 0.0f;
        state->fadeRate = -1.0f;
        state->fadeMax = 60.0f;
        Sfx_StopFromObject((u32)obj, SFXTRIG_lrope_powerup);
        Sfx_StopFromObject((u32)obj, SFXTRIG_lockon3_on);
        break;
    case 4:
    {
        f32 fade = 60.0f;
        f32 amp;
        state->fadeTarget = fade;
        amp = 1.0f;
        state->fadeRate = amp;
        state->fadeMax = fade;
        {
            int i;
            s16* phaseCursor;
            f32* segmentAlphaCursor;
            f32* valueCursor;
            f32* segmentScaleCursor;
            f32 k;
            i = 0;
            phaseCursor = segmentData;
            segmentAlphaCursor = segmentTable[0] + 8;
            valueCursor = segmentData;
            segmentScaleCursor = segmentTable[0] + 12;
            k = 0.5f;
            for (; i < 4; i++)
            {
                f32 wave;
                f32 sum;
                phaseCursor[0x1A] = -0x4000;
                wave = fcos16((u16)phaseCursor[0x1A]);
                sum = amp + wave;
                wave = sum * k;
                valueCursor[9] = *segmentAlphaCursor * wave;
                valueCursor[5] = *segmentScaleCursor;
                phaseCursor[0x1E] = (f32)(int)(i * randomGetRange(0x78, 0x7f)) + 136.0f;
                phaseCursor += 1;
                segmentAlphaCursor += 1;
                valueCursor += 1;
                segmentScaleCursor += 1;
            }
        }
        Sfx_PlayFromObject((u32)obj, SFXTRIG_lockon3_on);
        Sfx_PlayFromObject((u32)obj, SFXTRIG_lrope_powerup);
        break;
    }
    case 6:
    {
        int i;
        s16* phaseCursor;
        f32* segmentAlphaCursor;
        f32* valueCursor;
        f32* segmentScaleCursor;
        f32 amp;
        f32 k;
        i = 0;
        phaseCursor = segmentData;
        segmentAlphaCursor = segmentTable[0] + 8;
        valueCursor = segmentData;
        segmentScaleCursor = segmentTable[0] + 12;
        amp = 1.0f;
        k = 0.5f;
        for (; i < 4; i++)
        {
            f32 wave;
            f32 sum;
            phaseCursor[0x1A] = 0x4000;
            wave = fcos16((u16)phaseCursor[0x1A]);
            sum = amp + wave;
            wave = sum * k;
            valueCursor[9] = *segmentAlphaCursor * wave;
            valueCursor[5] = *segmentScaleCursor;
            phaseCursor += 1;
            segmentAlphaCursor += 1;
            valueCursor += 1;
            segmentScaleCursor += 1;
        }
        break;
    }
    }
}

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
    ShieldState* state = obj->extra;
    if (state->light != NULL)
    {
        ModelLightStruct_free(state->light);
        state->light = NULL;
    }
    Sfx_StopFromObject((u32)obj, SFXTRIG_lrope_powerup);
    Sfx_StopFromObject((u32)obj, SFXTRIG_lockon3_on);
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
        if (((GameObject*)obj)->anim.seqId == SHIELD_SEQID_OMNI_SHIELD)
        {
            for (i = 0; i < 4; i++)
            {
                if ((state[i + 0x5c] & 1) == 0)
                {
                    u32 k = i;
                    ((GameObject*)obj)->anim.rotX = ((ShieldState*)state)->segRotX[k];
                    ((GameObject*)obj)->anim.rotY = ((ShieldState*)state)->segRotY[k];
                    ((GameObject*)obj)->anim.rotZ = ((ShieldState*)state)->segRotZ[k];
                    ((ShieldState*)state)->segRotX[k] = dt * lbl_803DBD78[k] + (f32)((ShieldState*)state)->segRotX[k];
                    ((ShieldState*)state)->segRotY[k] = dt * lbl_803DBD80[k] + (f32)((ShieldState*)state)->segRotY[k];
                    ((ShieldState*)state)->segRotZ[k] = dt * lbl_803DBD88[k] + (f32)((ShieldState*)state)->segRotZ[k];
                    {
                        ((GameObject*)obj)->anim.rootMotionScale =
                            ((ShieldState*)state)->segAlpha[k] * savedF8 *
                            (((ShieldState*)state)->fadeValue / ((ShieldState*)state)->fadeMax);
                        ((GameObject*)obj)->anim.renderAlpha = ((ShieldState*)state)->segScale[k] * savedB36;
                    }
                    ((ObjModel*)model)->bufferFlags &= ~0x8;
                    objRenderModelAndHitVolumes((GameObject*)obj, p2, p3, p4, p5, 1.0f);
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
                    ((GameObject*)obj)->anim.rotX = ((ShieldState*)state)->segRotX[k];
                    ((ShieldState*)state)->segRotX[k] = dt * lbl_803DBD70[k] + (f32)((ShieldState*)state)->segRotX[k];
                    {
                        ((GameObject*)obj)->anim.rootMotionScale = ((ShieldState*)state)->segAlpha[k] * savedF8;
                        ((GameObject*)obj)->anim.renderAlpha = ((ShieldState*)state)->segScale[k] * savedB36;
                    }
                    ((ObjModel*)model)->bufferFlags &= ~0x8;
                    objRenderModelAndHitVolumes((GameObject*)obj, p2, p3, p4, p5, 1.0f);
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
                        cD = 1.0f;
                        for (; j < 2; j++)
                        {
                            f32 f8v = ((GameObject*)obj)->anim.rootMotionScale;
                            s.pos[0] = cA * f8v;
                            s.pos[1] = cB * f8v;
                            s.pos[2] = cC;
                            ((GameObject*)obj)->anim.rotX += 32767;
                            vecRotateZXY(&((GameObject*)obj)->anim.rotX, s.pos);
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
            ((ShieldState*)state)->segmentFlags[0] &= ~1;
            ((ShieldState*)state)->segmentFlags[1] &= ~1;
            ((ShieldState*)state)->segmentFlags[2] &= ~1;
            ((ShieldState*)state)->segmentFlags[3] &= ~1;
        }
        else
        {
            if (state[1] <= state[2])
            {
                state[1] = state[2];
                ((ShieldState*)state)->segmentFlags[0] |= 1;
                ((ShieldState*)state)->segmentFlags[1] |= 1;
                ((ShieldState*)state)->segmentFlags[2] |= 1;
                ((ShieldState*)state)->segmentFlags[3] |= 1;
            }
        }
    }
    if (((GameObject*)obj)->anim.seqId == SHIELD_SEQID_OMNI_SHIELD)
    {
        ((GameObject*)obj)->anim.alpha = state[1] / state[4] * (f32)(s32)randomGetRange(96, 127);
    }
    else
    {
        ((GameObject*)obj)->anim.alpha = state[1] / state[4] * (f32)(s32)randomGetRange(192, 255);
    }
    Sfx_SetObjectSfxVolume((u32)obj, SFXTRIG_lockon3_on, lbl_803E33E8 * (state[1] / state[4]), lbl_803E33A8);
    if (((GameObject*)obj)->anim.alpha != 0)
    {
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    }
    else
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    }
    {
        int i;
        f32* t12;
        f32* t4;
        s16* ps;
        f32* t8;
        f32* pf;
        i = 0;
        ps = (s16*)state;
        t8 = tbl[0] + 8;
        pf = state;
        t12 = tbl[0] + 12;
        t4 = tbl[0] + 4;
        for (; i < 4; i++)
        {
            ps[26] = (f32)ps[30] * timeDelta + ps[26];
            if (((GameObject*)obj)->anim.seqId == SHIELD_SEQID_OMNI_SHIELD)
            {
                f32 c = fcos16((u16)ps[26]);
                c = c * lbl_803E33EC + 1.0f;
                pf[9] = *t8 * c;
                pf[5] = *t12;
            }
            else
            {
                f32 c = fcos16((u16)ps[26]);
                f32 sum = 1.0f + c;
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
    if (((GameObject*)obj)->anim.seqId == SHIELD_SEQID_OMNI_SHIELD)
    {
        staffFn_80170380((GameObject*)obj, 5);
    }
    else
    {
        staffFn_80170380((GameObject*)obj, 7);
    }
}

void Shield_release(void)
{
}

void Shield_initialise(void)
{
}
