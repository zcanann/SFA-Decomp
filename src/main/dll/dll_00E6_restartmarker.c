/* DLL 0x00E6 (restartmarker) — Restart marker object [0x801713D8-0x801713FC). */
#include "main/dll/xyzanimator.h"

/* Particle/emitter system embedded in the restart-marker object's extra block
 * (single owner: FUN_8016e8cc's fade tick). The system holds 3 fading emitters
 * followed by a dedicated "special" emitter pointer; each emitter owns a packed
 * particle ring walked in steps of 2 half-slots (particle stride 0x28). */
typedef struct RMParticle {
    u8 pad00[0xc];
    f32 unkC;   /* +0x0c: per-particle scalar fed into the fade ramp */
    s16 levelA; /* +0x10: primary fade level, clamped 0..0xff */
    u8 pad12[0x24 - 0x12];
    s16 levelB; /* +0x24: mirror of levelA */
    u8 pad26[0x28 - 0x26];
} RMParticle;

typedef struct RMEmitter {
    RMParticle* particles; /* +0x00: base of this emitter's particle buffer */
    u8 pad04[0xc - 0x4];
    u16 startIdx; /* +0x0c: live-range start (half-slot units) */
    u16 count;    /* +0x0e: live-range end (half-slot units) */
    u8 pad10[0x12 - 0x10];
    s16 liveCount; /* +0x12: remaining live half-slots */
    u8 flags;      /* +0x14: bit 0x2 = active */
    u8 pad15[0x18 - 0x15];
} RMEmitter;

typedef struct RMParticleSystem {
    RMEmitter emitters[3]; /* +0x00: the three fading emitters */
    RMEmitter* specialEmitter; /* +0x48: dedicated emitter (not fade-cleared) */
    u8 pad4C[0x50 - 0x4C];
    int unk50; /* +0x50: count, converted to float for FUN_8002fc3c */
    u8 pad54[0x98 - 0x54];
    int unk98; /* +0x98: count, converted to float in the fade ramp */
} RMParticleSystem;

extern u32 ObjHitbox_SetSphereRadius();

void mikabomb_hitDetect(void);

void mikabomb_free(int obj, int mode);

int mikabomb_getExtraSize(void);
int mikabomb_getObjectTypeId(void);

extern void objRenderFn_8003b8f4(f32);
extern int kaldachompspit_getObjectTypeId(void);
extern int kaldachompspit_getExtraSize(void);

ObjectDescriptor gKaldaChompSpitObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)kaldachompspit_initialise,
    (ObjectDescriptorCallback)kaldachompspit_release,
    0,
    (ObjectDescriptorCallback)kaldachompspit_init,
    (ObjectDescriptorCallback)kaldachompspit_update,
    (ObjectDescriptorCallback)kaldachompspit_hitDetect,
    (ObjectDescriptorCallback)kaldachompspit_render,
    (ObjectDescriptorCallback)kaldachompspit_free,
    (ObjectDescriptorCallback)kaldachompspit_getObjectTypeId,
    kaldachompspit_getExtraSize,
};

ObjectDescriptor gPinPonSpikeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pinponspike_initialise,
    (ObjectDescriptorCallback)pinponspike_release,
    0,
    (ObjectDescriptorCallback)pinponspike_init,
    (ObjectDescriptorCallback)pinponspike_update,
    (ObjectDescriptorCallback)pinponspike_hitDetect,
    (ObjectDescriptorCallback)pinponspike_render,
    (ObjectDescriptorCallback)pinponspike_free,
    (ObjectDescriptorCallback)pinponspike_getObjectTypeId,
    pinponspike_getExtraSize,
};

ObjectDescriptor gPollenObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pollen_initialise,
    (ObjectDescriptorCallback)pollen_release,
    0,
    (ObjectDescriptorCallback)pollen_init,
    (ObjectDescriptorCallback)pollen_update,
    (ObjectDescriptorCallback)pollen_hitDetect,
    (ObjectDescriptorCallback)pollen_render,
    (ObjectDescriptorCallback)pollen_free,
    (ObjectDescriptorCallback)pollen_getObjectTypeId,
    pollen_getExtraSize,
};

PollenFragmentConfig lbl_80320538 = {
    0x0000,
    0x049F,
    0x00B9,
    0x04BA,
    0x04BA,
    -1,
    0.2f,
    0x0000,
    0xC000,
};

PollenFragmentConfig lbl_8032054C = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x7000,
};

PollenFragmentConfig lbl_80320560 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x2000,
};

PollenFragmentConfig lbl_80320574 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    -1,
    0.2f,
    0x0000,
    0x2000,
};

PollenFragmentConfig lbl_80320588 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x3000,
};

PollenFragmentConfig* lbl_8032059C[] = {
    &lbl_80320538,
    &lbl_8032054C,
    &lbl_80320560,
    &lbl_80320574,
    &lbl_80320588,
};

ObjectDescriptor gPollenFragmentObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pollenfragment_initialise,
    (ObjectDescriptorCallback)pollenfragment_release,
    0,
    (ObjectDescriptorCallback)pollenfragment_init,
    (ObjectDescriptorCallback)pollenfragment_update,
    (ObjectDescriptorCallback)pollenfragment_hitDetect,
    (ObjectDescriptorCallback)pollenfragment_render,
    (ObjectDescriptorCallback)pollenfragment_free,
    (ObjectDescriptorCallback)pollenfragment_getObjectTypeId,
    pollenfragment_getExtraSize,
};

/* includes for the drift-recovered functions below; kept mid-file because the
   top-section descriptors above resolve without them */
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/genprops.h"
#include "main/dll_000A_expgfx.h"
#include "main/objhits.h"
#include "main/objprint.h"
#include "main/dll/dll_00C8_depthoffieldpoint.h"
#include "main/dll/dll_00E3_fireball.h"
#include "main/dll/dll_00E4_flamethrowerspe.h"
#include "main/engine_shared.h"

#define RESTARTMARKER_OBJFLAG_HIDDEN 0x4000
extern u32 FUN_80006810();
extern u64 FUN_80006824();
extern u32 FUN_8001753c();
extern u32 FUN_80017588();
extern u32 FUN_8001759c();
extern u32 FUN_800175b0();
extern u32 FUN_800175bc();
extern u32 FUN_800175cc();
extern u32 FUN_800175d0();
extern u32 FUN_800175d8();
extern u32 FUN_800175ec();
extern void* FUN_80017624();
extern u32 FUN_80017688();
extern u32 FUN_80017690();
extern u64 FUN_80017698();
extern int FUN_80017a54();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern u32 FUN_80017ac8();
extern u64 FUN_8002fc3c();
extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void ObjGroup_AddObject(u32 obj, int group);
extern u32 FUN_800810f8();
extern u32 FUN_80081118();
extern u64 FUN_800e842c();
extern int FUN_80286838();
extern u32 FUN_80286884();
extern u32 fcos16Precise();
extern u32 FUN_80294c48();
extern u32 FUN_80294c60();
extern int FUN_80294cf8();
extern int FUN_80294d10();
extern u32 FUN_80294d60();
extern u32 FUN_80294d6c();
extern u32 DAT_80321678;
extern int DAT_80321688;
extern u32 DAT_80321698;
extern int DAT_803216a8;
extern u32 DAT_803ad324;
extern u32 DAT_803ad328;
extern u32 DAT_803ad32c;
extern u32 DAT_803ad330;
extern u32 DAT_803ad334;
extern u32 DAT_803ad338;
extern f64 DOUBLE_803e4068;
extern f32 lbl_803DC074;
extern f32 lbl_803E3F20;
extern f32 lbl_803E3F24;
extern f32 lbl_803E3F28;
extern f32 lbl_803E3F2C;
extern f32 lbl_803E3F30;
extern f32 lbl_803E3F34;
extern f32 lbl_803E3F38;
extern f32 lbl_803E3F3C;
extern f32 lbl_803E3F40;
extern f32 lbl_803E3F44;
extern f32 lbl_803E3F48;
extern f32 lbl_803E3F4C;
extern f32 lbl_803E3F50;
extern f32 lbl_803E3F54;
extern f32 lbl_803E3F58;
extern f32 lbl_803E3F5C;
extern f32 lbl_803E3F60;
extern f32 lbl_803E3F64;
extern f32 lbl_803E3F68;
extern f32 lbl_803E3F6C;
extern f32 lbl_803E3F70;
extern f32 lbl_803E3F74;
extern f32 lbl_803E3F78;
extern f32 lbl_803E3F7C;
extern f32 lbl_803E3F80;
extern f32 lbl_803E3F84;
extern f32 lbl_803E3F88;
extern f32 lbl_803E3F8C;
extern f32 lbl_803E3FA4;
extern f32 lbl_803E3FA8;
extern f32 lbl_803E3FC4;
extern f32 lbl_803E4040;
extern f32 lbl_803E4044;
extern f32 lbl_803E4048;
extern f32 lbl_803E404C;
extern f32 lbl_803E4050;
extern f32 lbl_803E4054;
extern f32 lbl_803E4058;
extern f32 lbl_803E405C;
extern f32 lbl_803E4060;
extern f32 lbl_803E4064;
extern f32 lbl_803E40E8;
extern f32 lbl_803E40EC;
extern f32 lbl_803E3420;
extern void gcbaddieshield_update(int* obj);








extern void shield_update(int* obj);
extern void dll_F7_update(int* obj);
extern void dll_F7_init(int* obj, int* params);

void staticCamera_free(int obj)
{
    ObjGroup_RemoveObject(obj, 7);
}

void staticCamera_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(obj);
    }
}

void staticCamera_init(short* obj, int placement, int flag)
{
    u8* colorState;

    *obj = -*(short*)(placement + 0x1c);
    obj[1] = -*(short*)(placement + 0x1e);
    obj[2] = -*(short*)(placement + 0x20);
    colorState = *(u8**)(obj + 0x5c);
    *colorState = *(u8*)(placement + 0x19);
    *(float*)(colorState + 4) =
        (float)((double)(u32) * (u8*)(placement + 0x1a));
    colorState[1] = 0;
    if (flag == 0)
    {
        ObjGroup_AddObject((int)obj, 7);
    }
}

void FUN_8016d188(int obj, int ownerObj)
{
    float intensity;
    int scratch2;
    u32 useAltTex;
    int amount;
    double spawnScale;
    int ownerXform;
    float progress;
    int seqId;
    u16 spawnParam[3];
    short frameCount;
    float spawnAlpha;
    u16 spawnArgs;
    u16 spawnArgsB;
    u16 spawnArgsC;
    short frames;
    float alpha;
    float yOffset;
    float scale;
    u32 ownerColB;
    s64 amountLL;

    amount = *(int*)&((GameObject*)obj)->extra;
    if ((obj != 0) && (ownerObj != 0))
    {
        if (*(char*)(amount + 0xba) != '\0')
        {
            scratch2 = FUN_80294d10(ownerObj);
            if (scratch2 == 0)
            {
                progress = lbl_803E3F24;
                intensity = lbl_803E3F28;
            }
            else
            {
                progress = lbl_803E3F20;
                intensity = lbl_803E3F20;
            }
            if (*(u8*)(amount + 0xbb) == 7)
            {
                spawnScale = (double)lbl_803E3F2C;
                amountLL = (s64)(int)(lbl_803E3F30 * intensity);
                FUN_800810f8(spawnScale, spawnScale, spawnScale, (double)(lbl_803E3F34 * progress), obj, 7,
                             (u32) * (u8*)(amount + 0xba), 1, (int)(lbl_803E3F30 * intensity), 0, 0);
            }
            else
            {
                spawnScale = (double)lbl_803E3F20;
                amountLL = (s64)(int)(lbl_803E3F30 * intensity);
                FUN_800810f8(spawnScale, spawnScale, spawnScale, (double)(lbl_803E3F34 * progress), obj,
                             (u32) * (u8*)(amount + 0xbb), (u32) * (u8*)(amount + 0xba), 1,
                             (int)(lbl_803E3F30 * intensity), 0, 0);
            }
        }
        FUN_80294c60(ownerObj, &seqId, &progress);
        spawnArgs = 0;
        spawnArgsB = 0;
        spawnArgsC = 0;
        alpha = lbl_803E3F20;
        if (seqId == 0x87)
        {
            amount = (int)(lbl_803E3F38 * (progress / lbl_803E3F30));
            amountLL = (s64)amount;
            frames = 0x15 - amount;
            yOffset = lbl_803E3F3C * (progress / lbl_803E3F40 - lbl_803E3F2C);
            spawnArgs = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            frames = 9;
            alpha = lbl_803E3F48 * (progress / lbl_803E3F40) + lbl_803E3F44;
            scale = lbl_803E3F4C;
            spawnArgs = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
        }
        else if (seqId < 0x87)
        {
            if (seqId == 0x7f)
            {
                alpha = lbl_803E3F58;
                frames = 10;
                scale = lbl_803E3F54;
                yOffset = lbl_803E3F50;
                spawnArgs = 0xc0e;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
            }
            else if (seqId < 0x7f)
            {
                if ((seqId == 0x43) && (lbl_803E3F4C < progress))
                {
                    amount = (int)(lbl_803E3F38 * (progress / lbl_803E3F30));
                    amountLL = (s64)amount;
                    frames = amount + 6;
                    yOffset = lbl_803E3F3C * (progress / lbl_803E3F40 - lbl_803E3F2C);
                    spawnArgs = 0xc94;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b4, &spawnArgs, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b4, &spawnArgs, 2, -1, NULL);
                    frames = 9;
                    alpha = lbl_803E3F48 * (progress / lbl_803E3F40) + lbl_803E3F44;
                    scale = lbl_803E3F4C;
                    spawnArgs = 0xc0e;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
                }
            }
            else if (seqId == 0x85)
            {
                if (lbl_803E3F4C < progress)
                {
                    useAltTex = FUN_80017690(0xc55);
                    if (useAltTex == 0)
                    {
                        intensity = progress / lbl_803E3F40;
                        amount = (int)(lbl_803E3F38 * intensity);
                        frames = amount;
                        spawnArgs = 0xc94;
                    }
                    else
                    {
                        intensity = progress / lbl_803E3F50;
                        amount = (int)(lbl_803E3F38 * intensity);
                        frames = amount;
                        spawnArgs = 0xc75;
                    }
                    amountLL = (s64)amount;
                    yOffset = lbl_803E3F5C * (lbl_803E3F28 - intensity);
                    frames = 0x15 - frames;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
                    frames = 9;
                    useAltTex = FUN_80017690(0xc55);
                    if (useAltTex == 0)
                    {
                        spawnArgs = 0xc0e;
                        intensity = lbl_803E3F40;
                    }
                    else
                    {
                        spawnArgs = 0xc75;
                        intensity = lbl_803E3F50;
                    }
                    alpha = lbl_803E3F48 * (progress / intensity) + lbl_803E3F44;
                    scale = lbl_803E3F4C;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
                }
            }
            else if (0x84 < seqId)
            {
                useAltTex = FUN_80017690(0xc55);
                if (useAltTex == 0)
                {
                    spawnArgs = 0xc0e;
                }
                else
                {
                    spawnArgs = 0xc75;
                }
                intensity = *(float*)(ownerObj + 0x98);
                if (lbl_803E3F68 <= intensity)
                {
                    if (intensity < lbl_803E3F70)
                    {
                        yOffset = lbl_803E3F5C * (lbl_803E3F74 * (intensity - lbl_803E3F68) - lbl_803E3F2C);
                        frames = 9;
                        alpha = lbl_803E3F20;
                        scale = lbl_803E3F4C;
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
                    }
                }
                else
                {
                    yOffset = lbl_803E3F6C;
                    frames = 9;
                    alpha = lbl_803E3F20;
                    scale = lbl_803E3F4C;
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
                }
            }
        }
        else if (seqId == 0x468)
        {
            if (lbl_803E3F4C < progress)
            {
                amount = (int)(lbl_803E3F38 * (progress / lbl_803E3F60));
                amountLL = (s64)amount;
                frameCount = 0x15 - amount;
                spawnParam[0] = 0xc95;
                FUN_80294c48(*(int*)&((GameObject*)obj)->ownerObj, &ownerXform);
                yOffset = *(float*)(ownerXform + 0xc);
                scale = *(float*)(ownerXform + 0x10);
                ownerColB = *(u32*)(ownerXform + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &spawnArgs,
                                                 0x200001, -1, spawnParam);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &spawnArgs,
                                                 0x200001, -1, spawnParam);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &spawnArgs,
                                                 0x200001, -1, spawnParam);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7b9, &spawnArgs,
                                                 0x200001, -1, spawnParam);
                frameCount = 9;
                spawnParam[0] = 0xc95;
                spawnAlpha = lbl_803E3F64 * (progress / lbl_803E3F60) + lbl_803E3F44;
                yOffset = *(float*)(ownerXform + 0xc);
                scale = *(float*)(ownerXform + 0x10);
                ownerColB = *(u32*)(ownerXform + 0x14);
                (*gPartfxInterface)->spawnObject((void*)*(int*)&((GameObject*)obj)->ownerObj, 0x7ba, &spawnArgs,
                                                 0x200001, -1, spawnParam);
            }
        }
        else if (seqId < 0x468)
        {
            if (seqId < 0x89)
            {
                frames = 0x23;
                scale = lbl_803E3F4C;
                yOffset = lbl_803E3F50;
                spawnArgs = 0xc0e;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
                frames = 0x12;
                scale = lbl_803E3F54;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
            }
        }
        else if ((seqId == 0x46f) && (lbl_803E3F4C < progress))
        {
            amount = (int)(lbl_803E3F38 * (progress / lbl_803E3F60));
            amountLL = (s64)amount;
            frames = 0x15 - amount;
            yOffset = lbl_803E3F5C * (lbl_803E3F28 - progress / lbl_803E3F60);
            spawnArgs = 0xc94;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b2, &spawnArgs, 2, -1, NULL);
            frames = 9;
            alpha = lbl_803E3F48 * (progress / lbl_803E3F60) + lbl_803E3F44;
            scale = lbl_803E3F4C;
            spawnArgs = 0xc0e;
            (*gPartfxInterface)->spawnObject((void*)obj, 0x7b3, &spawnArgs, 2, -1, NULL);
        }
    }
    return;
}

void FUN_8016d994(int obj, u8 typeId, u8 flag)
{
    int extra;

    extra = *(int*)&((GameObject*)obj)->extra;
    *(u8*)(extra + 0xbb) = typeId;
    *(u8*)(extra + 0xba) = flag;
    return;
}

void FUN_8016e8cc(u64 param_1, u64 param_2, double param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8,
                  int obj)
{
    short level;
    int scratch;
    RMEmitter* emitter;
    u32 partIdx;
    RMParticle* part;
    RMParticleSystem* extra;
    double computed;
    double clamped;

    extra = (RMParticleSystem*)((GameObject*)obj)->extra;
    scratch = FUN_80017a54(obj);
    *(u16*)(scratch + 0x18) = *(u16*)(scratch + 0x18) & ~0x8;
    FUN_8002fc3c((double)(float)extra->unk50, (double)lbl_803DC074);
    scratch = 3;
    emitter = extra->emitters;
    do
    {
        if ((emitter->flags & 2) != 0)
        {
            partIdx = (u32)emitter->startIdx;
            part = (RMParticle*)((char*)emitter->particles + partIdx * 0x14);
            for (; partIdx < (int)(u32)emitter->count; partIdx = partIdx + 2)
            {
                if (emitter == extra->specialEmitter)
                {
                    param_3 = (double)lbl_803E3F8C;
                    computed = (double)(float)(param_3 *
                        (double)((lbl_803E3FA4 * (float)extra->unk98 -
                            part->unkC) * lbl_803E3FA8));
                    clamped = (double)lbl_803E3F4C;
                    if ((clamped <= computed) && (clamped = computed, param_3 < computed))
                    {
                        clamped = param_3;
                    }
                    part->levelA = (short)(int)(param_3 - clamped);
                    *(u16*)&part->levelB = *(u16*)&part->levelA;
                }
                else
                {
                    param_3 = (double)lbl_803E3FC4;
                    part->levelA =
                        (short)(int)-(float)(param_3 * (double)lbl_803DC074 -
                            (double)(f32)(s32)((int)part->levelA));
                    *(u16*)&part->levelB = *(u16*)&part->levelA;
                }
                level = part->levelA;
                if (level < 0)
                {
                    level = 0;
                }
                else if (0xff < level)
                {
                    level = 0xff;
                }
                part->levelA = level;
                level = part->levelB;
                if (level < 0)
                {
                    level = 0;
                }
                else if (0xff < level)
                {
                    level = 0xff;
                }
                part->levelB = level;
                if ((part->levelA < 1) && (part->levelB < 1))
                {
                    emitter->liveCount = emitter->liveCount + -2;
                    *(s16*)&emitter->startIdx = *(s16*)&emitter->startIdx + 2;
                }
                part = (RMParticle*)((char*)part + 0x28);
            }
            if ((emitter != extra->specialEmitter) && (emitter->liveCount == 0))
            {
                emitter->flags = emitter->flags & 0xfd;
            }
        }
        emitter = emitter + 1;
        scratch = scratch + -1;
    }
    while (scratch != 0);
    FUN_8016d188(obj, *(int*)&((GameObject*)obj)->ownerObj);
    FUN_80294d6c(*(int*)&((GameObject*)obj)->ownerObj);
    *(u8*)((int)extra + 0xb9) = 0;
    if (DAT_803ad338 != '\0')
    {
        DAT_803ad324 = DAT_803ad324 + lbl_803E3F78;
        ObjHitbox_SetSphereRadius(DAT_803ad334, (short)(int)DAT_803ad324);
        ObjHits_SetHitVolumeSlot(DAT_803ad334, 0x11, 5, 0);
        DAT_803ad330 = DAT_803ad330 + lbl_803E3F7C;
        clamped = (double)DAT_803ad330;
        DAT_803ad328 = DAT_803ad328 * lbl_803E3F80;
        DAT_803ad32c = DAT_803ad32c * lbl_803E3F84;
        ((GameObject*)DAT_803ad334)->anim.alpha = (char)(int)DAT_803ad330;
        ((GameObject*)DAT_803ad334)->anim.rootMotionScale = ((GameObject*)DAT_803ad334)->anim.rootMotionScale +
            lbl_803E3F88;
        if ((double)DAT_803ad330 < (double)lbl_803E3F20)
        {
            DAT_803ad338 = '\0';
            FUN_80017ac8((double)DAT_803ad330, clamped, param_3, param_4, param_5, param_6, param_7, param_8,
                         DAT_803ad334);
            DAT_803ad334 = 0;
        }
    }
    return;
}

void FUN_80170048(void)
{
    float value;
    u32 world;
    int scratch;
    int* elem;
    u32 randVal;
    int effectObj;
    int* state;
    int* src;
    float* scaleTbl;
    double cosVal;
    double base;
    double phase;
    double bias;
    double offset;
    u64 ret;
    u64 randOffset;
    u64 randOffset2;

    ret = FUN_80286838();
    world = (u32)((u64)ret >> 0x20);
    scaleTbl = (float*)&DAT_80321678;
    state = *(int**)(world + 0xb8);
    scratch = FUN_80017a98();
    effectObj = 0;
    if (scratch != 0)
    {
        effectObj = FUN_80294cf8(scratch);
    }
    value = lbl_803E4064;
    switch ((u32)ret & 0xff)
    {
    case 0:
        if (*state != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *state, '\0');
        }
        value = lbl_803E4048;
        if (lbl_803E4044 != (float)state[2])
        {
            state[4] = lbl_803E4048;
            state[1] = value;
            if (effectObj != 0)
            {
                FUN_8016d994(effectObj, 7, 0);
            }
        }
        state[2] = lbl_803E4044;
        state[3] = lbl_803E404C;
        FUN_80006810(world, 0x42c);
        FUN_80006810(world, 0x42d);
        break;
    case 1:
        if (lbl_803E4044 == (float)state[2])
        {
            if (effectObj != 0)
            {
                FUN_8016d994(effectObj, 7, 8);
            }
            if (*state == 0)
            {
                elem = FUN_80017624(0, '\x01');
                *state = (int)elem;
            }
            if (*state != 0)
            {
                FUN_800175b0(*state, 2);
                FUN_800175ec((double)*(float*)(world + 0xc),
                             (double)(*(float*)(world + 0x10) - lbl_803E4050),
                             (double)*(float*)(world + 0x14), (int*)*state);
                FUN_8001759c(*state, 0, 0xff, 0xff, 0xff);
                FUN_80017588(*state, 0, 0xff, 0xff, 0xff);
                FUN_800175d0((double)lbl_803E4054, (double)lbl_803E4058, *state);
                FUN_800175bc(*state, 1);
                FUN_800175cc((double)lbl_803E4044, *state, '\x01');
                FUN_8001753c(*state, 0, 0);
                FUN_800175d8(*state, 1);
            }
            value = lbl_803E4044;
            if (lbl_803E4044 == (float)state[2])
            {
                state[4] = lbl_803E4048;
                state[1] = value;
            }
            state[2] = lbl_803E4048;
            phase = (double)lbl_803E405C;
            state[3] = lbl_803E405C;
            scratch = 0;
            src = &DAT_80321688;
            base = (double)lbl_803E4040;
            offset = (double)lbl_803E4060;
            elem = state;
            bias = DOUBLE_803e4068;
            do
            {
                *(u16*)(elem + 0xd) = 0xc000;
                cosVal = (double)fcos16Precise();
                state[9] = (int)(*scaleTbl * (float)((double)(float)(phase + cosVal) * base));
                state[5] = *src;
                randVal = randomGetRange(0x78, 0x7f);
                randOffset = (double)(int)(scratch * randVal);
                *(short*)(elem + 0xf) = (short)(int)(offset + (double)(float)(randOffset));
                elem = (int*)((int)elem + 2);
                scaleTbl = scaleTbl + 1;
                state = state + 1;
                src = src + 1;
                scratch = scratch + 1;
            }
            while (scratch < 4);
            FUN_80006824(world, 0x42c);
            FUN_80006824(world, 0x42d);
        }
        break;
    case 2:
        if (effectObj != 0)
        {
            FUN_8016d994(effectObj, 7, 0);
        }
        if (lbl_803E4044 != (float)state[2])
        {
            state[4] = lbl_803E4064;
        }
        state[2] = lbl_803E4044;
        state[3] = lbl_803E404C;
        if (*state != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *state, '\0');
        }
        FUN_80006810(world, 0x42c);
        FUN_80006810(world, 0x42d);
        break;
    case 3:
        if (effectObj != 0)
        {
            FUN_8016d994(effectObj, 7, 8);
        }
        if (*state == 0)
        {
            elem = FUN_80017624(0, '\x01');
            *state = (int)elem;
        }
        if (*state != 0)
        {
            FUN_800175b0(*state, 2);
            FUN_800175ec((double)*(float*)(world + 0xc),
                         (double)(*(float*)(world + 0x10) - lbl_803E4050),
                         (double)*(float*)(world + 0x14), (int*)*state);
            FUN_8001759c(*state, 0, 0xff, 0xff, 0xff);
            FUN_80017588(*state, 0, 0xff, 0xff, 0xff);
            FUN_800175d0((double)lbl_803E4054, (double)lbl_803E4058, *state);
            FUN_800175bc(*state, 1);
            FUN_800175cc((double)lbl_803E4044, *state, '\x01');
            FUN_8001753c(*state, 0, 0);
            FUN_800175d8(*state, 1);
        }
        if (lbl_803E4044 == (float)state[2])
        {
            state[4] = lbl_803E4064;
        }
        state[2] = lbl_803E4064;
        offset = (double)lbl_803E405C;
        state[3] = lbl_803E405C;
        scratch = 0;
        src = &DAT_80321688;
        bias = (double)lbl_803E4040;
        elem = state;
        do
        {
            *(u16*)(state + 0xd) = 0;
            base = (double)fcos16Precise();
            elem[9] = (int)(*scaleTbl * (float)((double)(float)(offset + base) * bias));
            elem[5] = *src;
            state = (int*)((int)state + 2);
            scaleTbl = scaleTbl + 1;
            elem = elem + 1;
            src = src + 1;
            scratch = scratch + 1;
        }
        while (scratch < 4);
        FUN_80006824(world, 0x42d);
        FUN_80006824(world, 0x42c);
        break;
    case 4:
        state[2] = lbl_803E4064;
        offset = (double)lbl_803E405C;
        state[3] = lbl_803E405C;
        state[4] = value;
        scratch = 0;
        scaleTbl = (float*)&DAT_80321698;
        src = &DAT_803216a8;
        base = (double)lbl_803E4040;
        phase = (double)lbl_803E4060;
        elem = state;
        bias = DOUBLE_803e4068;
        do
        {
            *(u16*)(state + 0xd) = 0xc000;
            cosVal = (double)fcos16Precise();
            elem[9] = (int)(*scaleTbl * (float)((double)(float)(offset + cosVal) * base));
            elem[5] = *src;
            randVal = randomGetRange(0x78, 0x7f);
            randOffset2 = (double)(int)(scratch * randVal);
            *(short*)(state + 0xf) = (short)(int)(phase + (double)(float)(randOffset2));
            state = (int*)((int)state + 2);
            scaleTbl = scaleTbl + 1;
            elem = elem + 1;
            src = src + 1;
            scratch = scratch + 1;
        }
        while (scratch < 4);
        FUN_80006824(world, 0x42d);
        FUN_80006824(world, 0x42c);
        break;
    case 5:
        state[2] = lbl_803E4044;
        state[3] = lbl_803E404C;
        state[4] = lbl_803E4064;
        FUN_80006810(world, 0x42c);
        FUN_80006810(world, 0x42d);
        break;
    case 6:
        scratch = 0;
        scaleTbl = (float*)&DAT_80321698;
        src = &DAT_803216a8;
        bias = (double)lbl_803E405C;
        offset = (double)lbl_803E4040;
        elem = state;
        do
        {
            *(u16*)(state + 0xd) = 0x4000;
            base = (double)fcos16Precise();
            elem[9] = (int)(*scaleTbl * (float)((double)(float)(bias + base) * offset));
            elem[5] = *src;
            state = (int*)((int)state + 2);
            scaleTbl = scaleTbl + 1;
            elem = elem + 1;
            src = src + 1;
            scratch = scratch + 1;
        }
        while (scratch < 4);
        break;
    case 7:
        if (effectObj != 0)
        {
            FUN_8016d994(effectObj, 7, 0);
        }
        if (*state != 0)
        {
            FUN_800175cc((double)lbl_803E4040, *state, '\0');
        }
        value = lbl_803E4044;
        state[2] = lbl_803E4044;
        state[3] = value;
        state[4] = value;
        state[1] = value;
        *(u8*)(state + 0x17) = *(u8*)(state + 0x17) | 1;
        *(u8*)((int)state + 0x5d) = *(u8*)((int)state + 0x5d) | 1;
        *(u8*)((int)state + 0x5e) = *(u8*)((int)state + 0x5e) | 1;
        *(u8*)((int)state + 0x5f) = *(u8*)((int)state + 0x5f) | 1;
    }
    FUN_80286884();
    return;
}

void mikabombshadow_update(int* obj);

void FUN_801713ac(u64 param_1, double param_2, double param_3, u64 param_4,
                  u64 param_5, u64 param_6, u64 param_7, u64 param_8,
                  u32 obj)
{
    extern u64 ObjHits_DisableObject(); /* #57 */
    short seqOrType;
    char counter;
    u32 scratchU;
    int audioObj;
    int placement;
    int extra;
    u64 result;

    extra = *(int*)&((GameObject*)obj)->extra;
    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    audioObj = (int)((GameObject*)obj)->anim.modelInstance->extraSetupData;
    FUN_80017a98();
    FUN_80017a90();
    FUN_80017a98();
    FUN_80017a90();
    result = ObjHits_DisableObject(obj);
    if ((*(u16*)&((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
    {
        *(float*)(extra + 8) = lbl_803E40E8;
        if (((GameObject*)obj)->anim.modelState != NULL)
        {
            ((GameObject*)obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    if ((int)*(short*)(extra + 0x10) != 0xffffffff)
    {
        FUN_80017698((int)*(short*)(extra + 0x10), 1);
        result = FUN_800e842c(obj);
    }
    scratchU = (u32) * (short*)(placement + 0x1e);
    if (scratchU != 0xffffffff)
    {
        result = FUN_80017698(scratchU, 1);
    }
    scratchU = (u32) * (short*)(placement + 0x2c);
    if (0 < scratchU)
    {
        FUN_80017688(scratchU);
    }
    seqOrType = *(short*)(audioObj + 2);
    if (seqOrType == 4)
    {
        seqOrType = ((GameObject*)obj)->anim.seqId;
        if (seqOrType == 0x3cd)
        {
            audioObj = FUN_80017a98();
            FUN_80294d60(result, param_2, param_3, param_4, param_5, param_6, param_7, param_8, audioObj, 2);
            scratchU = FUN_80017a98();
            FUN_80006824(scratchU, SFXen_treadlpc);
            FUN_80081118((double)lbl_803E40EC, obj, 1, 0x28);
        }
        else if ((seqOrType < 0x3cd) && (seqOrType == 0xb))
        {
            scratchU = FUN_80017a98();
            result = FUN_80006824(scratchU, SFXen_treadlpc);
            audioObj = FUN_80017a98();
            FUN_80294d60(result, param_2, param_3, param_4, param_5, param_6, param_7, param_8, audioObj, 4);
            FUN_80081118((double)lbl_803E40EC, obj, 3, 0x28);
        }
        else
        {
            scratchU = FUN_80017a98();
            FUN_80006824(scratchU, SFXen_waterblock_stop);
            FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
        }
    }
    else if ((seqOrType < 4) && (seqOrType == 1))
    {
        seqOrType = ((GameObject*)obj)->anim.seqId;
        if (seqOrType == 0x319)
        {
            FUN_80006824(obj, SFXwp_gprop2_c);
            FUN_80017698(0x3e9, 1);
            *(u16*)(extra + 0x3c) = 0x4b0;
            FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
        }
        else
        {
            if (seqOrType < 0x319)
            {
                if (seqOrType == 0x5a)
                {
                    FUN_80006824(obj, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, obj, 2, 0x28);
                    goto LAB_801725bc;
                }
                if ((seqOrType < 0x5a) && (seqOrType == 0x22))
                {
                    FUN_80006824(obj, SFXen_treadlpc);
                    FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
                    goto LAB_801725bc;
                }
            }
            else if (seqOrType == 0x6a6)
            {
                scratchU = FUN_80017690(0x86a);
                counter = scratchU;
                if (counter < '\a')
                {
                    counter = counter + '\x01';
                }
                FUN_80017698(0x86a, counter);
                FUN_80081118((double)lbl_803E40EC, obj, 6, 0x28);
                FUN_80006824(obj, SFXen_treadlpc);
                goto LAB_801725bc;
            }
            FUN_80006824(obj, SFXen_waterblock_stop);
            FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
        }
    }
    else
    {
        FUN_80006824(obj, SFXen_waterblock_stop);
        FUN_80081118((double)lbl_803E40EC, obj, 0xff, 0x28);
    }
LAB_801725bc:
    *(u32*)&((GameObject*)obj)->anim.rootMotionScale = *(u32*)(*(int*)&((GameObject*)obj)->anim.
        modelInstance + 4);
    ((GameObject*)obj)->unkF4 = 1;
    return;
}

void staff_func0F(void);

void staff_func0B(void);

void staff_setScale(void);

void staff_render(void);

void staff_hitDetect(void);

void fireball_release(void);

void fireball_initialise(void);

void flamethrowerspe_modelMtxFn(void);

void flamethrowerspe_free(void);

void flamethrowerspe_hitDetect(void);

void flamethrowerspe_release(void);

void flamethrowerspe_initialise(void);

void shield_hitDetect(void);

void shield_release(void);

void shield_initialise(void);

int animatedobj_getExtraSize(void);
int dim2roofrub_getExtraSize(void);
int depthoffieldpoint_getExtraSize(void);
int staff_getExtraSize(void);
int staff_getObjectTypeId(void);
int fireball_getExtraSize(void);
int fireball_getObjectTypeId(void);
int flamethrowerspe_getExtraSize(void);
int flamethrowerspe_getObjectTypeId(void);
int shield_getExtraSize(void);
int shield_getObjectTypeId(void);

void dim2roofrub_free(int* obj);

void staff_func10(int* obj, s32 v);
void staff_setHitReactValue(int* obj, s32 v);
void staff_addHitReactValue(int* obj, s32 delta);
void staff_getHitGeometryPoints(int* obj, f32* outA, f32* outB);
void staff_func15(int* obj, s16 idx, f32 f1, f32 f2);

void restartmarker_init(int* obj, int* placement)
{
    *(s16*)obj = (s16)(*(u8*)((char*)placement + 0x18) << 8);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | RESTARTMARKER_OBJFLAG_HIDDEN);
}

void staffFn_80170380(int* obj, int cmd);

void shield_init(int* obj, void* initData);

ObjectDescriptor gMikaBombObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mikabomb_initialise,
    (ObjectDescriptorCallback)mikabomb_release,
    0,
    (ObjectDescriptorCallback)mikabomb_init,
    (ObjectDescriptorCallback)mikabomb_update,
    (ObjectDescriptorCallback)mikabomb_hitDetect,
    (ObjectDescriptorCallback)mikabomb_render,
    (ObjectDescriptorCallback)mikabomb_free,
    (ObjectDescriptorCallback)mikabomb_getObjectTypeId,
    mikabomb_getExtraSize,
};

ObjectDescriptor gMikaBombShadowObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mikabombshadow_initialise,
    (ObjectDescriptorCallback)mikabombshadow_release,
    0,
    (ObjectDescriptorCallback)mikabombshadow_init,
    (ObjectDescriptorCallback)mikabombshadow_update,
    (ObjectDescriptorCallback)mikabombshadow_hitDetect,
    (ObjectDescriptorCallback)mikabombshadow_render,
    (ObjectDescriptorCallback)mikabombshadow_free,
    (ObjectDescriptorCallback)mikabombshadow_getObjectTypeId,
    mikabombshadow_getExtraSize,
};

ObjectDescriptor gStaticCameraObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)StaticCamera_initialise,
    (ObjectDescriptorCallback)StaticCamera_release,
    0,
    (ObjectDescriptorCallback)StaticCamera_init,
    (ObjectDescriptorCallback)StaticCamera_update,
    (ObjectDescriptorCallback)StaticCamera_hitDetect,
    (ObjectDescriptorCallback)StaticCamera_render,
    (ObjectDescriptorCallback)StaticCamera_free,
    (ObjectDescriptorCallback)StaticCamera_getObjectTypeId,
    StaticCamera_getExtraSize,
};

ObjectDescriptor gGCbaddieShieldObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)gcbaddieshield_initialise,
    (ObjectDescriptorCallback)gcbaddieshield_release,
    0,
    (ObjectDescriptorCallback)gcbaddieshield_init,
    (ObjectDescriptorCallback)gcbaddieshield_update,
    (ObjectDescriptorCallback)gcbaddieshield_hitDetect,
    (ObjectDescriptorCallback)gcbaddieshield_render,
    (ObjectDescriptorCallback)gcbaddieshield_free,
    (ObjectDescriptorCallback)gcbaddieshield_getObjectTypeId,
    gcbaddieshield_getExtraSize,
};

ObjectDescriptor gBaddieInterestPObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)baddieinterestp_initialise,
    (ObjectDescriptorCallback)baddieinterestp_release,
    0,
    (ObjectDescriptorCallback)baddieinterestp_init,
    (ObjectDescriptorCallback)baddieinterestp_update,
    (ObjectDescriptorCallback)baddieinterestp_hitDetect,
    (ObjectDescriptorCallback)baddieinterestp_render,
    (ObjectDescriptorCallback)baddieinterestp_free,
    (ObjectDescriptorCallback)baddieinterestp_getObjectTypeId,
    baddieinterestp_getExtraSize,
};

u32 lbl_80320700[] = {
    0xFFFFFFFF,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gAnimatedObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)animatedobj_init,
    (ObjectDescriptorCallback)animatedobj_update,
    0,
    (ObjectDescriptorCallback)animatedobj_render,
    (ObjectDescriptorCallback)animatedobj_free,
    0,
    animatedobj_getExtraSize,
};

u32 lbl_80320768[] = {
    0x00000000,
    0x3FD5A1CB,
    0xC0253F7D,
    0x3C23D70A,
    0x06100000,
    0x402F3B64,
    0x3F4B020C,
    0xBFFA1CAC,
    0x3C23D70A,
    0x09200000,
    0x402EB852,
    0x3F476C8B,
    0xBF73B646,
    0x3C23D70A,
    0x07200000,
    0x4032E148,
    0xBF795810,
    0xBFF8F5C3,
    0x3C23D70A,
    0x09200000,
    0x4033F7CF,
    0xBF810625,
    0xBF747AE1,
    0x3C23D70A,
    0x07200000,
    0xC02F3B64,
    0x3F4B020C,
    0xBFFC28F6,
    0x3C23D70A,
    0x09200000,
    0xC02EB852,
    0x3F476C8B,
    0xBF73B646,
    0x3C23D70A,
    0x07200000,
    0xC032E148,
    0xBF795810,
    0xBFFC49BA,
    0x3C23D70A,
    0x09200000,
    0xC033F7CF,
    0xBF810625,
    0xBF747AE1,
    0x3C23D70A,
    0x07200000,
    0x00000000,
    0x3ECF5C29,
    0x403CED91,
    0x3C23D70A,
    0x08400000,
};

ObjectDescriptor gDIM2RoofRubObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dim2roofrub_init,
    (ObjectDescriptorCallback)dim2roofrub_update,
    0,
    (ObjectDescriptorCallback)dim2roofrub_render,
    (ObjectDescriptorCallback)dim2roofrub_free,
    0,
    dim2roofrub_getExtraSize,
};

ObjectDescriptor gDepthOfFieldPointObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)depthoffieldpoint_init,
    (ObjectDescriptorCallback)depthoffieldpoint_update,
    0,
    0,
    0,
    0,
    depthoffieldpoint_getExtraSize,
};

u16 lbl_803208A0[] = {
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C2, 0x006F, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};

u32 lbl_803208E8[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0x01020000,
    0,
    0,
};

ObjectDescriptor23 gStaffObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_23_SLOTS,
    (ObjectDescriptorCallback)staff_initialise,
    (ObjectDescriptorCallback)staff_release,
    0,
    (ObjectDescriptorCallback)staff_init,
    (ObjectDescriptorCallback)staff_update,
    (ObjectDescriptorCallback)staff_hitDetect,
    (ObjectDescriptorCallback)staff_render,
    (ObjectDescriptorCallback)staff_free,
    (ObjectDescriptorCallback)staff_getObjectTypeId,
    staff_getExtraSize,
    (ObjectDescriptorCallback)staff_setScale,
    (ObjectDescriptorCallback)staff_func0B,
    (ObjectDescriptorCallback)staff_modelMtxFn,
    (ObjectDescriptorCallback)staff_hitDetectGeometry,
    (ObjectDescriptorCallback)staff_func0E,
    (ObjectDescriptorCallback)staff_func0F,
    (ObjectDescriptorCallback)staff_func10,
    (ObjectDescriptorCallback)staff_setHitReactValue,
    (ObjectDescriptorCallback)staff_addHitReactValue,
    (ObjectDescriptorCallback)staff_getHitReactValue,
    (ObjectDescriptorCallback)staff_getHitGeometryPoints,
    (ObjectDescriptorCallback)staff_func15,
    (ObjectDescriptorCallback)staff_func16,
};

u32 lbl_80320978[] = {
    0xFF202020,
    0xFF202020,
    0xFF000000,
};

ObjectDescriptor10WithPadding gFireballObjDescriptor = {
    {
        0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)fireball_initialise,
        (ObjectDescriptorCallback)fireball_release,
        0,
        (ObjectDescriptorCallback)fireball_init,
        (ObjectDescriptorCallback)fireball_update,
        (ObjectDescriptorCallback)fireball_hitDetect,
        (ObjectDescriptorCallback)fireball_render,
        (ObjectDescriptorCallback)fireball_free,
        (ObjectDescriptorCallback)fireball_getObjectTypeId,
        fireball_getExtraSize,
    },
    0,
};

u32 lbl_803209C0[] = {
    0x0000004F,
    0xFFC40000,
    0x0000001F,
    0x0000004F,
    0x00C4FF00,
    0x00000005,
    0x0000004F,
    0x00C4FF00,
    0x0000001E,
};

ObjectDescriptor13 gFlameThrowerSpeObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    (ObjectDescriptorCallback)flamethrowerspe_initialise,
    (ObjectDescriptorCallback)flamethrowerspe_release,
    0,
    (ObjectDescriptorCallback)flamethrowerspe_init,
    (ObjectDescriptorCallback)flamethrowerspe_update,
    (ObjectDescriptorCallback)flamethrowerspe_hitDetect,
    (ObjectDescriptorCallback)flamethrowerspe_render,
    (ObjectDescriptorCallback)flamethrowerspe_free,
    (ObjectDescriptorCallback)flamethrowerspe_getObjectTypeId,
    flamethrowerspe_getExtraSize,
    (ObjectDescriptorCallback)flamethrowerspe_setScale,
    (ObjectDescriptorCallback)flamethrowerspe_func0B,
    (ObjectDescriptorCallback)flamethrowerspe_modelMtxFn,
};

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

ObjectDescriptor gShieldObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)shield_initialise,
    (ObjectDescriptorCallback)shield_release,
    0,
    (ObjectDescriptorCallback)shield_init,
    (ObjectDescriptorCallback)shield_update,
    (ObjectDescriptorCallback)shield_hitDetect,
    (ObjectDescriptorCallback)shield_render,
    (ObjectDescriptorCallback)shield_free,
    (ObjectDescriptorCallback)shield_getObjectTypeId,
    shield_getExtraSize,
};

u32 jumptable_80320AA0[] = {
    (u32)((char*)staffFn_80170380 + 0x10C),
    (u32)((char*)staffFn_80170380 + 0x184),
    (u32)((char*)staffFn_80170380 + 0x35C),
    (u32)((char*)staffFn_80170380 + 0x3D0),
    (u32)((char*)staffFn_80170380 + 0x584),
    (u32)((char*)staffFn_80170380 + 0x550),
    (u32)((char*)staffFn_80170380 + 0x65C),
    (u32)((char*)staffFn_80170380 + 0x84),
};

ObjectDescriptor12 gCurveObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)curve_init,
    0,
    0,
    (ObjectDescriptorCallback)curve_render,
    (ObjectDescriptorCallback)curve_free,
    (ObjectDescriptorCallback)curve_getObjectTypeId,
    curve_getExtraSize,
    (ObjectDescriptorCallback)curve_setScale,
    (ObjectDescriptorCallback)curve_func11,
};

ObjectDescriptor gReStartMarkerObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)restartmarker_init,
    0,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor dll_F7 = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_F7_initialise,
    (ObjectDescriptorCallback)dll_F7_release,
    0,
    (ObjectDescriptorCallback)dll_F7_init,
    (ObjectDescriptorCallback)dll_F7_update,
    (ObjectDescriptorCallback)dll_F7_hitDetect,
    (ObjectDescriptorCallback)dll_F7_render,
    (ObjectDescriptorCallback)dll_F7_free,
    (ObjectDescriptorCallback)dll_F7_getObjectTypeId,
    dll_F7_getExtraSize,
};

ObjectDescriptor11WithPadding gCheckpoint4ObjDescriptor = {
    {
        0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)checkpoint4_initialise,
        (ObjectDescriptorCallback)checkpoint4_release,
        0,
        (ObjectDescriptorCallback)checkpoint4_init,
        (ObjectDescriptorCallback)checkpoint4_update,
        (ObjectDescriptorCallback)checkpoint4_hitDetect,
        (ObjectDescriptorCallback)checkpoint4_render,
        (ObjectDescriptorCallback)checkpoint4_free,
        (ObjectDescriptorCallback)checkpoint4_getObjectTypeId,
        checkpoint4_getExtraSize,
        (ObjectDescriptorCallback)checkpoint4_setScale,
    },
    0,
};

void fn_801719F8(void) { objRenderFn_8003b8f4(lbl_803E3420); }

void gcbaddieshield_update(int* obj);




void mikabombshadow_init(int* obj);

void StaticCamera_init(int* obj, int* params, int flag);


void dll_F7_init(int* obj, int* params);



void mikabomb_init(int* obj);



void shield_update(int* obj);

void dll_F7_update(int* obj);
