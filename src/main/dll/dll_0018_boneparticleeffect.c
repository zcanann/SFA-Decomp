#include "main/dll/partfx_interface.h"
#include "main/dll/bonespawndata_struct.h"
#include "main/shader_api.h"
#include "main/dll/fxnode9_struct.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/audio/sfx.h"
#include "main/dll/modgfx.h"
#include "main/gamebits.h"
#include "main/mm.h"
#include "main/texture.h"
#include "main/model.h"
#include "track/intersect_api.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/frame_timing.h"
#include "main/lightmap_api.h"
#include "main/lightmap_text_color_api.h"
#include "main/dll/dll_0018_boneparticleeffect.h"
#include "main/vecmath.h"
#include "main/camera.h"

s16 gBoneParticleEffectTimer;
s32 gBoneParticleScrollOffset;
s16 gBoneParticleStageIndex;
s32 lbl_803DD2B0;
f32 gBoneParticleDrift;
void* gBoneParticleTextureB;
void* gBoneParticleTextureA;
s32 gBoneParticleBufferFlip;

#define BONE_PARTICLE_EFFECT_PARTFX       0x28c
#define BONE_PARTICLE_EFFECT_BUFFER_COUNT 7
#define BONE_PARTICLE_EFFECT_BUFFER_BYTES 0x140
#define BONE_PARTICLE_EFFECT_SLOT_COUNT   20

/* the two bone-particle texture assets loaded at init (gBoneParticleTextureA/B) */
#define BONE_PARTICLE_TEXTURE_A_ID 0x16b
#define BONE_PARTICLE_TEXTURE_B_ID 0x201

#define GX_CULL_NONE 0

extern void* gBoneParticleEffectBuffers[];
extern f32 gBoneParticleDriftVelocity;
union BoneParticleConstF32 { f32 f; };
#pragma explicit_zero_data on
__declspec(section ".sdata2") const union BoneParticleConstF32 lbl_803DF4A8 = { 0.0f };
#pragma explicit_zero_data off
__declspec(section ".sdata2") f32 gBoneParticleDriftMax = 500.0f;
__declspec(section ".sdata2") f32 lbl_803DF4B0 = -1.0f;
__declspec(section ".sdata2") f32 gBoneParticleDriftMin = -500.0f;
__declspec(section ".sdata2") const union BoneParticleConstF32 lbl_803DF4B8 = { 1.0f };
__declspec(section ".sdata2") const union BoneParticleConstF32 lbl_803DF4BC = { 20.02f };

extern void GXSetCullMode(int mode);
extern void _textSetColor(void* ctx, int r, int g, int b, int a);
extern void textureFn_800541ac(void* ctx, void* tex, int a, int b, int c, int d, int e);
extern void PSMTXMultVec(void* m, void* src, void* dst);

static inline int* Modgfx_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

void boneParticleEffect_func08_nop(void)
{
}

/* scheduling-off intentionally stays in effect through end-of-file. Do not close. */
#pragma scheduling off
#pragma peephole off

f32 gBoneParticleConfigTable[108] = {
    -1500.0f, 0.0f,     -1500.0f, -1500.0f, 0.0f,     1500.0f, 1500.0f, 0.0f,    1500.0f, 1500.0f,  0.0f,    -1500.0f,
    -1500.0f, 0.0f,     -1500.0f, -1500.0f, 0.0f,     1500.0f, 1500.0f, 0.0f,    1500.0f, 1500.0f,  0.0f,    -1500.0f,
    -1500.0f, 0.0f,     -1500.0f, -1500.0f, 0.0f,     1500.0f, 1500.0f, 0.0f,    1500.0f, 1500.0f,  0.0f,    -1500.0f,
    0.0f,     -1500.0f, -1500.0f, 0.0f,     -1500.0f, 1500.0f, 0.0f,    1500.0f, 1500.0f, 0.0f,     1500.0f, -1500.0f,
    0.0f,     -1500.0f, -1500.0f, 0.0f,     -1500.0f, 1500.0f, 0.0f,    1500.0f, 1500.0f, 0.0f,     1500.0f, -1500.0f,
    0.0f,     -1500.0f, -1500.0f, 0.0f,     -1500.0f, 1500.0f, 0.0f,    1500.0f, 1500.0f, 0.0f,     1500.0f, -1500.0f,
    -1500.0f, -1500.0f, 0.0f,     1500.0f,  -1500.0f, 0.0f,    1500.0f, 1500.0f, 0.0f,    -1500.0f, 1500.0f, 0.0f,
    -1500.0f, -1500.0f, 0.0f,     1500.0f,  -1500.0f, 0.0f,    1500.0f, 1500.0f, 0.0f,    -1500.0f, 1500.0f, 0.0f,
    -1500.0f, -1500.0f, 0.0f,     1500.0f,  -1500.0f, 0.0f,    1500.0f, 1500.0f, 0.0f,    -1500.0f, 1500.0f, 0.0f,
};

/* Per-bone particle vertex update + draw. */
#pragma opt_propagation off
void boneParticleEffect_update(void* ctx, int renderParam, u8* obj)
{
    BoneFxVtx vtx;
    void** grp;
    s16 j;
    s16 k;
    int row;
    u32 id;
    u32 cls;
    u8* mtx;
    u8* idp;
    u8* base;
    f32* scaleA;
    f32* scaleB;
    f32* scaleC;
    int* model;
    void** grp2;
    int slot;
    u8* jb;
    s32 idx;
    f32 dx;
    f32 dy;
    f32 dz;

    base = (u8*)gBoneParticleConfigTable;
    if (mainGetBit(GAMEBIT_TRICKYCURVE_PLAYER_HIT) != 0)
    {
        mainSetBits(GAMEBIT_TRICKYCURVE_PLAYER_HIT, 0);
        gBoneParticleEffectTimer = 0xf;
        Sfx_PlayFromObject((u32)obj, SFXTRIG_id_281);
    }
    model = Modgfx_GetActiveModel((void*)obj);
    if (gBoneParticleStageIndex > 6)
    {
        gBoneParticleStageIndex = 0;
    }
    if (lbl_803DD2B0 > *(u8*)(*model + 0xf3) - 1)
    {
        lbl_803DD2B0 = 0;
    }
    gBoneParticleScrollOffset = gBoneParticleScrollOffset + framesThisStep;
    if (gBoneParticleScrollOffset > 0x1f)
    {
        gBoneParticleScrollOffset = gBoneParticleScrollOffset - 0x1f;
    }
    gBoneParticleDrift = gBoneParticleDriftVelocity * timeDelta + gBoneParticleDrift;
    if (gBoneParticleDrift > gBoneParticleDriftMax)
    {
        gBoneParticleDriftVelocity = gBoneParticleDriftVelocity * lbl_803DF4B0;
        gBoneParticleDrift = gBoneParticleDriftMax;
        Sfx_PlayFromObject((u32)obj, SFXTRIG_id_282);
    }
    else if (gBoneParticleDrift < gBoneParticleDriftMin)
    {
        gBoneParticleDriftVelocity = gBoneParticleDriftVelocity * lbl_803DF4B0;
        gBoneParticleDrift = gBoneParticleDriftMin;
        Sfx_PlayFromObject((u32)obj, SFXTRIG_id_282);
    }
    slot = 0;
    grp2 = gBoneParticleEffectBuffers;
    grp = gBoneParticleEffectBuffers;
    for (; slot < BONE_PARTICLE_EFFECT_BUFFER_COUNT; slot++)
    {
        if (slot != 5)
        {
            gBoneParticleStageIndex = slot;
            row = 0;
            j = 0;
            idp = base + 0x5b4;
            while (j < 5)
            {
                vtx.vx = lbl_803DF4A8.f;
                vtx.vy = lbl_803DF4A8.f;
                vtx.vz = lbl_803DF4A8.f;
                vtx.w = lbl_803DF4B8.f;
                vtx.sz = 0;
                vtx.sy = 0;
                vtx.sx = 0;
                jb = (u8*)model[(*(u16*)((u8*)model + 0x18) & 1) + 3];
                {
                    u8* idr2 = base + gBoneParticleStageIndex * 5;
                    idr2 = idr2 + j;
                    id = idr2[0x5b4];
                }
                mtx = (u8*)((BoneFxJRow*)jb + (id << 4));
                dx = *(f32*)(mtx + 0x30) + playerMapOffsetX;
                dy = *(f32*)(mtx + 0x34);
                dz = *(f32*)(mtx + 0x38) + playerMapOffsetZ;
                dx = dx - ((GameObject*)obj)->anim.localPosX;
                dy = dy - ((GameObject*)obj)->anim.localPosY;
                dz = dz - ((GameObject*)obj)->anim.localPosZ;
                dx = dx * lbl_803DF4BC.f;
                if (id == 0x1d || id == 0x1d)
                {
                    dy = *(f32*)&lbl_803DF4BC.f * (8.0f + dy);
                }
                else
                {
                    dy = dy * lbl_803DF4BC.f;
                }
                dz = dz * lbl_803DF4BC.f;
                Matrix_TransformPoint((f32*)mtx, vtx.vx, vtx.vy, vtx.vz, &vtx.vx, &vtx.vy, &vtx.vz);
                k = 0;
                scaleA = (f32*)(base + 0x90);
                scaleB = (f32*)base;
                scaleC = (f32*)(base + 0x120);
                while (k < 4)
                {
                    u8* idr;
                    f32 sc;
                    id = *(u8*)(idp + gBoneParticleStageIndex * 5);
                    idr = base + id;
                    cls = idr[0x590];
                    if (cls == 0)
                    {
                        vtx.vx = scaleA[0] * (sc = *(f32*)(base + id * 4 + 0x5d8));
                        vtx.vy = scaleA[1] * sc;
                        vtx.vz = scaleA[2] * *(f32*)(base + id * 4 + 0x664);
                    }
                    else if (cls == 1)
                    {
                        vtx.vx = scaleB[0] * (sc = *(f32*)(base + id * 4 + 0x5d8));
                        vtx.vy = scaleB[1] * sc;
                        vtx.vz = scaleB[2] * *(f32*)(base + id * 4 + 0x664);
                    }
                    else if (cls == 2)
                    {
                        vtx.vx = scaleC[0] * (sc = *(f32*)(base + id * 4 + 0x5d8));
                        vtx.vy = scaleC[1] * sc;
                        vtx.vz = scaleC[2] * *(f32*)(base + id * 4 + 0x664);
                    }
                    Matrix_TransformPoint((f32*)mtx, vtx.vx, vtx.vy, vtx.vz, &vtx.vx, &vtx.vy, &vtx.vz);
                    vtx.vx = vtx.vx + playerMapOffsetX;
                    vtx.vz = vtx.vz + playerMapOffsetZ;
                    ((ParticleSlot*)*grp)[k + row].posX = dx + (vtx.vx - ((GameObject*)obj)->anim.localPosX);
                    ((ParticleSlot*)*grp)[k + row].posY = dy + (vtx.vy - ((GameObject*)obj)->anim.localPosY);
                    ((ParticleSlot*)*grp)[k + row].posZ = dz + (vtx.vz - ((GameObject*)obj)->anim.localPosZ);
                    ((ParticleSlot*)*grp)[k + row].alpha = 0x9b;
                    ((ParticleSlot*)*grp)[k + row].texV =
                        (s16)(((ParticleSlot*)(base + 0x1b0))[k + row].texV - (gBoneParticleScrollOffset << 2));
                    scaleA += 3;
                    scaleB += 3;
                    scaleC += 3;
                    k += 1;
                }
                row += 4;
                idp += 1;
                j += 1;
            }
        }
        grp += 1;
    }
    vtx.vx = ((GameObject*)obj)->anim.localPosX;
    vtx.vy = ((GameObject*)obj)->anim.localPosY;
    vtx.vz = ((GameObject*)obj)->anim.localPosZ;
    vtx.w = 0.0495f;
    setTextColorContextLegacy(ctx, 0xff, 0xff, 0xff, 0xff);
    if (gBoneParticleEffectTimer != 0)
    {
        (*gPartfxInterface)->spawnObject(obj, BONE_PARTICLE_EFFECT_PARTFX, NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, BONE_PARTICLE_EFFECT_PARTFX, NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(obj, BONE_PARTICLE_EFFECT_PARTFX, NULL, 1, -1, NULL);
        if ((int)randomGetRange(0, 1) != 0)
        {
            textureFn_800541ac(ctx, gBoneParticleTextureA, 0, 0, 0, 0, 0);
        }
        else
        {
            textureFn_800541ac(ctx, gBoneParticleTextureB, 0, 0, 0, 0, 0);
        }
        gBoneParticleEffectTimer -= framesThisStep;
        if (gBoneParticleEffectTimer < 0)
        {
            gBoneParticleEffectTimer = 0;
        }
    }
    else
    {
        textureFn_800541ac(ctx, gBoneParticleTextureA, 0, 0, 0, 0, 0);
    }
    ((void (*)(void*, int, void*, f32, f32, int))Camera_LoadModelViewMatrix)(
        ctx, renderParam, &vtx, lbl_803DF4B8.f, lbl_803DF4A8.f, 0);
    GXSetCullMode(GX_CULL_NONE);
    _textSetColor(ctx, 0xff, 0xff, 0xff, 0xff);
    textureSetupFn_800799c0();
    geomDrawFn_800796f0();
    gxTexColorFn_80079254();
    textRenderSetupFn_80079804();
    gxBlendFn_80078b4c();
    {
        int i;
        i = 0;
        do
        {
            drawFn_8005cf8c((int)*grp2, (const u8*)(base + 0x2f0), 0x20);
            grp2 += 1;
            i += 1;
        } while (i < BONE_PARTICLE_EFFECT_BUFFER_COUNT);
    }
    gBoneParticleBufferFlip = 1 - gBoneParticleBufferFlip;
}
#pragma opt_propagation reset

void boneParticleEffect_func06_nop(void)
{
}


ParticleSlot gBoneParticleInitData[] = {
    {-500, -900, -500, 0, 0, 0, 255, 255, 255, 255},
    {500, -900, -500, 0, 63, 0, 255, 255, 255, 255},
    {500, -900, 500, 0, 127, 0, 255, 255, 255, 255},
    {-500, -900, 500, 0, 191, 0, 255, 255, 255, 255},
    {-500, -900, -500, 0, 0, 127, 255, 255, 255, 255},
    {500, -900, -500, 0, 63, 127, 255, 255, 255, 255},
    {500, -900, 500, 0, 127, 127, 255, 255, 255, 255},
    {-500, -900, 500, 0, 191, 127, 255, 255, 255, 255},
    {-500, -900, -500, 0, 0, 255, 255, 255, 255, 255},
    {500, -900, -500, 0, 63, 255, 255, 255, 255, 255},
    {500, -900, 500, 0, 127, 255, 255, 255, 255, 255},
    {-500, -900, 500, 0, 191, 255, 255, 255, 255, 255},
    {-500, -900, -500, 0, 0, 383, 255, 255, 255, 255},
    {500, -900, -500, 0, 63, 383, 255, 255, 255, 255},
    {500, -900, 500, 0, 127, 383, 255, 255, 255, 255},
    {-500, -900, 500, 0, 191, 383, 255, 255, 255, 255},
    {-500, -900, -500, 0, 0, 511, 255, 255, 255, 255},
    {500, -900, -500, 0, 63, 511, 255, 255, 255, 255},
    {500, -900, 500, 0, 127, 511, 255, 255, 255, 255},
    {-500, -900, 500, 0, 191, 511, 255, 255, 255, 255},
    {0, 1029, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 1281, 0, 0, 0, 0, 0, 0, 0, 0},
    {1, 1286, 0, 0, 0, 0, 0, 0, 0, 0},
    {1, 1538, 0, 0, 0, 0, 0, 0, 0, 0},
    {2, 1543, 0, 0, 0, 0, 0, 0, 0, 0},
    {2, 1795, 0, 0, 0, 0, 0, 0, 0, 0},
    {3, 1796, 0, 0, 0, 0, 0, 0, 0, 0},
    {3, 1024, 0, 0, 0, 0, 0, 0, 0, 0},
    {4, 2057, 0, 0, 0, 0, 0, 0, 0, 0},
    {4, 2309, 0, 0, 0, 0, 0, 0, 0, 0},
    {5, 2314, 0, 0, 0, 0, 0, 0, 0, 0},
    {5, 2566, 0, 0, 0, 0, 0, 0, 0, 0},
    {6, 2571, 0, 0, 0, 0, 0, 0, 0, 0},
    {6, 2823, 0, 0, 0, 0, 0, 0, 0, 0},
    {7, 2824, 0, 0, 0, 0, 0, 0, 0, 0},
    {7, 2052, 0, 0, 0, 0, 0, 0, 0, 0},
    {8, 3085, 0, 0, 0, 0, 0, 0, 0, 0},
    {8, 3337, 0, 0, 0, 0, 0, 0, 0, 0},
    {9, 3342, 0, 0, 0, 0, 0, 0, 0, 0},
    {9, 3594, 0, 0, 0, 0, 0, 0, 0, 0},
    {10, 3599, 0, 0, 0, 0, 0, 0, 0, 0},
    {10, 3851, 0, 0, 0, 0, 0, 0, 0, 0},
    {11, 3852, 0, 0, 0, 0, 0, 0, 0, 0},
    {11, 3080, 0, 0, 0, 0, 0, 0, 0, 0},
    {12, 4113, 0, 0, 0, 0, 0, 0, 0, 0},
    {12, 4365, 0, 0, 0, 0, 0, 0, 0, 0},
    {13, 4370, 0, 0, 0, 0, 0, 0, 0, 0},
    {13, 4622, 0, 0, 0, 0, 0, 0, 0, 0},
    {14, 4627, 0, 0, 0, 0, 0, 0, 0, 0},
    {14, 4879, 0, 0, 0, 0, 0, 0, 0, 0},
    {15, 4880, 0, 0, 0, 0, 0, 0, 0, 0},
    {15, 4108, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 513, 0, 0, 0, 0, 0, 0, 0, 0},
    {0, 515, 0, 0, 0, 0, 0, 0, 0, 0},
    {4, 1541, 0, 0, 0, 0, 0, 0, 0, 0},
    {4, 1543, 0, 0, 0, 0, 0, 0, 0, 0},
    {8, 2569, 0, 0, 0, 0, 0, 0, 0, 0},
    {8, 2571, 0, 0, 0, 0, 0, 0, 0, 0},
    {12, 3597, 0, 0, 0, 0, 0, 0, 0, 0},
    {12, 3599, 0, 0, 0, 0, 0, 0, 0, 0},
    {16, 4625, 0, 0, 0, 0, 0, 0, 0, 0},
    {16, 4627, 0, 0, 0, 0, 0, 0, 0, 0},
    {257, 257, 257, 257, 258, 514, 2, 2, 1, 1},
    {0, 0, 0, 0, 0, 0, 1, 1, 1, 1},
    {257, 0, 1, 515, 1024, 1286, 7, 8, 9, 10},
    {2829, 3344, 4370, 4884, 5655, 6169, 26, 15, 29, 32},
    {3855, 7196, 8448, 0, 16240, -23593, 63, 40, 245, 195},
    {16124, 27263, 16145, 26739, 16132, -25690, 63, 0, 0, 0},
    {16109, 3670, 16158, 13631, 16132, -25690, 62, 230, 102, 102},
    {16163, 21496, 16215, 36176, 16153, -26214, 62, 211, 116, 188},
    {16230, 26214, 16220, 44040, 16132, -25690, 63, 21, 194, 143},
    {16017, -5243, 16110, 5243, 16064, 0, 63, 64, 0, 0},
    {16138, 15729, 16157, 28836, 15897, -26214, 62, 234, 126, 250},
    {16075, 17302, 16192, 0, 16239, -8389, 63, 113, 235, 133},
    {16192, 0, 16192, 0, 16220, -21496, 63, 114, 110, 152},
    {16192, 0, 16192, 0, 16256, 0, 63, 69, 161, 203},
    {16247, -29360, 16247, 36176, 16272, -23593, 63, 54, 69, 162},
    {16260, -17302, 16193, 51905, 16102, 26214, 62, 54, 69, 162},
    {16109, 3670, 16153, 39322, 16083, 29884, 63, 102, 102, 102},
    {16220, -21496, 16132, 39846, 16149, -15729, 63, 14, 20, 123},
    {16110, 5243, 16064, 0, 16192, 0, 63, 10, 61, 113},
    {16157, 28836, 16130, 36700, 16106, 32506, 62, 203, 67, 150},
    {16192, 0, 16121, 56099, 16241, -5243, 63, 64, 0, 0},
    {16192, 0, 16220, 44040, 16142, -9961, 63, 64, 0, 0},
};

void boneParticleEffect_spawnAtBones(GameObject* obj, int effectId, void* extraArg, u8 prob, short* src)
{
    void* model;
    int i;
    BoneSpawnData data;

    model = Obj_GetActiveModel(obj);
    for (i = 0; i < *(u8*)(*(int*)model + 0xf3); i++)
    {
        if ((int)randomGetRange(1, 0x64) <= prob)
        {
            void* mtx;
            data.x = lbl_803DF4A8.f;
            data.y = lbl_803DF4A8.f;
            data.z = lbl_803DF4A8.f;
            data.scale = lbl_803DF4B8.f;
            data.unk4 = 0;
            data.unk2 = 0;
            data.unk0 = 0;
            mtx = ObjModel_GetJointMatrix(model, i);
            PSMTXMultVec(mtx, &data.x, &data.x);
            data.x = data.x - (obj)->anim.worldPosX;
            data.y = data.y - (obj)->anim.worldPosY;
            data.z = data.z - (obj)->anim.worldPosZ;
            data.x = data.x + playerMapOffsetX;
            data.z = data.z + playerMapOffsetZ;
            if (src != NULL)
            {
                data.scale = *(f32*)((char*)src + 0x8);
                data.unk0 = src[0];
                data.unk4 = src[2];
                data.unk2 = src[1];
                data.unk6 = src[3];
            }
            else
            {
                data.scale = lbl_803DF4B8.f;
                data.unk0 = 0;
                data.unk4 = 0;
                data.unk2 = 0;
                data.unk6 = 0;
            }
            (*gPartfxInterface)->spawnObject(obj, effectId, &data, 2, -1, extraArg);
        }
    }
}

void boneParticleEffect_func04_nop(void)
{
}

void boneParticleEffect_func03_nop(void)
{
}

void boneParticleEffect_release(void)
{
    int i;
    void* zero;
    i = 0;
    zero = NULL;
    do
    {
        if (gBoneParticleEffectBuffers[i] != NULL)
            mm_free(gBoneParticleEffectBuffers[i]);
        gBoneParticleEffectBuffers[i] = zero;
        i++;
    } while (i < BONE_PARTICLE_EFFECT_BUFFER_COUNT);
    if (gBoneParticleTextureA != NULL)
        textureFree((Texture*)(gBoneParticleTextureA));
    if (gBoneParticleTextureB != NULL)
        textureFree((Texture*)(gBoneParticleTextureB));
}

void boneParticleEffect_initialise(void)
{
    int i;
    int j;

    gBoneParticleTextureA = textureLoadAsset(BONE_PARTICLE_TEXTURE_A_ID);
    gBoneParticleTextureB = textureLoadAsset(BONE_PARTICLE_TEXTURE_B_ID);
    gBoneParticleEffectBuffers[0] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[1] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[2] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[3] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[4] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[5] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    gBoneParticleEffectBuffers[6] = mmAlloc(BONE_PARTICLE_EFFECT_BUFFER_BYTES, 0x15, 0);
    for (i = 0; i < BONE_PARTICLE_EFFECT_BUFFER_COUNT; i++)
    {
        for (j = 0; j < BONE_PARTICLE_EFFECT_SLOT_COUNT; j++)
        {
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].posX = gBoneParticleInitData[j].posX;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].posY = gBoneParticleInitData[j].posY;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].posZ = gBoneParticleInitData[j].posZ;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].texU = gBoneParticleInitData[j].texU;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].texV = gBoneParticleInitData[j].texV;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].red = gBoneParticleInitData[j].red;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].green = gBoneParticleInitData[j].green;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].blue = gBoneParticleInitData[j].blue;
            ((ParticleSlot*)gBoneParticleEffectBuffers[i])[j].alpha = 0xff;
        }
    }
}

/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* boneParticleEffect_funcs[14] = {(void*)0x00000000,
                                      (void*)0x00000000,
                                      (void*)0x00000000,
                                      (void*)0x00080000,
                                      boneParticleEffect_initialise,
                                      boneParticleEffect_release,
                                      (void*)0x00000000,
                                      boneParticleEffect_func03_nop,
                                      boneParticleEffect_func04_nop,
                                      boneParticleEffect_spawnAtBones,
                                      boneParticleEffect_func06_nop,
                                      boneParticleEffect_update,
                                      boneParticleEffect_func08_nop,
                                      (void*)0x00000000};
