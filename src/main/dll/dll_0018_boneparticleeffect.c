#include "main/dll/bonespawndata_struct.h"
#include "main/dll/fxnode9_struct.h"
#include "main/dll/modgfx_types.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/modgfx.h"
#include "main/gamebits.h"
#include "main/mm.h"
#include "main/texture.h"
#include "main/model.h"
#include "main/sfa_shared_decls.h"
#include "main/audio/sfx_ids.h"

static inline int* Modgfx_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

void boneParticleEffect_func08_nop(void)
{
}

void boneParticleEffect_func06_nop(void)
{
}

void boneParticleEffect_func04_nop(void)
{
}

void boneParticleEffect_func03_nop(void)
{
}

#define BONE_PARTICLE_EFFECT_BUFFER_COUNT 7
#define BONE_PARTICLE_EFFECT_BUFFER_BYTES 0x140
#define BONE_PARTICLE_EFFECT_SLOT_COUNT 20
extern void*gBoneParticleEffectBuffers[];
extern void* gBoneParticleTextureA;
extern void* gBoneParticleTextureB;

/* scheduling-off intentionally stays in effect through end-of-file (release/update/initialise/
   spawnAtBones); peephole is re-enabled at boneParticleEffect_spawnAtBones below. Do not close. */
#pragma scheduling off
#pragma peephole off
void boneParticleEffect_release(void)
{
    int i;
    void* zero;
    i = 0;
    zero = NULL;
    do
    {
        if (gBoneParticleEffectBuffers[i] != NULL) mm_free(gBoneParticleEffectBuffers[i]);
        gBoneParticleEffectBuffers[i] = zero;
        i++;
    }
    while (i < BONE_PARTICLE_EFFECT_BUFFER_COUNT);
    if (gBoneParticleTextureA != NULL) textureFree(gBoneParticleTextureA);
    if (gBoneParticleTextureB != NULL) textureFree(gBoneParticleTextureB);
}

extern void Sfx_PlayFromObject(void* obj, int id);
f32 gBoneParticleConfigTable[108] = {
    -1500.0f, 0.0f, -1500.0f,
    -1500.0f, 0.0f, 1500.0f,
    1500.0f, 0.0f, 1500.0f,
    1500.0f, 0.0f, -1500.0f,
    -1500.0f, 0.0f, -1500.0f,
    -1500.0f, 0.0f, 1500.0f,
    1500.0f, 0.0f, 1500.0f,
    1500.0f, 0.0f, -1500.0f,
    -1500.0f, 0.0f, -1500.0f,
    -1500.0f, 0.0f, 1500.0f,
    1500.0f, 0.0f, 1500.0f,
    1500.0f, 0.0f, -1500.0f,
    0.0f, -1500.0f, -1500.0f,
    0.0f, -1500.0f, 1500.0f,
    0.0f, 1500.0f, 1500.0f,
    0.0f, 1500.0f, -1500.0f,
    0.0f, -1500.0f, -1500.0f,
    0.0f, -1500.0f, 1500.0f,
    0.0f, 1500.0f, 1500.0f,
    0.0f, 1500.0f, -1500.0f,
    0.0f, -1500.0f, -1500.0f,
    0.0f, -1500.0f, 1500.0f,
    0.0f, 1500.0f, 1500.0f,
    0.0f, 1500.0f, -1500.0f,
    -1500.0f, -1500.0f, 0.0f,
    1500.0f, -1500.0f, 0.0f,
    1500.0f, 1500.0f, 0.0f,
    -1500.0f, 1500.0f, 0.0f,
    -1500.0f, -1500.0f, 0.0f,
    1500.0f, -1500.0f, 0.0f,
    1500.0f, 1500.0f, 0.0f,
    -1500.0f, 1500.0f, 0.0f,
    -1500.0f, -1500.0f, 0.0f,
    1500.0f, -1500.0f, 0.0f,
    1500.0f, 1500.0f, 0.0f,
    -1500.0f, 1500.0f, 0.0f,
};
extern s16 gBoneParticleEffectTimer;
extern s16 gBoneParticleStageIndex;
extern s32 lbl_803DD2B0;
extern s32 gBoneParticleScrollOffset;
extern f32 gBoneParticleDrift;
extern f32 gBoneParticleDriftVelocity;
extern s32 gBoneParticleBufferFlip;
extern const f32 lbl_803DF4A8;
extern f32 gBoneParticleDriftMax;
extern f32 lbl_803DF4B0;
extern f32 gBoneParticleDriftMin;
extern const f32 lbl_803DF4B8;
extern const f32 lbl_803DF4BC;
extern f32 lbl_803DF4C0;
extern f32 lbl_803DF4C4;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 timeDelta;
extern u8 framesThisStep;
typedef u8 BoneFxJRow[16];

typedef struct BoneFxVtx
{
    u16 sx;
    u16 sy;
    u16 sz;
    u16 pad;
    f32 w;
    f32 vx;
    f32 vy;
    f32 vz;
} BoneFxVtx;

/* One 0x10-byte rendered particle slot in a gBoneParticleEffectBuffers buffer. */
typedef struct ParticleSlot
{
    s16 posX, posY, posZ;
    u16 pad;
    s16 texU, texV;
    u8 red, green, blue, alpha;
} ParticleSlot;

extern void Matrix_TransformPoint(void* mtx, f32 x, f32 y, f32 z, f32* ox, f32* oy, f32* oz);
extern void Camera_LoadModelViewMatrix(void* a, int b, void* c, f32 e, f32 f, int d);
extern void GXSetCullMode(int mode);
extern void setTextColor(void* ctx, int r, int g, int b, int a);

#define GX_CULL_NONE 0
extern void _textSetColor(void* ctx, int r, int g, int b, int a);
extern void textureFn_800541ac(void* ctx, void* tex, int a, int b, int c, int d, int e);





extern void drawFn_8005cf8c(void* a, void* b, int count);

/* EN v1.0 0x800A433C  size: 1764b  per-bone particle vertex update + draw. */
#pragma opt_propagation off
void boneParticleEffect_update(void* ctx, int renderParam, u8* o)
{
    BoneFxVtx s;
    void** grp;
    s16 j;
    s16 k;
    int row;
    u32 id;
    u32 cls;
    u8* mtx;
    u8* idp;
    u8* base;
    f32* pa;
    f32* pb;
    f32* pc;
    int* m;
    void** grp2;
    int slot;
    u8* jb;
    s32 idx;
    f32 dx;
    f32 dy;
    f32 dz;

    base = (u8*)gBoneParticleConfigTable;
    if (GameBit_Get(0x468) != 0)
    {
        GameBit_Set(0x468, 0);
        gBoneParticleEffectTimer = 0xf;
        Sfx_PlayFromObject(o, SFXsc_mumble01);
    }
    m = Modgfx_GetActiveModel((void*)o);
    if (gBoneParticleStageIndex > 6)
    {
        gBoneParticleStageIndex = 0;
    }
    if (lbl_803DD2B0 > *(u8*)(*m + 0xf3) - 1)
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
        Sfx_PlayFromObject(o, SFXsc_mumble02);
    }
    else if (gBoneParticleDrift < gBoneParticleDriftMin)
    {
        gBoneParticleDriftVelocity = gBoneParticleDriftVelocity * lbl_803DF4B0;
        gBoneParticleDrift = gBoneParticleDriftMin;
        Sfx_PlayFromObject(o, SFXsc_mumble02);
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
                s.vx = lbl_803DF4A8;
                s.vy = lbl_803DF4A8;
                s.vz = lbl_803DF4A8;
                s.w = lbl_803DF4B8;
                s.sz = 0;
                s.sy = 0;
                s.sx = 0;
                jb = (u8*)m[(*(u16*)((u8*)m + 0x18) & 1) + 3];
                {
                    u8* idr2 = base + gBoneParticleStageIndex * 5;
                    idr2 = idr2 + j;
                    id = idr2[0x5b4];
                }
                mtx = (u8*)((BoneFxJRow*)jb + (id << 4));
                dx = *(f32*)(mtx + 0x30) + playerMapOffsetX;
                dy = *(f32*)(mtx + 0x34);
                dz = *(f32*)(mtx + 0x38) + playerMapOffsetZ;
                dx = dx - ((GameObject*)o)->anim.localPosX;
                dy = dy - ((GameObject*)o)->anim.localPosY;
                dz = dz - ((GameObject*)o)->anim.localPosZ;
                dx = dx * lbl_803DF4BC;
                if (id == 0x1d || id == 0x1d)
                {
                    dy = *(f32*)&lbl_803DF4BC * (lbl_803DF4C0 + dy);
                }
                else
                {
                    dy = dy * lbl_803DF4BC;
                }
                dz = dz * lbl_803DF4BC;
                Matrix_TransformPoint(mtx, s.vx, s.vy, s.vz, &s.vx, &s.vy, &s.vz);
                k = 0;
                pa = (f32*)(base + 0x90);
                pb = (f32*)base;
                pc = (f32*)(base + 0x120);
                while (k < 4)
                {
                    u8* idr;
                    f32 sc;
                    id = *(u8*)(idp + gBoneParticleStageIndex * 5);
                    idr = base + id;
                    cls = idr[0x590];
                    if (cls == 0)
                    {
                        s.vx = pa[0] * (sc = *(f32*)(base + id * 4 + 0x5d8));
                        s.vy = pa[1] * sc;
                        s.vz = pa[2] * *(f32*)(base + id * 4 + 0x664);
                    }
                    else if (cls == 1)
                    {
                        s.vx = pb[0] * (sc = *(f32*)(base + id * 4 + 0x5d8));
                        s.vy = pb[1] * sc;
                        s.vz = pb[2] * *(f32*)(base + id * 4 + 0x664);
                    }
                    else if (cls == 2)
                    {
                        s.vx = pc[0] * (sc = *(f32*)(base + id * 4 + 0x5d8));
                        s.vy = pc[1] * sc;
                        s.vz = pc[2] * *(f32*)(base + id * 4 + 0x664);
                    }
                    Matrix_TransformPoint(mtx, s.vx, s.vy, s.vz, &s.vx, &s.vy, &s.vz);
                    s.vx = s.vx + playerMapOffsetX;
                    s.vz = s.vz + playerMapOffsetZ;
                    ((ParticleSlot*)*grp)[k + row].posX = dx + (s.vx - ((GameObject*)o)->anim.localPosX);
                    ((ParticleSlot*)*grp)[k + row].posY = dy + (s.vy - ((GameObject*)o)->anim.localPosY);
                    ((ParticleSlot*)*grp)[k + row].posZ = dz + (s.vz - ((GameObject*)o)->anim.localPosZ);
                    ((ParticleSlot*)*grp)[k + row].alpha = 0x9b;
                    ((ParticleSlot*)*grp)[k + row].texV = (s16)(((ParticleSlot*)(base + 0x1b0))[k + row].texV - (gBoneParticleScrollOffset << 2));
                    pa += 3;
                    pb += 3;
                    pc += 3;
                    k += 1;
                }
                row += 4;
                idp += 1;
                j += 1;
            }
        }
        grp += 1;
    }
    s.vx = ((GameObject*)o)->anim.localPosX;
    s.vy = ((GameObject*)o)->anim.localPosY;
    s.vz = ((GameObject*)o)->anim.localPosZ;
    s.w = lbl_803DF4C4;
    setTextColor(ctx, 0xff, 0xff, 0xff, 0xff);
    if (gBoneParticleEffectTimer != 0)
    {
        (*gPartfxInterface)->spawnObject(o, 0x28c, NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(o, 0x28c, NULL, 1, -1, NULL);
        (*gPartfxInterface)->spawnObject(o, 0x28c, NULL, 1, -1, NULL);
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
    Camera_LoadModelViewMatrix(ctx, renderParam, &s, lbl_803DF4B8, lbl_803DF4A8, 0);
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
            drawFn_8005cf8c(*grp2, base + 0x2f0, 0x20);
            grp2 += 1;
            i += 1;
        }
        while (i < BONE_PARTICLE_EFFECT_BUFFER_COUNT);
    }
    gBoneParticleBufferFlip = 1 - gBoneParticleBufferFlip;
}
#pragma opt_propagation reset

ParticleSlot gBoneParticleInitData[] =
{
    { -500, -900, -500, 0, 0, 0, 255, 255, 255, 255 },
    { 500, -900, -500, 0, 63, 0, 255, 255, 255, 255 },
    { 500, -900, 500, 0, 127, 0, 255, 255, 255, 255 },
    { -500, -900, 500, 0, 191, 0, 255, 255, 255, 255 },
    { -500, -900, -500, 0, 0, 127, 255, 255, 255, 255 },
    { 500, -900, -500, 0, 63, 127, 255, 255, 255, 255 },
    { 500, -900, 500, 0, 127, 127, 255, 255, 255, 255 },
    { -500, -900, 500, 0, 191, 127, 255, 255, 255, 255 },
    { -500, -900, -500, 0, 0, 255, 255, 255, 255, 255 },
    { 500, -900, -500, 0, 63, 255, 255, 255, 255, 255 },
    { 500, -900, 500, 0, 127, 255, 255, 255, 255, 255 },
    { -500, -900, 500, 0, 191, 255, 255, 255, 255, 255 },
    { -500, -900, -500, 0, 0, 383, 255, 255, 255, 255 },
    { 500, -900, -500, 0, 63, 383, 255, 255, 255, 255 },
    { 500, -900, 500, 0, 127, 383, 255, 255, 255, 255 },
    { -500, -900, 500, 0, 191, 383, 255, 255, 255, 255 },
    { -500, -900, -500, 0, 0, 511, 255, 255, 255, 255 },
    { 500, -900, -500, 0, 63, 511, 255, 255, 255, 255 },
    { 500, -900, 500, 0, 127, 511, 255, 255, 255, 255 },
    { -500, -900, 500, 0, 191, 511, 255, 255, 255, 255 },
    { 0, 1029, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 1281, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 1286, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 1, 1538, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 2, 1543, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 2, 1795, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 3, 1796, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 3, 1024, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 4, 2057, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 4, 2309, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 5, 2314, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 5, 2566, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 2571, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 6, 2823, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 7, 2824, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 7, 2052, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 8, 3085, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 8, 3337, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 9, 3342, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 9, 3594, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 10, 3599, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 10, 3851, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 11, 3852, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 11, 3080, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 12, 4113, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 12, 4365, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 13, 4370, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 13, 4622, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 14, 4627, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 14, 4879, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 15, 4880, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 15, 4108, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 513, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 0, 515, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 4, 1541, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 4, 1543, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 8, 2569, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 8, 2571, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 12, 3597, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 12, 3599, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 16, 4625, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 16, 4627, 0, 0, 0, 0, 0, 0, 0, 0 },
    { 257, 257, 257, 257, 258, 514, 2, 2, 1, 1 },
    { 0, 0, 0, 0, 0, 0, 1, 1, 1, 1 },
    { 257, 0, 1, 515, 1024, 1286, 7, 8, 9, 10 },
    { 2829, 3344, 4370, 4884, 5655, 6169, 26, 15, 29, 32 },
    { 3855, 7196, 8448, 0, 16240, -23593, 63, 40, 245, 195 },
    { 16124, 27263, 16145, 26739, 16132, -25690, 63, 0, 0, 0 },
    { 16109, 3670, 16158, 13631, 16132, -25690, 62, 230, 102, 102 },
    { 16163, 21496, 16215, 36176, 16153, -26214, 62, 211, 116, 188 },
    { 16230, 26214, 16220, 44040, 16132, -25690, 63, 21, 194, 143 },
    { 16017, -5243, 16110, 5243, 16064, 0, 63, 64, 0, 0 },
    { 16138, 15729, 16157, 28836, 15897, -26214, 62, 234, 126, 250 },
    { 16075, 17302, 16192, 0, 16239, -8389, 63, 113, 235, 133 },
    { 16192, 0, 16192, 0, 16220, -21496, 63, 114, 110, 152 },
    { 16192, 0, 16192, 0, 16256, 0, 63, 69, 161, 203 },
    { 16247, -29360, 16247, 36176, 16272, -23593, 63, 54, 69, 162 },
    { 16260, -17302, 16193, 51905, 16102, 26214, 62, 54, 69, 162 },
    { 16109, 3670, 16153, 39322, 16083, 29884, 63, 102, 102, 102 },
    { 16220, -21496, 16132, 39846, 16149, -15729, 63, 14, 20, 123 },
    { 16110, 5243, 16064, 0, 16192, 0, 63, 10, 61, 113 },
    { 16157, 28836, 16130, 36700, 16106, 32506, 62, 203, 67, 150 },
    { 16192, 0, 16121, 56099, 16241, -5243, 63, 64, 0, 0 },
    { 16192, 0, 16220, 44040, 16142, -9961, 63, 64, 0, 0 },
};

void boneParticleEffect_initialise(void)
{
    int i;
    int j;

    gBoneParticleTextureA = textureLoadAsset(0x16b);
    gBoneParticleTextureB = textureLoadAsset(0x201);
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

extern void* Obj_GetActiveModel(void);
extern void PSMTXMultVec(void* m, void* src, void* dst);

#pragma peephole on
void boneParticleEffect_spawnAtBones(void* obj, int effectId, void* extraArg, u8 prob, short* src)
{
    void* model;
    int i;
    BoneSpawnData data;

    model = Obj_GetActiveModel();
    for (i = 0; i < *(u8*)(*(int*)model + 0xf3); i++)
    {
        if ((int)randomGetRange(1, 0x64) <= prob)
        {
            void* mtx;
            data.x = lbl_803DF4A8;
            data.y = lbl_803DF4A8;
            data.z = lbl_803DF4A8;
            data.scale = lbl_803DF4B8;
            data.unk4 = 0;
            data.unk2 = 0;
            data.unk0 = 0;
            mtx = ObjModel_GetJointMatrix(model, i);
            PSMTXMultVec(mtx, &data.x, &data.x);
            data.x = data.x - ((GameObject*)obj)->anim.worldPosX;
            data.y = data.y - ((GameObject*)obj)->anim.worldPosY;
            data.z = data.z - ((GameObject*)obj)->anim.worldPosZ;
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
                data.scale = lbl_803DF4B8;
                data.unk0 = 0;
                data.unk4 = 0;
                data.unk2 = 0;
                data.unk6 = 0;
            }
            (*gPartfxInterface)->spawnObject(obj, effectId, &data, 2, -1, extraArg);
        }
    }
}

/*__DATA_EXTERNS__*/
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* boneParticleEffect_funcs[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00080000, boneParticleEffect_initialise, boneParticleEffect_release, (void*)0x00000000, boneParticleEffect_func03_nop, boneParticleEffect_func04_nop, boneParticleEffect_spawnAtBones, boneParticleEffect_func06_nop, boneParticleEffect_update, boneParticleEffect_func08_nop, (void*)0x00000000 };
