#include "dlls/object_descriptor.h"
#include "main/newclouds_state.h"
#include "main/newclouds.h"
#include "main/newshadows.h"
#include "main/shader_api.h"
#include "main/texture.h"
#include "dolphin/gx/GXDispList.h"
#include "dolphin/gx/GXEnum.h"
#include "dolphin/os/OSCache.h"
#include "main/sky.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXLegacy.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/mtx.h"
#include "main/camera.h"
#include "main/object_transform.h"
#include "game/objects/object.h"
#include "main/dll/savegame_env_api.h"
#include "main/dll/savegame_load_api.h"
#include "main/gameloop_api.h"
#include "main/lightmap_api.h"
#include "main/model_light.h"
#include "main/mm.h"
#include "main/render_mode_api.h"
#include "main/vecmath.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "stdlib.h"
#include "string.h"
#include "track/intersect_api.h"
#include "track/intersect_render_setup_api.h"
#include "main/audio/music_api.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/trig_float_helpers.h"
#include "dolphin/mtx/vec.h"
#include "main/debug.h"
#include "main/hud_visibility_api.h"

u8 gNewCloudBlizzardActivePrev;
void* sNewCloudsTexture;
void* gNewCloudType1Texture;
u8 gNewCloudInitialized;
f32 gNewCloudScrollPhaseA;
f32 gNewCloudScrollPhaseB;
f32 gNewCloudScrollPhaseC;
f32 lbl_803DD1B0;
f32 gSnowFlakeWaveValue;
s16 gSnowFlakeWaveAngle;
int gNewCloudFlashRotAngle;
ModelLightStruct* gNewCloudModelLight;
LightningEffect* gActiveLightning;
u8 gNewCloudBlizzardActive;
u8 gNewCloudSnowFlashAlphaK1;
u8 gNewCloudSnowFlashAlphaK0;
u8 gNewCloudSnowFlashAlpha;
f32 gNewCloudOvercastFadeRate;
f32 gNewCloudSnowFlashScroll;

f32 gNewCloudOvercastFadeLevel = 1.0f;
f32 gNewCloudSnowFlashScale = 1.0f;
f32 gNewCloudSnowFlashParallax = 1.0f;
int gNewCloudWindSourcesInit = 1;

const GXColor gNewCloudSnowFogColor = {255, 255, 255, 255};
const GXColor gNewCloudLightningFogColor = {255, 255, 255, 255};

typedef struct {
    s16 uv[6];
} SnowFlakeUVs;
extern char sSnowFreeSnowCloudInvalidCloudId[];
typedef struct WindSource {
    s32 x;
    s32 z;
    f32 vx;
    f32 vy;
    f32 vz;
    f32 scale;
    s16 flag;
    s16 pad1a;
} WindSource;
#define NEWCLOUD_WIND_SOURCE_COUNT 6
extern NewCloud* gNewClouds[8];

#define NC_CLOUD (gNewClouds[((CloudSpawnParams*)params)->cloudIndex])
extern char sSnowPrintSnowCloudInvalidCloudId[];

static inline void snowFifoTexCoord2s16(s16 s, s16 t) {
    GXWGFifo.s16 = s;
    GXWGFifo.s16 = t;
}

f32 lightningGetRemainingFraction(void) {
    LightningEffect* state;
    u16 totalFrames;
    u16 currentFrame;

    state = gActiveLightning;
    if (state != NULL) {
        totalFrames = state->lifetime;
        currentFrame = state->timer;
        return (f32)(s32)(totalFrames - currentFrame) / totalFrames;
    }
    return 0.0f;
}

void lightningGetStartPos(Vec* out) {
    LightningEffect* state;

    state = gActiveLightning;
    if (state == NULL) {
        return;
    }
    out->x = state->start[0];
    out->y = gActiveLightning->start[1];
    out->z = gActiveLightning->start[2];
}

static void lightningDrawStrand(f32* from, f32* to, u8 width, f32 segScale, int* seed) {
    int segs;
    int savedRand;
    int i;
    f32 total;
    f32 len;
    f32 px;
    f32 py;
    f32 pz;
    f32 weight;
    f32 step;
    f32 mtx[12];
    f32 dir[3];
    f32 scaled[3];
    f32 up[3];
    f32 side[3];
    f32 offset[3];

    if (getHudHiddenFrameCount() == 0) {
        savedRand = rand();
        srand(*seed);
    }
    PSVECSubtract((Vec*)to, (Vec*)from, (Vec*)dir);
    len = PSVECMag((Vec*)dir);
    PSVECScale((Vec*)dir, (Vec*)scaled, 1.0f / len);
    if (__fabsf(scaled[0]) < 0.9f) {
        up[0] = 1.0f;
        up[1] = 0.0f;
        up[2] = 0.0f;
    } else {
        up[0] = 0.0f;
        up[1] = 0.0f;
        up[2] = 1.0f;
    }
    PSVECCrossProduct((Vec*)scaled, (Vec*)up, (Vec*)side);
    PSVECCrossProduct((Vec*)side, (Vec*)scaled, (Vec*)up);
    PSVECNormalize((Vec*)up, (Vec*)up);
    segs = (len * segScale);
    if (segs > 10) {
        segs = 10;
    }
    if (segs == 0) {
        segs = 1;
    }
    total = 0.0f;
    for (i = 0; i < segs; i++) {
        total += (i + 1);
    }
    weight = 1.0f / total;
    GXSetLineWidth(width, GX_TO_ONE);
    GXBegin(GX_LINESTRIP, GX_VTXFMT2, segs + 1);
    for (i = 0; i <= segs; i++) {
        if (i == 0) {
            f32 a0, a1, a2;
            a2 = from[2];
            a1 = from[1];
            a0 = from[0];
            GXWGFifo.f32 = a0;
            GXWGFifo.f32 = a1;
            GXWGFifo.f32 = a2;
            GXWGFifo.f32 = 0.0f;
            GXWGFifo.f32 = 0.0f;
            px = from[0];
            py = from[1];
            pz = from[2];
        } else if (i < segs) {
            f32 e0, e1, e2;
            PSVECScale((Vec*)up, (Vec*)offset, 0.01f * (0.075f * (len * randomGetRange(1, 100))));
            PSMTXRotAxisRad((MtxPtr)mtx, (Vec*)scaled, 3.142f * (2.0f * (0.001f * randomGetRange(0, 1000))));
            PSMTXMultVecSR((MtxPtr)mtx, (Vec*)offset, (Vec*)offset);
            px += scaled[0] * (step = weight * (len * (segs - i)));
            py += scaled[1] * step;
            pz += scaled[2] * step;
            e2 = pz;
            e2 += offset[2];
            e1 = py;
            e1 += offset[1];
            e0 = px;
            e0 += offset[0];
            GXWGFifo.f32 = e0;
            GXWGFifo.f32 = e1;
            GXWGFifo.f32 = e2;
            GXWGFifo.f32 = 0.0f;
            GXWGFifo.f32 = 0.0f;
        } else {
            f32 b0, b1, b2;
            b2 = to[2];
            b1 = to[1];
            b0 = to[0];
            GXWGFifo.f32 = b0;
            GXWGFifo.f32 = b1;
            GXWGFifo.f32 = b2;
            GXWGFifo.f32 = 0.0f;
            GXWGFifo.f32 = 0.0f;
        }
    }
    if (getHudHiddenFrameCount() == 0) {
        *seed = rand();
        srand(savedRand);
    }
}

static void lightningDrawBolt(f32* start, f32* end, u8 width, f32 segScale, f32 d, int* seed, int depth, u8 flags) {
    f32 len;
    f32 total;
    f32 py;
    f32 pz;
    f32 nx;
    f32 ny;
    f32 nz;
    f32 px;
    f32 weight;
    f32 progress;
    f32 step;
    f32 bfrac;
    int oddFlag;
    int halfWidth;
    int i;
    int j;
    int segs;
    f32 mtx[12];
    f32 dir[3];
    f32 scaled[3];
    f32 up[3];
    f32 side[3];
    f32 offset[3];
    f32 cur[3];
    f32 next[3];
    f32 branchEnd[3];

    if ((u32)depth > 2) {
        return;
    }
    PSVECSubtract((Vec*)end, (Vec*)start, (Vec*)dir);
    len = PSVECMag((Vec*)dir);
    PSVECScale((Vec*)dir, (Vec*)scaled, 1.0f / len);
    if (__fabsf(scaled[0]) < 0.9f) {
        up[0] = 1.0f;
        up[1] = 0.0f;
        up[2] = 0.0f;
    } else {
        up[0] = 0.0f;
        up[1] = 0.0f;
        up[2] = 1.0f;
    }
    PSVECCrossProduct((Vec*)scaled, (Vec*)up, (Vec*)side);
    PSVECCrossProduct((Vec*)side, (Vec*)scaled, (Vec*)up);
    PSVECNormalize((Vec*)up, (Vec*)up);
    segs = (len * segScale);
    if (segs > 10) {
        segs = 10;
    }
    if (segs == 0) {
        return;
    }
    total = 0.0f;
    for (j = 0; j < segs; j++) {
        total += (j + 1);
    }
    weight = 1.0f / total;
    px = start[0];
    py = start[1];
    pz = start[2];
    cur[0] = px;
    cur[1] = py;
    cur[2] = pz;
    progress = 0.0f;
    i = 0;
    oddFlag = flags & 1;
    halfWidth = width >> 1;
    for (; i <= segs; i++) {
        if (i < segs) {
            PSVECScale((Vec*)up, (Vec*)offset, 0.01f * (0.075f * (len * randomGetRange(1, 100))));
            PSMTXRotAxisRad((MtxPtr)mtx, (Vec*)scaled, 3.142f * (2.0f * (0.001f * randomGetRange(0, 1000))));
            PSMTXMultVecSR((MtxPtr)mtx, (Vec*)offset, (Vec*)offset);
            progress += weight * (segs - i);
            nx = px + scaled[0] * (step = weight * (len * (segs - i)));
            ny = py + scaled[1] * step;
            nz = pz + scaled[2] * step;
            next[0] = nx + offset[0];
            next[1] = ny + offset[1];
            next[2] = nz + offset[2];
            if (randomGetRange(1, 3) == 1 && width >= 0xc && oddFlag == 0) {
                PSVECScale((Vec*)up, (Vec*)offset, 0.01f * (0.3f * (len * randomGetRange(0x32, 0x64))));
                PSMTXRotAxisRad((MtxPtr)mtx, (Vec*)scaled, 3.142f * (2.0f * (0.001f * randomGetRange(0, 1000))));
                PSMTXMultVecSR((MtxPtr)mtx, (Vec*)offset, (Vec*)offset);
                bfrac = 0.001f * ((1.0f - progress) * randomGetRange(0, 1000)) + progress;
                PSVECScale((Vec*)scaled, (Vec*)branchEnd, bfrac * len);
                PSVECAdd((Vec*)start, (Vec*)branchEnd, (Vec*)branchEnd);
                PSVECAdd((Vec*)branchEnd, (Vec*)offset, (Vec*)branchEnd);
                lightningDrawBolt(next, branchEnd, halfWidth, segScale, d, seed, depth + 1, flags);
            }
        } else {
            next[0] = end[0];
            next[1] = end[1];
            next[2] = end[2];
        }
        lightningDrawStrand(cur, next, width, d, seed);
        px = nx;
        py = ny;
        pz = nz;
        cur[0] = next[0];
        cur[1] = next[1];
        cur[2] = next[2];
    }
}

void lightningRender(LightningEffect* p) {
    f32 start[3];
    f32 end[3];
    f32 diff[3];
    Texture* tex;
    int savedSeed;
    GXColor color;
    int timer;
    int lifetime;
    int half;

    color = gNewCloudLightningFogColor;
    start[0] = p->start[0] - playerMapOffsetX;
    start[1] = p->start[1];
    start[2] = p->start[2] - playerMapOffsetZ;
    end[0] = p->end[0] - playerMapOffsetX;
    end[1] = p->end[1];
    end[2] = p->end[2] - playerMapOffsetZ;
    timer = p->timer;
    lifetime = p->lifetime;
    half = (u32)lifetime >> 1;
    if (timer <= half) {
        _gxSetTevColor2(0x80, 0x80, 0xff, 0xff);
    } else {
        _gxSetTevColor2(0x80, 0x80, 0xff, (int)((255.0f * (lifetime - timer)) / half));
    }
    GXSetCullMode(GX_CULL_NONE);
    Camera_RebuildProjectionMatrix();
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    gxTevResetStages();
    gxTevColor1TexAlphaStage();
    gxTevCommitStages();
    gxSetAdditiveBlendZTest();
    newshadows_getLightningTexture(&tex);
    selectTexture(tex, 0);
    GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, color);
    Camera_UpdateViewMatrices();
    GXLoadPosMtxImm((MtxPtr)Camera_GetViewMatrix(), GX_PNMTX0);
    GXSetCurrentMtx(GX_PNMTX0);
    savedSeed = rand();
    if (p->seed == 0xffff) {
        p->seed = savedSeed;
    }
    srand(p->seed);
    PSVECSubtract((Vec*)end, (Vec*)start, (Vec*)diff);
    PSVECMag((Vec*)diff);
    lightningDrawBolt(start, end, p->width, p->radiusX, p->radiusY, &savedSeed, 0, p->flags);
    srand(savedSeed);
}

extern inline float sqrtf__inline(float x) {
    volatile float y;
    if (x > 0.0f) {
        double guess = __frsqrte((double)x);
        guess = .5 * guess * (3.0 - guess * guess * x);
        guess = .5 * guess * (3.0 - guess * guess * x);
        guess = .5 * guess * (3.0 - guess * guess * x);
        y = (float)(x * guess);
        return y;
    }
    return x;
}

/* CloudSpawnParams.flags58 / NewCloud.flags144A - spawn command / trigger bits */
#define NEWCLOUD_CMD_SPIN      0x1  /* enable cloud spin */
#define NEWCLOUD_CMD_SPAWN     0x2  /* create/spawn cloud */
#define NEWCLOUD_CMD_DESPAWN   0x4  /* despawn / finish toggle */
#define NEWCLOUD_CMD_RELOCATE  0x8  /* reposition existing cloud */
#define NEWCLOUD_CMD_ANCHOROBJ 0x10 /* anchor to object-B position */
#define NEWCLOUD_CMD_KILL      0x20 /* kill snow cloud */
#define NEWCLOUD_CMD_ROTFIXED  0x80 /* fixed flash rotation (cloudType 4) */

/* CloudSpawnParams.flags59 / NewCloud.lightningFlags - lightning cadence bits */
#define NEWCLOUD_LTG_SLOW 0x8  /* slow lightning cadence */
#define NEWCLOUD_LTG_MED  0x10 /* medium lightning cadence */
#define NEWCLOUD_LTG_FAST 0x20 /* fast lightning cadence */

void lightningRenderActive(void) {
    if (gActiveLightning != NULL) {
        lightningRender(gActiveLightning);
    }
}

LightningEffect* lightningCreate(const Vec3f* start, const Vec3f* end, f32 radiusX, f32 radiusY, u16 lifetime, u8 width,
                                 u8 flags) {
    LightningEffect* p = mmAlloc(40, 23, 0);

    if (p == NULL) {
        return NULL;
    }
    p->start[0] = start->x;
    p->start[1] = start->y;
    p->start[2] = start->z;
    p->end[0] = end->x;
    p->end[1] = end->y;
    p->end[2] = end->z;
    p->radiusX = radiusX;
    p->radiusY = radiusY;
    p->lifetime = lifetime;
    p->width = width;
    p->timer = 0;
    p->seed = 0xFFFF;
    p->flags = flags;
    return p;
}

void snowCloudBuildBoxVerts(f32* out, f32 height, f32 scale) {
    f32 side;
    f32 zero;
    f32 scaledHeight;
    f32 edge;

    side = -50.0f * scale;
    out[0] = side;
    zero = 0.0f;
    out[1] = zero;
    out[2] = side;
    out[3] = side;
    scaledHeight = height * scale;
    out[4] = scaledHeight;
    out[5] = side;
    edge = 50.0f * scale;
    out[6] = edge;
    out[7] = scaledHeight;
    out[8] = side;
    out[9] = edge;
    out[10] = zero;
    out[11] = side;
    out[12] = side;
    out[13] = zero;
    out[14] = edge;
    out[15] = side;
    out[16] = scaledHeight;
    out[17] = edge;
    out[18] = edge;
    out[19] = scaledHeight;
    out[20] = edge;
    out[21] = edge;
    out[22] = zero;
    out[23] = edge;
}
void mm_free_(void* ptr) {
    mm_free(ptr);
}

#define SNOW_FLAKE_SIZE 8.0f

Texture* gNewCloudLayerTextures[4];

void snowCloudInitFlakes(f32* buf, f32 a, f32 b, int cloudId) {
    NewCloud* p;
    SnowQuad* e;
    f32* dst;
    int i;
    int j;
    int widx;
    f32 amp;
    f32 halfNeg;
    f32 negSize;
    f32 size;
    f32 ab;

    ab = a * b;
    amp = ab / 1024.0f;
    for (i = 0; i < 8; i++) {
        p = gNewClouds[i];
        if (p != NULL && cloudId == p->cloudId) {
            break;
        }
    }
    p = gNewClouds[i];
    if (p == NULL || SNOW_FLAKE_SIZE == gSnowFlakeWaveValue) {
        return;
    }
    if (cloudId != p->cloudId) {
        debugPrintf(sSnowFreeSnowCloudInvalidCloudId, cloudId);
        return;
    }
    if (p->cloudType == 4) {
        size = SNOW_FLAKE_SIZE;
    } else {
        size = 16.0f;
    }
    j = 0;
    e = p->quads;
    negSize = -size;
    halfNeg = 64.0f * negSize;
    for (; j < 20; j++) {
        e->verts[0] = negSize;
        e->verts[6] = 0.0f;
        e->verts[1] = size;
        e->verts[7] = 0.0f;
        e->verts[2] = 0.0f;
        e->verts[8] = 0.0f;
        if (gNewClouds[i]->cloudType == 0) {
            e->verts[3] = negSize;
            e->verts[4] = negSize;
            e->verts[5] = size;
        } else {
            e->verts[3] = negSize;
            e->verts[4] = negSize;
            e->verts[5] = halfNeg;
        }
        e->angA = randomGetRange(0, 0xffff);
        e->angB = randomGetRange(0, 0xffff);
        e->angVelA = randomGetRange(0x96, 0x1f4);
        e->angVelB = randomGetRange(0x96, 0x1f4);
        e += 1;
    }
    widx = gNewClouds[i]->waveWriteIdx;
    dst = buf + widx;
    while (widx < gNewClouds[i]->waveWriteIdx + 0xfa0) {
        if (widx == 0x400) {
            gNewClouds[i]->active = 0;
            gNewClouds[i]->waveWriteIdx = 0;
            return;
        }
        if (widx == 0) {
            gSnowFlakeWaveAngle = 0;
            gSnowFlakeWaveValue = 0.0f;
            lbl_803DD1B0 = 0.0f;
        }
        mathSinf((3.14159265f * gSnowFlakeWaveAngle) / 32768.0f);
        mathCosf((3.14159265f * gSnowFlakeWaveAngle) / 32768.0f);
        *dst = gSnowFlakeWaveValue * amp;
        gSnowFlakeWaveAngle += 127.99805f;
        gSnowFlakeWaveValue += 1.0f;
        dst++;
        widx++;
    }
    gNewClouds[i]->waveWriteIdx = gNewClouds[i]->waveWriteIdx + 0xfa0;
}

void snowFreeSnowCloud(int cloudId) {
    SaveGameEnvState* env;
    NewCloud* p;
    int i;

    env = saveGameGetEnvState();
    if (cloudId >= 0 && cloudId <= 2 && getSaveGameLoadStatus() == 0) {
        env->cloudEnvfxActIds[cloudId] = -1;
        env->cloudStationary[cloudId] = -1;
    }
    for (i = 0; i < 8; i++) {
        p = gNewClouds[i];
        if (p != NULL && cloudId == p->cloudId) {
            break;
        }
    }
    p = gNewClouds[i];
    if (p == NULL || i == 8) {
        return;
    }
    if (cloudId != p->cloudId) {
        debugPrintf(sSnowFreeSnowCloudInvalidCloudId, cloudId);
        return;
    }
    if (p->flakes != NULL) {
        mm_free(p->flakes);
        gNewClouds[i]->flakes = NULL;
    }
    if (gNewClouds[i] != NULL) {
        mm_free(gNewClouds[i]);
        gNewClouds[i] = NULL;
    }
}

void dll_07_func0A_nop(void) {
}

extern WindSource gNewCloudWindSources[NEWCLOUD_WIND_SOURCE_COUNT];

typedef struct {
    f32 v[3];
} SnowVec3;

const SnowVec3 sNewCloudDefaultStartPos = {{0.0f, 0.0f, 0.0f}};
const SnowVec3 sNewCloudDefaultEndPos = {{0.0f, 0.0f, 0.0f}};
const SnowVec3 sSnowCloudDefaultDirection = {{0.0f, 0.0f, 0.0f}};

static const SnowFlakeUVs kSnowFlakeUVs = {{-48, 0, 176, 0, 64, 256}};

int snowPrintSnowCloud(void* arg, int cloudId) {
    NewCloud* p;
    SnowFlake* part;
    int i;
    int j;
    u8 hudHidden;
    int texIdx;
    int ct;
    f32 scale;
    f32 driftX;
    f32 driftZ;
    f32 stepX;
    f32 stepZ;
    f32 quadOffsetX;
    f32 quadOffsetY;
    f32 quadOffsetZ;
    f32 yb;
    f32 mtxB[16];
    f32 mtxT[12];
    f32 mtxA[16];
    f32 mtxOut[16];
    f32 vx[3];
    f32 vy[3];
    f32 vz[3];
    struct {
        u8 cb;
        u8 cg;
        u8 cr;
        SnowFlakeUVs uvs;
    } attr;
    s16 us;
    s16 ut;
    f32* qx;
    f32* qy;
    f32* qz;
    s16* puv;

    attr.uvs = kSnowFlakeUVs;
    qx = (f32*)vx;
    qy = (f32*)vy;
    qz = (f32*)vz;
    scale = 1.0f;
    if (renderModeSetOrGet(-1) == 1) {
        return 0;
    }
    for (i = 0; i < 8; i++) {
        p = gNewClouds[i];
        if (p != NULL && cloudId == p->cloudId) {
            break;
        }
    }
    p = gNewClouds[i];
    if (p == NULL || i == 8) {
        return 0;
    }
    if (cloudId != p->cloudId) {
        debugPrintf(sSnowPrintSnowCloudInvalidCloudId, cloudId);
        return 0;
    }
    gNewCloudFlashRotAngle = 100.0f * timeDelta + gNewCloudFlashRotAngle;
    if (gNewCloudFlashRotAngle > 0xffff) {
        gNewCloudFlashRotAngle = 0;
    }
    scale *= 0.125f;
    initRotationMtx(mtxA, scale, scale, scale);
    memset(mtxB, 0, 0x40);
    mtxB[0] = 1.0f;
    mtxB[5] = 1.0f;
    mtxB[10] = 1.0f;
    mtxB[15] = 1.0f;
    ct = p->cloudType;
    if (ct != 4 && p->spinEnabled != 0) {
        mtxB[0] = mathCosf((3.14159265f * gNewCloudFlashRotAngle) / 32768.0f);
        mtxB[1] = -mathSinf((3.14159265f * gNewCloudFlashRotAngle) / 32768.0f);
        mtxB[4] = mathSinf((3.14159265f * gNewCloudFlashRotAngle) / 32768.0f);
        mtxB[5] = mathCosf((3.14159265f * gNewCloudFlashRotAngle) / 32768.0f);
    } else if (ct == 4) {
        if (p->flags144A & NEWCLOUD_CMD_ROTFIXED) {
            mtxB[0] = mathCosf(-0.5752428f);
            mtxB[1] = -mathSinf(-0.5752428f);
            mtxB[4] = mathSinf(-0.5752428f);
            mtxB[5] = mathCosf(-0.5752428f);
        } else if (p->spinEnabled != 0) {
            gNewCloudFlashRotAngle = 6000.0f * (p->driftOffset / 10.0f) + 3000.0f;
            mtxB[0] = mathCosf((3.14159265f * -gNewCloudFlashRotAngle) / 32768.0f);
            mtxB[1] = -mathSinf((3.14159265f * -gNewCloudFlashRotAngle) / 32768.0f);
            mtxB[4] = mathSinf((3.14159265f * -gNewCloudFlashRotAngle) / 32768.0f);
            mtxB[5] = mathCosf((3.14159265f * -gNewCloudFlashRotAngle) / 32768.0f);
        }
    }
    mtxB[12] = p->worldPosX - playerMapOffsetX;
    mtxB[13] = p->worldPosY;
    mtxB[14] = p->worldPosZ - playerMapOffsetZ;
    mtx44_mult(mtxA, mtxB, mtxOut);
    mtx44Transpose(mtxOut, mtxT);
    PSMTXConcat((MtxPtr)Camera_GetViewMatrix(), (MtxPtr)mtxT, (MtxPtr)mtxT);
    GXLoadPosMtxImm((MtxPtr)mtxT, GX_PNMTX0);
    texIdx = 0;
    selectTexture((Texture*)(p->cloudType == 0 ? gNewCloudLayerTextures[0] : gNewCloudType1Texture), 0);
    GXSetCullMode(GX_CULL_NONE);
    gxTevResetStages();
    gxTevTextureTimesColor1Stage();
    gxTevCommitStages();
    if (p->cloudType == 4) {
        setTextColor(arg, 0x7d, 0x7d, 0x9b, 0xff);
    } else if (p->cloudType == 0) {
        skyGetSunColor(0, &attr.cr, &attr.cg, &attr.cb);
        setTextColor(arg, attr.cr, attr.cg, attr.cb, 0xff);
    }
    gxSetAlphaBlendZTest();
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCurrentMtx(GX_PNMTX0);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    hudHidden = getHudHiddenFrameCount();
    driftX = SNOW_FLAKE_SIZE * (p->curPosX - p->lastPosX);
    stepX = (driftX < 0.5f * p->flakeMinX) ? 0.5f * p->flakeMinX
                                           : ((driftX > 0.5f * p->driftSpeed) ? 0.5f * p->driftSpeed : driftX);
    driftZ = SNOW_FLAKE_SIZE * (p->curPosZ - p->lastPosZ);
    stepZ = (driftZ < 0.5f * p->flakeMinZ) ? 0.5f * p->flakeMinZ
                                           : ((driftZ > 0.5f * p->flakeMaxZ) ? 0.5f * p->flakeMaxZ : driftZ);
    if (p->cloudType == 4) {
        GXBegin(GX_TRIANGLES, GX_VTXFMT4, (p->flakeCount * 3));
    } else {
        GXBegin(GX_TRIANGLES, GX_VTXFMT4, (p->flakeCount * 3 / 4));
    }
    for (j = 0, part = p->flakes; j < p->flakeCount; j++) {
        if (part->texLayer != (u8)texIdx) {
            texIdx = part->texLayer;
            selectTexture(gNewCloudLayerTextures[texIdx], 0);
            GXBegin(GX_TRIANGLES, GX_VTXFMT4, (p->flakeCount * 3 / 4));
        }
        if (hudHidden == 0) {
            if (p->stationary == 0) {
                part->x += stepX;
                part->z += stepZ;
            }
            part->x = p->windVelX * timeDelta + part->x;
            part->z = p->windVelZ * timeDelta + part->z;
            if (part->x < p->flakeMinX) {
                part->x = 2.0f * p->driftSpeed + part->x;
            } else if (part->x > p->driftSpeed) {
                part->x = part->x - 2.0f * p->driftSpeed;
            }
            if (part->z < p->flakeMinZ) {
                part->z = 2.0f * p->flakeMaxZ + part->z;
            } else if (part->z > p->flakeMaxZ) {
                part->z = part->z - 2.0f * p->flakeMaxZ;
            }
        }
        yb = part->y - *(f32*)((u8*)p + part->angle * 4 + 8);
        quadOffsetX = ((f32*)p)[part->quadIndex * 11 + 1026];
        vx[0] = quadOffsetX * part->fallSpeed + part->x;
        quadOffsetY = ((f32*)p)[part->quadIndex * 11 + 1029];
        vy[0] = quadOffsetY * part->fallSpeed + yb;
        quadOffsetZ = ((f32*)p)[part->quadIndex * 11 + 1032];
        vz[0] = quadOffsetZ * part->fallSpeed + part->z;
        quadOffsetX = ((f32*)p)[part->quadIndex * 11 + 1027];
        vx[1] = quadOffsetX * part->fallSpeed + part->x;
        quadOffsetY = ((f32*)p)[part->quadIndex * 11 + 1030];
        vy[1] = quadOffsetY * part->fallSpeed + yb;
        quadOffsetZ = ((f32*)p)[part->quadIndex * 11 + 1033];
        vz[1] = quadOffsetZ * part->fallSpeed + part->z;
        quadOffsetX = ((f32*)p)[part->quadIndex * 11 + 1028];
        vx[2] = quadOffsetX * part->fallSpeed + part->x;
        quadOffsetY = ((f32*)p)[part->quadIndex * 11 + 1031];
        vy[2] = quadOffsetY * part->fallSpeed + yb;
        quadOffsetZ = ((f32*)p)[part->quadIndex * 11 + 1034];
        vz[2] = quadOffsetZ * part->fallSpeed + part->z;
        puv = attr.uvs.uv;
        GXWGFifo.f32 = (f64)qx[0];
        GXWGFifo.f32 = (f64)qy[0];
        GXWGFifo.f32 = (f64)qz[0];
        ut = puv[1];
        us = puv[0];
        snowFifoTexCoord2s16(us, ut);
        puv += 2;
        GXWGFifo.f32 = (f64)qx[1];
        GXWGFifo.f32 = (f64)qy[1];
        GXWGFifo.f32 = (f64)qz[1];
        ut = puv[1];
        us = puv[0];
        snowFifoTexCoord2s16(us, ut);
        puv += 2;
        GXWGFifo.f32 = (f64)qx[2];
        GXWGFifo.f32 = (f64)qy[2];
        GXWGFifo.f32 = (f64)qz[2];
        ut = puv[1];
        us = puv[0];
        snowFifoTexCoord2s16(us, ut);
        part += 1;
    }
    return 0;
}

NewCloud* gNewClouds[8];
WindSource gNewCloudWindSources[NEWCLOUD_WIND_SOURCE_COUNT];
f32 gNewCloudSnowFlashDirection[4];

extern char sSnowCloudErrorMessageBlock[];

void snowCloudUpdateFlakes(NewCloud* snow) {
    Camera* cam;
    SnowQuad* e;
    f32* m;
    int i;
    int c;
    f32 c1;
    f32 s1;
    f32 c2;
    f32 s2;
    f32 c3;
    f32 s3;

    cam = Camera_GetCurrent();
    e = snow->quads;
    if (snow->cloudType == 0) {
        for (i = 0; i < 20; i++) {
            f32 size = 16.0f;
            f32 negSize = -size;
            m = e->verts;
            m[0] = negSize;
            m[3] = negSize;
            m[6] = 0.0f;
            m[1] = size;
            m[4] = negSize;
            m[7] = 0.0f;
            m[2] = 0.0f;
            m[5] = size;
            m[8] = 0.0f;
            e->angA = timeDelta * (f32)e->angVelA + (f32)e->angA;
            e->angB = timeDelta * (f32)e->angVelB + (f32)e->angB;
            angleToVec2((u16)(0xffff - cam->yaw), &c1, &s1);
            angleToVec2(e->angA, &c2, &s2);
            angleToVec2(e->angB, &c3, &s3);
            for (c = 0; c < 3; c++) {
                f32 t2;
                f32 m0 = m[c];
                f32 m1 = m[c + 3];
                f32 m2 = m[c + 6];
                f32 t1 = m0 * s3 - m1 * c3;
                t2 = m0 * c3 + m1 * s3;
                m[c] = t1 * s1 + c1 * (t2 * c2) + c1 * (m2 * s2);
                m[c + 3] = t2 * s2 + -m2 * c2;
                m[c + 6] = -t1 * c1 + s1 * (t2 * c2) + s1 * (m2 * s2);
            }
            e += 1;
        }
    } else {
        f32 size2;
        f32 negSize2;
        angleToVec2((u16)(0xffff - cam->yaw), &c1, &s1);
        m = (f32*)snow->quads;
        size2 = SNOW_FLAKE_SIZE;
        negSize2 = -size2;
        for (i = 0; i < 20; i++) {
            m[0] = negSize2 * s1;
            m[6] = size2 * c1;
            m[1] = size2 * s1;
            m[7] = size2 * -c1;
            m += 0xb;
        }
    }
}

static void snowReposSnowCloud(int cloudId) {
    NewCloud* p;
    SnowFlake* part;
    Camera* cam;
    f32* m;
    NewCloud* q;
    int i;
    int j;
    int dx;
    int dy;
    int dz;
    int distSq;
    u8 fl;
    MatrixTransform args;
    f32 dir[3];
    f32 fwd[3];
    f32 from[3];
    f32 to[3];

    *(SnowVec3*)dir = sSnowCloudDefaultDirection;
    if (renderModeSetOrGet(-1) == 1) {
        return;
    }
    srand(randomGetRange(1, 0xffff));
    for (i = 0; i < 8; i++) {
        p = gNewClouds[i];
        if (p != NULL && cloudId == p->cloudId) {
            break;
        }
    }
    p = gNewClouds[i];
    if (p == NULL || i == 8) {
        return;
    }
    if (cloudId != p->cloudId) {
        debugPrintf(sSnowCloudErrorMessageBlock, cloudId);
        return;
    }
    part = p->flakes;
    cam = Camera_GetCurrent();
    dx = cam->worldX - gNewClouds[i]->worldPosX;
    dy = cam->worldY - gNewClouds[i]->worldPosY;
    dz = cam->worldZ - gNewClouds[i]->worldPosZ;
    distSq = dx * dx + dy * dy + dz * dz;
    sqrtf__inline((f32)distSq);
    gNewClouds[i]->lightningTimer = (f32)gNewClouds[i]->lightningTimer - timeDelta;
    q = gNewClouds[cloudId];
    if (q->cloudType == 4 && (q->lightningFlags & 0x38) != 0 && q->lightningTimer <= 0 && q->stationary == 0 &&
        gActiveLightning == 0) {
        if (q->followCamera != 0 && cam != NULL) {
            dir[0] = 0.0f;
            dir[1] = 0.0f;
            dir[2] = 400.0f;
            args.x = 0.0f;
            args.y = 0.0f;
            args.z = 0.0f;
            args.scale = 1.0f;
            args.rotZ = 0;
            args.rotY = 0;
            args.rotX = 0xffff - (cam->yaw + randomGetRange(-5000, 5000));
            vecRotateZXY(&args.rotX, dir);
        }
        args.x = dir[0];
        args.y = dir[1];
        args.z = dir[2];
        args.scale = 1.0f;
        args.rotX = 0;
        args.rotZ = 0;
        args.rotY = 0;
        m = Camera_GetViewMatrix();
        fwd[0] = m[8];
        fwd[1] = m[9];
        fwd[2] = m[10];
        PSVECNormalize((Vec*)fwd, (Vec*)fwd);
        from[0] = (cam->worldX + (int)randomGetRange(-3000, 3000)) - 7000.0f * fwd[0];
        from[1] = (cam->worldY + (int)randomGetRange(2000, 4000)) - 7000.0f * fwd[1];
        from[2] = (cam->worldZ + (int)randomGetRange(-3000, 3000)) - 7000.0f * fwd[2];
        to[0] = (cam->worldX + (int)randomGetRange(-3000, 3000)) - 7000.0f * fwd[0];
        to[1] = (cam->worldY - (int)randomGetRange(2000, 4000)) - 7000.0f * fwd[1];
        to[2] = (cam->worldZ + (int)randomGetRange(-3000, 3000)) - 7000.0f * fwd[2];
        gActiveLightning = lightningCreate((const Vec3f*)from, (const Vec3f*)to, 0.002f, 0.01f, 0xf, 0xc0, 0);
        {
            Sfx_PlayAtPositionFromObject(0, from[0], from[1], from[2], SFXTRIG_barrelgrabber_suck);
        }
        fl = gNewClouds[cloudId]->lightningFlags;
        if (fl & NEWCLOUD_LTG_SLOW) {
            gNewClouds[cloudId]->lightningTimer = randomGetRange(0x78, 0xf0);
        } else if (fl & NEWCLOUD_LTG_MED) {
            gNewClouds[cloudId]->lightningTimer = randomGetRange(0x78, 0xf0);
        } else if (fl & NEWCLOUD_LTG_FAST) {
            gNewClouds[cloudId]->lightningTimer = randomGetRange(0x5a, 0xb4);
        }
    }
    snowCloudUpdateFlakes(gNewClouds[i]);
    for (j = 0; j < gNewClouds[i]->flakeCount; j++) {
        if (gNewClouds[i]->cloudType == 0) {
            part->angle = part->angle + part->size * framesThisStep;
            if ((int)part->angle > 0x3ff) {
                part->angle -= 0x3ff;
            }
        } else if (gNewClouds[i]->cloudType == 4) {
            part->angle = part->angle + framesThisStep * (part->size + part->size);
            if ((int)part->angle > 0x3ff) {
                part->angle -= 0x3ff;
            }
        }
        part += 1;
    }
}

extern char sSnowKillSnowCloudInvalidCloudId[];

void snowCloudComputeDrift(f32* out, f32* pos, f32 scale) {
    f32 accX;
    f32 accZ;
    f32 delta;
    f32 dxSq;
    f32 dSq;
    f32 dists[NEWCLOUD_WIND_SOURCE_COUNT];
    int i;

    if (renderModeSetOrGet(-1) == 1) {
        return;
    }
    accX = 0.0f;
    accZ = 0.0f;
    for (i = 0; i < NEWCLOUD_WIND_SOURCE_COUNT; i++) {
        delta = gNewCloudWindSources[i].x - pos[0];
        dxSq = delta * delta;
        delta = gNewCloudWindSources[i].z - pos[2];
        delta *= delta;
        dSq = dxSq + delta;
        if (dSq) {
            dists[i] = sqrtf__inline(dSq);
        } else {
            dists[i] = 0.0f;
        }
        if (dists[i] < 50.0f) {
            dists[i] = 50.0f;
        }
    }
    for (i = 0; i < NEWCLOUD_WIND_SOURCE_COUNT; i++) {
        dists[i] = 1.0f / sqrtf__inline(dists[i]);
    }
    for (i = 0; i < NEWCLOUD_WIND_SOURCE_COUNT; i++) {
        accX += gNewCloudWindSources[i].vx * dists[i];
        accZ += gNewCloudWindSources[i].vz * dists[i];
    }
    out[0] = -accX;
    out[2] = -accZ;
    out[1] = 0.0f;
    normalize(out, out + 1, out + 2);
    out[0] *= scale;
    out[1] = 0.0f;
    out[2] *= scale;
}

u8 lbl_8030F500[160] = {255, 206, 0,   0,   255, 206, 255, 206, 0, 100, 255, 206, 0, 50,  0, 100, 255, 206, 0, 50,
                        0,   0,   255, 206, 255, 206, 0,   0,   0, 50,  255, 206, 0, 100, 0, 50,  0,   50,  0, 100,
                        0,   50,  0,   50,  0,   0,   0,   50,  0, 0,   0,   0,   0, 0,   0, 6,   0,   0,   0, 2,
                        0,   0,   0,   8,   0,   0,   0,   2,   0, 0,   0,   16,  0, 0,   0, 8,   0,   0,   0, 32,
                        0,   0,   0,   40,  0,   0,   0,   48,  0, 0,   0,   1,   0, 0,   0, 2,   0,   0,   0, 2,
                        0,   0,   0,   4,   0,   0,   0,   3,   0, 0,   0,   6,   0, 0,   0, 6,   0,   0,   0, 12,
                        0,   0,   0,   12,  0,   0,   0,   24,  0, 0,   0,   24,  0, 0,   0, 32,  0,   0,   0, 32,
                        0,   0,   0,   40,  0,   0,   0,   40,  0, 0,   0,   48,  0, 0,   0, 48,  0,   0,   0, 56};

#define NC_PARTS (gNewClouds[id]->flakes)

#undef NC_CLOUD
#define NC_CLOUD (gNewClouds[id])
void newClouds(CloudSpawnParams* params, void* owner, f32 x, f32 y, f32 z) {
    char* strs;
    int id;
    int ok;
    int i;
    u8 fl;
    int(*sizeRange)[2];
    int(*spinRange)[2];

    strs = (char*)lbl_8030F500;
    ok = 1;
    id = params->cloudIndex;
    if (gNewClouds[id] != NULL) {
        snowFreeSnowCloud(id);
    }
    gNewClouds[id] = mmAlloc(sizeof(NewCloud), 0x17, 0);
    if (gNewClouds[id] == NULL) {
        debugPrintf(strs + 0x1b0);
        return;
    }
    memset(gNewClouds[id], 0, sizeof(NewCloud));
    NC_CLOUD->cloudId = id;
    NC_CLOUD->posInitialized = 0;
    NC_CLOUD->cloudType = params->cloudType;
    gNewClouds[id]->owner = owner;
    NC_CLOUD->flags144A = params->flags58;
    NC_CLOUD->lightningFlags = params->flags59;
    NC_CLOUD->worldPosX = x;
    NC_CLOUD->worldPosY = y;
    NC_CLOUD->worldPosZ = z;
    if (params->flags58 & NEWCLOUD_CMD_SPIN) {
        NC_CLOUD->spinEnabled = 1;
    }
    if (params->flags58 & NEWCLOUD_CMD_ANCHOROBJ) {
        NC_CLOUD->anchoredToObj = 1;
    }
    NC_CLOUD->followCamera = 1;
    NC_CLOUD->stationary = params->stationaryInit;
    if (NC_CLOUD->cloudType == 0) {
        NC_CLOUD->flakeCount = params->flakeCount << 3;
    } else {
        NC_CLOUD->flakeCount = params->flakeCount;
    }
    if (params->fillDivisor != 0) {
        NC_CLOUD->flakeFillRate = (f32)NC_CLOUD->flakeCount / (f32)params->fillDivisor;
    } else {
        NC_CLOUD->flakeFillRate = NC_CLOUD->flakeCount;
    }
    if (params->drainDivisor != 0) {
        NC_CLOUD->flakeDrainRate = (f32)NC_CLOUD->flakeCount / (f32)params->drainDivisor;
    } else {
        NC_CLOUD->flakeDrainRate = NC_CLOUD->flakeCount;
    }
    NC_CLOUD->driftScale = params->driftMax;
    if (NC_CLOUD->cloudType == 0) {
        NC_CLOUD->cloudHeight = 35.0f;
        NC_CLOUD->scale = 28.0f;
    } else {
        NC_CLOUD->cloudHeight = params->heightBase;
        NC_CLOUD->scale = SNOW_FLAKE_SIZE * params->driftBase;
    }
    if (params->driftMax < 1.0f) {
        params->driftMax = 0.0f;
    }
    if (params->driftMax != 0.0f) {
        NC_CLOUD->driftRate = 0.1f;
        {
            int r = randomGetRange(1, params->driftMax);
            NC_CLOUD->driftLimit = r / 2.0f;
        }
    }
    NC_CLOUD->active = 1;
    fl = NC_CLOUD->lightningFlags;
    if (fl & NEWCLOUD_LTG_SLOW) {
        NC_CLOUD->lightningTimer = 0x320;
    } else if (fl & NEWCLOUD_LTG_MED) {
        NC_CLOUD->lightningTimer = 0xc8;
    } else if (fl & NEWCLOUD_LTG_FAST) {
        NC_CLOUD->lightningTimer = 0x64;
    }
    snowCloudInitFlakes((f32*)NC_CLOUD->unk0008, NC_CLOUD->cloudHeight, NC_CLOUD->scale, id);
    snowCloudBuildBoxVerts(&NC_CLOUD->flakeMinX, NC_CLOUD->cloudHeight, NC_CLOUD->scale);
    gNewClouds[id]->flakes = mmAlloc(gNewClouds[id]->flakeCount * sizeof(SnowFlake), 0x17, 0);
    if (gNewClouds[id]->flakes == NULL) {
        ok = 0;
    }
    if (ok == 0) {
        debugPrintf(strs + 0x1f0);
        mm_free(gNewClouds[id]);
        gNewClouds[id] = NULL;
        return;
    }
    for (i = 0; i < NC_CLOUD->flakeCount; i++) {
        NC_PARTS[i].x = (int)randomGetRange((int)NC_CLOUD->flakeMinX, NC_CLOUD->flakeMaxX);
        NC_PARTS[i].y = NC_CLOUD->flakeCenterY;
        NC_PARTS[i].z = (int)randomGetRange((int)NC_CLOUD->flakeMinZ, NC_CLOUD->flakeMaxZ);
        NC_PARTS[i].angle = randomGetRange(0, 0x3d0);
        NC_PARTS[i].quadIndex = randomGetRange(0, 0x13);
        if (NC_CLOUD->cloudType == 0) {
            sizeRange = (int(*)[2])(strs + 0x58);
            NC_PARTS[i].size = (randomGetRange(sizeRange[params->sizeClass][0], sizeRange[params->sizeClass][1]) / 4);
            NC_PARTS[i].fallSpeed = (int)randomGetRange(0x4b, 0x64) / 100.0f;
            NC_PARTS[i].texLayer = (i / (NC_CLOUD->flakeCount / 4));
        } else {
            sizeRange = (int(*)[2])(strs + 0x58);
            NC_PARTS[i].size = (randomGetRange(sizeRange[params->sizeClass][0], sizeRange[params->sizeClass][1]) * 2);
            NC_PARTS[i].fallSpeed = 1.0f;
            NC_PARTS[i].texLayer = 0;
        }
        if (NC_PARTS[i].size < 1) {
            NC_PARTS[i].size = 1;
        }
        spinRange = (int(*)[2])(strs + 0x30);
        NC_PARTS[i].spin = (((int(*)[2])(strs + 0x30))[params->spinClass][1] / 2 -
                            randomGetRange(spinRange[params->spinClass][0], spinRange[params->spinClass][1]));
    }
    if (gNewCloudWindSourcesInit != 0) {
        gNewCloudWindSources[0].x = 0x31e;
        gNewCloudWindSources[0].z = 0xa9c;
        gNewCloudWindSources[0].vx = -100.0f;
        gNewCloudWindSources[0].vy = 0.0f;
        gNewCloudWindSources[0].vz = 0.0f;
        normalize(&gNewCloudWindSources[0].vx, &gNewCloudWindSources[0].vy, &gNewCloudWindSources[0].vz);
        gNewCloudWindSources[0].scale = 1.0f;
        gNewCloudWindSources[0].flag = 0;
        gNewCloudWindSources[1].x = 0x3c5;
        gNewCloudWindSources[1].z = 0xb72;
        gNewCloudWindSources[1].vx = 0.0f;
        gNewCloudWindSources[1].vy = 0.0f;
        gNewCloudWindSources[1].vz = -100.0f;
        normalize(&gNewCloudWindSources[1].vx, &gNewCloudWindSources[1].vy, &gNewCloudWindSources[1].vz);
        gNewCloudWindSources[1].scale = 1.0f;
        gNewCloudWindSources[1].flag = 0;
        gNewCloudWindSources[2].x = 0x335;
        gNewCloudWindSources[2].z = 0xe13;
        gNewCloudWindSources[2].vx = 100.0f;
        gNewCloudWindSources[2].vy = 0.0f;
        gNewCloudWindSources[2].vz = 0.0f;
        normalize(&gNewCloudWindSources[2].vx, &gNewCloudWindSources[2].vy, &gNewCloudWindSources[2].vz);
        gNewCloudWindSources[2].scale = 1.0f;
        gNewCloudWindSources[2].flag = 0;
        gNewCloudWindSources[3].x = 0x254;
        gNewCloudWindSources[3].z = 0xc70;
        gNewCloudWindSources[3].vx = 0.0f;
        gNewCloudWindSources[3].vy = 0.0f;
        gNewCloudWindSources[3].vz = 100.0f;
        normalize(&gNewCloudWindSources[3].vx, &gNewCloudWindSources[3].vy, &gNewCloudWindSources[3].vz);
        gNewCloudWindSources[3].scale = 1.0f;
        gNewCloudWindSources[3].flag = 0;
        gNewCloudWindSources[4].x = 0x107;
        gNewCloudWindSources[4].z = 0xb4a;
        gNewCloudWindSources[4].vx = 100.0f;
        gNewCloudWindSources[4].vy = 0.0f;
        gNewCloudWindSources[4].vz = 0.001f;
        normalize(&gNewCloudWindSources[4].vx, &gNewCloudWindSources[4].vy, &gNewCloudWindSources[4].vz);
        gNewCloudWindSources[4].scale = 1.0f;
        gNewCloudWindSources[4].flag = 0;
        gNewCloudWindSources[5].x = 0x68;
        gNewCloudWindSources[5].z = 0xdf6;
        gNewCloudWindSources[5].vx = 0.0f;
        gNewCloudWindSources[5].vy = 0.0f;
        gNewCloudWindSources[5].vz = -100.0f;
        normalize(&gNewCloudWindSources[5].vx, &gNewCloudWindSources[5].vy, &gNewCloudWindSources[5].vz);
        gNewCloudWindSources[5].scale = 1.0f;
        gNewCloudWindSources[5].flag = 0;
        gNewCloudWindSources[0].x = 0x31e;
        gNewCloudWindSources[0].z = 0xa9c;
        gNewCloudWindSources[0].vx = 0.0f;
        gNewCloudWindSources[0].vy = 0.0f;
        gNewCloudWindSources[0].vz = 0.0f;
        gNewCloudWindSources[0].scale = 0.0f;
        gNewCloudWindSources[0].flag = 0;
        gNewCloudWindSources[1].x = 0x3c5;
        gNewCloudWindSources[1].z = 0xb72;
        gNewCloudWindSources[1].vx = 0.0f;
        gNewCloudWindSources[1].vy = 0.0f;
        gNewCloudWindSources[1].vz = 0.0f;
        gNewCloudWindSources[1].scale = 0.0f;
        gNewCloudWindSources[1].flag = 0;
        gNewCloudWindSources[2].x = 0x335;
        gNewCloudWindSources[2].z = 0xe13;
        gNewCloudWindSources[2].vx = 0.0f;
        gNewCloudWindSources[2].vy = 0.0f;
        gNewCloudWindSources[2].vz = 0.0f;
        gNewCloudWindSources[2].scale = 0.0f;
        gNewCloudWindSources[2].flag = 0;
        gNewCloudWindSources[3].x = 0x254;
        gNewCloudWindSources[3].z = 0xc70;
        gNewCloudWindSources[3].vx = 0.0f;
        gNewCloudWindSources[3].vy = 0.0f;
        gNewCloudWindSources[3].vz = 0.0f;
        gNewCloudWindSources[3].scale = 0.0f;
        gNewCloudWindSources[3].flag = 0;
        gNewCloudWindSources[4].x = 0x107;
        gNewCloudWindSources[4].z = 0xb4a;
        gNewCloudWindSources[4].vx = 0.0f;
        gNewCloudWindSources[4].vy = 0.0f;
        gNewCloudWindSources[4].vz = 0.0f;
        gNewCloudWindSources[4].scale = 0.0f;
        gNewCloudWindSources[4].flag = 0;
        gNewCloudWindSources[5].x = 0;
        gNewCloudWindSources[5].z = 0x7d0;
        gNewCloudWindSources[5].vx = 0.0f;
        gNewCloudWindSources[5].vy = 0.0f;
        gNewCloudWindSources[5].vz = -1.0f;
        normalize(&gNewCloudWindSources[5].vx, &gNewCloudWindSources[5].vy, &gNewCloudWindSources[5].vz);
        gNewCloudWindSources[5].scale = 100.0f;
        gNewCloudWindSources[5].flag = 0;
        gNewCloudWindSourcesInit = 0;
    }
}

void dll_07_func09(void) {
    Camera_GetCurrent();
    randomGetRange(5, 5);
}

int newclouds_isBlizzardActive(void) {
    return gNewCloudBlizzardActive;
}

void newclouds_renderSnowClouds(void* renderPass) {
    int i;
    int total;
    NewCloud* snow;

    GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, gNewCloudSnowFogColor);
    for (i = 0, total = 0; i < 8; i++) {
        snow = gNewClouds[i];
        if (snow != NULL && snow->finished == 0) {
            total += snowPrintSnowCloud(renderPass, snow->cloudId);
        }
    }
    if (gNewCloudSnowFlashAlpha != 0) {
        drawSnowFlashOverlay(gNewCloudSnowFlashScroll, gNewCloudSnowFlashAlpha, gNewCloudSnowFlashDirection,
                             gNewCloudSnowFlashScale, gNewCloudSnowFlashAlphaK0, gNewCloudSnowFlashAlphaK1,
                             gNewCloudSnowFlashParallax);
    }
}
void newclouds_run(void) {
    Camera* camera;
    NewCloud** cloudSlot;
    int cloudIndex;
    NewCloud* nearestCloud;
    u8 movingBlizzardCount;
    NewCloud* cloud;
    f32* viewRotationMatrix;
    f32 distance;
    f32 value;
    f32 flashRotation;
    f32 nearestDistance;
    f32 windOrigin[3];
    f32 windVelocity[3];
    f32 cloudPosition[3];
    f32 cameraOffset[3];
    f32 cameraDelta[3];
    MatrixTransform cameraTransform;
    Mtx flashMatrix;

    cloudIndex = 0;
    camera = Camera_GetCurrent();
    movingBlizzardCount = 0;
    nearestCloud = NULL;
    nearestDistance = 1e30f;
    if (gNewCloudInitialized == 0) {
        sNewCloudsTexture = textureLoadAsset(0x16a);
        gNewCloudLayerTextures[0] = textureLoadAsset(0x5da);
        gNewCloudLayerTextures[1] = textureLoadAsset(0x63f);
        gNewCloudLayerTextures[2] = textureLoadAsset(0x640);
        gNewCloudLayerTextures[3] = textureLoadAsset(0x641);
        gNewCloudType1Texture = textureLoadAsset(0x151);
        gNewCloudInitialized = 1;
    }
    if (renderModeSetOrGet(-1) == 1) {
        return;
    }
    gNewCloudBlizzardActivePrev = gNewCloudBlizzardActive;
    gNewCloudBlizzardActive = 0;
    while (cloudIndex < 8) {
        cloudSlot = &gNewClouds[cloudIndex];
        cloud = *cloudSlot;
        if (cloud != NULL &&
            (cloud->owner == NULL || (((GameObject*)cloud->owner)->objectFlags & OBJECT_OBJFLAG_FREED))) {
            snowFreeSnowCloud(cloud->cloudId);
            cloudIndex++;
            continue;
        }
        if (cloud != NULL && cloud->active != 0) {
            snowCloudInitFlakes((f32*)cloud->unk0008, cloud->cloudHeight, cloud->scale, cloudIndex);
        } else if (cloud != NULL && cloud->finished == 0) {
            if (cloud->cloudType == 4) {
                gNewCloudBlizzardActive = 1;
            }
            if (cloud->despawning != 0) {
                cloud->activeFlakes = framesThisStep * cloud->flakeDrainRate + cloud->activeFlakes;
                if ((*cloudSlot)->activeFlakes <= 0.0f) {
                    (*cloudSlot)->finished = 1;
                }
            } else {
                if ((int)cloud->activeFlakes < cloud->flakeCount) {
                    cloud->activeFlakes = framesThisStep * cloud->flakeFillRate + cloud->activeFlakes;
                }
            }
            if ((int)(*cloudSlot)->activeFlakes > (*cloudSlot)->flakeCount) {
                (*cloudSlot)->activeFlakes = (*cloudSlot)->flakeCount;
            }
            if ((*cloudSlot)->activeFlakes < 0.0f) {
                (*cloudSlot)->activeFlakes = 0.0f;
            }
            if ((*cloudSlot)->owner != NULL) {
                Obj_GetWorldPosition((GameObject*)(*cloudSlot)->owner, &cloudPosition[0], &cloudPosition[1],
                                     &cloudPosition[2]);
            }
            if ((*cloudSlot)->followCamera != 0 && camera != NULL) {
                if ((*cloudSlot)->cloudType == 4) {
                    cameraOffset[0] = 0.0f;
                    cameraOffset[1] = 0.0f;
                    cameraOffset[2] = 100.0f;
                    cameraTransform.x = 0.0f;
                    cameraTransform.y = 0.0f;
                    cameraTransform.z = 0.0f;
                    cameraTransform.scale = 1.0f;
                    cameraTransform.rotZ = 0;
                    cameraTransform.rotY = 0;
                    cameraTransform.rotX = 0xffff - camera->yaw;
                    vecRotateZXY(&cameraTransform.rotX, cameraOffset);
                    cloudPosition[0] = camera->worldX + cameraOffset[0];
                    value = camera->worldY - 60.0f;
                    cloudPosition[1] = value + cameraOffset[1];
                    cloudPosition[2] = camera->worldZ + cameraOffset[2];
                } else {
                    cloudPosition[0] = camera->worldX;
                    cloudPosition[1] = camera->worldY - 60.0f;
                    cloudPosition[2] = camera->worldZ;
                }
            }
            (*cloudSlot)->driftOffset = framesThisStep * (*cloudSlot)->driftRate + (*cloudSlot)->driftOffset;
            if ((*cloudSlot)->driftScale != 0.0f) {
                if ((*cloudSlot)->driftOffset > (*cloudSlot)->driftLimit) {
                    (*cloudSlot)->driftRate *= -1.0f;
                    (*cloudSlot)->driftOffset = (*cloudSlot)->driftLimit;
                } else if ((*cloudSlot)->driftOffset < 0.0f) {
                    (*cloudSlot)->driftRate *= -1.0f;
                    (*cloudSlot)->driftLimit = (int)randomGetRange(1, (2.0f * (*cloudSlot)->driftScale));
                    (*cloudSlot)->driftOffset = 0.0f;
                }
            }
            if ((*cloudSlot)->stationary == 0) {
                windOrigin[0] = cloudPosition[0];
                windOrigin[1] = cloudPosition[1];
                windOrigin[2] = cloudPosition[2];
                snowCloudComputeDrift(windVelocity, windOrigin, (*cloudSlot)->driftScale);
                if ((*cloudSlot)->cloudType == 0) {
                    (*cloudSlot)->windVelX = -windVelocity[0];
                    (*cloudSlot)->windVelZ = -windVelocity[2];
                } else {
                    (*cloudSlot)->windVelX = -(windVelocity[0] + (*cloudSlot)->driftOffset);
                    (*cloudSlot)->windVelZ = -(windVelocity[2] + (*cloudSlot)->driftOffset);
                    (*cloudSlot)->unk1428 = 0.0f;
                }
                (*cloudSlot)->worldPosX = cloudPosition[0];
                (*cloudSlot)->worldPosY = cloudPosition[1];
                (*cloudSlot)->worldPosZ = cloudPosition[2];
            } else {
                windOrigin[0] = (*cloudSlot)->worldPosX;
                windOrigin[1] = (*cloudSlot)->worldPosY;
                windOrigin[2] = (*cloudSlot)->worldPosZ;
                snowCloudComputeDrift(windVelocity, windOrigin, (*cloudSlot)->driftScale);
                (*cloudSlot)->windVelX = -windVelocity[0] + (*cloudSlot)->driftOffset;
                (*cloudSlot)->windVelZ = -windVelocity[2] + (*cloudSlot)->driftOffset;
                (*cloudSlot)->unk1428 = 0.0f;
            }
            if ((*cloudSlot)->posInitialized != 0) {
                (*cloudSlot)->curPosX = (*cloudSlot)->lastPosX;
                (*cloudSlot)->curPosY = (*cloudSlot)->lastPosY;
                (*cloudSlot)->curPosZ = (*cloudSlot)->lastPosZ;
            } else {
                (*cloudSlot)->curPosX = cloudPosition[0];
                (*cloudSlot)->curPosY = cloudPosition[1];
                (*cloudSlot)->curPosZ = cloudPosition[2];
                (*cloudSlot)->posInitialized = 1;
            }
            (*cloudSlot)->lastPosX = cloudPosition[0];
            (*cloudSlot)->lastPosY = cloudPosition[1];
            (*cloudSlot)->lastPosZ = cloudPosition[2];
            snowReposSnowCloud((*cloudSlot)->cloudId);
            if ((*cloudSlot)->activeFlakes > 0.0f) {
                cameraDelta[0] = (*cloudSlot)->worldPosX - camera->x;
                cameraDelta[1] = (*cloudSlot)->worldPosY - camera->y;
                cameraDelta[2] = (*cloudSlot)->worldPosZ - camera->z;
                distance = PSVECMag((Vec*)cameraDelta);
                if (distance < nearestDistance) {
                    nearestDistance = distance;
                    nearestCloud = (*cloudSlot);
                }
            }
        }
        if ((*cloudSlot) != NULL && (*cloudSlot)->cloudType == 4 && (*cloudSlot)->stationary == 0) {
            movingBlizzardCount++;
        }
        cloudIndex++;
    }
    if (movingBlizzardCount != 0) {
        gNewCloudOvercastFadeRate = 0.01f;
    } else {
        gNewCloudOvercastFadeRate = -0.01f;
    }
    if (gActiveLightning != NULL) {
        gActiveLightning->timer += 1;
        if (gActiveLightning->timer >= gActiveLightning->lifetime) {
            mm_free(gActiveLightning);
            gActiveLightning = NULL;
        }
    }
    value = gNewCloudScrollPhaseA + 0.02f * timeDelta;
    gNewCloudScrollPhaseA = value;
    if (value > 25.13274f) {
        gNewCloudScrollPhaseA = value - 25.13274f;
    }
    value = gNewCloudScrollPhaseB + 0.015f * timeDelta;
    gNewCloudScrollPhaseB = value;
    if (value > 25.13274f) {
        gNewCloudScrollPhaseB = value - 25.13274f;
    }
    value = gNewCloudScrollPhaseC - 0.025f * timeDelta;
    gNewCloudScrollPhaseC = value;
    if (value < -25.13274f) {
        gNewCloudScrollPhaseC += 25.13274f;
    }
    value = gNewCloudOvercastFadeLevel + gNewCloudOvercastFadeRate;
    gNewCloudOvercastFadeLevel = value;
    if (value > 1.0f) {
        gNewCloudOvercastFadeLevel = 1.0f;
    } else if (value < 0.0f) {
        gNewCloudOvercastFadeLevel = 0.0f;
    }
    gNewCloudSnowFlashAlpha = 0;
    if (nearestCloud != NULL && nearestCloud->cloudType == 4) {
        gNewCloudSnowFlashAlpha = 255.0f * gNewCloudOvercastFadeLevel;
        if (gNewCloudSnowFlashAlpha != 0) {
            flashRotation = 3.142f * (2.0f * -(6000.0f * (nearestCloud->driftOffset / 10.0f) + 3000.0f)) / 65536.0f;
            {
                f32 zero = 0.0f;
                gNewCloudSnowFlashDirection[0] = zero;
                gNewCloudSnowFlashDirection[1] = -1.0f;
                gNewCloudSnowFlashDirection[2] = zero;
            }
            viewRotationMatrix = Camera_GetViewRotationMatrix();
            if (nearestCloud->cloudType == 0) {
                gNewCloudSnowFlashScroll = 0.125f * (-0.12f * timeDelta) + gNewCloudSnowFlashScroll;
                gNewCloudSnowFlashScale = 1.5f;
                gNewCloudSnowFlashAlphaK0 = 0xf9;
                gNewCloudSnowFlashAlphaK1 = 0xfd;
                gNewCloudSnowFlashParallax = 5.0f;
                PSMTXIdentity(flashMatrix);
            } else {
                gNewCloudSnowFlashScroll = -0.12f * timeDelta + gNewCloudSnowFlashScroll;
                gNewCloudSnowFlashScale = 1.0f;
                gNewCloudSnowFlashAlphaK0 = 0xf8;
                gNewCloudSnowFlashAlphaK1 = 0xfc;
                gNewCloudSnowFlashParallax = 1.0f;
                PSMTXRotRad(flashMatrix, 'z', flashRotation);
            }
            PSMTXConcat((MtxPtr)viewRotationMatrix, flashMatrix, flashMatrix);
            PSMTXMultVec(flashMatrix, (Vec*)gNewCloudSnowFlashDirection, (Vec*)gNewCloudSnowFlashDirection);
            if (gNewCloudSnowFlashScroll < -16.0f) {
                gNewCloudSnowFlashScroll += 16.0f;
            }
        }
    }
    if (gNewCloudBlizzardActive != 0 && gNewCloudBlizzardActivePrev == 0) {
        Music_Trigger(MUSICTRIG_crun_dungeon, 1);
    } else if (gNewCloudBlizzardActive == 0 && gNewCloudBlizzardActivePrev != 0) {
        Music_Trigger(MUSICTRIG_crun_dungeon, 0);
    }
}

void newclouds_killSnowCloud(int cloudId, int flag) {
    NewCloud* p;
    int i;

    if (flag == 0) {
        if (cloudId == -1) {
            for (i = 0; i < 8; i++) {
                snowFreeSnowCloud(i);
            }
        } else {
            snowFreeSnowCloud(cloudId);
        }
        return;
    }
    for (i = 0; i < 8; i++) {
        p = gNewClouds[i];
        if (p != NULL && cloudId == p->cloudId) {
            break;
        }
    }
    if (gNewClouds[i] == NULL || i == 8) {
        return;
    }
    if (cloudId != gNewClouds[i]->cloudId) {
        debugPrintf(sSnowKillSnowCloudInvalidCloudId, cloudId);
        return;
    }
    gNewClouds[i]->despawning = 1;
    gNewClouds[i]->flakeDrainRate = -((f32)flag / (f32)gNewClouds[i]->flakeCount);
}

void newclouds_onMapSetup(void) {
    int i;
    f32 a;
    f32 b;

    for (i = 0; i < 8; i++) {
        if (gNewClouds[i] != NULL) {
            snowFreeSnowCloud(i);
        }
        gNewClouds[i] = NULL;
    }
    a = 0.0f;
    gNewCloudScrollPhaseA = a;
    gNewCloudScrollPhaseB = a;
    gNewCloudScrollPhaseC = a;
    gNewCloudSnowFlashScroll = a;
    b = (gNewCloudOvercastFadeLevel = 1.0f);
    gNewCloudOvercastFadeRate = a;
    gNewCloudSnowFlashAlpha = 0;
    gNewCloudSnowFlashScale = b;
    gNewCloudSnowFlashAlphaK0 = 0;
    gNewCloudSnowFlashAlphaK1 = 0;
    gNewCloudSnowFlashParallax = b;
    gNewCloudBlizzardActivePrev = 0;
    Music_Trigger(MUSICTRIG_crun_dungeon, 0);
}

/*
 * The NC_CLOUD macro and the env slot writes index `params` as
 * `params + 0x26` / `params + 0x26 * 0xc` byte arithmetic. `env` is the
 * savegame environment-state blob returned by saveGameGetEnvState().
 */
#undef NC_CLOUD
#undef NC_CLOUD
#define NC_CLOUD (gNewClouds[cfg->cloudIndex])
extern int gNewCloudMusicIdByType[5];

void newclouds_updateEnvfxAct(GameObject* objA, GameObject* objB, u8* params) {
    CloudSpawnParams* cfg = (CloudSpawnParams*)params;
    u8* env;
    NewCloud* cloud;
    u8 fl;
    MatrixTransform args;
    f32 posA[3];
    f32 posB[3];
    f32 vec[3];

    *(SnowVec3*)posA = sNewCloudDefaultStartPos;
    *(SnowVec3*)posB = sNewCloudDefaultEndPos;
    env = (u8*)saveGameGetEnvState();
    if (params == NULL) {
        return;
    }
    if (objA != NULL) {
        posA[0] = objA->anim.worldPosX;
        posA[1] = objA->anim.worldPosY;
        posA[2] = objA->anim.worldPosZ;
    }
    if (objB != NULL) {
        posB[0] = objB->anim.worldPosX;
        posB[1] = objB->anim.worldPosY;
        posB[2] = objB->anim.worldPosZ;
    }
    if ((u32)cfg->cloudIndex > 8) {
        return;
    }
    cloud = NC_CLOUD;
    if (cloud == NULL) {
        fl = cfg->flags58;
        if (!(fl & NEWCLOUD_CMD_DESPAWN) && !(fl & NEWCLOUD_CMD_RELOCATE) && !(fl & NEWCLOUD_CMD_KILL)) {
            if ((fl & NEWCLOUD_CMD_SPAWN) && (fl & NEWCLOUD_CMD_ANCHOROBJ) && cfg->stationaryInit != 0) {
                newClouds(cfg, objB, posA[0], posA[1], posA[2]);
            } else if ((fl & NEWCLOUD_CMD_SPAWN) && (fl & NEWCLOUD_CMD_ANCHOROBJ)) {
                newClouds(cfg, objB, posB[0], posB[1], posB[2]);
            } else if (fl & NEWCLOUD_CMD_SPAWN) {
                newClouds(cfg, objB, posA[0], posA[1], posA[2]);
            }
        }
        if (cfg->flags58 & NEWCLOUD_CMD_SPAWN) {
            if (cfg->cloudType == 0 || cfg->cloudType == 4) {
                switch (cfg->cloudIndex) {
                case 0:
                    ((SaveGameEnvState*)env)->cloudEnvfxActIds[0] = (s16)cfg->envfxActId - 1;
                    ((SaveGameEnvState*)env)->cloudPos[0][0] = posA[0];
                    ((SaveGameEnvState*)env)->cloudPos[0][1] = posA[1];
                    ((SaveGameEnvState*)env)->cloudPos[0][2] = posA[2];
                    if ((s8)env[cfg->cloudIndex + 0x41] == -1) {
                        return;
                    }
                    NC_CLOUD->stationary = 1 - env[cfg->cloudIndex + 0x41];
                    if ((s8)env[cfg->cloudIndex + 0x41] != 0) {
                        return;
                    }
                    {
                        u8* p14 = env + 0x14;
                        u8* p18 = env + 0x18;
                        u8* p1c = env + 0x1c;
                        NC_CLOUD->worldPosX = (f32) * (int*)(p14 + cfg->cloudIndex * 0xc);
                        NC_CLOUD->worldPosY = (f32) * (int*)(p18 + cfg->cloudIndex * 0xc);
                        NC_CLOUD->worldPosZ = (f32) * (int*)(p1c + cfg->cloudIndex * 0xc);
                    }
                    break;
                case 1:
                    ((SaveGameEnvState*)env)->cloudEnvfxActIds[1] = (s16)cfg->envfxActId - 1;
                    ((SaveGameEnvState*)env)->cloudPos[1][0] = posA[0];
                    ((SaveGameEnvState*)env)->cloudPos[1][1] = posA[1];
                    ((SaveGameEnvState*)env)->cloudPos[1][2] = posA[2];
                    if ((s8)env[cfg->cloudIndex + 0x41] == -1) {
                        return;
                    }
                    NC_CLOUD->stationary = 1 - env[cfg->cloudIndex + 0x41];
                    if ((s8)env[cfg->cloudIndex + 0x41] != 0) {
                        return;
                    }
                    {
                        u8* p14 = env + 0x14;
                        u8* p18 = env + 0x18;
                        u8* p1c = env + 0x1c;
                        NC_CLOUD->worldPosX = (f32) * (int*)(p14 + cfg->cloudIndex * 0xc);
                        NC_CLOUD->worldPosY = (f32) * (int*)(p18 + cfg->cloudIndex * 0xc);
                        NC_CLOUD->worldPosZ = (f32) * (int*)(p1c + cfg->cloudIndex * 0xc);
                    }
                    break;
                case 2:
                    ((SaveGameEnvState*)env)->cloudEnvfxActIds[2] = (s16)cfg->envfxActId - 1;
                    ((SaveGameEnvState*)env)->cloudPos[2][0] = posA[0];
                    ((SaveGameEnvState*)env)->cloudPos[2][1] = posA[1];
                    ((SaveGameEnvState*)env)->cloudPos[2][2] = posA[2];
                    if ((s8)env[cfg->cloudIndex + 0x41] == -1) {
                        return;
                    }
                    NC_CLOUD->stationary = 1 - env[cfg->cloudIndex + 0x41];
                    if ((s8)env[cfg->cloudIndex + 0x41] != 0) {
                        return;
                    }
                    {
                        u8* p14 = env + 0x14;
                        u8* p18 = env + 0x18;
                        u8* p1c = env + 0x1c;
                        NC_CLOUD->worldPosX = (f32) * (int*)(p14 + cfg->cloudIndex * 0xc);
                        NC_CLOUD->worldPosY = (f32) * (int*)(p18 + cfg->cloudIndex * 0xc);
                        NC_CLOUD->worldPosZ = (f32) * (int*)(p1c + cfg->cloudIndex * 0xc);
                    }
                    break;
                }
            }
        }
        return;
    }
    if (cloud == NULL) {
        return;
    }
    if ((fl = cfg->flags58) & NEWCLOUD_CMD_SPAWN) {
        return;
    }
    if ((fl & NEWCLOUD_CMD_RELOCATE) && cloud->anchoredToObj != 0) {
        ((s8*)(env + 0x41))[cfg->cloudIndex] = cloud->stationary;
        NC_CLOUD->stationary = 1 - NC_CLOUD->stationary;
        if (NC_CLOUD->stationary == 1) {
            vec[0] = 0.0f;
            vec[1] = 0.0f;
            vec[2] = 0.0f;
            args.x = 0.0f;
            args.y = 0.0f;
            args.z = 0.0f;
            args.scale = 1.0f;
            args.rotZ = 0;
            args.rotY = 0;
            args.rotX = objA->anim.rotX;
            vecRotateZXY(&args.rotX, vec);
            NC_CLOUD->worldPosX = vec[0] + objA->anim.worldPosX;
            NC_CLOUD->worldPosY = vec[1] + objA->anim.worldPosY;
            NC_CLOUD->worldPosZ = vec[2] + objA->anim.worldPosZ;
            if (NC_CLOUD->driftScale > 9.0f) {
                Music_Trigger(gNewCloudMusicIdByType[NC_CLOUD->cloudType], 0);
            }
        } else {
            if (NC_CLOUD->driftScale > 9.0f) {
                Music_Trigger(gNewCloudMusicIdByType[NC_CLOUD->cloudType], 1);
            }
        }
        if ((s8)env[cfg->cloudIndex + 0x41] == 0) {
            u8* p14 = env + 0x14;
            u8* p18 = env + 0x18;
            u8* p1c = env + 0x1c;
            *(int*)(p14 + cfg->cloudIndex * 0xc) = posA[0];
            *(int*)(p18 + cfg->cloudIndex * 0xc) = posA[1];
            *(int*)(p1c + cfg->cloudIndex * 0xc) = posA[2];
        }
    } else if (fl & NEWCLOUD_CMD_KILL) {
        newclouds_killSnowCloud(cfg->cloudIndex, 0);
    } else if (fl & NEWCLOUD_CMD_DESPAWN) {
        if (cloud->finished != 0) {
            cloud->finished = 0;
        }
        NC_CLOUD->despawning = 1 - NC_CLOUD->despawning;
        if (cfg->fillDivisor != 0) {
            NC_CLOUD->flakeFillRate = (f32)NC_CLOUD->flakeCount / (f32)cfg->fillDivisor;
        } else {
            NC_CLOUD->flakeFillRate = (NC_CLOUD->flakeCount - 1);
        }
        if (cfg->drainDivisor != 0) {
            NC_CLOUD->flakeDrainRate = -((f32)NC_CLOUD->flakeCount / (f32)cfg->drainDivisor);
        } else {
            NC_CLOUD->flakeDrainRate = (-(NC_CLOUD->flakeCount - 1));
        }
    }
}

void newclouds_release(void) {
    int i;

    if (sNewCloudsTexture != NULL) {
        textureFree((Texture*)(sNewCloudsTexture));
        sNewCloudsTexture = NULL;
    }
    for (i = 0; i < 4; i++) {
        if (gNewCloudLayerTextures[i] != NULL) {
            textureFree(gNewCloudLayerTextures[i]);
            gNewCloudLayerTextures[i] = NULL;
        }
    }
    if (gNewCloudType1Texture != NULL) {
        textureFree((Texture*)(gNewCloudType1Texture));
        gNewCloudType1Texture = NULL;
    }
    if (gNewCloudModelLight != NULL) {
        ModelLightStruct_free(gNewCloudModelLight);
    }
    gNewCloudInitialized = 0;
}

void newclouds_initialise(void) {
    gNewCloudInitialized = 0;
}
int gNewCloudMusicIdByType[5] = {43, 0, 0, 0, 0};
typedef struct NewCloudsDllInterface {
    u32 reserved0;
    u32 reserved1;
    u32 reserved2;
    u32 slotCountAndFlags;
    ObjectDescriptorCallback initialise;
    ObjectDescriptorCallback release;
    ObjectDescriptorCallback slot02;
    ObjectDescriptorCallback updateEnvfxAct;
    ObjectDescriptorCallback onMapSetup;
    ObjectDescriptorCallback killSnowCloud;
    ObjectDescriptorCallback run;
    ObjectDescriptorCallback renderSnowClouds;
    ObjectDescriptorCallback isBlizzardActive;
    ObjectDescriptorCallback slot09;
    ObjectDescriptorCallback slot0A;
} NewCloudsDllInterface;

NewCloudsDllInterface newclouds_funcs = {
    0,
    0,
    0,
    0x000a0000,
    (ObjectDescriptorCallback)newclouds_initialise,
    (ObjectDescriptorCallback)newclouds_release,
    0,
    (ObjectDescriptorCallback)newclouds_updateEnvfxAct,
    (ObjectDescriptorCallback)newclouds_onMapSetup,
    (ObjectDescriptorCallback)newclouds_killSnowCloud,
    (ObjectDescriptorCallback)newclouds_run,
    (ObjectDescriptorCallback)newclouds_renderSnowClouds,
    (ObjectDescriptorCallback)newclouds_isBlizzardActive,
    (ObjectDescriptorCallback)dll_07_func09,
    (ObjectDescriptorCallback)dll_07_func0A_nop,
};

char sSnowFreeSnowCloudInvalidCloudId[] = "!!! Error non-existant cloud id - %i - in snowFreeSnowCloud\n";
char sSnowPrintSnowCloudInvalidCloudId[] = "!!! Error non-existant cloud id - %i - in snowPrintSnowCloud\n";

char sSnowCloudErrorMessageBlock[] = {
    0x21, 0x21, 0x21, 0x20, 0x45, 0x72, 0x72, 0x6F, 0x72, 0x20, 0x6E, 0x6F, 0x6E, 0x2D, 0x65, 0x78, 0x69, 0x73,
    0x74, 0x61, 0x6E, 0x74, 0x20, 0x63, 0x6C, 0x6F, 0x75, 0x64, 0x20, 0x69, 0x64, 0x20, 0x2D, 0x20, 0x25, 0x69,
    0x20, 0x2D, 0x20, 0x69, 0x6E, 0x20, 0x73, 0x6E, 0x6F, 0x77, 0x52, 0x65, 0x70, 0x6F, 0x73, 0x53, 0x6E, 0x6F,
    0x77, 0x43, 0x6C, 0x6F, 0x75, 0x64, 0x0A, 0x00, 0x00, 0x00, 0x77, 0x61, 0x72, 0x6E, 0x69, 0x6E, 0x67, 0x20,
    0x69, 0x6E, 0x20, 0x6E, 0x65, 0x77, 0x63, 0x6C, 0x6F, 0x75, 0x64, 0x20, 0x64, 0x6C, 0x6C, 0x20, 0x6E, 0x6F,
    0x20, 0x73, 0x70, 0x61, 0x72, 0x65, 0x20, 0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x20, 0x66, 0x6F, 0x72, 0x20,
    0x6C, 0x69, 0x67, 0x68, 0x74, 0x20, 0x61, 0x76, 0x61, 0x69, 0x6C, 0x61, 0x62, 0x6C, 0x65, 0x0A, 0x00, 0x00,
    0x00, 0x00, 0x77, 0x61, 0x72, 0x6E, 0x69, 0x6E, 0x67, 0x20, 0x69, 0x6E, 0x20, 0x6E, 0x65, 0x77, 0x63, 0x6C,
    0x6F, 0x75, 0x64, 0x73, 0x20, 0x64, 0x6C, 0x6C, 0x20, 0x6E, 0x6F, 0x20, 0x73, 0x70, 0x61, 0x72, 0x65, 0x20,
    0x6D, 0x65, 0x6D, 0x6F, 0x72, 0x79, 0x20, 0x66, 0x6F, 0x72, 0x20, 0x63, 0x6C, 0x6F, 0x75, 0x64, 0x73, 0x20,
    0x61, 0x76, 0x61, 0x69, 0x6C, 0x61, 0x62, 0x6C, 0x65, 0x0A, 0x00, 0x00,
};
char sSnowKillSnowCloudInvalidCloudId[] = "!!! Error non-existant cloud id - %i - in snowKillSnowCloud\n";
