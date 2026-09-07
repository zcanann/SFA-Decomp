#include "main/ground_shadow.h"
#include "main/shadow_volume.h"
#include "main/map_block.h"
#include "main/texture.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_depth_read_api.h"
#include "track/intersect_render_setup_api.h"
#include "main/lightmap_api.h"
#include "main/shader_api.h"
#include "main/debug.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frustum.h"
#include "main/asset_load.h"
#include "game/objects/object.h"
#include "main/gameloop_api.h"
#include "sys/objects.h"
#include "main/mm.h"
#include "main/model_light.h"
#include "main/model.h"
#include "main/model_render_instrs_api.h"
#include "main/objHitReact.h"
#include "main/objhits.h"
#include "main/objtype.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "dolphin/mtx.h"
#include "dolphin/os/OSFastCast.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "main/camera.h"
#include "main/sky_state.h"
#include "main/track_dolphin.h"
#include "main/track_dolphin_api.h"
#include "main/track_dolphin_shadow_api.h"
#include "main/newshadows_shadow_api.h"
#include "dolphin/mtx/vec.h"
#define TRACK_BBOX_FLAGS_S8
#include "main/track_bbox_api.h"
#undef TRACK_BBOX_FLAGS_S8
#include "main/dll/player_api.h"
#include "main/pause_menu_api.h"
#include "main/pi_dolphin.h"
#include "dolphin/os/OSCache.h"
#include "main/voxmaps.h"
#include "track/intersect_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/objmodel.h"
#include "main/newshadows.h"
#include "main/sky.h"
#include "main/newshadows_texture_api.h"
#include "main/acosf_api.h"
#include "main/tex_dolphin.h"
#include "string.h"
#include "main/track_dolphin_sky_api.h"
#include "main/dll/ppcwgpipe_struct.h"

Vec3f* gShadowVolumeBuffer;
void* gShadowVolumeBuffers[2];
int lbl_803DCF20;
int lbl_803DCF1C;
int lbl_803DCF18;
int lbl_803DCF14;
int lbl_803DCF10;
int lbl_803DCF0C;
void* lbl_803DCF08;
void* lbl_803DCF04;
f32 gSunDotCos;
s16 lbl_803DCEFC;
s16 lbl_803DCEFA;
s16 lbl_803DCEF8;
s16 lbl_803DCEF6;
s16 lbl_803DCEF4;
s16 gShadowVisibleCount;
s16 gShadowTrackTriangleCount;
s8 lbl_803DCEEE;
s8 lbl_803DCEED;
s8 gShadowVolumeBufferSelect;
s8 lbl_803DCEEB;
s8 lbl_803DCEEA;
u8 lbl_803DCEE9;
u8 lbl_803DCEE8;
int gShadowTrackGridOrigin;
int gShadowTrackTriangleBuffer;
f32 gShadowOffsetZ;
f32 gShadowOffsetX;

f32 gShadowOffsetY = 1.0f;
f32 gShadowAlphaScale = 1.0f;
s8 gShadowVolumesDirty = 10;
s16 gSunMagnitude = 100;
int gSunDirChanged = 1;

extern volatile PPCWGPipe GXWGFifo : (0xCC008000);

static void trackDolphin_buildShadowVolumePlanes(GameObject* unusedObject, Vec3f* corners, ShadowVolumePlane* planes);

/* Begin a new shadow-volume frame: clear the per-frame
 * counts, flip the three double-buffer selectors, and rotate the current
 * write pointers to the buffer picked by this frame's flip index. */
static void vecGetRanges(Vec3f* points, Vec3f* origin, f32 scale, TrackQueryBounds* bounds);

static int objShadowGetFadedAlpha(GameObject* obj, u8 param);

extern f32 gShadowVolumeBoxCorners[0x19];
f32 gPrevSunDir[3];

extern u8 gShadowDrawScratch[0x5DC0];

extern f32 lbl_8038D77C[0x18];

static inline void GXPosition3s16(const int x, const int y, const int z) {
    GXWGFifo.s16 = x;
    GXWGFifo.s16 = y;
    GXWGFifo.s16 = z;
}

static inline void GXTexCoord2s16(const s16 x, const s16 y) {
    GXWGFifo.s16 = x;
    GXWGFifo.s16 = y;
}

static inline void GXPosition3f32(const f32 x, const f32 y, const f32 z) {
    GXWGFifo.f32 = x;
    GXWGFifo.f32 = y;
    GXWGFifo.f32 = z;
}

static f32 shadowGetSunMagnitude(void) {
    f32 magnitude = 0.0f;

    if (gSunMagnitude > 0) {
        magnitude = (f32)gSunMagnitude;
    }
    return magnitude;
}

void buildShadowVolumeBox(Vec3f* direction, Vec3f* corners, f32 lowerScale) {
    MatrixTransform xf;
    f32 ax;
    f32 az;
    int i;
    int rotY;

    xf.x = 0.0f;
    xf.y = 0.0f;
    xf.z = 0.0f;
    xf.scale = 1.0f;
    xf.rotZ = 0;
    ax = __fabsf(direction->x);
    az = __fabsf(direction->z);
    if (ax > az) {
        rotY = (u16)getAngle(ax, direction->y);
    } else {
        rotY = (u16)getAngle(az, direction->y);
    }
    xf.rotY = rotY;
    if (xf.rotY > 0x2000) {
        xf.rotY = 0x2000;
    }
    xf.rotX = (s16)getAngle(direction->x, direction->z);
    for (i = 0; i < 8; i++) {
        corners[i].x = gShadowVolumeBoxCorners[i * 3 + 0];
        if (gShadowVolumeBoxCorners[i * 3 + 1] > 0.0f) {
            corners[i].y = gShadowVolumeBoxCorners[i * 3 + 1];
        } else {
            corners[i].y = lowerScale * gShadowVolumeBoxCorners[i * 3 + 1];
        }
        corners[i].z = gShadowVolumeBoxCorners[i * 3 + 2];
        vecRotateZXY(&xf.rotX, (f32*)&corners[i]);
    }
}

static void vecGetRanges(Vec3f* points, Vec3f* origin, f32 scale, TrackQueryBounds* bounds) {
    int i;

    bounds->minX = 0x7fffffff;
    bounds->maxX = 0x80000000;
    bounds->minY = 0x7fffffff;
    bounds->maxY = 0x80000000;
    bounds->minZ = 0x7fffffff;
    bounds->maxZ = 0x80000000;
    for (i = 0; i < 8; i++) {
        f32 x = scale * points->x + origin->x;
        f32 y = scale * points->y + origin->y;
        f32 z = scale * points->z + origin->z;
        if (x < bounds->minX) {
            bounds->minX = x;
        }
        if (x > bounds->maxX) {
            bounds->maxX = x;
        }
        if (y < bounds->minY) {
            bounds->minY = y;
        }
        if (y > bounds->maxY) {
            bounds->maxY = y;
        }
        if (z < bounds->minZ) {
            bounds->minZ = z;
        }
        if (z > bounds->maxZ) {
            bounds->maxZ = z;
        }
        points++;
    }
}

static void buildGroundShadowQuad(GroundShadowQuad* quad, GameObject* obj) {
    f32 groundOffset;
    Vec tangent;
    Vec bitangent;
    Vec groundNormal;
    f32 axisAlignment;
    f32 halfSize;
    f32 zero;
    f32 fixedScale;
    f32 localGroundY;

    if (trackGetNearestGroundOffsetAndNormal(obj, obj->anim.localPosX, obj->anim.localPosY, obj->anim.localPosZ,
                                             &groundOffset, (f32*)&groundNormal, 0) == 0) {
        PSVECNormalize(&groundNormal, &groundNormal);
        tangent.x = 1.0f;
        tangent.y = 0.0f;
        tangent.z = 0.0f;
        axisAlignment = __fabsf(PSVECDotProduct(&groundNormal, &tangent));
        if (axisAlignment >= 0.9f) {
            tangent.x = 0.0f;
            tangent.z = 1.0f;
        }
        PSVECCrossProduct(&groundNormal, &tangent, &bitangent);
        PSVECCrossProduct(&bitangent, &groundNormal, &tangent);
        PSVECNormalize(&tangent, &tangent);
        PSVECNormalize(&bitangent, &bitangent);
        halfSize = 0.5f * (&obj->anim)->modelState->shadowScale;
        PSVECScale(&tangent, &tangent, halfSize);
        PSVECScale(&bitangent, &bitangent, halfSize);
        localGroundY = -groundOffset;
        fixedScale = 256.0f;
        zero = 0.0f;
        quad->vertices[0].x = (fixedScale * ((zero - tangent.x) - bitangent.x));
        quad->vertices[0].y = (fixedScale * ((localGroundY - tangent.y) - bitangent.y));
        quad->vertices[0].z = (fixedScale * ((zero - tangent.z) - bitangent.z));
        quad->vertices[1].x = (fixedScale * ((zero + tangent.x) - bitangent.x));
        quad->vertices[1].y = (fixedScale * ((localGroundY + tangent.y) - bitangent.y));
        quad->vertices[1].z = (fixedScale * ((zero + tangent.z) - bitangent.z));
        quad->vertices[2].x = (fixedScale * (bitangent.x + (zero + tangent.x)));
        quad->vertices[2].y = (fixedScale * (bitangent.y + (localGroundY + tangent.y)));
        quad->vertices[2].z = (fixedScale * (bitangent.z + (zero + tangent.z)));
        quad->vertices[3].x = (fixedScale * (bitangent.x + (zero - tangent.x)));
        quad->vertices[3].y = (fixedScale * (bitangent.y + (localGroundY - tangent.y)));
        quad->vertices[3].z = (fixedScale * (bitangent.z + (zero - tangent.z)));
        quad->status = 1;
    } else {
        quad->status = 0xff;
    }
}

void objDrawGroundShadow(GameObject* obj, ObjModel* model) {
    GroundShadowQuad* quad;
    u8 alpha;
    MtxPtr viewMtx;
    GXColor kColor;
    f32 mtx[16];
    f32 outMtx[16];

    quad = model->groundShadowQuad;
    if (quad->status == 0) {
        buildGroundShadowQuad(quad, obj);
    }
    if (quad->status != 0xff) {
        alpha = (u8)objShadowGetFadedAlpha(obj, 0x96);
        kColor.a = alpha;
        if (alpha != 0) {
            viewMtx = (MtxPtr)Camera_GetViewMatrix();
            Obj_BuildWorldTransformMatrix(obj, mtx, 0);
            mtx[0] = 1.0f;
            mtx[1] = 0.0f;
            mtx[2] = 0.0f;
            mtx[4] = 0.0f;
            mtx[5] = 1.0f;
            mtx[6] = 0.0f;
            mtx[8] = 0.0f;
            mtx[9] = 0.0f;
            mtx[10] = 1.0f;
            PSMTXConcat(viewMtx, (MtxPtr)mtx, (MtxPtr)outMtx);
            GXLoadPosMtxImm((const f32(*)[4])outMtx, GX_PNMTX9);
            GXClearVtxDesc();
            GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
            GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
            GXSetNumTexGens(1);
            GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
            GXSetTevKColor(GX_KCOLOR0, kColor);
            GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
            GXSetNumTevStages(1);
            GXSetNumIndStages(0);
            GXSetChanCtrl(GX_COLOR0A0, GX_DISABLE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
            GXSetChanCtrl(GX_COLOR1A1, GX_DISABLE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
            GXSetNumChans(0);
            GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
            GXSetTevDirect(GX_TEVSTAGE0);
            GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
            GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_KONST, GX_CA_TEXA, GX_CA_ZERO);
            GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_ENABLE, GX_TEVPREV);
            GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_ENABLE, GX_TEVPREV);
            gxSetZMode_(1, GX_LEQUAL, 0);
            GXSetCullMode(GX_CULL_NONE);
            GXSetCurrentMtx(GX_PNMTX9);
            GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
            selectTexture((Texture*)(&obj->anim)->modelState->shadowTexture, 0);
            GXBegin(GX_QUADS, GX_VTXFMT6, 4);
            GXPosition3s16(quad->vertices[0].x, quad->vertices[0].y, quad->vertices[0].z);
            GXTexCoord2s16(0, 0);
            GXPosition3s16(quad->vertices[1].x, quad->vertices[1].y, quad->vertices[1].z);
            GXTexCoord2s16(0x400, 0);
            GXPosition3s16(quad->vertices[2].x, quad->vertices[2].y, quad->vertices[2].z);
            GXTexCoord2s16(0x400, 0x400);
            GXPosition3s16(quad->vertices[3].x, quad->vertices[3].y, quad->vertices[3].z);
            GXTexCoord2s16(0, 0x400);
            GXSetCurrentMtx(GX_PNMTX0);
        }
    }
}

static void trackDolphin_buildShadowVolumePlanes(GameObject* unusedObject, Vec3f* corners, ShadowVolumePlane* planes) {
    Vec nrm;

    {
        Vec3f edge1;
        Vec3f edge2;

        edge1.x = corners[2].x - corners[3].x;
        edge1.y = corners[2].y - corners[3].y;
        edge1.z = corners[2].z - corners[3].z;
        edge2.x = corners[7].x - corners[3].x;
        edge2.y = corners[7].y - corners[3].y;
        edge2.z = corners[7].z - corners[3].z;
        nrm.x = edge2.y * edge1.z - edge2.z * edge1.y;
        nrm.y = -(edge2.x * edge1.z - edge2.z * edge1.x);
        nrm.z = edge2.x * edge1.y - edge2.y * edge1.x;
        PSVECNormalize(&nrm, &nrm);
        planes[0].normal.x = -nrm.x;
        planes[0].normal.y = -nrm.y;
        planes[0].normal.z = -nrm.z;
        planes[0].distance = -(planes[0].normal.x * corners[3].x + planes[0].normal.y * corners[3].y +
                               planes[0].normal.z * corners[3].z);
    }

    {
        Vec3f edge1;
        Vec3f edge2;

        edge1.x = corners[6].x - corners[5].x;
        edge1.y = corners[6].y - corners[5].y;
        edge1.z = corners[6].z - corners[5].z;
        edge2.x = corners[1].x - corners[5].x;
        edge2.y = corners[1].y - corners[5].y;
        edge2.z = corners[1].z - corners[5].z;
        nrm.x = edge2.y * edge1.z - edge2.z * edge1.y;
        nrm.y = -(edge2.x * edge1.z - edge2.z * edge1.x);
        nrm.z = edge2.x * edge1.y - edge2.y * edge1.x;
        PSVECNormalize(&nrm, &nrm);
        planes[1].normal.x = -nrm.x;
        planes[1].normal.y = -nrm.y;
        planes[1].normal.z = -nrm.z;
        planes[1].distance = -(planes[1].normal.x * corners[5].x + planes[1].normal.y * corners[5].y +
                               planes[1].normal.z * corners[5].z);
    }

    {
        Vec3f edge1;
        Vec3f edge2;

        edge1.x = corners[5].x - corners[4].x;
        edge1.y = corners[5].y - corners[4].y;
        edge1.z = corners[5].z - corners[4].z;
        edge2.x = corners[0].x - corners[4].x;
        edge2.y = corners[0].y - corners[4].y;
        edge2.z = corners[0].z - corners[4].z;
        nrm.x = edge2.y * edge1.z - edge2.z * edge1.y;
        nrm.y = -(edge2.x * edge1.z - edge2.z * edge1.x);
        nrm.z = edge2.x * edge1.y - edge2.y * edge1.x;
        PSVECNormalize(&nrm, &nrm);
        planes[2].normal.x = -nrm.x;
        planes[2].normal.y = -nrm.y;
        planes[2].normal.z = -nrm.z;
        planes[2].distance = -(planes[2].normal.x * corners[4].x + planes[2].normal.y * corners[4].y +
                               planes[2].normal.z * corners[4].z);
    }

    {
        Vec3f edge1;
        Vec3f edge2;

        edge1.x = corners[3].x - corners[0].x;
        edge1.y = corners[3].y - corners[0].y;
        edge1.z = corners[3].z - corners[0].z;
        edge2.x = corners[4].x - corners[0].x;
        edge2.y = corners[4].y - corners[0].y;
        edge2.z = corners[4].z - corners[0].z;
        nrm.x = edge2.y * edge1.z - edge2.z * edge1.y;
        nrm.y = -(edge2.x * edge1.z - edge2.z * edge1.x);
        nrm.z = edge2.x * edge1.y - edge2.y * edge1.x;
        PSVECNormalize(&nrm, &nrm);
        planes[3].normal.x = -nrm.x;
        planes[3].normal.y = -nrm.y;
        planes[3].normal.z = -nrm.z;
        planes[3].distance = -(planes[3].normal.x * corners[0].x + planes[3].normal.y * corners[0].y +
                               planes[3].normal.z * corners[0].z);
    }

    {
        Vec3f edge1;
        Vec3f edge2;

        edge1.x = corners[6].x - corners[7].x;
        edge1.y = corners[6].y - corners[7].y;
        edge1.z = corners[6].z - corners[7].z;
        edge2.x = corners[4].x - corners[7].x;
        edge2.y = corners[4].y - corners[7].y;
        edge2.z = corners[4].z - corners[7].z;
        nrm.x = edge2.y * edge1.z - edge2.z * edge1.y;
        nrm.y = -(edge2.x * edge1.z - edge2.z * edge1.x);
        nrm.z = edge2.x * edge1.y - edge2.y * edge1.x;
        PSVECNormalize(&nrm, &nrm);
        planes[4].normal.x = -nrm.x;
        planes[4].normal.y = -nrm.y;
        planes[4].normal.z = -nrm.z;
        planes[4].distance = -(planes[4].normal.x * corners[7].x + planes[4].normal.y * corners[7].y +
                               planes[4].normal.z * corners[7].z);
    }

    {
        Vec3f edge1;
        Vec3f edge2;

        edge1.x = corners[1].x - corners[0].x;
        edge1.y = corners[1].y - corners[0].y;
        edge1.z = corners[1].z - corners[0].z;
        edge2.x = corners[3].x - corners[0].x;
        edge2.y = corners[3].y - corners[0].y;
        edge2.z = corners[3].z - corners[0].z;
        nrm.x = edge2.y * edge1.z - edge2.z * edge1.y;
        nrm.y = -(edge2.x * edge1.z - edge2.z * edge1.x);
        nrm.z = edge2.x * edge1.y - edge2.y * edge1.x;
        PSVECNormalize(&nrm, &nrm);
        planes[5].normal.x = -nrm.x;
        planes[5].normal.y = -nrm.y;
        planes[5].normal.z = -nrm.z;
        planes[5].distance = -(planes[5].normal.x * corners[0].x + planes[5].normal.y * corners[0].y +
                               planes[5].normal.z * corners[0].z);
    }
}

static int cullVisibleShadowTriangles(GameObject* obj, Vec3f* unusedCorners, ShadowVolumePlane* unusedPlanes, int count,
                                      Vec3f* vertices, Vec3f* outVertices, TrackShadowTriangle* triangles, int limit) {
    int vertexIndex = 0;
    int outCount = 0;
    int i = 0;
    int j;
    ObjModelState* modelState = obj->anim.modelState;

    gShadowVisibleCount = 0;
    for (; i < count; i++, vertexIndex += 3, triangles++) {
        int vis = 1;
        f32 dot = modelState->shadowOffsetX * triangles->normal.x + modelState->shadowOffsetY * triangles->normal.y +
                  modelState->shadowOffsetZ * triangles->normal.z;
        if (dot < 0.0f) {
            vis = -1;
        }
        if (vis == 1) {
            gShadowVisibleCount++;
            for (j = 0; j < 3; j++) {
                outVertices->x = vertices[vertexIndex + j].x;
                outVertices->y = vertices[vertexIndex + j].y;
                outVertices->z = vertices[vertexIndex + j].z;
                outVertices++;
                if (++outCount >= limit) {
                    return 0;
                }
            }
        }
    }
    return gShadowVisibleCount > 0;
}

void objDrawShadowCasterMesh(Vec3f* vertices, ObjModelState* modelState, GameObject* obj, int triangleCount,
                             void* unusedDrawScratch, void* unusedBounds, f32 unusedYOffset) {
    u8 shadowColor[4];
    Vec3f savedWorldPos;
    Vec3f savedLocalPos;
    f32 worldMtx[4][4];
    f32 viewWorldMtx[4][4];
    f32 savedRootMotionScale;
    f32 projectionScale;
    f32 meshVertexScale;
    s16 savedRotX;
    s16 savedRotZ;
    s16 savedRotY;
    Texture* diskTexture;
    MtxPtr viewMtx;
    u32 vertexIndex;
    /* Counts s16 components in the cache, or Vec3f entries in the uncached stream. */
    u32 streamIndex;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    shadowColor[0] = 0;
    shadowColor[1] = 0;
    shadowColor[2] = 0;
    shadowColor[3] = modelState->shadowCastSlot->alpha;
    savedRootMotionScale = obj->anim.rootMotionScale;
    savedRotX = obj->anim.rotX;
    savedRotZ = obj->anim.rotZ;
    savedRotY = obj->anim.rotY;
    if (modelState->shadowRenderResource == NULL || modelState->shadowRenderResource != OBJECT_SHADOW_MESH_UNCACHED) {
        obj->anim.rootMotionScale = 0.05f;
    } else {
        obj->anim.rootMotionScale = 1.0f;
    }
    obj->anim.rotX = 0;
    obj->anim.rotY = 0;
    if ((modelState->flags & OBJ_MODEL_STATE_SHADOW_KEEP_ROT_Z) == 0) {
        obj->anim.rotZ = 0;
    }
    if (modelState->flags & OBJ_MODEL_STATE_SHADOW_POS_OVERRIDE) {
        memcpy(&savedLocalPos, &obj->anim.localPos, sizeof(Vec3f));
        memcpy(&savedWorldPos, &obj->anim.worldPos, sizeof(Vec3f));
        memcpy(&obj->anim.worldPos, &modelState->overrideWorldPos, sizeof(Vec3f));
        memcpy(&obj->anim.localPos, &modelState->overrideWorldPos, sizeof(Vec3f));
    }
    Obj_BuildWorldTransformMatrix(obj, (f32*)worldMtx, 0);
    viewMtx = (MtxPtr)Camera_GetViewMatrix();
    PSMTXConcat(viewMtx, (MtxPtr)worldMtx, (MtxPtr)viewWorldMtx);
    GXLoadPosMtxImm((const f32(*)[4])viewWorldMtx, GX_PNMTX0);
    if (obj->anim.modelInstance->renderFlags & OBJDEF_RENDERFLAG_PROJECTED_SHADOW) {
        GXColor color = *(GXColor*)shadowColor;
        objectShadow_setupSwappedProjectedTexture(modelState->shadowCastSlot, &color, worldMtx);
    } else {
        if (obj == Obj_GetPlayerObject()) {
            projectionScale = 10.0f;
        } else {
            projectionScale = obj->anim.hitboxScale * obj->anim.rootMotionScale;
        }
        if (modelState->shadowRenderResource != OBJECT_SHADOW_MESH_UNCACHED ||
            (diskTexture = newshadows_getSmallDiskTexture(), modelState->shadowCastSlot->texture == diskTexture)) {
            GXColor color = *(GXColor*)shadowColor;
            objectShadow_setupProjectedTexture(modelState->shadowCastSlot, &color, worldMtx);
        } else if (modelState->shadowCastSlot->mode == 0xff) {
            GXColor color = *(GXColor*)shadowColor;
            objectShadow_setupProjectedTextureDepthFade(modelState->shadowCastSlot, &color, worldMtx, projectionScale);
        } else {
            GXColor color = *(GXColor*)shadowColor;
            objectShadow_setupProjectedTextureChannel(modelState->shadowCastSlot, &color, worldMtx, projectionScale);
        }
    }
    GXSetCullMode(GX_CULL_FRONT);
    GXSetCurrentMtx(GX_PNMTX0);
    obj->anim.rootMotionScale = savedRootMotionScale;
    obj->anim.rotX = savedRotX;
    obj->anim.rotY = savedRotY;
    obj->anim.rotZ = savedRotZ;
    if (modelState->shadowRenderResource == NULL) {
        modelState->shadowRenderResource = mmAlloc(triangleCount * 0x12 + sizeof(ObjectShadowMesh), 0x18, 0);
        if (modelState->shadowRenderResource == NULL) {
            return;
        }
        modelState->shadowRenderResource->coordinates =
            (s16*)((u8*)modelState->shadowRenderResource + sizeof(ObjectShadowMesh));
        modelState->shadowRenderResource->vertexCount = triangleCount * 3;
        vertexIndex = 0;
        meshVertexScale = 20.0f;
        for (streamIndex = 0; vertexIndex < modelState->shadowRenderResource->vertexCount;
             vertexIndex++, streamIndex += 3) {
            modelState->shadowRenderResource->coordinates[streamIndex + 0] = meshVertexScale * vertices[vertexIndex].x;
            modelState->shadowRenderResource->coordinates[streamIndex + 1] = meshVertexScale * vertices[vertexIndex].y;
            modelState->shadowRenderResource->coordinates[streamIndex + 2] = meshVertexScale * vertices[vertexIndex].z;
        }
    }
    if (modelState->shadowRenderResource != OBJECT_SHADOW_MESH_UNCACHED) {
        GXBegin(GX_TRIANGLES, GX_VTXFMT0, modelState->shadowRenderResource->vertexCount & 0xffff);
        for (vertexIndex = 0, streamIndex = 0; vertexIndex < modelState->shadowRenderResource->vertexCount;
             vertexIndex++, streamIndex += 3) {
            GXPosition3s16(modelState->shadowRenderResource->coordinates[streamIndex + 0],
                           modelState->shadowRenderResource->coordinates[streamIndex + 1],
                           modelState->shadowRenderResource->coordinates[streamIndex + 2]);
        }
    } else {
        int triangleIndex;
        GXBegin(GX_TRIANGLES, GX_VTXFMT2, (triangleCount * 3) & 0xffff);
        streamIndex = 0;
        for (triangleIndex = 0; triangleIndex < triangleCount; triangleIndex++) {
            int k;
            for (k = 0; k < 3; k++) {
                f32 y;
                f32 z;
                f32 x;
                z = vertices[streamIndex + k].z;
                y = vertices[streamIndex + k].y;
                x = vertices[streamIndex + k].x;
                GXWGFifo.f32 = x;
                GXWGFifo.f32 = y;
                GXWGFifo.f32 = z;
            }
            streamIndex += 3;
        }
    }
    if (modelState->flags & OBJ_MODEL_STATE_SHADOW_POS_OVERRIDE) {
        memcpy(&obj->anim.localPos, &savedLocalPos, sizeof(Vec3f));
        memcpy(&obj->anim.worldPos, &savedWorldPos, sizeof(Vec3f));
    }
}

static int objShadowGetFadedAlpha(GameObject* obj, u8 param) {
    int lo;
    int hi;
    f32 inv;
    ObjDef* p;

    p = (ObjDef*)(obj->anim.modelInstance);
    if (p->renderFlags & OBJDEF_RENDERFLAG_PROJECTED_SHADOW) {
        lo = 1000;
        hi = 2000;
    } else {
        lo = 400;
        hi = 500;
    }
    inv = (Camera_DistanceToCurrentViewPosition(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ) - lo) /
          (f32)(hi - lo);
    if (inv < 0.0f) {
        inv = 0.0f;
    } else if (inv > 1.0f) {
        inv = 1.0f;
    }
    inv = 1.0f - inv;
    {
        int n = (int)((f32)param * inv);
        return (n * (obj->anim.renderAlpha + 1)) >> 8;
    }
}

int objShadowRender(GameObject* obj, int renderMode, int unused, int frameCount) {
    ObjModelState* modelState;
    Vec3f* cache;
    f32 yOff;
    int idxOut = 0;
    int drawScratch;
    u32* vtx;
    int triangleTable = 0;
    int triangleBuffer;
    ObjectShadowMesh* shadowMesh;
    Vec3f direction;
    Vec3f queryOrigin;
    TrackQueryBounds ranges;
    Vec3f boxCorners[8];
    u8 planeWorkspace[304];

    cache = (Vec3f*)(getCache());
    modelState = obj->anim.modelState;
    if ((s32)shouldDrawShadows() == 0) {
        obj->anim.modelState->shadowCastSlot = NULL;
        return 0;
    }

    shadowMesh = modelState->shadowRenderResource;
    if (shadowMesh == NULL || shadowMesh == OBJECT_SHADOW_MESH_UNCACHED) {
        direction.x = modelState->shadowOffsetX;
        direction.y = modelState->shadowOffsetY;
        direction.z = modelState->shadowOffsetZ;
        buildShadowVolumeBox(&direction, boxCorners, modelState->shadowModelScale);

        {
            ObjHitsPriorityState* p54 = (ObjHitsPriorityState*)(obj->anim.hitReactState);
            if (p54 != NULL) {
                yOff = (f32)((int)p54->primaryCapsuleOffsetB / 2);
            } else {
                yOff = 0.0f;
            }
        }

        queryOrigin.x = obj->anim.worldPosX;
        queryOrigin.y = obj->anim.worldPosY + yOff;
        queryOrigin.z = obj->anim.worldPosZ;
        vecGetRanges(boxCorners, &queryOrigin, modelState->shadowScale, &ranges);

        trackIntersectBroadphase(obj, &ranges, 0x81, 0);
        trackGetGridOrigin((int**)&vtx);
        trackGetTriangleBuffer(&idxOut, &triangleTable);

        triangleBuffer = triangleTable;
        idxOut =
            collectShadowTrackTriangles(obj, (TrackTriangle*)triangleBuffer, (TrackShadowTriangle*)gShadowDrawScratch,
                                        gShadowVolumeBuffer, idxOut, (f32)(int)vtx[0], (f32)(int)vtx[2], renderMode,
                                        modelState->flags & OBJ_MODEL_STATE_SHADOW_ALT_TRACK_SURFACE);
        gShadowTrackTriangleBuffer = triangleBuffer;
        gShadowTrackTriangleCount = idxOut;
        gShadowTrackGridOrigin = (int)vtx;
        trackDolphin_buildShadowVolumePlanes(obj, boxCorners, (ShadowVolumePlane*)planeWorkspace);
        cullVisibleShadowTriangles(obj, boxCorners, (ShadowVolumePlane*)planeWorkspace, idxOut, gShadowVolumeBuffer,
                                   cache, (TrackShadowTriangle*)gShadowDrawScratch, 0x555);
    }
    objDrawShadowCasterMesh(cache, modelState, obj, gShadowVisibleCount, &drawScratch, boxCorners, yOff);
    return 0;
}

u8 objShadowUpdateAlpha(GameObject* obj, int delta) {
    ObjModelState* modelState;
    s16* alphaStep;
    f32 alphaScale;
    int v;

    modelState = obj->anim.modelState;
    alphaStep = &modelState->shadowAlphaStep;
    if (modelState->flags & OBJ_MODEL_STATE_SHADOW_FADE_OUT) {
        *alphaStep = *alphaStep - (delta << 9);
        if (*alphaStep <= 0) {
            *alphaStep = 0;
        }
        if (*alphaStep == 0) {
            modelState->shadowCastSlot = NULL;
            return 0;
        }
    } else if (!(modelState->flags & OBJ_MODEL_STATE_SHADOW_ALPHA_HOLD)) {
        *alphaStep = *alphaStep + (delta << 9);
        if (*alphaStep >= 0x4000) {
            *alphaStep = 0x4000;
        }
    }
    alphaScale = (1.0f / 16384.0f) * (f32)*alphaStep;
    alphaScale = gShadowAlphaScale * alphaScale;
    {
        f32 tint = objShadowGetFadedAlpha(obj, modelState->shadowTintA);
        v = (s16)(int)(tint * alphaScale);
    }
    if (v > 0xff) {
        v = 0xff;
    } else if (v < 0) {
        v = 0;
    }
    return v & 0xff;
}

void shadowVolumeBeginFrame(void) {
    if ((s8)gShadowVolumesDirty == 0) {
        return;
    }
    lbl_803DCEF8 = 0;
    lbl_803DCEFC = 0;
    lbl_803DCEF4 = 0;
    gShadowVolumeBufferSelect = 1 - gShadowVolumeBufferSelect;
    lbl_803DCEED = 1 - lbl_803DCEED;
    lbl_803DCEEE = 1 - lbl_803DCEEE;
    lbl_803DCF08 = gShadowVolumeBuffers[gShadowVolumeBufferSelect];
    lbl_803DCEF4 = 0;
    /* Keep address-based reads here: scalar reads change MWCC register allocation. */
    lbl_803DCF10 = *(const int*)&lbl_803DCF20;
    lbl_803DCF18 = *(const int*)&lbl_803DCF1C;
    lbl_803DCF04 = lbl_803DCF08;
    lbl_803DCF14 = lbl_803DCF18;
    lbl_803DCF0C = lbl_803DCF10;
}

void shadowBeginFrame(void) {
    lbl_803DCEF6 = 0;
    lbl_803DCEFA = 0;
    lbl_803DCEEA = (s8)(1 - lbl_803DCEEA);
    lbl_803DCEEB = (s8)(1 - lbl_803DCEEB);
    lbl_803DCEE9 = 0;
    lbl_803DCEE8 = 0;
}

void objShadowInvalidate(GameObject* obj) {
    gShadowVolumesDirty = 0x1;
}

void shadowVolumesSetDirty(s32 dirty) {
    gShadowVolumesDirty = dirty;
}

int shadowInit(GameObject* obj, u32 arena, int flags) {
    int rounded;
    ObjModelState* modelState;
    s16 texId;

    rounded = roundUpTo4(arena);
    obj->anim.modelState = (ObjModelState*)rounded;
    modelState = obj->anim.modelState;
    texId = obj->anim.modelInstance->shadowTextureId;
    if (texId != -1 && obj->anim.modelInstance->shadowType != OBJ_SHADOW_TYPE_MODEL_GEOMETRIC) {
        modelState->shadowTexture = (void*)textureLoad(-texId, 0);
    } else if (obj->anim.modelInstance->renderFlags & OBJDEF_RENDERFLAG_PROJECTED_SHADOW) {
        modelState->shadowTexture = (void*)newshadows_allocTexture512();
    } else if (obj->anim.modelInstance->renderFlags & 0x2) {
        modelState->shadowTexture = NULL;
        modelState->shadowWorkBuffer = NULL;
    } else {
        modelState->shadowTexture = newshadows_getSmallDiskTexture();
    }
    if (obj->anim.modelInstance->shadowType == OBJ_SHADOW_TYPE_BIG_BOX) {
        modelState->shadowRenderResource = NULL;
    } else {
        modelState->shadowRenderResource = OBJECT_SHADOW_MESH_UNCACHED;
    }
    modelState->shadowScale = obj->anim.modelInstance->shadowScaleBase;
    modelState->shadowModelScale = obj->anim.modelInstance->shadowModelScaleBase;
    modelState->shadowOffsetX = gShadowOffsetX;
    modelState->shadowOffsetY = gShadowOffsetY;
    modelState->shadowOffsetZ = gShadowOffsetZ;
    modelState->shadowAlphaStep = 0x4000;
    modelState->flags = OBJ_MODEL_STATE_SHADOW_VISIBLE;
    modelState->pad38[0] = 0x19;
    modelState->pad38[1] = 0x4b;
    modelState->shadowTintA = 0x96;
    modelState->shadowTintB = 0x64;
    gShadowVolumesDirty = 1;
    return rounded + sizeof(ObjModelState);
}

void playerShadowClearPositionOverride(GameObject* obj) {
    ObjModelState* modelState = obj->anim.modelState;
    if (modelState == NULL) {
        return;
    }
    modelState->flags &= ~(OBJ_MODEL_STATE_SHADOW_POS_OVERRIDE | OBJ_MODEL_STATE_SHADOW_KEEP_ROT_Z);
}

void playerShadowSetPositionOverride(GameObject* obj, f32 x, f32 y, f32 z) {
}

void shadowSetLightDirection(f32 directionX, f32 directionY, f32 directionZ, int magnitude) {
    Vec normalizedDirection;
    f32 directionSimilarity;
    f32 directionMagnitudeSquared;
    f32 magnitudeSquared;
    f32 combinedMagnitudeSquared;

    normalizedDirection.x = directionX;
    normalizedDirection.y = directionY;
    normalizedDirection.z = directionZ;
    PSVECNormalize(&normalizedDirection, &normalizedDirection);
    gSunMagnitude = magnitude;
    gShadowOffsetX = directionX * magnitude;
    gShadowOffsetY = directionY * magnitude;
    gShadowAlphaScale = 1.0f;
    if (gShadowOffsetY < 80.0f) {
        gShadowOffsetY = 80.0f;
    }
    gShadowOffsetZ = directionZ * magnitude;
    directionSimilarity = normalizedDirection.x * gPrevSunDir[0] + normalizedDirection.y * gPrevSunDir[1] +
                          normalizedDirection.z * gPrevSunDir[2];
    magnitudeSquared = normalizedDirection.x * normalizedDirection.x + normalizedDirection.y * normalizedDirection.y;
    directionMagnitudeSquared = magnitudeSquared + normalizedDirection.z * normalizedDirection.z;
    magnitudeSquared =
        gPrevSunDir[0] * gPrevSunDir[0] + gPrevSunDir[1] * gPrevSunDir[1] + gPrevSunDir[2] * gPrevSunDir[2];
    combinedMagnitudeSquared = directionMagnitudeSquared * magnitudeSquared;
    if (combinedMagnitudeSquared) {
        magnitudeSquared = sqrtf(combinedMagnitudeSquared);
    }
    if (magnitudeSquared) {
        gSunDotCos = directionSimilarity / magnitudeSquared;
    } else {
        gSunDotCos = 0.0f;
    }
    if (gSunDotCos < 0.0f) {
        gSunDotCos *= -1.0f;
    }
    if (gSunDotCos <= 0.99619f) {
        gSunDirChanged = 1;
    }
    if (gSunDirChanged != 0) {
        gPrevSunDir[0] = normalizedDirection.x;
        gPrevSunDir[1] = normalizedDirection.y;
        gPrevSunDir[2] = normalizedDirection.z;
        gSunDirChanged = 0;
        gShadowVolumesDirty = 1;
    }
}

void initTextures(void) {
    f32* a = lbl_8038D77C;
    f32* b = gShadowVolumeBoxCorners;

    gShadowVolumesDirty = 10;
    gShadowVolumeBuffer = mmAlloc(0xa8c0, 0x18, 0);
    a[0] = -1.0f;
    b[0] = -1.0f;
    a[1] = -1.0f;
    b[1] = -1.0f;
    a[2] = -1.0f;
    b[2] = -1.0f;
    a[3] = -1.0f;
    b[3] = -1.0f;
    a[4] = 0.0f;
    b[4] = 0.0f;
    a[5] = -1.0f;
    b[5] = -1.0f;
    a[6] = 1.0f;
    b[6] = 1.0f;
    a[7] = 0.0f;
    b[7] = 0.0f;
    a[8] = -1.0f;
    b[8] = -1.0f;
    a[9] = 1.0f;
    b[9] = 1.0f;
    a[10] = -1.0f;
    b[10] = -1.0f;
    a[11] = -1.0f;
    b[11] = -1.0f;
    b[12] = -1.0f;
    b[13] = -1.0f;
    b[14] = 1.0f;
    b[15] = -1.0f;
    b[16] = 0.0f;
    b[17] = 1.0f;
    b[18] = 1.0f;
    b[19] = 0.0f;
    b[20] = 1.0f;
    b[21] = 1.0f;
    b[22] = -1.0f;
    b[23] = 1.0f;
    a[12] = -6.0f;
    a[13] = 0.0f;
    a[14] = 55.0f;
    a[15] = -6.0f;
    a[16] = 16.0f;
    a[17] = 55.0f;
    a[18] = 6.0f;
    a[19] = 16.0f;
    a[20] = 55.0f;
    a[21] = 6.0f;
    a[22] = 0.0f;
    a[23] = 55.0f;
    allocLotsOfTextures();
}

f32 gShadowVolumeBoxCorners[0x19];
f32 lbl_8038D77C[0x18];
u8 gShadowDrawScratch[0x5DC0];
