/* Optional EN retail practice payload. No definitions exist without SFA_PRACTICE.
 * tools/practice/build.py links this separately and verifies every retail hook.
 */
#ifdef SFA_PRACTICE
#include "practice/practice.h"
#include "dlls/objects/294.h"
#include "dolphin/gx.h"
#include "dolphin/mtx.h"
#include "dolphin/pad.h"
#include "dolphin/os/OSArena.h"
#include "main/camera.h"
#include "main/debug_display.h"
#include "main/frame_timing.h"
#include "main/map_block.h"
#include "main/obj_list.h"
#include "main/object_transform.h"
#include "main/objhits_types.h"
#include "main/pad.h"
#include "main/shader_api.h"
#include "sys/objects.h"

extern u8 __practice_start[];
extern u8 __practice_limit[];
extern u8 gDebugFontAndErrorData[];
extern PADStatus gPadStatuses[];
extern u8 timeStop;
extern int gMapBlockOriginWorldX, gMapBlockOriginWorldZ;
extern void resetSomeGxFlags(void);
extern MapBlockData* mapGetBlockAtPos(int x, int z, int layer);
extern void playerDoControls(GameObject*, PlayerState*, f32);
extern void playerUpdateSurfaceResponse(GameObject*, PlayerState*, PlayerState*, f32);
extern void playerEnterDeepWater(GameObject*, PlayerState*, PlayerState*);
extern f32 mathSinf(f32);
extern f32 mathCosf(f32);
extern u32 getScreenResolution(void);

enum {
    COLLISION,
    TERRAIN,
    OBJECT_MESH,
    HIT_SPHERES,
    WATER_MESH,
    BARRIERS,
    TRIGGERS,
    PLANES,
    BOXES,
    SPHERES,
    CYLINDERS,
    TARGET_PATH,
    TRIGGER_FILL,
    SWIMMING,
    WATER_HEIGHT,
    WATER_GRID,
    XRAY,
    RANGE,
    ROW_COUNT
};
typedef struct PracticeRow {
    const char* label;
    s8 parent;
    u8 group;
} PracticeRow;
static const PracticeRow rows[ROW_COUNT] = {{"COLLISION", -1, 1},
                                            {"TERRAIN TRIANGLES", COLLISION, 0},
                                            {"OBJECT TRIANGLES", COLLISION, 0},
                                            {"OBJECT HIT SPHERES", COLLISION, 0},
                                            {"WATER TRIANGLES", COLLISION, 0},
                                            {"BARRIERS / LEDGES", COLLISION, 0},
                                            {"TRIGGERS", -1, 1},
                                            {"CROSSING PLANES", TRIGGERS, 0},
                                            {"BOXES", TRIGGERS, 0},
                                            {"SPHERES", TRIGGERS, 0},
                                            {"CYLINDERS", TRIGGERS, 0},
                                            {"TARGET MOTION", TRIGGERS, 0},
                                            {"TRANSLUCENT FILL", TRIGGERS, 0},
                                            {"FORCED SWIMMING", -1, 1},
                                            {"WATER HEIGHT", SWIMMING, 0},
                                            {"SHOW WATER PLANE", SWIMMING, 0},
                                            {"DRAW THROUGH WALLS", -1, 0},
                                            {"DRAW DISTANCE", -1, 0}};
static u8 enabled[ROW_COUNT] = {0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0};
static u8 expanded[ROW_COUNT];
static u8 menuOpen, chordLatched, savedTimeStop, swimApplied;
static int selected, repeatTimer, visibleCount, visible[ROW_COUNT], menuTop;
static int drawDistance = 1000;
static f32 waterHeight;
static GameObject* swimOwner;
static int linesDrawn, trianglesDrawn, triggersDrawn;
static int fillsDrawn;
static int drawLimitReached;
static int lineLimit = 12000;
static int fillLimit = 6000;
static Vec origin;
static const u32 WHITE = 0xE7EFFAFF, MUTED = 0x95A5BFFF, GOLD = 0xFFD16AFF;

static Vec point(f32 x, f32 y, f32 z) {
    Vec p;
    p.x = x;
    p.y = y;
    p.z = z;
    return p;
}

static int validPointer(const void* p) {
    return (u32)p >= 0x80003100 && (u32)p < 0x81800000 && ((u32)p & 3) == 0 &&
           ((u32)p < (u32)__practice_start || (u32)p >= (u32)__practice_limit);
}

static int nearPoint(Vec p) {
    f32 x = p.x - origin.x, y = p.y - origin.y, z = p.z - origin.z;
    return x * x + y * y + z * z < (f32)drawDistance * drawDistance;
}

static void vertex(f32 x, f32 y, f32 z, u32 color) {
    GXPosition3f32(x, y, z);
    GXColor1u32(color);
}

/* The view matrix consumes positions relative to the current map origin. */
static void line(Vec a, Vec b, u32 color) {
    if (linesDrawn >= lineLimit) {
        drawLimitReached = 1;
        return;
    }
    GXBegin(GX_LINES, GX_VTXFMT7, 2);
    vertex(a.x - playerMapOffsetX, a.y, a.z - playerMapOffsetZ, color);
    vertex(b.x - playerMapOffsetX, b.y, b.z - playerMapOffsetZ, color);
    linesDrawn++;
}

/* Conservative bounds include large faces crossing the draw radius even when
 * every vertex lies outside it. Vertex-only culling leaves holes under Fox. */
static int nearTriangle(Vec a, Vec b, Vec c) {
    f32 distance = 0;
    int axis;
    for (axis = 0; axis < 3; axis++) {
        f32 low = ((f32*)&a)[axis], high = low, p = ((f32*)&origin)[axis], delta = 0;
        if (((f32*)&b)[axis] < low) {
            low = ((f32*)&b)[axis];
        }
        if (((f32*)&c)[axis] < low) {
            low = ((f32*)&c)[axis];
        }
        if (((f32*)&b)[axis] > high) {
            high = ((f32*)&b)[axis];
        }
        if (((f32*)&c)[axis] > high) {
            high = ((f32*)&c)[axis];
        }
        if (p < low) {
            delta = low - p;
        }
        if (p > high) {
            delta = p - high;
        }
        distance += delta * delta;
    }
    return distance <= (f32)drawDistance * drawDistance;
}

static void triangle(Vec a, Vec b, Vec c, u32 color) {
    Vec ab = point(b.x - a.x, b.y - a.y, b.z - a.z);
    Vec ac = point(c.x - a.x, c.y - a.y, c.z - a.z);
    Vec normal = point(ab.y * ac.z - ab.z * ac.y, ab.z * ac.x - ab.x * ac.z, ab.x * ac.y - ab.y * ac.x);
    if (!(normal.x * normal.x + normal.y * normal.y + normal.z * normal.z > 0)) {
        return;
    }
    if (nearTriangle(a, b, c)) {
        line(a, b, color);
        line(b, c, color);
        line(c, a, color);
        trianglesDrawn++;
    }
}

/* Translucent surfaces test against scene depth but never write to it. Keep
 * both sides visible so volumes remain readable when the camera is inside. */
static void fillTriangle(Vec a, Vec b, Vec c, u32 color) {
    if (!enabled[TRIGGER_FILL] || fillsDrawn >= fillLimit) {
        return;
    }
    color = (color & 0xFFFFFF00) | 0x30;
    GXBegin(GX_TRIANGLES, GX_VTXFMT7, 3);
    vertex(a.x - playerMapOffsetX, a.y, a.z - playerMapOffsetZ, color);
    vertex(b.x - playerMapOffsetX, b.y, b.z - playerMapOffsetZ, color);
    vertex(c.x - playerMapOffsetX, c.y, c.z - playerMapOffsetZ, color);
    fillsDrawn++;
}

static void fillQuad(Vec a, Vec b, Vec c, Vec d, u32 color) {
    fillTriangle(a, b, c, color);
    fillTriangle(a, c, d, color);
}

static void fillSphere(Vec center, f32 radius, u32 color) {
    Vec previous[16], ring[16];
    int latitude, longitude;
    if (!enabled[TRIGGER_FILL] || !(radius > 0 && radius < 50000)) {
        return;
    }
    for (longitude = 0; longitude < 16; longitude++) {
        previous[longitude] = point(center.x, center.y - radius, center.z);
    }
    for (latitude = 1; latitude <= 8 && fillsDrawn < fillLimit; latitude++) {
        f32 angle = -1.57079632679f + latitude * (3.14159265359f / 8);
        f32 y = center.y + mathSinf(angle) * radius;
        f32 r = mathCosf(angle) * radius;
        for (longitude = 0; longitude < 16; longitude++) {
            f32 yaw = longitude * (6.28318530718f / 16);
            ring[longitude] = point(center.x + mathCosf(yaw) * r, y, center.z + mathSinf(yaw) * r);
        }
        for (longitude = 0; longitude < 16; longitude++) {
            int next = (longitude + 1) & 15;
            if (latitude == 1) {
                fillTriangle(previous[longitude], ring[longitude], ring[next], color);
            } else if (latitude == 8) {
                fillTriangle(previous[longitude], ring[longitude], previous[next], color);
            } else {
                fillQuad(previous[longitude], ring[longitude], ring[next], previous[next], color);
            }
        }
        for (longitude = 0; longitude < 16; longitude++) {
            previous[longitude] = ring[longitude];
        }
    }
}

static void fillCylinder(Vec bottom, Vec top, f32 radius, u32 color) {
    Vec firstA, firstB, prevA, prevB;
    int i;
    if (!enabled[TRIGGER_FILL] || !(radius > 0 && radius < 50000)) {
        return;
    }
    for (i = 0; i <= 24 && fillsDrawn < fillLimit; i++) {
        f32 angle = i * (6.28318530718f / 24);
        Vec a = point(bottom.x + mathCosf(angle) * radius, bottom.y, bottom.z + mathSinf(angle) * radius);
        Vec b = point(a.x, top.y, a.z);
        if (i == 0) {
            firstA = a;
            firstB = b;
        } else {
            if (i == 24) {
                a = firstA;
                b = firstB;
            }
            fillQuad(prevA, prevB, b, a, color);
            fillTriangle(bottom, prevA, a, color);
            fillTriangle(top, b, prevB, color);
        }
        prevA = a;
        prevB = b;
    }
}

static void setupGeometry(int depth) {
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_POS, GX_POS_XYZ, GX_F32, 0);
    GXSetVtxAttrFmt(GX_VTXFMT7, GX_VA_CLR0, GX_CLR_RGBA, GX_RGBA8, 0);
    GXSetCurrentMtx(GX_PNMTX0);
    GXSetNumChans(1);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXSetNumIndStages(0);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevOp(GX_TEVSTAGE0, GX_PASSCLR);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetCullMode(GX_CULL_NONE);
    GXSetZMode(depth != 0, GX_LEQUAL, GX_FALSE);
    GXSetZCompLoc(GX_TRUE);
    GXSetColorUpdate(GX_TRUE);
    GXSetAlphaUpdate(GX_FALSE);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    {
        GXColor c = {0, 0, 0, 0};
        GXSetFog(GX_FOG_NONE, 0, 1, 0, 1, c);
    }
    GXSetLineWidth(12, GX_TO_ZERO);
}

static void circle(Vec center, f32 radius, int axis, u32 color) {
    int i;
    Vec first, prev;
    if (!(radius > 0.0f && radius < 50000.0f)) {
        return;
    }
    for (i = 0; i <= 24; i++) {
        f32 a = i * (6.28318530718f / 24.0f);
        f32 s = mathSinf(a) * radius, c = mathCosf(a) * radius;
        Vec p = center;
        if (axis == 0) {
            p.y += c;
            p.z += s;
        }
        if (axis == 1) {
            p.x += c;
            p.z += s;
        }
        if (axis == 2) {
            p.x += c;
            p.y += s;
        }
        if (i == 0) {
            first = p;
        } else {
            line(prev, i == 24 ? first : p, color);
        }
        prev = p;
    }
}

static void sphere(Vec p, f32 radius, u32 color) {
    circle(p, radius, 0, color);
    circle(p, radius, 1, color);
    circle(p, radius, 2, color);
}

static Vec transformPoint(f32* matrix, Vec p) {
    Vec out;
    Matrix_TransformPoint(matrix, p.x, p.y, p.z, &out.x, &out.y, &out.z);
    return out;
}

static void drawTriggers(GameObject* obj) {
    TriggerPlacement* def = (TriggerPlacement*)obj->anim.placementData;
    TriggerState* state = obj->extra;
    Vec center = point(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ);
    u32 color;
    int type;
    if (!validPointer(def) || !validPointer(state) || !validPointer(obj->anim.modelInstance) ||
        obj->anim.modelInstance->dllId != 294 || !nearPoint(center)) {
        return;
    }
    color = (state->status & 4) ? 0x7D8796FF : 0xFF69D4FF;
    type = def->base.objectId;
    if (type == 0x4c && enabled[PLANES]) {
        MmpTriggerPlaneState* plane = (MmpTriggerPlaneState*)state;
        Mtx inverse;
        Vec p[4];
        int i;
        if (PSMTXInverse(plane->mtx, inverse) == 0) {
            return;
        }
        for (i = 0; i < 4; i++) {
            Vec local = point((i & 1) ? plane->clipHalfExtent : -plane->clipHalfExtent,
                              (i & 2) ? plane->clipHalfExtent : -plane->clipHalfExtent, 0);
            PSMTXMultVec(inverse, &local, &p[i]);
        }
        fillQuad(p[0], p[1], p[3], p[2], color);
        line(p[0], p[1], color);
        line(p[1], p[3], color);
        line(p[3], p[2], color);
        line(p[2], p[0], color);
        {
            Vec n =
                point(center.x + plane->normalX * 40, center.y + plane->normalY * 40, center.z + plane->normalZ * 40);
            line(center, n, GOLD);
        }
    } else if (type == 0x4d && enabled[BOXES]) {
        Vec p[8];
        int i, j;
        f32 yaw = obj->anim.rotX * (3.14159265359f / 32768.0f);
        f32 pitch = obj->anim.rotY * (3.14159265359f / 32768.0f);
        f32 sy = mathSinf(yaw), cy = mathCosf(yaw), sp = mathSinf(pitch), cp = mathCosf(pitch);
        for (i = 0; i < 8; i++) {
            f32 x = def->size[0] * ((i & 1) ? 2.0f : -2.0f);
            f32 y = def->size[1] * ((i & 2) ? 2.0f : -2.0f);
            f32 z = def->size[2] * ((i & 4) ? 2.0f : -2.0f);
            f32 forward = z * cp - y * sp;
            p[i].x = center.x + x * cy + forward * sy;
            p[i].y = center.y + y * cp + z * sp;
            p[i].z = center.z - x * sy + forward * cy;
        }
        fillQuad(p[0], p[1], p[3], p[2], color);
        fillQuad(p[4], p[5], p[7], p[6], color);
        fillQuad(p[0], p[1], p[5], p[4], color);
        fillQuad(p[2], p[3], p[7], p[6], color);
        fillQuad(p[0], p[2], p[6], p[4], color);
        fillQuad(p[1], p[3], p[7], p[5], color);
        for (i = 0; i < 8; i++) {
            for (j = 1; j <= 4; j <<= 1) {
                if (!(i & j)) {
                    line(p[i], p[i | j], color);
                }
            }
        }
    } else if (type == 0x4b && enabled[SPHERES]) {
        fillSphere(center, def->size[0] * 2.0f, color);
        sphere(center, def->size[0] * 2.0f, color);
    } else if (type == 0x230 && enabled[CYLINDERS]) {
        Vec a = center, b = center;
        int i;
        f32 radius = def->size[0] * 2.0f;
        a.y -= def->size[1] * 2.0f;
        b.y += def->size[1] * 2.0f;
        fillCylinder(a, b, radius, color);
        circle(a, radius, 1, color);
        circle(b, radius, 1, color);
        for (i = 0; i < 4; i++) {
            Vec c = a, d = b;
            c.x += mathCosf(i * 1.57079632679f) * radius;
            c.z += mathSinf(i * 1.57079632679f) * radius;
            d.x = c.x;
            d.z = c.z;
            line(c, d, color);
        }
    } else {
        return;
    }
    triggersDrawn++;
    if (enabled[TARGET_PATH]) {
        Vec a = point(state->targetPosX, state->targetPosY, state->targetPosZ);
        Vec b = point(state->prevTargetPosX, state->prevTargetPosY, state->prevTargetPosZ);
        if (a.x > -1000000 && a.x < 1000000 && a.y > -1000000 && a.y < 1000000 && a.z > -1000000 && a.z < 1000000 &&
            b.x > -1000000 && b.x < 1000000 && b.y > -1000000 && b.y < 1000000 && b.z > -1000000 && b.z < 1000000) {
            line(a, b, 0xFFE067FF);
        }
    }
}

static int floorCell(f32 x) {
    int n = (int)(x / 640.0f);
    return x < n * 640.0f ? n - 1 : n;
}

/* HITS.bin / model lines form vertical interaction planes independent of the
 * triangle meshes. Match trackSweepCircleAgainstLines' signed height decode. */
static void drawHitLines(MapHitLine* hits, int count, f32 x, f32 z, GameObject* owner) {
    int i, j;
    if (!enabled[BARRIERS] || !validPointer(hits)) {
        return;
    }
    for (i = 0; i < count && linesDrawn < lineLimit; i++) {
        MapHitLine* hit = &hits[i];
        f32 ha = (s8)hit->endpointData[0], hb = (s8)hit->endpointData[1];
        Vec p[4];
        if (hit->flags & 0x80) {
            ha = hb = (s16)((hit->endpointData[0] << 8) | hit->endpointData[1]);
        }
        p[0] = point(hit->x[0] + x, hit->y[0], hit->z[0] + z);
        p[1] = point(hit->x[1] + x, hit->y[1], hit->z[1] + z);
        p[2] = p[1];
        p[2].y += hb;
        p[3] = p[0];
        p[3].y += ha;
        if (owner != NULL) {
            for (j = 0; j < 4; j++) {
                Obj_TransformLocalPointToWorld(p[j].x, p[j].y, p[j].z, &p[j].x, &p[j].y, &p[j].z, owner);
            }
        }
        if (nearTriangle(p[0], p[1], p[2]) || nearTriangle(p[0], p[2], p[3])) {
            for (j = 0; j < 4; j++) {
                line(p[j], p[(j + 1) & 3], 0xFF875FFF);
            }
        }
    }
}

static void drawTerrain(void) {
    int cx = floorCell(origin.x - gMapBlockOriginWorldX), cz = floorCell(origin.z - gMapBlockOriginWorldZ);
    int x, z, layer, groupIndex, triIndex, corner, ring;
    int radius = (drawDistance + 639) / 640;
    for (ring = 0; ring <= radius && linesDrawn < lineLimit; ring++) {
        for (z = cz - ring; z <= cz + ring && linesDrawn < lineLimit; z++) {
            for (x = cx - ring; x <= cx + ring && linesDrawn < lineLimit; x++) {
                if (x != cx - ring && x != cx + ring && z != cz - ring && z != cz + ring) {
                    continue;
                }
                for (layer = 0; layer < 5 && linesDrawn < lineLimit; layer++) {
                    MapBlockData* block = mapGetBlockAtPos(x, z, layer);
                    if (!validPointer(block)) {
                        continue;
                    }
                    drawHitLines(block->hits, block->hitCount, x * 640 + playerMapOffsetX, z * 640 + playerMapOffsetZ,
                                 NULL);
                    if (!validPointer(block->gcPolygons) || !validPointer(block->polygonGroups) ||
                        !validPointer(block->vertices)) {
                        continue;
                    }
                    for (groupIndex = 0; groupIndex < block->polyGroupCount && linesDrawn < lineLimit; groupIndex++) {
                        CollisionPolygonGroup* group = &block->polygonGroups[groupIndex];
                        int water = (group->flags & 8) != 0;
                        int end = group[1].firstTri;
                        u32 color = water ? 0x42BFFFFF : 0x59E99AFF;
                        if (water ? !enabled[WATER_MESH] : !enabled[TERRAIN]) {
                            continue;
                        }
                        /* Water with bit 1 is never queried. Retain solid bit-2
                     * groups: Fox's side-contact query (0x29) includes those. */
                        if (water && (group->flags & 1)) {
                            continue;
                        }
                        if (end > block->nPolygons) {
                            end = block->nPolygons;
                        }
                        for (triIndex = group->firstTri; triIndex < end && linesDrawn < lineLimit; triIndex++) {
                            MapTriIndex* tri = &block->gcPolygons[triIndex];
                            Vec p[3];
                            if (!(tri->cellMask & 0xFF) || !(tri->cellMask & 0xFF00)) {
                                continue;
                            }
                            for (corner = 0; corner < 3; corner++) {
                                s16* v;
                                if (tri->vert[corner] >= block->vertexCount) {
                                    break;
                                }
                                v = (s16*)block->vertices + tri->vert[corner] * 3;
                                p[corner].x = (v[0] >> 3) + x * 640 + gMapBlockOriginWorldX;
                                p[corner].y = (v[1] >> 3) + block->collisionYOffset;
                                p[corner].z = (v[2] >> 3) + z * 640 + gMapBlockOriginWorldZ;
                            }
                            if (corner == 3) {
                                triangle(p[0], p[1], p[2], color);
                            }
                        }
                    }
                }
            }
        }
    }
}

static void drawObjectCollision(GameObject* obj) {
    ObjModel* model;
    ModelFileHeader* file;
    ObjHitboxTransformState* hit = obj->anim.hitboxTransformState;
    Vec center = point(obj->anim.worldPosX, obj->anim.worldPosY, obj->anim.worldPosZ);
    int bank = 0, i, j, k;
    if (validPointer(obj->anim.modelInstance) && obj->anim.transformMatrixIndex >= 0) {
        drawHitLines(obj->anim.modelInstance->modLines, obj->anim.modelInstance->modLineCount, 0, 0, obj);
    }
    if (!nearPoint(center) || !validPointer(obj->anim.modelBanks) || !validPointer(obj->anim.modelInstance)) {
        return;
    }
    if (obj->anim.hitReactState != NULL) {
        bank = ((ObjHitsPriorityState*)obj->anim.hitReactState)->stateIndex;
    }
    if (bank < 0 || bank >= obj->anim.modelInstance->modelCount) {
        return;
    }
    model = obj->anim.modelBanks[bank];
    if (!validPointer(model) || !validPointer(model->file)) {
        return;
    }
    file = model->file;
    if (enabled[HIT_SPHERES] && validPointer(model->activeHitVolumeSpheres)) {
        ObjModelHitSphere* spheres = (ObjModelHitSphere*)model->activeHitVolumeSpheres;
        for (i = 0; i < file->hitVolumeCount && linesDrawn < lineLimit; i++) {
            Vec p =
                point(spheres[i].pos[0] + playerMapOffsetX, spheres[i].pos[1], spheres[i].pos[2] + playerMapOffsetZ);
            sphere(p, spheres[i].radius, 0xFFAB4FFF);
        }
    }
    if (!enabled[OBJECT_MESH] || !validPointer(hit) || hit->activeMatrixIndex > 1 ||
        !validPointer(file->collisionBlocks) || !validPointer(file->collisionTriangles) ||
        !validPointer(file->vertices)) {
        return;
    }
    for (i = 0; i < file->collisionBlockCount && linesDrawn < lineLimit; i++) {
        CollisionPolygonGroup* group = &file->collisionBlocks[i];
        int end = group[1].firstTri;
        if (end > 20000 || (group->flags & 0x100000)) {
            continue;
        }
        for (j = group->firstTri; j < end && linesDrawn < lineLimit; j++) {
            Vec p[3];
            for (k = 0; k < 3; k++) {
                int idx = file->collisionTriangles[j].vertexIndices[k];
                s16* v;
                f32 scale = (file->flags & MODEL_FLAG_INTEGER_VERTEX_COORDS) ? 1.0f : 1.0f / 256.0f;
                Vec local;
                if (idx >= file->vertexCount) {
                    break;
                }
                v = (s16*)file->vertices + idx * 3;
                local.x = v[0] * scale;
                local.y = v[1] * scale;
                local.z = v[2] * scale;
                p[k] = transformPoint(&hit->matrices[hit->activeMatrixIndex + 2][0][0], local);
            }
            if (k == 3) {
                triangle(p[0], p[1], p[2], 0xF4BE5FFF);
            }
        }
    }
}

static void drawWorld(void) {
    GameObject* player = Obj_GetPlayerObject();
    int i, count, start;
    GameObject** objects;
    if (!validPointer(player)) {
        return;
    }
    origin.x = player->anim.worldPosX;
    origin.y = player->anim.worldPosY;
    origin.z = player->anim.worldPosZ;
    Camera_SetCurrentViewIndex(0);
    Camera_UpdateProjection(NULL, 0);
    GXLoadPosMtxImm((MtxPtr)gCameraViewMatrix, GX_PNMTX0);
    setupGeometry(!enabled[XRAY]);
    /* Reserve half the wire budget for nearby map collision. */
    if (enabled[COLLISION] && (enabled[TERRAIN] || enabled[WATER_MESH] || enabled[BARRIERS])) {
        lineLimit = 6000;
    }
    objects = ObjList_GetObjects(&start, &count);
    if (validPointer(objects) && count >= 0 && count <= 2048) {
        for (i = start; i < count && linesDrawn < lineLimit; i++) {
            GameObject* obj = objects[i];
            if (!validPointer(obj)) {
                continue;
            }
            if (enabled[TRIGGERS]) {
                drawTriggers(obj);
            }
            if (enabled[COLLISION]) {
                drawObjectCollision(obj);
            }
        }
    }
    if (enabled[SWIMMING] && enabled[WATER_GRID]) {
        for (i = -5; i <= 5; i++) {
            Vec a = point(origin.x - 250, waterHeight, origin.z + i * 50);
            Vec b = point(origin.x + 250, waterHeight, origin.z + i * 50);
            Vec c = point(origin.x + i * 50, waterHeight, origin.z - 250);
            Vec d = point(origin.x + i * 50, waterHeight, origin.z + 250);
            line(a, b, 0x3BBFFFFF);
            line(c, d, 0x3BBFFFFF);
        }
    }
    if (linesDrawn >= lineLimit) {
        drawLimitReached = 1;
    }
    lineLimit = 12000;
    if (enabled[COLLISION] && (enabled[TERRAIN] || enabled[WATER_MESH] || enabled[BARRIERS])) {
        drawTerrain();
    }
    if (linesDrawn >= lineLimit) {
        drawLimitReached = 1;
    }
}

static void rectangle(f32 x, f32 y, f32 w, f32 h, u32 color) {
    GXBegin(GX_QUADS, GX_VTXFMT7, 4);
    vertex(x, y, 0, color);
    vertex(x + w, y, 0, color);
    vertex(x + w, y + h, 0, color);
    vertex(x, y + h, 0, color);
}

/* Reuse the retail error-display bitmap without loading or allocating a font. */
static void textAt(int x, int y, const char* text, u32 color) {
    for (; *text; text++, x += 12) {
        unsigned int c = (u8)*text;
        int row, col;
        if (c >= 'a' && c <= 'z') {
            c -= 'a' - 'A';
        }
        if (c < 0x21 || c > 0x5a) {
            continue;
        }
        for (row = 0; row < 5; row++) {
            u8 bits = gDebugFontAndErrorData[(c - 0x21) * 5 + row];
            for (col = 0; col < 6; col++) {
                if (bits & (1 << col)) {
                    rectangle(x + col * 2, y + row * 2, 2, 2, color);
                }
            }
        }
    }
}

static void numberAt(int x, int y, int number, u32 color) {
    char buffer[16];
    int pos = 15;
    u32 value = number < 0 ? -(u32)number : (u32)number;
    buffer[pos] = 0;
    do {
        buffer[--pos] = '0' + value % 10;
        value /= 10;
    } while (value);
    if (number < 0) {
        buffer[--pos] = '-';
    }
    textAt(x, y, &buffer[pos], color);
}

static void rebuildRows(void) {
    int i;
    visibleCount = 0;
    for (i = 0; i < ROW_COUNT; i++) {
        if (rows[i].parent < 0 || expanded[(int)rows[i].parent]) {
            visible[visibleCount++] = i;
        }
    }
    if (selected >= visibleCount) {
        selected = visibleCount - 1;
    }
}

static void drawMenu(void) {
    Mtx identity = {{1, 0, 0, 0}, {0, 1, 0, 0}, {0, 0, 1, 0}};
    f32 projection[4][4] = {{2.0f / 640, 0, 0, -1}, {0, -2.0f / 480, 0, 1}, {0, 0, -1, 0}, {0, 0, 0, 1}};
    u32 res = getScreenResolution();
    int i;
    GXSetViewport(0, 0, res & 0xffff, res >> 16, 0, 1);
    GXSetScissor(0, 0, res & 0xffff, res >> 16);
    GXSetProjection(projection, GX_ORTHOGRAPHIC);
    GXLoadPosMtxImm(identity, GX_PNMTX0);
    setupGeometry(0);
    if (!menuOpen) {
        rectangle(16, 16, 444, enabled[SWIMMING] ? 42 : 24, 0x0B1427DD);
        textAt(24, 23, "SFA PRACTICE  L+R+DOWN: MENU", WHITE);
        if (enabled[SWIMMING]) {
            textAt(24, 41, "SWIM Y:", 0x63D5FFFF);
            numberAt(120, 41, (int)waterHeight, WHITE);
            textAt(228, 41, "L+UP/DOWN", MUTED);
        }
        return;
    }
    rectangle(20, 20, 600, 430, 0x081020EF);
    rectangle(20, 20, 600, 4, 0x59D5FFFF);
    textAt(36, 38, "STAR FOX ADVENTURES / PRACTICE V1.2", WHITE);
    textAt(36, 59, "A: TOGGLE  LEFT/RIGHT: EXPAND  B: CLOSE", MUTED);
    rebuildRows();
    if (menuTop > selected) {
        menuTop = selected;
    }
    if (menuTop < selected - 16) {
        menuTop = selected - 16;
    }
    for (i = menuTop; i < visibleCount && i < menuTop + 17; i++) {
        int row = visible[i], y = 86 + (i - menuTop) * 18;
        int indent = rows[row].parent < 0 ? 0 : 24;
        u32 color = rows[row].parent >= 0 && !enabled[(int)rows[row].parent] ? MUTED : WHITE;
        if (i == selected) {
            rectangle(28, y - 4, 584, 18, 0x263C60FF);
            color = GOLD;
        }
        if (rows[row].group) {
            textAt(36, y, expanded[row] ? "-" : "+", color);
        }
        if (row != WATER_HEIGHT && row != RANGE) {
            rectangle(58 + indent, y - 1, 12, 12, color);
            rectangle(60 + indent, y + 1, 8, 8, enabled[row] ? 0x56C7FFFF : 0x101B2EFF);
        }
        textAt(80 + indent, y, rows[row].label, color);
        if (row == WATER_HEIGHT) {
            numberAt(400, y, (int)waterHeight, color);
        }
        if (row == RANGE) {
            numberAt(400, y, drawDistance, color);
        }
    }
    textAt(36, 395, "TRIS:", MUTED);
    numberAt(108, 395, trianglesDrawn, WHITE);
    textAt(252, 395, "TRIGGERS:", MUTED);
    numberAt(372, 395, triggersDrawn, WHITE);
    textAt(36, 419,
           drawLimitReached || fillsDrawn >= fillLimit ? "DRAW LIMIT REACHED - REDUCE DISTANCE"
                                                       : "SWIM HEIGHT: L+UP/DOWN  X: RESET TO FOX",
           MUTED);
}

void Practice_SetArenaLo(void* start) {
    if ((u32)start < (u32)__practice_limit) {
        start = __practice_limit;
    }
    OSSetArenaLo(start);
}

static void closeMenu(void) {
    menuOpen = 0;
    if (timeStop == 0xff) {
        timeStop = savedTimeStop;
    }
}

static void swallowInput(void) {
    PADStatus* pad = &gPadStatuses[gPadStatusBufferIndex * PAD_MAX_CONTROLLERS];
    pad->button = 0;
    pad->stickX = 0;
    pad->stickY = 0;
    pad->substickX = 0;
    pad->substickY = 0;
    pad->triggerLeft = 0;
    pad->triggerRight = 0;
    gPadButtonsHeld[0] = gPadButtonsJustPressed[0] = gPadButtonsReleased[0] = 0;
    gPadTriggers[0] = gPadTriggersPressed[0] = gPadTriggersReleased[0] = 0;
    gPadLastStickX[0] = gPadLastStickY[0] = 0;
    gPadMenuStickXSign[0] = gPadMenuStickYSign[0] = 0;
}

void Practice_PadUpdate(void) {
    u32 held, pressed, shoulders;
    int chord, wasOpen;
    GameObject* player;
    padUpdate();
    held = gPadButtonsHeld[0];
    pressed = gPadButtonsJustPressed[0];
    shoulders = held | gPadTriggers[0];
    chord =
        (shoulders & (PAD_TRIGGER_L | PAD_TRIGGER_R)) == (PAD_TRIGGER_L | PAD_TRIGGER_R) && (held & PAD_BUTTON_DOWN);
    wasOpen = menuOpen;
    if (chord && !chordLatched) {
        if (menuOpen) {
            closeMenu();
        } else {
            savedTimeStop = timeStop;
            timeStop = 0xff;
            menuOpen = 1;
        }
    }
    chordLatched = chord != 0;
    player = Obj_GetPlayerObject();
    if (player != swimOwner) {
        swimApplied = 0;
        swimOwner = player;
        if (enabled[SWIMMING] && validPointer(player)) {
            waterHeight = player->anim.worldPosY + 40.0f;
        }
    }
    if (menuOpen && !chord) {
        int row;
        rebuildRows();
        if (held & (PAD_BUTTON_UP | PAD_BUTTON_DOWN)) {
            repeatTimer++;
            if ((pressed & (PAD_BUTTON_UP | PAD_BUTTON_DOWN)) || (repeatTimer > 20 && repeatTimer % 5 == 0)) {
                selected += (held & PAD_BUTTON_DOWN) ? 1 : -1;
                if (selected < 0) {
                    selected = visibleCount - 1;
                }
                if (selected >= visibleCount) {
                    selected = 0;
                }
            }
        } else {
            repeatTimer = 0;
        }
        row = visible[selected];
        if (pressed & PAD_BUTTON_B) {
            closeMenu();
        } else if (row == WATER_HEIGHT || row == RANGE) {
            int delta = (pressed & PAD_BUTTON_RIGHT) ? 1 : (pressed & PAD_BUTTON_LEFT) ? -1 : 0;
            if (row == WATER_HEIGHT) {
                waterHeight += delta * 10.0f;
            } else {
                drawDistance += delta * 250;
                if (drawDistance < 250) {
                    drawDistance = 250;
                }
                if (drawDistance > 2500) {
                    drawDistance = 2500;
                }
            }
        } else {
            if (rows[row].group) {
                if (pressed & PAD_BUTTON_RIGHT) {
                    expanded[row] = 1;
                }
                if (pressed & PAD_BUTTON_LEFT) {
                    expanded[row] = 0;
                }
            } else if ((pressed & PAD_BUTTON_LEFT) && rows[row].parent >= 0) {
                int parent = rows[row].parent, i;
                expanded[parent] = 0;
                rebuildRows();
                for (i = 0; i < visibleCount; i++) {
                    if (visible[i] == parent) {
                        selected = i;
                    }
                }
            }
            if (pressed & PAD_BUTTON_A) {
                enabled[row] ^= 1;
                if (rows[row].group && enabled[row]) {
                    expanded[row] = 1;
                }
                if (row == SWIMMING && enabled[row] && validPointer(player)) {
                    waterHeight = player->anim.worldPosY + 40.0f;
                }
            }
        }
        if ((pressed & PAD_BUTTON_X) && validPointer(player)) {
            waterHeight = player->anim.worldPosY + 40.0f;
        }
    }
    if (!menuOpen && !wasOpen && !chord && enabled[SWIMMING] && (shoulders & PAD_TRIGGER_L) &&
        (held & (PAD_BUTTON_UP | PAD_BUTTON_DOWN))) {
        f32 delta = timeDelta * ((held & PAD_BUTTON_UP) ? 2.0f : -2.0f);
        if (delta > 10) {
            delta = 10;
        }
        if (delta < -10) {
            delta = -10;
        }
        waterHeight += delta;
        swallowInput();
    }
    if (menuOpen || wasOpen || chord) {
        swallowInput();
    }
}

static void applyWater(GameObject* obj, PlayerState* state) {
    state->baddie.waterSurfaceY = waterHeight;
    state->waterSurfaceY = waterHeight;
    state->waterDepth = waterHeight - obj->anim.worldPosY;
}

void Practice_PlayerControls(GameObject* obj, PlayerState* state, f32 dt) {
    f32 original = state->baddie.waterSurfaceY;
    int active = enabled[SWIMMING] && obj == Obj_GetPlayerObject();
    if (obj == Obj_GetPlayerObject()) {
        if (enabled[SWIMMING]) {
            applyWater(obj, state);
            if (!state->flags3F0.b20 && state->waterDepth > 25.0f && state->focusObject == NULL) {
                playerEnterDeepWater(obj, state, state);
            }
            swimApplied = 1;
        } else if (swimApplied) {
            state->flags3F0.b20 = 0;
            state->waterSurfaceY = state->baddie.waterSurfaceY;
            state->waterDepth = state->waterSurfaceY == -100000.0f ? 0 : state->waterSurfaceY - obj->anim.worldPosY;
            swimApplied = 0;
        }
    }
    playerDoControls(obj, state, dt);
    if (active) {
        state->baddie.waterSurfaceY = original;
    }
}

void Practice_SurfaceResponse(GameObject* obj, PlayerState* state, PlayerState* cfg, f32 dt) {
    f32 original = cfg->baddie.waterSurfaceY;
    int active = enabled[SWIMMING] && obj == Obj_GetPlayerObject();
    if (active) {
        cfg->baddie.waterSurfaceY = waterHeight;
    }
    playerUpdateSurfaceResponse(obj, state, cfg, dt);
    if (active) {
        cfg->baddie.waterSurfaceY = original;
        state->waterSurfaceY = waterHeight;
        state->waterDepth = waterHeight - obj->anim.worldPosY;
    }
}

void Practice_Draw(void) {
    u8 viewIndex = gCameraCurrentViewIndex;
    linesDrawn = trianglesDrawn = triggersDrawn = fillsDrawn = 0;
    drawLimitReached = 0;
    if (enabled[COLLISION] || enabled[TRIGGERS] || (enabled[SWIMMING] && enabled[WATER_GRID])) {
        drawWorld();
    }
    drawMenu();
    gCameraCurrentViewIndex = viewIndex;
    resetSomeGxFlags();
}
#endif
