/* Optional EN retail practice payload. No definitions exist without SFA_PRACTICE.
 * tools/practice/build.py links this separately and verifies every retail hook.
 */
#ifdef SFA_PRACTICE
#include "practice/practice.h"
#include "practice/warp_catalog.h"
#include "practice/state_catalog.h"
#include "sys/objects/lifecycle.h"
#include "dolphin/exi.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "main/dll/dll_0017_savegame_api.h"
#include "main/dll/savegame.h"
#include "main/dll/player.h"
#include "main/mldf_fileid.h"
#include "main/pi_data_file_api.h"
#include "dlls/objects/294.h"
#include "dolphin/gx.h"
#include "dolphin/mtx.h"
#include "dolphin/pad.h"
#include "dolphin/os/OSArena.h"
#include "main/camera.h"
#include "main/hud_visibility_api.h"
#include "main/audio_internal.h"
#include "musyx/mcmd.h"
#include "musyx/snd_synth_api.h"
#include "main/debug_display.h"
#include "main/frame_timing.h"
#include "main/gameloop_api.h"
#include "main/gameloop_internal.h"
#include "main/fileio.h"
#include "main/mm.h"
#include "string.h"
#include "track/intersect_card_api.h"
#include "main/gamebits_api.h"
#include "main/map_block.h"
#include "main/map_load.h"
#include "main/lightmap_api.h"
#include "main/obj_list.h"
#include "main/object_transform.h"
#include "main/objhits_types.h"
#include "main/objhits.h"
#include "main/pad.h"
#include "main/shader_api.h"
#include "main/shader_map_api.h"
#include "sys/objects.h"

extern u8 __practice_start[];
extern u8 __practice_limit[];
extern u8 gDebugFontAndErrorData[];
extern PADStatus gPadStatuses[];
extern u8 timeStop;
extern int gMapBlockOriginWorldX, gMapBlockOriginWorldZ;
extern int gShaderCurMapEventId;
extern void* gShaderMapRomBuffers[5];
extern u8 gWarpRequested;
extern void resetSomeGxFlags(void);
extern MapBlockData* mapGetBlockAtPos(int x, int z, int layer);
extern void playerDoControls(GameObject*, PlayerState*, f32);
extern void playerUpdateSurfaceResponse(GameObject*, PlayerState*, PlayerState*, f32);
extern void playerEnterDeepWater(GameObject*, PlayerState*, PlayerState*);
extern void playerRefreshCollisionState(GameObject*, int, int);
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
    BARRIER_FILL,
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
    SHIELD_HOVER,
    ROLL_BLANKS,
    SHIELD_BLANKS,
    FOX_COLLISION,
    FOX_OBJECT_BODY,
    FOX_MODEL_SPHERES,
    FOX_FEET,
    FOX_BODY_POINTS,
    FOX_WALL_POINTS,
    FOX_SWEEPS,
    WARP_CATEGORY,
    WARP_MAP,
    WARP_SPAWN,
    WARP_X,
    WARP_Y,
    WARP_Z,
    WARP_LAYER,
    WARP_ANGLE,
    WARP_STEP,
    WARP_RESET,
    WARP_GO,
    LOG_ENABLED,
    LOG_INVENTORY,
    LOG_SPELLS,
    LOG_TRICKY,
    LOG_AREA,
    LOG_OTHER,
    LOG_GROUPS,
    LOG_STATS,
    AUTO_ROLL,
    AUTO_ROLL_BLANKS,
    LOG_CHECKPOINTS,
    LOG_ACTIONS,
    FREE_MOVE,
    INFINITE_HEALTH,
    INFINITE_MAGIC,
    MAP_CELLS,
    ROW_COUNT
};
enum {
    TAB_COLLISION,
    TAB_CHEATS,
    TAB_WARP,
    TAB_FLAGS,
    TAB_LOG,
    TAB_COUNT
};
static const char* tabLabels[TAB_COUNT] = {"COLLISION", "CHEATS", "WARP", "FLAGS", "LOG"};
typedef struct PracticeRow {
    const char* label;
    s8 parent;
    u8 group;
    u8 tab;
} PracticeRow;
static const PracticeRow rows[ROW_COUNT] = {{"COLLISION", -1, 1},
                                            {"TERRAIN TRIANGLES", COLLISION, 0},
                                            {"OBJECT TRIANGLES", COLLISION, 0},
                                            {"OBJECT HIT VOLUMES", COLLISION, 0},
                                            {"WATER TRIANGLES", COLLISION, 0},
                                            {"BARRIERS / LEDGES", COLLISION, 0},
                                            {"BARRIER FILL", COLLISION, 0},
                                            {"TRIGGERS", -1, 1},
                                            {"CROSSING PLANES", TRIGGERS, 0},
                                            {"BOXES", TRIGGERS, 0},
                                            {"SPHERES", TRIGGERS, 0},
                                            {"CYLINDERS", TRIGGERS, 0},
                                            {"TARGET MOTION", TRIGGERS, 0},
                                            {"TRANSLUCENT FILL", TRIGGERS, 0},
                                            {"FORCED SWIMMING", -1, 1, TAB_CHEATS},
                                            {"WATER HEIGHT", SWIMMING, 0, TAB_CHEATS},
                                            {"SHOW WATER PLANE", SWIMMING, 0, TAB_CHEATS},
                                            {"DRAW THROUGH WALLS", -1, 0},
                                            {"DRAW DISTANCE", -1, 0},
                                            {"AUTO-SHIELD HOVER", -1, 1, TAB_CHEATS},
                                            {"BLANKS AFTER ROLL", SHIELD_HOVER, 0, TAB_CHEATS},
                                            {"BLANKS AFTER SHIELD", SHIELD_HOVER, 0, TAB_CHEATS},
                                            {"FOX / PLAYER", -1, 1},
                                            {"OBJECT BODY", FOX_COLLISION, 0},
                                            {"MODEL HIT SPHERES", FOX_COLLISION, 0},
                                            {"FEET / FLOOR CONTACT", FOX_COLLISION, 0},
                                            {"MOVEMENT BODY SPHERES", FOX_COLLISION, 0},
                                            {"WALL PROBE SPHERES", FOX_COLLISION, 0},
                                            {"CACHED SWEEP LINES", FOX_COLLISION, 0},
                                            {"CATEGORY", -1, 0, TAB_WARP},
                                            {"MAP", -1, 0, TAB_WARP},
                                            {"SPAWN", -1, 0, TAB_WARP},
                                            {"POSITION X", -1, 0, TAB_WARP},
                                            {"POSITION Y", -1, 0, TAB_WARP},
                                            {"POSITION Z", -1, 0, TAB_WARP},
                                            {"LAYER", -1, 0, TAB_WARP},
                                            {"FACING (0-255)", -1, 0, TAB_WARP},
                                            {"POSITION STEP", -1, 0, TAB_WARP},
                                            {"RESET TO SPAWN", -1, 0, TAB_WARP},
                                            {"WARP NOW", -1, 0, TAB_WARP},
                                            {"LOG TO DOLPHIN", -1, 0, TAB_LOG},
                                            {"INVENTORY", -1, 0, TAB_LOG},
                                            {"SPELLS", -1, 0, TAB_LOG},
                                            {"TRICKY", -1, 0, TAB_LOG},
                                            {"AREA / MAP ACTS", -1, 0, TAB_LOG},
                                            {"OTHER / UNKNOWN BITS", -1, 0, TAB_LOG},
                                            {"OBJECT GROUPS", -1, 0, TAB_LOG},
                                            {"PLAYER STATS", -1, 0, TAB_LOG},
                                            {"AUTO ROLL", -1, 1, TAB_CHEATS},
                                            {"AUTO-ROLL BLANK FRAMES", AUTO_ROLL, 0, TAB_CHEATS},
                                            {"SAVE / RESPAWN CHECKPOINTS", -1, 0, TAB_LOG},
                                            {"RUNTIME / ACTION FLAGS", -1, 0, TAB_LOG},
                                            {"FREE MOVE", -1, 0, TAB_CHEATS},
                                            {"INFINITE HEALTH", -1, 0, TAB_CHEATS},
                                            {"INFINITE MAGIC", -1, 0, TAB_CHEATS},
                                            {"MAP CELLS / GRAVITY", -1, 0}};
static u8 enabled[ROW_COUNT] = {1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1,
                                1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0};
static u8 expanded[ROW_COUNT] = {1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0,
                                 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static u8 menuOpen, chordLatched, savedTimeStop, swimApplied;
static u8 menuSoundActive, menuSoundOwned[SFX_OBJECT_CHANNEL_COUNT];
static int menuSoundHudDepth;
static u8 menuSoundDvdPaused;
static u32 menuSoundHandles[SFX_OBJECT_CHANNEL_COUNT];
static u64 menuSoundAges[SFX_OBJECT_CHANNEL_COUNT];
static u8 activeTab, hoverPhase, hoverActive, autoRollPhase;
static u32 hoverButtons;
static u32 previousShoulders;
static int hoverWait, rollBlanks = 3, shieldBlanks;
static int autoRollWait, autoRollBlanks = 39;
static const char* warpCategories[] = {"ALL MAPS",         "AREAS",          "KRAZOA SHRINES", "BOSSES",
                                       "CONNECTING PATHS", "ARWING / WORLD", "TEST / UNUSED",  "OBJECT CHUNKS"};
static const int warpSteps[] = {1, 10, 100, 640};
static int warpCategory = 1, warpMap = 23, warpSpawn, warpStep = 1;
static u8 warpReady, warpEdited;
static WarpDestination warpDestination;
static WarpDestination warpQueuedDestination;
static u8 warpLoadPending;
static const char* warpMessage;
static int selected, repeatTimer, visibleCount, visible[ROW_COUNT], menuTop;
static int drawDistance = 1000;
static f32 waterHeight;
static GameObject* swimOwner;
static u8 swimActive, freeActive, quickLatch;
static Vec freeStep;
static GameObject* freePoseOwner;
static PlayerState* freePoseState;
static s16 freeYaw, freePitch, freeSavedPitch, freeSavedRoll;
static int linesDrawn, trianglesDrawn, triggersDrawn;
static int fillsDrawn;
static int drawLimitReached;
static int lineLimit = 12000;
static int fillLimit = 6000;
static Vec origin;
static const u32 WHITE = 0xE7EFFAFF, MUTED = 0x95A5BFFF, GOLD = 0xFFD16AFF;

/* Keep repeated debug geometry helpers out of line to fit the fixed payload. */
#pragma push
#pragma auto_inline off
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
    if (fillsDrawn >= fillLimit) {
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
    int type, disabled;
    if (!validPointer(def) || !validPointer(state) || !validPointer(obj->anim.modelInstance) ||
        obj->anim.modelInstance->dllId != 294 || !nearPoint(center)) {
        return;
    }
    type = def->base.objectId;
    disabled = (state->status & 4) || (obj->objectFlags & OBJECT_OBJFLAG_HITDETECT_DISABLED);
    if (type == 0x4c && state->gateBits[0] != -1 && mainGetBit(state->gateBits[0]) == 0) {
        disabled = 1;
    }
    color = disabled ? 0x929292FF : 0xFF69D4FF;
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
        if (enabled[TRIGGER_FILL]) {
            fillQuad(p[0], p[1], p[3], p[2], color);
        }
        line(p[0], p[1], color);
        line(p[1], p[3], color);
        line(p[3], p[2], color);
        line(p[2], p[0], color);
        {
            Vec n =
                point(center.x + plane->normalX * 40, center.y + plane->normalY * 40, center.z + plane->normalZ * 40);
            line(center, n, disabled ? color : GOLD);
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
        if (enabled[TRIGGER_FILL]) {
            fillQuad(p[0], p[1], p[3], p[2], color);
            fillQuad(p[4], p[5], p[7], p[6], color);
            fillQuad(p[0], p[1], p[5], p[4], color);
            fillQuad(p[2], p[3], p[7], p[6], color);
            fillQuad(p[0], p[2], p[6], p[4], color);
            fillQuad(p[1], p[3], p[7], p[5], color);
        }
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
            line(a, b, disabled ? color : 0xFFE067FF);
        }
    }
}

static int floorCell(f32 x) {
    int n = (int)(x / 640.0f);
    return x < n * 640.0f ? n - 1 : n;
}

/* playerUpdate freezes ordinary unparented movement only when isInBounds is
 * exactly zero. It checks all five block layers, ignores Y, and returns -1
 * outside the streaming window. Do not equate missing geometry with that case. */
static void drawMapCells(void) {
    int x, z, i, state, haveCurrent = 0;
    int cx = floorCell(origin.x), cz = floorCell(origin.z);
    int radius = (drawDistance + 639) / 640;
    Vec p[4], current[4];
    u32 color;
    if (isSaveGameLoading()) {
        return;
    }
    for (i = 0; i < 5; i++) {
        if (!validPointer(gMapBlockLayerTables[i])) {
            return;
        }
    }
    for (z = cz - radius; z <= cz + radius && linesDrawn < lineLimit; z++) {
        for (x = cx - radius; x <= cx + radius && linesDrawn < lineLimit; x++) {
            state = isInBounds(x * 640.0f + 320, z * 640.0f + 320);
            color = state == 0 ? 0xFF6578FF : state > 0 ? 0x58D98CFF : 0xE4B45AFF;
            p[0] = point(x * 640.0f, origin.y + 2, z * 640.0f);
            p[1] = p[0];
            p[1].x += 640;
            p[2] = p[1];
            p[2].z += 640;
            p[3] = p[0];
            p[3].z += 640;
            if (!nearTriangle(p[0], p[1], p[2]) && !nearTriangle(p[0], p[2], p[3])) {
                continue;
            }
            fillQuad(p[0], p[1], p[2], p[3], color);
            for (i = 0; i < 4; i++) {
                Vec a = p[i], b = p[i];
                line(p[i], p[(i + 1) & 3], color);
                a.y -= 160;
                b.y += 160;
                line(a, b, color);
                if (x == cx && z == cz) {
                    current[i] = p[i];
                    haveCurrent = 1;
                }
            }
        }
    }
    /* Neighboring cells share edges; draw the current outline last. */
    if (haveCurrent) {
        for (i = 0; i < 4; i++) {
            line(current[i], current[(i + 1) & 3], GOLD);
        }
    }
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
            if (enabled[BARRIER_FILL]) {
                fillQuad(p[0], p[1], p[2], p[3], 0xFF875FFF);
            }
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
    int isPlayer = obj == Obj_GetPlayerObject();
    int bodyEnabled = isPlayer ? enabled[FOX_COLLISION] && enabled[FOX_OBJECT_BODY] : enabled[HIT_SPHERES];
    int spheresEnabled = isPlayer ? enabled[FOX_COLLISION] && enabled[FOX_MODEL_SPHERES] : enabled[HIT_SPHERES];
    if (bodyEnabled && validPointer(obj->anim.hitReactState) && nearPoint(center)) {
        ObjHitsPriorityState* state = (ObjHitsPriorityState*)obj->anim.hitReactState;
        u32 color = (state->flags & OBJHITS_PRIORITY_STATE_ENABLED) &&
                            !(state->flags & OBJHITS_PRIORITY_STATE_HIT_EXCLUDED) && state->activeHitboxMode == 0
                        ? 0xFFAB4FFF
                        : 0x929292FF;
        if (state->shapeFlags & OBJHITS_SHAPE_SPHERE) {
            sphere(center, state->primaryRadius, color);
        } else if (state->shapeFlags & OBJHITS_SHAPE_CAPSULE) {
            Vec a = center, b = center;
            a.y += state->primaryCapsuleOffsetA;
            b.y += state->primaryCapsuleOffsetB;
            circle(a, state->primaryRadius, 1, color);
            circle(b, state->primaryRadius, 1, color);
            for (i = 0; i < 4; i++) {
                Vec c = a, d = b;
                c.x += mathCosf(i * 1.57079632679f) * state->primaryRadius;
                c.z += mathSinf(i * 1.57079632679f) * state->primaryRadius;
                d.x = c.x;
                d.z = c.z;
                line(c, d, color);
            }
        }
    }
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
    if (spheresEnabled && validPointer(model->activeHitVolumeSpheres)) {
        ObjModelHitSphere* spheres = (ObjModelHitSphere*)model->activeHitVolumeSpheres;
        for (i = 0; i < file->hitVolumeCount && linesDrawn < lineLimit; i++) {
            Vec p =
                point(spheres[i].pos[0] + playerMapOffsetX, spheres[i].pos[1], spheres[i].pos[2] + playerMapOffsetZ);
            /* Animation hit buffers can remain stale on culled objects. Never
             * spend the nearby draw budget on a cached sphere outside range. */
            if (nearPoint(p)) {
                sphere(p, spheres[i].radius, 0xFFAB4FFF);
            }
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

static Vec playerProbeWorld(GameObject* player, const f32* position) {
    Vec p = point(position[0], position[1], position[2]);
    GameObject* parent = player->anim.parent;
    if (validPointer(parent)) {
        ObjHitboxTransformState* hit = parent->anim.hitboxTransformState;
        if (validPointer(hit) && hit->activeMatrixIndex <= 1 && ObjHits_IsObjectEnabled(&parent->anim)) {
            p = transformPoint(&hit->matrices[hit->activeMatrixIndex + 2][0][0], p);
        } else {
            Obj_TransformLocalPointToWorld(p.x, p.y, p.z, &p.x, &p.y, &p.z, parent);
        }
    }
    return p;
}

static void drawPlayerCollision(GameObject* player) {
    PlayerState* state = player->extra;
    CurvesCollisionState* collision;
    int i, count;
    if (!enabled[FOX_COLLISION] || !validPointer(state)) {
        return;
    }
    collision = &state->baddie.curvesCollision;
    if (!(collision->flags & CURVES_COLLISION_STATE_ACTIVE)) {
        return;
    }
    if (collision->flags & CURVES_COLLISION_STATE_HIT_SEGMENTS) {
        count = collision->pointCounts >> CURVES_POINT_COUNT_SEGMENT_SHIFT;
        if (count > 4) {
            count = 4;
        }
        for (i = 0; i < count; i++) {
            Vec p = point(collision->points[i][0], collision->points[i][1], collision->points[i][2]);
            f32 radius = collision->segmentHits.radii[i];
            u32 color = i ? 0xCF8FFFFF : 0x66FFB3FF;
            if (!nearPoint(p)) {
                continue;
            }
            if ((i ? enabled[FOX_BODY_POINTS] : enabled[FOX_FEET]) && radius > 0 && radius < 1000) {
                sphere(p, radius, color);
                if (i == 0 && radius < 1) {
                    /* Fox's normal ground radius is only 0.05. Mark its center
                     * without presenting the marker as a larger collision shape. */
                    line(point(p.x - 3, p.y, p.z), point(p.x + 3, p.y, p.z), color);
                    line(point(p.x, p.y, p.z - 3), point(p.x, p.y, p.z + 3), color);
                }
            }
            if (enabled[FOX_SWEEPS]) {
                Vec from = point(collision->traceStart[i][0], collision->traceStart[i][1], collision->traceStart[i][2]);
                if (nearPoint(from)) {
                    line(from, p, color);
                }
            }
            if (i == 0 && enabled[FOX_FEET] && (collision->flags & 1) && collision->floorY[0] > -100000 &&
                collision->floorY[0] < 100000) {
                Vec floor = p;
                floor.y = collision->floorY[0];
                if (nearPoint(floor)) {
                    line(p, floor, color);
                    /* Cross marks a query result, not an extra hit radius. */
                    line(point(floor.x - 5, floor.y, floor.z), point(floor.x + 5, floor.y, floor.z), color);
                    line(point(floor.x, floor.y, floor.z - 5), point(floor.x, floor.y, floor.z + 5), color);
                }
            }
        }
    }
    if ((collision->flags & CURVES_COLLISION_STATE_LOCAL_POINTS) && validPointer(collision->localPointRadii)) {
        count = collision->pointCounts & CURVES_POINT_COUNT_LOCAL_MASK;
        if (count > 4) {
            count = 4;
        }
        for (i = 0; i < count; i++) {
            Vec p = playerProbeWorld(player, collision->localPointWorld[i]);
            f32 radius = collision->localPointRadii[i];
            if (!nearPoint(p)) {
                continue;
            }
            if (enabled[FOX_WALL_POINTS] && radius > 0 && radius < 1000) {
                sphere(p, radius, 0x5CDAFFFF);
            }
            if (enabled[FOX_SWEEPS]) {
                Vec from = playerProbeWorld(player, collision->localPointTarget[i]);
                if (nearPoint(from)) {
                    line(from, p, 0x5CDAFFFF);
                }
            }
        }
    }
}

static void drawWorld(void) {
    GameObject* player = Obj_GetPlayerObject();
    int i, count, start, band;
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
    if (enabled[MAP_CELLS]) {
        drawMapCells();
    }
    if (enabled[COLLISION]) {
        drawPlayerCollision(player);
    }
    /* Reserve half the wire budget for nearby map collision. */
    if (enabled[COLLISION] && (enabled[TERRAIN] || enabled[WATER_MESH] || enabled[BARRIERS])) {
        lineLimit = 6000;
    }
    objects = ObjList_GetObjects(&start, &count);
    if (validPointer(objects) && count >= 0 && count <= 2048) {
        /* Hit-volume outlines can be numerous. Give nearby objects the first
         * opportunity to draw instead of depending on object spawn order. */
        for (band = 0; band < drawDistance && linesDrawn < lineLimit; band += 250) {
            for (i = start; i < count && linesDrawn < lineLimit; i++) {
                GameObject* obj = objects[i];
                f32 x, y, z, distance;
                if (!validPointer(obj)) {
                    continue;
                }
                x = obj->anim.worldPosX - origin.x;
                y = obj->anim.worldPosY - origin.y;
                z = obj->anim.worldPosZ - origin.z;
                distance = x * x + y * y + z * z;
                if (distance < (f32)band * band || distance >= (f32)(band + 250) * (band + 250)) {
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
    }
    if (enabled[SWIMMING] && swimActive && enabled[WATER_GRID]) {
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

#pragma pop

static void resetWarpSpawn(void) {
    const PracticeWarpMap* map = &practiceWarpMaps[warpMap];
    warpEdited = 0;
    warpMessage = NULL;
    warpReady = 1;
    if (map->spawnCount) {
        warpDestination = practiceWarpSpawns[map->firstSpawn + warpSpawn].destination;
    } else {
        warpDestination.x = warpDestination.y = warpDestination.z = 0;
        warpDestination.layer = warpDestination.angle = 0;
    }
}

static void changeWarpMap(int direction) {
    int i;
    for (i = 0; i < 117; i++) {
        warpMap = (warpMap + 117 + direction) % 117;
        if (!warpCategory || practiceWarpMaps[warpMap].category == warpCategory) {
            break;
        }
    }
    warpSpawn = 0;
    resetWarpSpawn();
}

static void editWarpRow(int row, int delta) {
    const PracticeWarpMap* map = &practiceWarpMaps[warpMap];
    if (!delta) {
        return;
    }
    warpMessage = NULL;
    if (row == WARP_CATEGORY) {
        warpCategory = (warpCategory + 8 + delta) % 8;
        warpMap = 116;
        changeWarpMap(1);
    } else if (row == WARP_MAP) {
        changeWarpMap(delta);
    } else if (row == WARP_SPAWN && map->spawnCount) {
        warpSpawn = (warpSpawn + map->spawnCount + delta) % map->spawnCount;
        resetWarpSpawn();
    } else if (row == WARP_STEP) {
        warpStep = (warpStep + 4 + delta) % 4;
    } else if (map->spawnCount && row >= WARP_X && row <= WARP_ANGLE) {
        f32 step = delta * warpSteps[warpStep];
        if (row == WARP_X) {
            warpDestination.x += step;
        } else if (row == WARP_Y) {
            warpDestination.y += step;
        } else if (row == WARP_Z) {
            warpDestination.z += step;
        } else if (row == WARP_LAYER) {
            warpDestination.layer = (warpDestination.layer + delta + 7) % 5 - 2;
        } else {
            warpDestination.angle = (warpDestination.angle + delta + 256) % 256;
        }
        warpEdited = 1;
    }
}

static void drawWarpValue(int row, int y, u32 color) {
    const PracticeWarpMap* map = &practiceWarpMaps[warpMap];
    if (row == WARP_CATEGORY) {
        textAt(260, y, warpCategories[warpCategory], color);
    } else if (row == WARP_MAP) {
        textAt(260, y, map->name, color);
    } else if (row == WARP_SPAWN) {
        if (!map->spawnCount) {
            textAt(260, y, "NO WORLD DESTINATION", MUTED);
        } else {
            int index = practiceWarpSpawns[map->firstSpawn + warpSpawn].warp;
            numberAt(260, y, warpSpawn + 1, color);
            textAt(290, y, "/", color);
            numberAt(310, y, map->spawnCount, color);
            textAt(350, y, index >= 0 ? "WARP ID:" : "ESTIMATED", color);
            if (index >= 0) {
                numberAt(465, y, index, color);
            }
        }
    } else if (row >= WARP_X && row <= WARP_ANGLE) {
        int value = row == WARP_X       ? (int)warpDestination.x
                    : row == WARP_Y     ? (int)warpDestination.y
                    : row == WARP_Z     ? (int)warpDestination.z
                    : row == WARP_LAYER ? warpDestination.layer
                                        : warpDestination.angle;
        numberAt(380, y, value, color);
    } else if (row == WARP_STEP) {
        numberAt(380, y, warpSteps[warpStep], color);
    } else {
        textAt(380, y, "PRESS A", color);
    }
}

/* The retail count is in halfwords; use the asset's byte size to bound four-byte
 * descriptors. Never use the retail getter to walk arbitrary/invalid records. */
#pragma push
#pragma auto_inline off
extern u16 gSaveGameMapActBits[120], gSaveGameMapObjGroupBits[120];
extern u32 gMapObjGroupStatuses[120];
static const int bitBankOffsets[] = {0xef0, 0x564, 0x24, 0x5d8};
static const int bitBankSizes[] = {0x80, 0x74, 0x144, 0xac};
static const int bitSnapshotOffsets[] = {0, 0x80, 0xf4, 0x238};
static const char* flagPages[] = {"FLAGS",        "INVENTORY",          "STAFF SPELLS",  "TRICKY",
                                  "PLAYER STATS", "AREA PROGRESS",      "OBJECT GROUPS", "ADVANCED",
                                  "RAW BIT ID",   "UNUSED / UNCERTAIN", "UPGRADES",      "STAFF SPELLS",
                                  "CONSUMABLES",  "AREA ITEMS",         "SPELLSTONES",   "KRAZOA SPIRITS",
                                  "MAPS",         "AREA ITEMS",         "ITEM DISCOVERY"};
static const char* statLabels[] = {"HEALTH (RAW UNITS)", "MAX HEALTH",   "MAGIC", "MAX MAGIC", "SCARABS",
                                   "BAFOMDADS",          "MAX BAFOMDADS"};
static const int flagSteps[] = {1, 16, 256};
static int flagPage, flagMap = 23, flagRawId, flagStep, flagItemArea;
static GameBitDef* checkedBitTable;
static int checkedBitCount;
static u8 logBits[740], logBaseline;
static u8 logWasEnabled, logLayerReady;
static int logLayer;
static char logLine[192];
static u32 logGroups[120], logFrame, logConfig;
static int logStats[7];
static PlayerStatus* logStatsOwner;
static u8* logSaveOwner;

static int practiceStateReady(void) {
    if (!validPointer(gGameBitTable) || !validPointer(gGameBitSaveData) || (u32)gGameBitSaveData > 0x817ff000 ||
        isSaveGameLoading()) {
        return 0;
    }
    if (checkedBitTable != gGameBitTable) {
        int bytes = getDataFileSize(MLDF_FILEID_BITTABLE_BIN);
        logBaseline = 0;
        checkedBitCount = 0;
        if (bytes > 0 && bytes <= 0x4000 && !(bytes & 3) && (u32)gGameBitTable <= 0x81800000 - bytes) {
            checkedBitCount = bytes / sizeof(GameBitDef);
        }
        checkedBitTable = gGameBitTable;
    }
    return checkedBitCount > 0;
}

static int stateBitWidth(int id) {
    GameBitDef* def;
    int width;
    if (id < 0 || id >= checkedBitCount || id >= gGameBitCount || id == 0x95 || id == 0x96) {
        return 0;
    }
    def = &gGameBitTable[id];
    width = (def->flags & 31) + 1;
    return def->firstBit + width <= bitBankSizes[def->flags >> 6] * 8 ? width : 0;
}

static u32 readStateBit(int id, int snapshot) {
    GameBitDef* def = &gGameBitTable[id];
    int bank = def->flags >> 6, i;
    u8* data = snapshot ? logBits + bitSnapshotOffsets[bank] : gGameBitSaveData + bitBankOffsets[bank];
    u32 value = 0;
    for (i = 0; i <= (def->flags & 31); i++) {
        int bit = def->firstBit + i;
        if (data[bit >> 3] & (1 << (bit & 7))) {
            value |= 1u << i;
        }
    }
    return value;
}

static const PracticeBitLabel* namedBit(int id) {
    int i;
    for (i = 0; i < sizeof(practiceBits) / sizeof(practiceBits[0]); i++) {
        if (practiceBits[i].id == id) {
            return &practiceBits[i];
        }
    }
    return NULL;
}

/* Route edits of act/group bits through the same API as their dedicated pages
 * so the game's cached masks, aliases and transient-group timers stay coherent.
 * IDs >= 80 are runtime aliases; only the 75 world map IDs are editable here. */
static void writeStateBit(int id, u32 value) {
    int i, bit;
    u32 old;
    if (!practiceStateReady() || !stateBitWidth(id) || !validPointer(Obj_GetPlayerObject())) {
        return;
    }
    old = readStateBit(id, 0);
    if (old == value) {
        return;
    }
    for (i = 0; i < 75; i++) {
        if (gSaveGameMapObjGroupBits[i] && gSaveGameMapObjGroupBits[i] == id) {
            for (bit = 0; bit < stateBitWidth(id); bit++) {
                if ((old ^ value) & (1u << bit)) {
                    SaveGame_gplaySetObjGroupStatus(i, bit, (value >> bit) & 1);
                }
            }
            return;
        }
    }
    for (i = 0; i < 75; i++) {
        if (gSaveGameMapActBits[i] && gSaveGameMapActBits[i] == id) {
            SaveGame_gplaySetAct(i, value);
            return;
        }
    }
    mainSetBits(id, value);
}

static PlayerStatus* practiceStats(void) {
    PlayerStatus* stats;
    if (!validPointer(Obj_GetPlayerObject())) {
        return NULL;
    }
    stats = SaveGame_getPlayerStats();
    return validPointer(stats) ? stats : NULL;
}

static int statValue(PlayerStatus* stats, int row) {
    switch (row) {
    case 0:
        return stats->health;
    case 1:
        return stats->maxHealth;
    case 2:
        return stats->magic;
    case 3:
        return stats->maxMagic;
    case 4:
        return stats->money;
    case 5:
        return stats->healCount;
    default:
        return stats->healCountMax;
    }
}

static void editStat(int row, int delta) {
    PlayerStatus* stats = practiceStats();
    int value, max;
    if (!stats || !practiceStateReady()) {
        return;
    }
    max = row == 0   ? stats->maxHealth
          : row == 1 ? 127
          : row == 2 ? stats->maxMagic
          : row == 3 ? 32767
          : row == 5 ? stats->healCountMax
                     : 255;
    value = statValue(stats, row) + delta;
    if (value > max) {
        value = max;
    }
    if (value < 0) {
        value = 0;
    }
    switch (row) {
    case 0:
        stats->health = value;
        break;
    case 1:
        stats->maxHealth = value;
        if (stats->health > value) {
            stats->health = value;
        }
        break;
    case 2:
        stats->magic = value;
        break;
    case 3:
        stats->maxMagic = value;
        if (stats->magic > value) {
            stats->magic = value;
        }
        break;
    case 4:
        stats->money = value;
        break;
    case 5:
        stats->healCount = value;
        break;
    case 6:
        stats->healCountMax = value;
        if (stats->healCount > value) {
            stats->healCount = value;
        }
        break;
    }
}

static const PracticeBitLabel* pageBit(int index) {
    int i;
    for (i = 0; i < sizeof(practiceBits) / sizeof(practiceBits[0]); i++) {
        if ((flagPage == FLAGS_ITEM_AREA && practiceBits[i].page == FLAGS_ITEM_AREA &&
             practiceBits[i].map == flagItemArea) ||
            (flagPage == FLAGS_INVENTORY_SPELLS && practiceBits[i].page == FLAGS_SPELLS) ||
            (flagPage >= FLAGS_UPGRADES && practiceBits[i].page == FLAGS_INVENTORY &&
             practiceBits[i].map == flagPage - FLAGS_UPGRADES) ||
            ((flagPage < FLAGS_UPGRADES || flagPage == FLAGS_DISCOVERY) && practiceBits[i].page == flagPage &&
             (flagPage != FLAGS_AREA || practiceBits[i].map == flagMap))) {
            if (index-- == 0) {
                return &practiceBits[i];
            }
        }
    }
    return NULL;
}

static int flagRowCount(void) {
    int n = 0;
    if (flagPage == FLAGS_ROOT) {
        return 8;
    }
    if (flagPage == FLAGS_STATS) {
        return 7;
    }
    if (flagPage == FLAGS_AREA_ITEMS) {
        return sizeof(itemAreaNames) / sizeof(itemAreaNames[0]);
    }
    if (flagPage == FLAGS_INVENTORY) {
        return 7;
    }
    if (flagPage == FLAGS_ADVANCED || flagPage == FLAGS_RAW) {
        return 2;
    }
    if (flagPage == FLAGS_GROUPS) {
        int id = gSaveGameMapObjGroupBits[flagMap];
        return 1 + (practiceStateReady() && id ? stateBitWidth(id) : 0);
    }
    while (pageBit(n)) {
        n++;
    }
    return n + (flagPage == FLAGS_AREA || flagPage == FLAGS_MAPS            ? 2
                : flagPage == FLAGS_TRICKY || flagPage == FLAGS_CONSUMABLES ? 1
                                                                            : 0);
}

static int flagBitId(int row) {
    const PracticeBitLabel* entry;
    if (flagPage == FLAGS_RAW) {
        return row == 1 ? flagRawId : -1;
    }
    if (flagPage == FLAGS_GROUPS) {
        return row ? gSaveGameMapObjGroupBits[flagMap] : -1;
    }
    if (flagPage == FLAGS_AREA) {
        if (row < 2) {
            return row == 1 && gSaveGameMapActBits[flagMap] ? gSaveGameMapActBits[flagMap] : -1;
        }
        row -= 2;
    }
    if (flagPage == FLAGS_TRICKY || flagPage == FLAGS_MAPS || flagPage == FLAGS_CONSUMABLES) {
        row -= flagPage == FLAGS_MAPS ? 2 : 1;
    }
    entry = pageBit(row);
    return entry ? entry->id : -1;
}

static void editFlags(u32 pressed) {
    int delta = (pressed & PAD_BUTTON_RIGHT) ? 1 : (pressed & PAD_BUTTON_LEFT) ? -1 : 0;
    int id, width;
    u32 value, max, step = flagSteps[flagStep];
    if (pressed & PAD_BUTTON_X) {
        flagStep = (flagStep + 1) % 3;
    }
    if (flagPage == FLAGS_ROOT || flagPage == FLAGS_ADVANCED || flagPage == FLAGS_INVENTORY ||
        flagPage == FLAGS_AREA_ITEMS) {
        if (pressed & PAD_BUTTON_A) {
            if (flagPage == FLAGS_AREA_ITEMS) {
                flagItemArea = selected;
                flagPage = FLAGS_ITEM_AREA;
            } else {
                flagPage = flagPage == FLAGS_ROOT
                               ? (selected == 7 ? FLAGS_DISCOVERY : selected + 1)
                               : selected + (flagPage == FLAGS_INVENTORY ? FLAGS_UPGRADES : FLAGS_RAW);
            }
            /* The streaming engine tracks the active map as the player travels.
             * Choose it on entry only; retain manual selection while browsing. */
            if (flagPage == FLAGS_GROUPS && !isSaveGameLoading() && gShaderCurMapEventId >= 0 &&
                gShaderCurMapEventId < 75) {
                flagMap = gShaderCurMapEventId;
            }
            selected = menuTop = 0;
        }
        return;
    }
    if ((flagPage == FLAGS_AREA || flagPage == FLAGS_GROUPS) && selected == 0) {
        flagMap = (flagMap + 75 + delta) % 75;
        return;
    }
    if (flagPage == FLAGS_RAW && selected == 0) {
        flagRawId += delta * step;
        if (flagRawId < 0) {
            flagRawId = 0;
        }
        if (flagRawId > 4095) {
            flagRawId = 4095;
        }
        return;
    }
    if (!practiceStateReady()) {
        return;
    }
    if (flagPage == FLAGS_MAPS && selected < 2) {
        if (pressed & PAD_BUTTON_A) {
            const PracticeBitLabel* entry;
            int i = 0;
            while ((entry = pageBit(i++)) != NULL) {
                writeStateBit(entry->id, selected == 0);
            }
        }
        return;
    }
    if (flagPage == FLAGS_STATS || (flagPage == FLAGS_CONSUMABLES && selected == 0)) {
        if (delta) {
            editStat(flagPage == FLAGS_STATS ? selected : 4, delta * step);
        }
        return;
    }
    id = flagBitId(selected);
    width = stateBitWidth(id);
    if (!width) {
        return;
    }
    value = readStateBit(id, 0);
    if (flagPage == FLAGS_GROUPS) {
        u32 mask = 1u << (selected - 1);
        if (pressed & PAD_BUTTON_A) {
            value ^= mask;
        } else if (delta > 0) {
            value |= mask;
        } else if (delta < 0) {
            value &= ~mask;
        }
    } else if (width == 1) {
        if (pressed & PAD_BUTTON_A) {
            value ^= 1;
        } else if (delta) {
            value = delta > 0;
        }
    } else {
        max = 0xffffffffu >> (32 - width);
        if (delta > 0) {
            value = max - value < step ? max : value + step;
        }
        if (delta < 0) {
            value = value < step ? 0 : value - step;
        }
    }
    writeStateBit(id, value);
}

static void hexAt(int x, int y, u32 value, int digits, u32 color) {
    char buffer[9];
    int i;
    buffer[digits] = 0;
    for (i = digits - 1; i >= 0; i--) {
        buffer[i] = "0123456789ABCDEF"[value & 15];
        value >>= 4;
    }
    textAt(x, y, buffer, color);
}

static void drawFlags(void) {
    int i, ready = practiceStateReady();
    for (i = menuTop; i < visibleCount && i < menuTop + 15; i++) {
        int y = 110 + (i - menuTop) * 18, id = -1, width;
        const PracticeBitLabel* entry;
        const char* label = NULL;
        u32 color = i == selected ? GOLD : WHITE;
        if (i == selected) {
            rectangle(28, y - 4, 584, 18, 0x263C60FF);
        }
        if (flagPage == FLAGS_ROOT || flagPage == FLAGS_ADVANCED || flagPage == FLAGS_INVENTORY ||
            flagPage == FLAGS_AREA_ITEMS) {
            label = flagPage == FLAGS_AREA_ITEMS
                        ? itemAreaNames[i]
                        : flagPages[flagPage == FLAGS_ROOT
                                        ? (i == 7 ? FLAGS_DISCOVERY : i + 1)
                                        : i + (flagPage == FLAGS_INVENTORY ? FLAGS_UPGRADES : FLAGS_RAW)];
            textAt(564, y, ">", color);
        } else if (flagPage == FLAGS_MAPS && i < 2) {
            label = i == 0 ? "UNLOCK ALL" : "REMOVE ALL";
            textAt(528, y, ready ? "A" : "N/A", ready ? color : MUTED);
        } else if ((flagPage == FLAGS_AREA || flagPage == FLAGS_GROUPS) && i == 0) {
            label = "MAP";
            textAt(250, y, practiceWarpMaps[flagMap].name, color);
        } else if (flagPage == FLAGS_TRICKY && i == 0) {
            label = "OBJECT PRESENT (READ ONLY)";
            textAt(528, y, validPointer(getTrickyObject()) ? "YES" : "NO", color);
        } else if (flagPage == FLAGS_STATS || (flagPage == FLAGS_CONSUMABLES && i == 0)) {
            PlayerStatus* stats = ready ? practiceStats() : NULL;
            int stat = flagPage == FLAGS_STATS ? i : 4;
            label = statLabels[stat];
            if (stats) {
                numberAt(480, y, statValue(stats, stat), color);
            } else {
                textAt(528, y, "N/A", MUTED);
            }
        } else if (flagPage == FLAGS_RAW && i == 0) {
            label = "BIT ID (HEX)";
            hexAt(480, y, flagRawId, 4, color);
        } else {
            id = flagBitId(i);
            entry = namedBit(id);
            label = flagPage == FLAGS_GROUPS           ? "GROUP"
                    : flagPage == FLAGS_AREA && i == 1 ? "MAP ACT"
                    : entry                            ? entry->name
                                                       : "VALUE (HEX)";
            if (flagPage == FLAGS_GROUPS) {
                numberAt(132, y, i - 1, color);
            }
            width = ready ? stateBitWidth(id) : 0;
            if (!width) {
                textAt(528, y, "N/A", MUTED);
            } else {
                u32 value = readStateBit(id, 0);
                if (flagPage == FLAGS_GROUPS) {
                    value = (value >> (i - 1)) & 1;
                    width = 1;
                    textAt(252, y, gMapObjGroupStatuses[flagMap] & (1u << (i - 1)) ? "ACTIVE" : "INACTIVE", MUTED);
                }
                if (width == 1) {
                    textAt(528, y, value ? "ON" : "OFF", color);
                } else if (flagPage == FLAGS_RAW || width == 32) {
                    hexAt(480, y, value, 8, color);
                } else {
                    numberAt(480, y, value, color);
                }
            }
        }
        textAt(36, y, label, color);
    }
    textAt(36, 387, flagPage == FLAGS_ITEM_AREA ? itemAreaNames[flagItemArea] : flagPages[flagPage], MUTED);
    if (!ready) {
        textAt(36, 407, "STATE UNAVAILABLE / SAVE LOADING", MUTED);
    } else if (flagPage == FLAGS_UNUSED) {
        textAt(36, 407, "UNUSED OR UNCERTAIN - NOT NORMAL ITEMS", MUTED);
    } else if (flagPage == FLAGS_DISCOVERY) {
        textAt(36, 407, "ON: SEEN  OFF: INTRO ARMED", MUTED);
    } else if (flagPage == FLAGS_GROUPS) {
        textAt(36, 407, "SAVED SWITCH + ACTIVE MASK; NOT OBJECT COUNT", MUTED);
    } else {
        int id = flagBitId(selected), width = stateBitWidth(id);
        if (width && flagPage != FLAGS_ROOT && flagPage != FLAGS_ADVANCED && flagPage != FLAGS_INVENTORY &&
            flagPage != FLAGS_STATS) {
            textAt(36, 407, "BIT:", MUTED);
            hexAt(96, 407, id, 4, WHITE);
            textAt(168, 407, "BANK:", MUTED);
            numberAt(240, 407, gGameBitTable[id].flags >> 6, WHITE);
            textAt(288, 407, "WIDTH:", MUTED);
            numberAt(372, 407, width, WHITE);
        }
    }
    textAt(36, 429, "L/R: TABS  B: BACK  X: STEP", MUTED);
    numberAt(360, 429, flagSteps[flagStep], WHITE);
}

static int bitLogCategory(int id) {
    const PracticeBitLabel* entry = namedBit(id);
    int i;
    switch (id) {
    case GAMEBIT_ITEM_PortalSpell_Disabled:
    case GAMEBIT_ITEM_Spell0961_Disabled:
    case GAMEBIT_ITEM_StaffBooster_Disabled:
    case GAMEBIT_ITEM_Spell0965_Disabled:
    case GAMEBIT_ITEM_DinoHorn_Disabled:
    case GAMEBIT_ITEM_Firefly_Disabled:
    case GAMEBIT_Tricky_CantFeed:
    case GAMEBIT_ITEM_SharpClawDisguise_Disabled:
    case GAMEBIT_ITEM_SuperQuake_Disabled:
    case GAMEBIT_ITEM_FireBlaster_Disabled:
    case GAMEBIT_ITEM_SpellStone_Disabled:
    case GAMEBIT_NoBallsAllowed:
    case GAMEBIT_ITEM_Flute_Disabled:
    case GAMEBIT_ENV_isOutdoor:
    case GAMEBIT_ENV_disableDayFX1:
    case GAMEBIT_ENV_disableDayFX2:
    case GAMEBIT_ENV_disableDayFX3:
        return LOG_ACTIONS;
    case GAMEBIT_ITEM_TrickyBall_Bought:
    case GAMEBIT_ITEM_TrickyBall_Usable:
        return LOG_TRICKY;
    }
    if (entry) {
        if (entry->page == FLAGS_INVENTORY || entry->page == FLAGS_ITEM_AREA || entry->page == FLAGS_DISCOVERY) {
            return LOG_INVENTORY;
        }
        if (entry->page == FLAGS_SPELLS) {
            return LOG_SPELLS;
        }
        if (entry->page == FLAGS_TRICKY) {
            return LOG_TRICKY;
        }
        if (entry->page == FLAGS_AREA) {
            return LOG_AREA;
        }
    }
    for (i = 0; i < 120; i++) {
        if (gSaveGameMapObjGroupBits[i] && gSaveGameMapObjGroupBits[i] == id) {
            return LOG_GROUPS;
        }
        if (gSaveGameMapActBits[i] && gSaveGameMapActBits[i] == id) {
            return LOG_AREA;
        }
    }
    return LOG_OTHER;
}

/* Retail OSReport is intentionally empty. Send bounded lines to the IPL UART,
 * which Dolphin exposes under OSREPORT without symbol maps or HLE signatures.
 * Use the SDK EXI bus lock; abandon output if the bus/FIFO is busy. Never spin
 * waiting for log space, and never alter the game's UART/console-type globals.
 * Callers format only fixed strings and bounded catalog labels into logLine. */
static void sendPracticeLog(void) {
    int length = 0, offset = 0;
    while (logLine[length] && length < sizeof(logLine) - 1) {
        if (logLine[length] == '\n') {
            logLine[length] = '\r';
        }
        length++;
    }
    if (!EXILock(0, 1, NULL)) {
        return;
    }
    while (offset < length) {
        u32 command = 0x20010000;
        int available, amount;
        if (!EXISelect(0, 1, EXI_FREQ_8M)) {
            break;
        }
        EXIImm(0, &command, 4, EXI_WRITE, NULL);
        EXISync(0);
        EXIImm(0, &command, 1, EXI_READ, NULL);
        EXISync(0);
        EXIDeselect(0);
        available = 16 - (int)(command >> 24);
        if (available <= 0 || available > 16) {
            break;
        }
        if (!EXISelect(0, 1, EXI_FREQ_8M)) {
            break;
        }
        command = 0xa0010000;
        EXIImm(0, &command, 4, EXI_WRITE, NULL);
        EXISync(0);
        while (available > 0 && offset < length) {
            amount = length - offset;
            if (amount > 4) {
                amount = 4;
            }
            if (amount > available) {
                amount = available;
            }
            EXIImm(0, logLine + offset, amount, EXI_WRITE, NULL);
            EXISync(0);
            offset += amount;
            available -= amount;
        }
        EXIDeselect(0);
    }
    EXIUnlock(0);
}

/* Hook accepted checkpoint operations inside the retail implementations. This
 * also covers indirect map-event calls, repeated writes of identical state, and
 * operations during loading. The original operation always runs unchanged. */
extern u32 pRestartPoint;
extern void loadMapForCurrentSaveGame(void);

static void logCheckpoint(const char* action, const u8* save) {
    const SaveGameCharacterPosition* pos;
    if (!enabled[LOG_ENABLED] || !enabled[LOG_CHECKPOINTS] || !validPointer(save) || (u32)save > 0x817ff000 ||
        save[0x20] > 1) {
        return;
    }
    /* EN save layout, established by engine/23: character at 0x20, positions
     * at 0x684. Use the character stored in this snapshot, not the live one. */
    pos = (const SaveGameCharacterPosition*)(save + 0x684) + save[0x20];
    sprintf(logLine, "[PRACTICE][%u][CHECKPOINT] %s layer=%d XYZ=%d,%d,%d\n", logFrame, action, pos->mapLayer,
            (int)pos->x, (int)pos->y, (int)pos->z);
    sendPracticeLog();
}

void* Practice_SaveCheckpointCopy(void* dest, const void* src, size_t size) {
    void* result = memcpy(dest, src, size);
    if (dest == gSaveGameWorkBuffer) {
        logCheckpoint(size == 0x5d8 ? "SAVE REFRESH (POSITION KEPT)" : "SAVE SET", dest);
    }
    return result;
}

void Practice_RestartCheckpointBit(int bit, u32 value) {
    mainSetBits(bit, value);
    if (bit == GAMEBIT_CF_DoStandUpAnim && value == 0) {
        logCheckpoint("RESTART SET", (const u8*)pRestartPoint);
    }
}

void Practice_ClearCheckpoint(void* pointer) {
    logCheckpoint("RESTART CLEAR", pointer);
    mm_free(pointer);
}

void Practice_GotoSaveCheckpoint(void) {
    logCheckpoint("RESTORE SAVE", gSaveGameData);
    loadMapForCurrentSaveGame();
}

void Practice_GotoRestartCheckpoint(void) {
    logCheckpoint(pRestartPoint ? "RESPAWN RESTART" : "RESPAWN SAVE (FALLBACK)", gSaveGameData);
    loadMapForCurrentSaveGame();
}

int Practice_WriteSave(int slot, void* save, void* data) {
    /* This is a card-write request, not a claim of asynchronous completion. */
    logCheckpoint("CARD SAVE REQUEST", save);
    return _saveGame(slot, save, data);
}

/* Observational net changes between draw frames, not a hook on every setter.
 * Baselines advance even for filtered/suppressed events. No gameplay writes. */
static void pollStateLog(void) {
    int bank, i, count = 0;
    u32 config = 0, changedBanks = 0;
    PlayerStatus* stats;
    logFrame++;
    if (!enabled[LOG_ENABLED]) {
        if (logWasEnabled) {
            sprintf(logLine, "[PRACTICE] Logging disabled\n");
            sendPracticeLog();
        }
        logWasEnabled = 0;
        logLayerReady = 0;
        logBaseline = 0;
        return;
    }
    if (!logWasEnabled) {
        sprintf(logLine, "[PRACTICE] Logging enabled - waiting for game state\n");
        sendPracticeLog();
        logWasEnabled = 1;
    }
    /* Layer changes remain observable across load/baseline resets. */
    if (enabled[LOG_AREA]) {
        int layer = getCurMapLayer();
        if (logLayerReady && layer != logLayer) {
            sprintf(logLine, "[PRACTICE][%u][LAYER] %d -> %d\n", logFrame, logLayer, layer);
            sendPracticeLog();
        }
        logLayer = layer;
        logLayerReady = 1;
    } else {
        logLayerReady = 0;
    }
    if (!practiceStateReady()) {
        logBaseline = 0;
        return;
    }
    for (i = LOG_INVENTORY; i <= LOG_STATS; i++) {
        config |= enabled[i] << (i - LOG_INVENTORY);
    }
    config |= enabled[LOG_CHECKPOINTS] << 7;
    config |= enabled[LOG_ACTIONS] << 8;
    if (logSaveOwner != gGameBitSaveData || logConfig != config) {
        logBaseline = 0;
    }
    if (!logBaseline) {
        sprintf(logLine, "[PRACTICE] Watching %d game bits; filters %02X; net changes per frame\n", checkedBitCount,
                config);
        sendPracticeLog();
    }
    for (bank = 0; bank < 4; bank++) {
        for (i = 0; i < bitBankSizes[bank]; i++) {
            if (logBits[bitSnapshotOffsets[bank] + i] != gGameBitSaveData[bitBankOffsets[bank] + i]) {
                changedBanks |= 1 << bank;
                break;
            }
        }
    }
    if (logBaseline && changedBanks) {
        for (i = 0; i < checkedBitCount; i++) {
            if (stateBitWidth(i) && (changedBanks & (1 << (gGameBitTable[i].flags >> 6)))) {
                u32 before = readStateBit(i, 1), after = readStateBit(i, 0);
                if (before != after && enabled[bitLogCategory(i)]) {
                    const PracticeBitLabel* entry = namedBit(i);
                    if (count++ < 32) {
                        if (entry && entry->page == FLAGS_ITEM_AREA) {
                            sprintf(logLine, "[PRACTICE][%u][BIT %03X][%s] %s: %08X -> %08X\n", logFrame, i,
                                    itemAreaNames[entry->map], entry->name, before, after);
                        } else {
                            sprintf(logLine, "[PRACTICE][%u][BIT %03X] %s: %08X -> %08X\n", logFrame, i,
                                    entry ? entry->name : "UNNAMED", before, after);
                        }
                        sendPracticeLog();
                    }
                }
            }
        }
    }
    for (bank = 0; bank < 4; bank++) {
        for (i = 0; i < bitBankSizes[bank]; i++) {
            logBits[bitSnapshotOffsets[bank] + i] = gGameBitSaveData[bitBankOffsets[bank] + i];
        }
    }
    for (i = 0; i < 120; i++) {
        if (logBaseline && enabled[LOG_GROUPS] && logGroups[i] != gMapObjGroupStatuses[i] && count++ < 32) {
            sprintf(logLine, "[PRACTICE][%u][GROUPS %d] %08X -> %08X\n", logFrame, i, logGroups[i],
                    gMapObjGroupStatuses[i]);
            sendPracticeLog();
        }
        logGroups[i] = gMapObjGroupStatuses[i];
    }
    stats = practiceStats();
    if (stats) {
        for (i = 0; i < 7; i++) {
            int value = statValue(stats, i);
            if (logBaseline && enabled[LOG_STATS] && stats == logStatsOwner && logStats[i] != value && count++ < 32) {
                sprintf(logLine, "[PRACTICE][%u][STAT] %s: %d -> %d\n", logFrame, statLabels[i], logStats[i], value);
                sendPracticeLog();
            }
            logStats[i] = value;
        }
    }
    if (count > 32) {
        sprintf(logLine, "[PRACTICE][%u] %d additional changes suppressed\n", logFrame, count - 32);
        sendPracticeLog();
    }
    logStatsOwner = stats;
    logSaveOwner = gGameBitSaveData;
    logConfig = config;
    logBaseline = 1;
}

#pragma pop

static void rebuildRows(void) {
    int i;
    if (activeTab == TAB_FLAGS) {
        visibleCount = flagRowCount();
        if (selected >= visibleCount) {
            selected = visibleCount - 1;
        }
        return;
    }
    visibleCount = 0;
    for (i = 0; i < ROW_COUNT; i++) {
        if (rows[i].tab != activeTab || i == WARP_GO) {
            continue;
        }
        if (rows[i].parent < 0 || expanded[(int)rows[i].parent]) {
            visible[visibleCount++] = i;
            /* Keep the action beside the three destination selectors. */
            if (i == WARP_SPAWN) {
                visible[visibleCount++] = WARP_GO;
            }
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
        int y = 41;
        rectangle(16, 16, 564,
                  24 + (enabled[SWIMMING] + enabled[SHIELD_HOVER] + enabled[AUTO_ROLL] + enabled[FREE_MOVE]) * 18,
                  0x0B1427DD);
        textAt(24, 23, "SFA PRACTICE  L+R+DOWN: MENU", WHITE);
        if (enabled[SWIMMING]) {
            textAt(24, y, swimActive ? "SWIM ON" : "SWIM READY", 0x63D5FFFF);
            textAt(168, y, "L+DOWN  L+C: HEIGHT", MUTED);
            numberAt(456, y, (int)waterHeight, WHITE);
            y += 18;
        }
        if (enabled[FREE_MOVE]) {
            textAt(24, y, freeActive ? "MOVE ON" : "MOVE READY", GOLD);
            textAt(168, y, "L+UP C:HEIGHT L+C:LOOK", MUTED);
            y += 18;
        }
        if (enabled[SHIELD_HOVER]) {
            textAt(24, y, "AUTO-SHIELD HOVER: HOLD X+R", GOLD);
            y += 18;
        }
        if (enabled[AUTO_ROLL]) {
            textAt(24, y, "AUTO ROLL: HOLD X", GOLD);
        }
        if (enabled[MAP_CELLS]) {
            rectangle(16, 422, 608, 46, 0x0B1427DD);
            textAt(24, 429, "CELLS: GREEN LOADED / RED EMPTY (FREEZE)", WHITE);
            textAt(24, 447, "YELLOW OUTSIDE GRID / GOLD CURRENT CELL", MUTED);
        }
        return;
    }
    rectangle(20, 20, 600, 430, 0x081020EF);
    rectangle(20, 20, 600, 4, 0x59D5FFFF);
    textAt(36, 38, "STAR FOX ADVENTURES / PRACTICE V1.11", WHITE);
    for (i = 0; i < TAB_COUNT; i++) {
        int width = 580 / TAB_COUNT;
        if (i == activeTab) {
            rectangle(28 + i * width, 55, width - 4, 20, 0x263C60FF);
        }
        textAt(36 + i * width, 60, tabLabels[i], i == activeTab ? GOLD : MUTED);
    }
    textAt(36, 83,
           activeTab == TAB_FLAGS  ? "A: OPEN/TOGGLE  LEFT/RIGHT: VALUE"
           : activeTab == TAB_WARP ? "LEFT/RIGHT: CHANGE  A: ACTION  B: CLOSE"
                                   : "A: TOGGLE  LEFT/RIGHT: EXPAND  B: CLOSE",
           MUTED);
    rebuildRows();
    if (menuTop > selected) {
        menuTop = selected;
    }
    if (menuTop < selected - 14) {
        menuTop = selected - 14;
    }
    if (activeTab == TAB_FLAGS) {
        drawFlags();
        return;
    }
    for (i = menuTop; i < visibleCount && i < menuTop + 15; i++) {
        int row = visible[i], y = 110 + (i - menuTop) * 18;
        int indent = rows[row].parent < 0 ? 0 : 24;
        u32 color = rows[row].parent >= 0 && !enabled[(int)rows[row].parent] ? MUTED : WHITE;
        if (i == selected) {
            rectangle(28, y - 4, 584, 18, 0x263C60FF);
            color = GOLD;
        }
        if (rows[row].group) {
            textAt(36, y, expanded[row] ? "-" : "+", color);
        }
        if ((row < WARP_CATEGORY || row >= LOG_ENABLED) && row != WATER_HEIGHT && row != RANGE && row != ROLL_BLANKS &&
            row != SHIELD_BLANKS && row != AUTO_ROLL_BLANKS) {
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
        if (row == ROLL_BLANKS || row == SHIELD_BLANKS) {
            numberAt(440, y, row == ROLL_BLANKS ? rollBlanks : shieldBlanks, color);
        }
        if (row == AUTO_ROLL_BLANKS) {
            numberAt(440, y, autoRollBlanks, color);
        }
        if (row >= WARP_CATEGORY && row <= WARP_GO) {
            drawWarpValue(row, y, color);
        }
    }
    if (activeTab == TAB_WARP) {
        const PracticeWarpMap* map = &practiceWarpMaps[warpMap];
        textAt(36, 350, "MAP ID:", MUTED);
        numberAt(132, 350, warpMap, WHITE);
        textAt(220, 350, warpEdited ? "CUSTOM POSITION" : "SPAWN PRESET", MUTED);
        textAt(36, 377,
               warpMessage        ? warpMessage
               : !map->spawnCount ? "OBJECT / UNPLACED MAP: NO STANDALONE WARP"
               : practiceWarpSpawns[map->firstSpawn + warpSpawn].warp < 0
                   ? "ESTIMATED SPAWN - ADJUST POSITION AS NEEDED"
                   : "MAP OR SPAWN CHANGE RESTORES ITS DEFAULTS",
               MUTED);
        textAt(36, 419, "L/R: TABS  WARP NOW + A: TRAVEL", MUTED);
        return;
    }
    if (activeTab == TAB_LOG) {
        textAt(36, 365, "DOLPHIN: OSREPORT LOG (NOTICE)", MUTED);
        textAt(36, 389, "NET CHANGES PER FRAME; 32 EVENT LIMIT", MUTED);
        textAt(36, 419, "L/R: TABS  A: TOGGLE  B: CLOSE", MUTED);
        return;
    }
    textAt(36, 395, "TRIS:", MUTED);
    numberAt(108, 395, trianglesDrawn, WHITE);
    textAt(252, 395, "TRIGGERS:", MUTED);
    numberAt(372, 395, triggersDrawn, WHITE);
    textAt(36, 419,
           drawLimitReached || fillsDrawn >= fillLimit ? "DRAW LIMIT REACHED - REDUCE DISTANCE"
           : activeTab == TAB_CHEATS                   ? "HOVER: HOLD X+R  AUTO ROLL: HOLD X"
                                                       : "L/R: TABS  L+R+DOWN: CLOSE",
           MUTED);
}

void Practice_SetArenaLo(void* start) {
    if ((u32)start < (u32)__practice_limit) {
        start = __practice_limit;
    }
    OSSetArenaLo(start);
}

/* Match the engine's object-SFX pause behavior without unpausing channels that
 * were already muted by the game. Handle + allocation age identify a voice even
 * if a channel is recycled while paused. Music/stream volumes are untouched. */
static void updateMenuSounds(void) {
    int i;
    if (!menuOpen && !menuSoundActive) {
        return;
    }
    if (menuOpen && !menuSoundActive) {
        menuSoundHudDepth = getHudHiddenFrameCount();
        menuSoundDvdPaused = gDvdErrorPauseActive;
    }
    for (i = 0; i < SFX_OBJECT_CHANNEL_COUNT; i++) {
        SfxObjectChannel* channel = &gSfxObjectChannels[i];
        if (channel->handle == (u32)-1 || channel->handle != menuSoundHandles[i] || channel->age != menuSoundAges[i]) {
            menuSoundOwned[i] = 0;
        }
        if (menuOpen) {
            if (channel->handle != (u32)-1 && !channel->paused) {
                menuSoundHandles[i] = channel->handle;
                menuSoundAges[i] = channel->age;
                menuSoundOwned[i] = 1;
                channel->paused = 1;
                sndFXCtrl(channel->handle, MCMD_CTRL_VOLUME, 0);
            }
        } else {
            if (menuSoundOwned[i] && channel->paused && (!gDvdErrorPauseActive || menuSoundDvdPaused) &&
                getHudHiddenFrameCount() <= menuSoundHudDepth && timeStop == savedTimeStop) {
                channel->paused = 0;
                if (channel->hasPosition) {
                    Sfx_UpdateObjectChannel3D(channel);
                } else {
                    sndFXCtrl(channel->handle, MCMD_CTRL_VOLUME, channel->volume);
                }
            }
            menuSoundOwned[i] = 0;
        }
    }
    menuSoundActive = menuOpen;
}

static void closeMenu(void) {
    menuOpen = 0;
    if (timeStop == 0xff) {
        timeStop = savedTimeStop;
    }
}

/* Read the same world-map bounds/occupied-cell tables as mapCoordsToId,
 * using an absolute layer without modifying the game's current layer. */
static int warpDestinationMap(void) {
    typedef struct PracticeMapBounds {
        s16 minX, maxX, minZ, maxZ;
        s8 originX, originZ;
    } PracticeMapBounds;
    PracticeMapBounds* bounds = (PracticeMapBounds*)gShaderMapRomBuffers[1];
    s8* layers = (s8*)gShaderMapRomBuffers[3];
    u8* cells = (u8*)gShaderMapRomBuffers[4];
    int x, z, i;
    if (!validPointer(bounds) || !validPointer(layers) || !validPointer(cells) ||
        !(warpDestination.x >= -100000 && warpDestination.x <= 100000) ||
        !(warpDestination.y >= -100000 && warpDestination.y <= 100000) ||
        !(warpDestination.z >= -100000 && warpDestination.z <= 100000)) {
        return -1;
    }
    x = (int)(warpDestination.x / 640.0f);
    z = (int)(warpDestination.z / 640.0f);
    if (warpDestination.x < x * 640.0f) {
        x--;
    }
    if (warpDestination.z < z * 640.0f) {
        z--;
    }
    for (i = 0; i < 128; i++) {
        if (layers[i] == warpDestination.layer && x >= bounds[i].minX && x <= bounds[i].maxX && z >= bounds[i].minZ &&
            z <= bounds[i].maxZ) {
            int cell = x - bounds[i].minX + (z - bounds[i].minZ) * (bounds[i].maxX - bounds[i].minX + 1);
            if (cell >= 0 && cell < 512 && (cells[i * 64 + (cell >> 3)] & (1 << (cell & 7)))) {
                return i;
            }
        }
    }
    return -1;
}

static void requestPracticeWarp(GameObject* player) {
    const PracticeWarpMap* map = &practiceWarpMaps[warpMap];
    int index;
    if (!map->spawnCount || !validPointer(player) || savedTimeStop || joypadDisabled || gDvdErrorPauseActive ||
        gWarpRequested) {
        warpMessage = "WARP UNAVAILABLE IN THIS STATE";
        return;
    }
    if (warpDestinationMap() != warpMap) {
        warpMessage = "POSITION / LAYER IS OUTSIDE THE SELECTED MAP";
        return;
    }
    index = practiceWarpSpawns[map->firstSpawn + warpSpawn].warp;
    closeMenu();
    hoverActive = hoverPhase = 0;
    hoverWait = 0;
    /* Use the retail fade/reload path. Custom positions use an unused arrival
     * ID, so they do not pretend to arrive at an unrelated checkpoint marker. */
    warpToMap(index >= 0 ? index : 2, 1);
    gRcpPendingWarpDest = warpDestination;
    warpQueuedDestination = warpDestination;
    warpLoadPending = 1;
    if (index < 0 || warpEdited) {
        gPendingWarpIndex = 128;
    }
}

/* Called only at loadNextMap's mapReload call, after it commits the new
 * character coordinates and the fade has finished. Retail callers normally
 * arrange resource banks before warping; arbitrary practice travel must queue
 * them explicitly. doQueuedLoads unloads old objects before loading the banks. */
void Practice_WarpReload(void) {
    int practice = warpLoadPending && gRcpPendingWarpDest.x == warpQueuedDestination.x &&
                   gRcpPendingWarpDest.y == warpQueuedDestination.y &&
                   gRcpPendingWarpDest.z == warpQueuedDestination.z &&
                   gRcpPendingWarpDest.layer == warpQueuedDestination.layer;
    warpLoadPending = 0;
    if (!practice) {
        mapReload();
        return;
    }
    unlockLevel(0, 0, 1);
    mapLoadByCoords(gRcpPendingWarpDest.x, gRcpPendingWarpDest.y, gRcpPendingWarpDest.z, gRcpPendingWarpDest.layer);
    /* A saved auxiliary bank belongs to the source area, not this destination. */
    gGameLoopPendingMapDataFileId = -1;
}

#pragma push
#pragma auto_inline off
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

/* Alternate real controller inputs once per game input poll. Preserve the
 * physical pad history: padUpdate needs it for menu chords and other buttons.
 * Build X/R edges against our last effective input, including when disabled.
 * Hover requires physical X+R. Auto roll requires physical X and sends one X
 * frame, configurable blank frames, one R frame, then repeats. Hover wins.
 * Sample physical buttons before injection; preserve history for padUpdate. */
static void updateShieldHover(GameObject* player, int blocked) {
    u32 mask = PAD_BUTTON_X | PAD_TRIGGER_R;
    u32 before, after;
    u16 beforeTrigger, afterTrigger;
    u32 physical = gPadButtonsHeld[0] | gPadTriggers[0];
    int mode = enabled[SHIELD_HOVER] && (physical & mask) == mask ? 1
               : enabled[AUTO_ROLL] && (physical & PAD_BUTTON_X)  ? 2
                                                                  : 0;
    PADStatus* pad = &gPadStatuses[gPadStatusBufferIndex * PAD_MAX_CONTROLLERS];
    if (blocked || timeStop || joypadDisabled || gDvdErrorPauseActive || !validPointer(player)) {
        hoverActive = hoverPhase = 0;
        hoverWait = 0;
        autoRollWait = 0;
        autoRollPhase = 0;
        return;
    }
    if (!mode && !hoverActive) {
        hoverPhase = 0;
        hoverWait = 0;
        autoRollWait = 0;
        autoRollPhase = 0;
        return;
    }
    before =
        hoverActive ? hoverButtons : (gPadButtonsHeld[0] ^ gPadButtonsJustPressed[0] ^ gPadButtonsReleased[0]) & mask;
    beforeTrigger = hoverActive ? hoverButtons & PAD_TRIGGER_R
                                : (gPadTriggers[0] ^ gPadTriggersPressed[0] ^ gPadTriggersReleased[0]) & PAD_TRIGGER_R;
    after = gPadButtonsHeld[0] & mask;
    afterTrigger = gPadTriggers[0] & PAD_TRIGGER_R;
    if (mode != hoverActive) {
        hoverPhase = 0;
        hoverWait = autoRollWait = 0;
        autoRollPhase = 0;
    }
    if (mode) {
        if (mode == 2) {
            after = 0;
            if (autoRollWait > 0) {
                autoRollWait--;
            } else if (autoRollPhase) {
                after = PAD_TRIGGER_R;
                autoRollPhase = 0;
            } else {
                after = PAD_BUTTON_X;
                autoRollWait = autoRollBlanks;
                autoRollPhase = 1;
            }
        } else if (hoverWait > 0) {
            after = 0;
            hoverWait--;
        } else {
            after = hoverPhase ? PAD_BUTTON_X : PAD_TRIGGER_R;
            hoverWait = hoverPhase ? rollBlanks : shieldBlanks;
            hoverPhase ^= 1;
        }
        afterTrigger = after & PAD_TRIGGER_R;
        pad->button = (pad->button & ~mask) | after;
        pad->triggerRight = afterTrigger ? 255 : 0;
    } else {
        hoverPhase = 0;
        hoverWait = 0;
    }
    gPadButtonsHeld[0] = (gPadButtonsHeld[0] & ~mask) | after;
    gPadButtonsJustPressed[0] = (gPadButtonsJustPressed[0] & ~mask) | (after & ~before);
    gPadButtonsReleased[0] = (gPadButtonsReleased[0] & ~mask) | (before & ~after);
    gPadTriggers[0] = (gPadTriggers[0] & ~PAD_TRIGGER_R) | afterTrigger;
    gPadTriggersPressed[0] = (gPadTriggersPressed[0] & ~PAD_TRIGGER_R) | (afterTrigger & ~beforeTrigger);
    gPadTriggersReleased[0] = (gPadTriggersReleased[0] & ~PAD_TRIGGER_R) | (beforeTrigger & ~afterTrigger);
    hoverButtons = after;
    hoverActive = mode;
}

/* padUpdate already applies PADClamp: cardinal maxima are 72 / 59. */
static f32 freeAxis(s8 value, f32 maximum) {
    f32 range = maximum - 20.0f;
    f32 axis = value > 20 ? (value - 20) / range : value < -20 ? (value + 20) / range : 0;
    return axis < -1 ? -1 : axis > 1 ? 1 : axis;
}

static Vec freeForward(void) {
    f32 yaw = freeYaw * (3.14159265359f / 32768);
    f32 pitch = freePitch * (3.14159265359f / 32768);
    f32 horizontal = mathCosf(pitch);
    return point(-mathSinf(yaw) * horizontal, mathSinf(pitch), -mathCosf(yaw) * horizontal);
}

static void restoreFreePose(GameObject* player) {
    if (freePoseOwner == player && validPointer(player) && player->extra == freePoseState &&
        validPointer(freePoseState) && !isSaveGameLoading() && !gWarpRequested) {
        player->anim.rotY = freeSavedPitch;
        player->anim.rotZ = freeSavedRoll;
        playerRefreshCollisionState(player, (int)freePoseState, validPointer(player->anim.hitReactState) ? 7 : 3);
    }
    freePoseOwner = NULL;
    freePoseState = NULL;
}

/* Menu switches arm the shortcuts. Only one movement override runs at once.
 * Use physical button chords before input injection and consume activation frames. */
static int updateQuickMovement(GameObject* player, u32 held, u32 shoulders, int blocked) {
    int quick =
        (shoulders & PAD_TRIGGER_L) && !(shoulders & PAD_TRIGGER_R) ? held & (PAD_BUTTON_UP | PAD_BUTTON_DOWN) : 0;
    int edge = quick & ~quickLatch;
    int wasFree = freeActive;
    PADStatus* pad = &gPadStatuses[gPadStatusBufferIndex * PAD_MAX_CONTROLLERS];
    quickLatch = quick;
    freeStep = point(0, 0, 0);
    if (!enabled[SWIMMING]) {
        swimActive = 0;
    }
    if (!enabled[FREE_MOVE]) {
        freeActive = 0;
    }
    if (!validPointer(player) || isSaveGameLoading() || gWarpRequested) {
        swimActive = freeActive = 0;
        restoreFreePose(player);
        return wasFree;
    }
    if ((!menuOpen && timeStop && !blocked) || joypadDisabled || gDvdErrorPauseActive) {
        freeActive = 0;
    }
    if (!blocked && !timeStop && !joypadDisabled && !gDvdErrorPauseActive) {
        if (edge == PAD_BUTTON_DOWN && enabled[SWIMMING]) {
            swimActive ^= 1;
            if (swimActive) {
                freeActive = 0;
                waterHeight = player->anim.worldPosY + 40.0f;
            }
        } else if (edge == PAD_BUTTON_UP && enabled[FREE_MOVE]) {
            freeActive ^= 1;
            if (freeActive) {
                swimActive = 0;
                freePoseOwner = player;
                freePoseState = player->extra;
                freeYaw = player->anim.rotX + (player->anim.parent ? player->anim.parentAnim->rotX : 0);
                freePitch = 0;
                freeSavedPitch = player->anim.rotY;
                freeSavedRoll = player->anim.rotZ;
            }
        }
        if (freeActive && !quick) {
            f32 dt = timeDelta;
            f32 right, forward, angle;
            int pitch;
            Vec direction;
            if (!(dt > 0)) {
                dt = 0;
            } else if (dt > 3) {
                dt = 3;
            }
            /* Fox faces local -Z: decreasing yaw turns right. Positive pitch
             * points upward. Keep a stable yaw at steep angles, without flips. */
            if (shoulders & PAD_TRIGGER_L) {
                freeYaw -= (int)(freeAxis(pad->substickX, 59.0f) * 364.0f * dt);
                pitch = freePitch + (int)(freeAxis(pad->substickY, 59.0f) * 364.0f * dt);
                freePitch = pitch < -0x3800 ? -0x3800 : pitch > 0x3800 ? 0x3800 : pitch;
            } else {
                freeStep.y = freeAxis(pad->substickY, 59.0f) * 5.0f * dt;
            }
            right = freeAxis(pad->stickX, 72.0f) * 5.0f * dt;
            forward = freeAxis(pad->stickY, 72.0f) * 5.0f * dt;
            angle = freeYaw * (3.14159265359f / 32768);
            direction = freeForward();
            freeStep.x = right * mathCosf(angle) + forward * direction.x;
            freeStep.z = -right * mathSinf(angle) + forward * direction.z;
            freeStep.y += forward * direction.y;
        }
    }
    if (!freeActive) {
        restoreFreePose(player);
    }
    return freeActive || wasFree || (quick && (enabled[SWIMMING] || enabled[FREE_MOVE]));
}

/* This replaces only camcontrol_applyState's load-center call, after retail
 * camera logic and before view matrices/culling. On exit retail owns the view
 * again; no handler, target, parent, or camera mode is replaced. */
void Practice_CameraLoadPos(f32 x, f32 y, f32 z) {
    GameObject* player = Obj_GetPlayerObject();
    PlayerState* state = validPointer(player) ? player->extra : NULL;
    if (freeActive && enabled[FREE_MOVE] && player == freePoseOwner && state == freePoseState && validPointer(state) &&
        !isSaveGameLoading() && !gWarpRequested && !joypadDisabled && !gDvdErrorPauseActive &&
        !(state->cutsceneTimer > 0) && state->focusObject == NULL && gCameraCurrentViewIndex == 0 &&
        (!timeStop || menuOpen)) {
        Camera* view = &gCameras[0];
        Vec forward = freeForward();
        x = player->anim.worldPosX - forward.x * 180.0f;
        y = player->anim.worldPosY + 25.0f - forward.y * 180.0f;
        z = player->anim.worldPosZ - forward.z * 180.0f;
        Obj_TransformWorldPointToLocal(x, y, z, &view->x, &view->y, &view->z, view->parentObject);
        view->yaw = 32768 - freeYaw + (view->parentObject ? view->parentObject->anim.rotX : 0);
        view->pitch = -freePitch;
        view->roll = 0;
        Camera_UpdateForObject(view);
    }
    loadMapForCameraPos(x, y, z);
}

static void refillResources(GameObject* obj) {
    PlayerStatus* stats;
    if ((!enabled[INFINITE_HEALTH] && !enabled[INFINITE_MAGIC]) || obj != Obj_GetPlayerObject() ||
        isSaveGameLoading()) {
        return;
    }
    stats = practiceStats();
    if (stats) {
        if (enabled[INFINITE_HEALTH] && stats->maxHealth > 0) {
            stats->health = stats->maxHealth;
        }
        if (enabled[INFINITE_MAGIC] && stats->maxMagic > 0) {
            stats->magic = stats->maxMagic;
        }
    }
}

extern void playerDie(GameObject* obj);
void Practice_PlayerDie(GameObject* obj) {
    PlayerStatus* stats = NULL;
    if (enabled[INFINITE_HEALTH] && obj == Obj_GetPlayerObject() && !isSaveGameLoading()) {
        stats = practiceStats();
    }
    if (stats && stats->health <= 0 && stats->maxHealth > 0) {
        stats->health = stats->maxHealth;
        return;
    }
    playerDie(obj);
}

void Practice_PlayerUpdate(GameObject* obj) {
    PlayerState* state = obj->extra;
    Vec delta = freeStep;
    refillResources(obj);
    if (freeActive && obj == swimOwner && validPointer(state) &&
        (state->cutsceneTimer > 0 || state->focusObject != NULL || joypadDisabled || gDvdErrorPauseActive)) {
        freeActive = 0;
    }
    if (!freeActive || !enabled[FREE_MOVE] || obj != swimOwner || !validPointer(state)) {
        if (obj == freePoseOwner) {
            restoreFreePose(obj);
        }
        playerUpdate(obj);
        refillResources(obj);
        return;
    }
    if (obj->anim.parent) {
        Obj_TransformWorldVectorToLocal(delta.x, delta.y, delta.z, &delta.x, &delta.y, &delta.z, obj->anim.parent);
    }
    obj->anim.localPosX += delta.x;
    obj->anim.localPosY += delta.y;
    obj->anim.localPosZ += delta.z;
    obj->anim.rotX = freeYaw - (obj->anim.parent ? obj->anim.parentAnim->rotX : 0);
    obj->anim.rotY = freePitch;
    obj->anim.rotZ = 0;
    state->yaw = state->targetYaw = state->prevYaw = state->prevTargetYaw = obj->anim.rotX;
    /* Teleport-style refresh: skipping retail update/hit detection leaves both
     * terrain sweeps and object-hit positions at the last ordinary frame.
     * Rebuild them here so releasing Free Move cannot sweep across the journey. */
    Obj_GetWorldPosition(obj, &obj->anim.worldPosX, &obj->anim.worldPosY, &obj->anim.worldPosZ);
    playerRefreshCollisionState(obj, (int)state, validPointer(obj->anim.hitReactState) ? 7 : 3);
    obj->anim.previousLocalPosX = obj->anim.localPosX;
    obj->anim.previousLocalPosY = obj->anim.localPosY;
    obj->anim.previousLocalPosZ = obj->anim.localPosZ;
    obj->anim.previousWorldPosX = obj->anim.worldPosX;
    obj->anim.previousWorldPosY = obj->anim.worldPosY;
    obj->anim.previousWorldPosZ = obj->anim.worldPosZ;
    obj->anim.velocityX = obj->anim.velocityY = obj->anim.velocityZ = 0;
    obj->externalVelX = obj->externalVelY = obj->externalVelZ = 0;
    state->baddie.animSpeedA = state->baddie.animSpeedB = state->baddie.animSpeedC = 0;
    state->smoothVelX = state->smoothVelZ = state->verticalVel = 0;
    if (swimApplied) {
        state->flags3F0.b20 = 0;
        swimApplied = 0;
    }
}

void Practice_PlayerHitDetection(GameObject* obj) {
    if (!freeActive || !enabled[FREE_MOVE] || obj != swimOwner) {
        playerDoHitDetection(obj);
    }
}

void Practice_PadUpdate(void) {
    u32 held, pressed, shoulders, shoulderPressed;
    int chord, wasOpen, movementInput, waterStick;
    GameObject* player;
    padUpdate();
    held = gPadButtonsHeld[0];
    pressed = gPadButtonsJustPressed[0];
    shoulders = held | gPadTriggers[0];
    shoulderPressed = shoulders & ~previousShoulders & (PAD_TRIGGER_L | PAD_TRIGGER_R);
    previousShoulders = shoulders & (PAD_TRIGGER_L | PAD_TRIGGER_R);
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
        hoverActive = hoverPhase = 0;
        hoverWait = 0;
        swimApplied = swimActive = freeActive = 0;
        swimOwner = player;
    }
    if (menuOpen && !chord) {
        int row;
        int tabDelta = ((shoulderPressed & PAD_TRIGGER_R) != 0) - ((shoulderPressed & PAD_TRIGGER_L) != 0);
        if (tabDelta != 0) {
            activeTab = (activeTab + TAB_COUNT + tabDelta) % TAB_COUNT;
            selected = menuTop = repeatTimer = 0;
            pressed &= ~(PAD_BUTTON_A | PAD_BUTTON_LEFT | PAD_BUTTON_RIGHT | PAD_BUTTON_UP | PAD_BUTTON_DOWN);
            held &= ~(PAD_BUTTON_UP | PAD_BUTTON_DOWN);
        }
        rebuildRows();
        if (activeTab == TAB_WARP && !warpReady) {
            resetWarpSpawn();
        }
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
        row = activeTab == TAB_FLAGS ? -1 : visible[selected];
        if (pressed & PAD_BUTTON_B) {
            if (activeTab == TAB_FLAGS && flagPage != FLAGS_ROOT) {
                int backSelection = flagPage == FLAGS_DISCOVERY                            ? 7
                                    : flagPage == FLAGS_ITEM_AREA                          ? flagItemArea
                                    : flagPage >= FLAGS_UPGRADES && flagPage <= FLAGS_MAPS ? flagPage - FLAGS_UPGRADES
                                    : flagPage == FLAGS_RAW || flagPage == FLAGS_UNUSED    ? flagPage - FLAGS_RAW
                                                                                           : flagPage - 1;
                flagPage = flagPage == FLAGS_DISCOVERY                         ? FLAGS_ROOT
                           : flagPage == FLAGS_ITEM_AREA                       ? FLAGS_AREA_ITEMS
                           : flagPage >= FLAGS_UPGRADES                        ? FLAGS_INVENTORY
                           : flagPage == FLAGS_RAW || flagPage == FLAGS_UNUSED ? FLAGS_ADVANCED
                                                                               : FLAGS_ROOT;
                selected = backSelection;
                menuTop = 0;
            } else {
                closeMenu();
            }
        } else if (activeTab == TAB_FLAGS) {
            editFlags(pressed);
        } else if (row >= WARP_CATEGORY && row <= WARP_GO) {
            int delta = (pressed & PAD_BUTTON_RIGHT) ? 1 : (pressed & PAD_BUTTON_LEFT) ? -1 : 0;
            editWarpRow(row, delta);
            if (pressed & PAD_BUTTON_A) {
                if (row == WARP_RESET) {
                    resetWarpSpawn();
                } else if (row == WARP_GO) {
                    requestPracticeWarp(player);
                }
            }
        } else if (row == WATER_HEIGHT || row == RANGE || row == ROLL_BLANKS || row == SHIELD_BLANKS ||
                   row == AUTO_ROLL_BLANKS) {
            int delta = (pressed & PAD_BUTTON_RIGHT) ? 1 : (pressed & PAD_BUTTON_LEFT) ? -1 : 0;
            if (row == WATER_HEIGHT) {
                waterHeight += delta * 10.0f;
            } else if (row == RANGE) {
                drawDistance += delta * 250;
                if (drawDistance < 250) {
                    drawDistance = 250;
                }
                if (drawDistance > 2500) {
                    drawDistance = 2500;
                }
            } else {
                int* blanks = row == ROLL_BLANKS ? &rollBlanks : row == SHIELD_BLANKS ? &shieldBlanks : &autoRollBlanks;
                int max = row == AUTO_ROLL_BLANKS ? 120 : 60;
                *blanks += delta;
                if (*blanks < 0) {
                    *blanks = 0;
                }
                if (*blanks > max) {
                    *blanks = max;
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
            }
        }
        if (activeTab == TAB_CHEATS && (pressed & PAD_BUTTON_X) && validPointer(player)) {
            waterHeight = player->anim.worldPosY + 40.0f;
        }
    }
    movementInput = updateQuickMovement(player, held, shoulders, menuOpen || wasOpen || chord);
    waterStick = gPadStatuses[gPadStatusBufferIndex * PAD_MAX_CONTROLLERS].substickY;
    if (!menuOpen && !wasOpen && !chord && !timeStop && !joypadDisabled && !gDvdErrorPauseActive && enabled[SWIMMING] &&
        swimActive && (shoulders & (PAD_TRIGGER_L | PAD_TRIGGER_R)) == PAD_TRIGGER_L &&
        (waterStick > 20 || waterStick < -20)) {
        f32 delta = timeDelta * (waterStick > 20 ? 2.0f : -2.0f);
        if (delta > 10) {
            delta = 10;
        }
        if (delta < -10) {
            delta = -10;
        }
        waterHeight += delta;
        swallowInput();
    }
    if (menuOpen || wasOpen || chord || movementInput) {
        swallowInput();
    }
    updateShieldHover(player, menuOpen || wasOpen || chord || movementInput);
    updateMenuSounds();
}

static void applyWater(GameObject* obj, PlayerState* state) {
    state->baddie.waterSurfaceY = waterHeight;
    state->waterSurfaceY = waterHeight;
    state->waterDepth = waterHeight - obj->anim.worldPosY;
}

void Practice_PlayerControls(GameObject* obj, PlayerState* state, f32 dt) {
    f32 original = state->baddie.waterSurfaceY;
    int active = enabled[SWIMMING] && swimActive && obj == Obj_GetPlayerObject();
    if (obj == Obj_GetPlayerObject()) {
        if (active) {
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
    int active = enabled[SWIMMING] && swimActive && obj == Obj_GetPlayerObject();
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

#pragma pop

void Practice_Draw(void) {
    u8 viewIndex = gCameraCurrentViewIndex;
    updateMenuSounds();
    pollStateLog();
    linesDrawn = trianglesDrawn = triggersDrawn = fillsDrawn = 0;
    drawLimitReached = 0;
    if (enabled[COLLISION] || enabled[TRIGGERS] || enabled[MAP_CELLS] ||
        (enabled[SWIMMING] && swimActive && enabled[WATER_GRID])) {
        drawWorld();
    }
    drawMenu();
    gCameraCurrentViewIndex = viewIndex;
    resetSomeGxFlags();
}
#endif
