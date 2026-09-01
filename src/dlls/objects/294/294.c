/*
 * trigger (DLL 0x126) - generic scripted trigger object.
 *
 * Trigger_init dispatches on the placement's object-sequence type id
 * (*(s16*)params: 0x4b/0x4c/0x4d/0x4e/0x50/0x54/0x230/0xf4) to set up the
 * instance's range/timer state, then Trigger_hitDetect picks a target
 * (player / Tricky / Arwing / camera / nearest object of a group, per the
 * placement's mode byte at 0x43), tracks its position, and on a positive
 * activation runs the trigger's command list through objInterpretSeq.
 *
 * objInterpretSeq walks up to 8 four-byte command entries. Each entry is
 * a flags byte at [0], opcode at [1], and args at [2]/[3]. The flags byte
 * gates whether the entry runs: bit0 = run on enter (p3 > 0), bit1 = run on
 * exit (p3 < 0), bit2/bit3 = once-only for the enter/exit direction (latched
 * against sflags bit0/bit1), bit4 = unconditional (ignore enter/exit), bit5 =
 * override-disabled (run even when the trigger's disabled flag, *state & 4,
 * is set). A zero opcode entry is skipped.
 * On a matching entry it fires the corresponding effect: player anims, sfx,
 * triggered camera actions, sky / cloud / lighting / time-of-day toggles,
 * game-bit set/toggle, env effects, map-layer navigation, level
 * lock/load/unload, save/restart points, texture preload, and NPC
 * dialogue. p3 carries the activation direction (1 = enter, -1 = exit).
 *
 * Trigger_render/update/release/initialise are stubs; Trigger_free stops
 * any sfx the trigger started.
 */
#include "dlls/objects/294.h"

#include "main/frame_timing.h"
#include "main/texture.h"
#include "sys/objects/lifecycle.h"
#include "main/dll/player_api.h"
#include "main/dll/dll_000D_playershadow.h"
#include "main/camera_interface.h"
#include "main/dll/cloudaction_interface.h"
#include "main/game_ui_interface.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "sys/objects.h"
#include "main/obj_list.h"
#include "main/mapEventTypes.h"
#include "main/objseq.h"
#include "main/objtype.h"
#include "main/sky_state.h"
#include "main/lightmap_render_control_api.h"
#include "main/rcp_dolphin.h"
#include "main/shader_api.h"
#include "dolphin/os/OSReport.h"
#include "main/model.h"
#include "main/sky_api.h"
#include "main/render_envfx_api.h"
#include "main/render_lactions_api.h"
#include "main/gamebit_ids.h"
#include "main/gamebits_api.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/dll/dll_0126_trigger.h"
#include "main/dll/dll_02B5_timer.h"
#include "main/dll/headdisplay.h"
#include "main/sky.h"
#include "main/dll/dll_0126_trigger_api.h"
#include "main/dll/rom_curve_interface.h"
#include "main/vecmath.h"
#include "dolphin/mtx.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/gameloop_api.h"
#include "track/intersect_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/map_load.h"

ObjectDescriptor gTriggerObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)Trigger_initialise,
    (ObjectDescriptorCallback)Trigger_release,
    0,
    (ObjectDescriptorCallback)Trigger_init,
    (ObjectDescriptorCallback)Trigger_update,
    (ObjectDescriptorCallback)Trigger_hitDetect,
    (ObjectDescriptorCallback)Trigger_render,
    (ObjectDescriptorCallback)Trigger_free,
    (ObjectDescriptorCallback)Trigger_getObjectTypeId,
    Trigger_getExtraSize,
};

char sMoonrockTriggerIdentFormat[] = "!!!!!!!!!!! TRIGGER %d  ident %d\n";
char sTriggerDebugTextBlock[] = "initialise\n\0"
                                "Trigger [%d], Environment Effect, Action Num [%d], Range [%d]\0\0\0"
                                "^^^^^^^^\n^^^^^^^^\nLOAD %d\n\0\0"
                                "^^^^^^^^\n^^^^^^^^\nFREE %d\n\0\0"
                                "^^^^^^^^\n^^^^^^^^\nLEVELLOCKED level %d  bucket %d\n\0\0"
                                "^^^^^^^^\n^^^^^^^^\nLEVELUNLOCKED level %d  bucket %d\n\0\0\0";

typedef struct MmpTriggerPlaneState {
    u8 header[0xC];     /* 0x00 */
    f32 normalX;        /* 0x0C plane normal */
    f32 normalY;        /* 0x10 */
    f32 normalZ;        /* 0x14 */
    f32 planeD;         /* 0x18 plane constant */
    f32 ptA[3];         /* 0x1C near segment endpoint */
    f32 ptB[3];         /* 0x28 far segment endpoint */
    f32 clipHalfExtent; /* 0x34 trigger-local half size */
    f32 mtx[3][4];      /* 0x38 world->trigger-local transform */
} MmpTriggerPlaneState;

STATIC_ASSERT(offsetof(MmpTriggerPlaneState, normalX) == 0x0C);
STATIC_ASSERT(offsetof(MmpTriggerPlaneState, planeD) == 0x18);
STATIC_ASSERT(offsetof(MmpTriggerPlaneState, ptA) == 0x1C);
STATIC_ASSERT(offsetof(MmpTriggerPlaneState, ptB) == 0x28);
STATIC_ASSERT(offsetof(MmpTriggerPlaneState, clipHalfExtent) == 0x34);
STATIC_ASSERT(offsetof(MmpTriggerPlaneState, mtx) == 0x38);

#define MOONROCK_ANGLE_TO_RADIANS(angle) ((3.1415927f * (f32)(s32)(-(angle))) / 32768.0f)

static void triggerEvalCurveLoop(GameObject* obj, GameObject* seqObj) {
    MmpTriggerPlaneState* state;
    f32 hitDistance;
    int queryType;
    int curveHit;
    int frontBlocked;
    int rearBlocked;

    queryType = 0x17;
    state = (MmpTriggerPlaneState*)obj->extra;
    curveHit = (*gRomCurveInterface)
                   ->find(state->ptB[0], state->ptB[1], state->ptB[2], &queryType, 1,
                          *(s16*)((u8*)obj->anim.placementData + 0x38));
    frontBlocked =
        (*gRomCurveInterface)->isPointInsideLoop(curveHit, state->ptB[0], state->ptB[1], state->ptB[2], &hitDistance);
    rearBlocked =
        (*gRomCurveInterface)->isPointInsideLoop(curveHit, state->ptA[0], state->ptA[1], state->ptA[2], &hitDistance);

    if (frontBlocked != 0) {
        if (rearBlocked == 0) {
            objInterpretSeq(obj, seqObj, 1, (int)hitDistance);
        } else {
            objInterpretSeq(obj, seqObj, 2, (int)hitDistance);
        }
    } else if (rearBlocked != 0) {
        objInterpretSeq(obj, seqObj, -1, (int)hitDistance);
    } else {
        objInterpretSeq(obj, seqObj, -2, (int)hitDistance);
    }
}

static f32 moonrockAngleToRadians(s16 angle) {
    return MOONROCK_ANGLE_TO_RADIANS(angle);
}

static int triggerPointInBox(GameObject* obj, f32* point) {
    u8* data;
    f32 pointX;
    f32 pointY;
    f32 pointZ;
    f32 yawSin;
    f32 yawCos;
    f32 pitchSin;
    f32 pitchCos;
    f32 relZ;
    f32 relY;
    f32 relX;
    f32 localX;
    f32 localY;
    f32 localZ;
    f32 forward;
    GameObject* o = obj;

    data = (u8*)o->anim.placementData;
    pointX = point[0];
    pointY = point[1];
    pointZ = point[2];

    yawSin = mathSinf(moonrockAngleToRadians(o->anim.rotX));
    yawCos = mathCosf(moonrockAngleToRadians(o->anim.rotX));
    pitchSin = mathSinf(moonrockAngleToRadians(o->anim.rotY));
    pitchCos = mathCosf(moonrockAngleToRadians(o->anim.rotY));

    relX = pointX - o->anim.worldPosX;
    relY = pointY - o->anim.worldPosY;
    relZ = pointZ - o->anim.worldPosZ;
    localX = relX * yawCos - relZ * yawSin;
    forward = relX * yawSin + relZ * yawCos;
    localY = relY * pitchCos - forward * pitchSin;
    localZ = relY * pitchSin + forward * pitchCos;

    if (localX < 0.0f) {
        localX = -localX;
    }
    if (localY < 0.0f) {
        localY = -localY;
    }
    if (localZ < 0.0f) {
        localZ = -localZ;
    }

    if ((localX <= (f32)(s32)(data[0x3a] << 1)) && (localY <= (f32)(s32)(data[0x3b] << 1)) &&
        (localZ <= (f32)(s32)(data[0x3c] << 1))) {
        return 1;
    }
    return 0;
}

static void triggerEvalPlaneCrossing(GameObject* obj, GameObject* seqObj) {
    f32 ny;
    MmpTriggerPlaneState* state;
    s8 triggerState;
    u8* data;
    f32 planeBase;
    f32 normalY;
    f32 normalX;
    f32 normalZ;
    f32 nearX;
    f32 farX;
    f32 nearY;
    f32 farY;
    f32 nearZ;
    f32 farZ;
    f32 prodY;
    f32 prodZ;
    f32 nearDist;
    f32 farDist;
    f32 deltaX;
    f32 deltaY;
    f32 deltaZ;
    f32 t;
    Vec localPos;

    data = (u8*)obj->anim.placementData;
    state = (MmpTriggerPlaneState*)obj->extra;

    planeBase = state->planeD;
    normalZ = state->normalZ;
    nearZ = state->ptA[2];
    prodZ = normalZ * nearZ;
    normalX = state->normalX;
    nearX = state->ptA[0];
    normalY = state->normalY;
    nearY = state->ptA[1];
    prodY = normalY * nearY;
    nearDist = planeBase + (prodZ + (normalX * nearX + prodY));
    farZ = state->ptB[2];
    farX = state->ptB[0];
    farY = state->ptB[1];
    farDist = planeBase + (normalZ * farZ + (normalX * farX + normalY * farY));

    if (farDist < 0.0f) {
        triggerState = (nearDist < 0.0f) ? 2 : 1;
    } else {
        triggerState = (nearDist < 0.0f) ? -1 : -2;
    }

    if ((triggerState == 1) || (triggerState == -1)) {
        deltaX = farX - nearX;
        deltaY = farY - nearY;
        deltaZ = farZ - nearZ;
        ny = normalY * deltaY;
        t = (((-normalX * nearX - prodY) - prodZ) - planeBase) / ((ny + (normalX * deltaX)) + (normalZ * deltaZ));

        localPos.x = t * deltaX + nearX;
        localPos.y = t * deltaY + state->ptA[1];
        localPos.z = t * deltaZ + state->ptA[2];
        PSMTXMultVec(state->mtx, &localPos, &localPos);

        if ((localPos.x >= -state->clipHalfExtent) && (localPos.x <= state->clipHalfExtent) &&
            (localPos.y >= -state->clipHalfExtent) && (localPos.y <= state->clipHalfExtent)) {
            OSReport(sMoonrockTriggerIdentFormat, triggerState, ((ObjPlacement*)data)->ident);
            objInterpretSeq(obj, seqObj, triggerState, (int)farDist);
        }
    }
}

/* ObjPlacement.ident of the one vent that emits a debug OSReport */
#define MMP_GYSERVENT_DEBUG_IDENT 0x46a31

/* placement (WmSpiritPlaceMapData) byte offsets read at setup / per-frame */
#define MMP_GYSERVENT_PLACE_REACH 0x3a /* eruption reach scale byte */
#define MMP_GYSERVENT_PLACE_SPEED 0x3b /* per-frame speed byte */
#define MMP_GYSERVENT_PLACE_ROTX  0x3d /* rotX (low 6 bits) */
#define MMP_GYSERVENT_PLACE_ROTY  0x3e /* rotY */
#define MMP_GYSERVENT_PLACE_IDENT 0x14 /* ObjPlacement.ident */

void MmpGyservent_setup(GameObject* obj, MMPTriggerGeyserPlacement* placement) {
    MmpGyserventState* state;
    MatrixTransform xf;
    union {
        f32 m[16];
        f64 a8;
    } rotU;
    f32 outX;
    f32 outY;
    f32 outZ;
    f32 posMtx[16];
#define rotMtx rotU.m

    state = obj->extra;
    obj->anim.rotX = (s16)((placement->rotX & 0x3f) << 10);
    obj->anim.rotY = (s16)(placement->rotY << 8);
    obj->anim.rootMotionScale =
        obj->anim.modelInstance->rootMotionScaleBase * ((float)(u32)placement->reachScale / 16.0f);

    xf.rotX = obj->anim.rotX;
    xf.rotY = obj->anim.rotY;
    xf.rotZ = obj->anim.rotZ;
    xf.scale = 1.0f;
    xf.x = 0.0f;
    xf.y = 0.0f;
    xf.z = 0.0f;
    setMatrixFromObjectPos(posMtx, &xf);
    Matrix_TransformPoint(posMtx, 0.0f, 0.0f, 1.0f, &outX, &outY, &outZ);
    state->planeNormalX = outX;
    state->planeNormalY = outY;
    state->planeNormalZ = outZ;
    state->planeOffset = -(obj->anim.worldPosZ * outZ + (obj->anim.worldPosX * outX + obj->anim.worldPosY * outY));

    xf.rotX = (s16)-obj->anim.rotX;
    xf.rotY = (s16)-obj->anim.rotY;
    xf.rotZ = 0;
    xf.scale = 1.0f;
    xf.x = -obj->anim.worldPosX;
    xf.y = -obj->anim.worldPosY;
    xf.z = -obj->anim.worldPosZ;
    mtxRotateByVec3s(rotMtx, &xf);
    mtx44Transpose(rotMtx, &state->mtx[0][0]);

    state->reach = 100.0f * obj->anim.rootMotionScale;
    state->nearRadiusSq = (145.0f * obj->anim.rootMotionScale) * (145.0f * obj->anim.rootMotionScale);
    if (placement->base.ident == MMP_GYSERVENT_DEBUG_IDENT) {
        OSReport(sTriggerDebugTextBlock);
    }
#undef rotMtx
}

/* Classify the target against the two vertical endpoint cylinders used by trigger type 0x230. */
static f32 triggerRangeToModelScale(f32 range) {
    return range / 55.4256f;
}

void triggerEvalEndpointCylinders(GameObject* obj, GameObject* seqObj) {
    f32 distSqA;
    f32 dyB;
    f32 dyA;
    f32 speed;
    f32 t;
    f32 distSqB;
    bool nearEnd;
    s8 leg;
    MmpGyserventState* state;

    state = (obj)->extra;
    speed = (float)(s32)(((MMPTriggerGeyserPlacement*)obj->anim.placementData)->speed * 2);
    t = state->reachAX - (obj)->anim.worldPosX;
    dyA = state->reachAY - (obj)->anim.worldPosY;
    distSqA = state->reachAZ - (obj)->anim.worldPosZ;
    distSqA = t * t + distSqA * distSqA;
    t = state->reachBX - (obj)->anim.worldPosX;
    dyB = state->reachBY - (obj)->anim.worldPosY;
    distSqB = state->reachBZ - (obj)->anim.worldPosZ;
    distSqB = t * t + distSqB * distSqB;
    t = state->nearRadiusSq;
    if ((distSqB < t) && (((dyB < 0.0f) ? -dyB : dyB) < speed)) {
        nearEnd = false;
        if (distSqA < t) {
            dyA = (dyA < 0.0f) ? -dyA : dyA;
            if (dyA < speed) {
                nearEnd = true;
            }
        }
        leg = nearEnd ? 2 : 1;
    } else {
        nearEnd = false;
        if (distSqA < t) {
            dyA = (dyA < 0.0f) ? -dyA : dyA;
            if (dyA < speed) {
                nearEnd = true;
            }
        }
        leg = nearEnd ? -1 : -2;
    }
    objInterpretSeq(obj, seqObj, leg, distSqB);
}

/* Classify the target against the two endpoint spheres used by trigger type 0x4B. */
void triggerEvalEndpointSpheres(GameObject* obj, GameObject* seqObj) {
    MmpGyserventState* state;
    f32 dx0, dy0, dz0, d0;
    f32 dx1, dy1, dz1, d1;
    s8 cat;

    state = (MmpGyserventState*)(obj)->extra;

    dx0 = state->reachAX - (obj)->anim.worldPosX;
    dy0 = state->reachAY - (obj)->anim.worldPosY;
    dz0 = state->reachAZ - (obj)->anim.worldPosZ;
    d0 = dx0 * dx0 + dy0 * dy0 + dz0 * dz0;

    dx1 = state->reachBX - (obj)->anim.worldPosX;
    dy1 = state->reachBY - (obj)->anim.worldPosY;
    dz1 = state->reachBZ - (obj)->anim.worldPosZ;
    d1 = dx1 * dx1 + dy1 * dy1 + dz1 * dz1;

    if (d1 < state->nearRadiusSq) {
        cat = (d0 < state->nearRadiusSq) ? 2 : 1;
    } else {
        cat = (d0 < state->nearRadiusSq) ? -1 : -2;
    }
    objInterpretSeq(obj, seqObj, cat, d1);
}

#define TARGET_OBJGROUP                 0xf  /* player-target group; nearest object gets the trigger's sequence */
#define TRICKY_TARGET_OBJGROUP          0x32 /* nearest object searched from the tricky object */
#define TRICKY_TARGET_OBJGROUP_FALLBACK 0x31 /* fallback group when TRICKY_TARGET_OBJGROUP has none */
#define TRIGGER_ENVFX_A0                0x134
#define TRIGGER_ENVFX_A1                0x135
#define TRIGGER_ENVFX_A2                0x142
#define TRIGGER_ENVFX_B0                0x136
#define TRIGGER_ENVFX_B1                0x137
#define TRIGGER_ENVFX_B2                0x143
#define TRIGGER_SFLAG_ENTERED           0x01 /* enter-direction command list has run (latch) */
#define TRIGGER_SFLAG_EXITED            0x02 /* exit-direction command list has run (latch) */
#define TRIGGER_SFLAG_DISABLED          0x04 /* trigger's game bit was already set at init: fire enter once */
#define TRIGGER_CMD_ON_ENTER            0x01 /* run when activation direction is enter (legCode > 0) */
#define TRIGGER_CMD_ON_EXIT             0x02 /* run when activation direction is exit (legCode < 0) */
#define TRIGGER_CMD_ONCE_ENTER          0x04 /* enter leg runs only once (latched vs SFLAG_ENTERED) */
#define TRIGGER_CMD_ONCE_EXIT           0x08 /* exit leg runs only once (latched vs SFLAG_EXITED) */
#define TRIGGER_CMD_UNCONDITIONAL       0x10 /* ignore enter/exit gating */
#define TRIGGER_CMD_OVERRIDE_DISABLED   0x20 /* run even when SFLAG_DISABLED is set */
#define TRIGGER_SFLAG_SEED_TARGET       0x40 /* first hit: seed target position from current, not previous */

typedef enum TriggerCommandOpcode {
    TRIGGER_COMMAND_PLAYER_STATE = 0x01,
    TRIGGER_COMMAND_MUSIC_ACTION = 0x03,
    TRIGGER_COMMAND_SFX = 0x04,
    TRIGGER_COMMAND_UNUSED_05 = 0x05,
    TRIGGER_COMMAND_CAMERA_ACTION = 0x06,
    TRIGGER_COMMAND_RENDER_CONTROL = 0x08,
    TRIGGER_COMMAND_ENVFX_ACTION = 0x0A,
    TRIGGER_COMMAND_SEQUENCE = 0x0B,
    TRIGGER_COMMAND_ACTIVATE_TRIGGER = 0x0C,
    TRIGGER_COMMAND_LIGHTING_ACTION = 0x0D,
    TRIGGER_COMMAND_SET_PLAYER_MODEL = 0x10,
    TRIGGER_COMMAND_SET_TRICKY_TALK = 0x11,
    TRIGGER_COMMAND_UPDATE_GAME_BIT = 0x12,
    TRIGGER_COMMAND_SHOW_OBJECT_GROUP = 0x13,
    TRIGGER_COMMAND_HIDE_OBJECT_GROUP = 0x14,
    TRIGGER_COMMAND_REQUIRE_TEXTURES = 0x15,
    TRIGGER_COMMAND_FREE_TEXTURES = 0x16,
    TRIGGER_COMMAND_SET_MAP_ACT = 0x18,
    TRIGGER_COMMAND_SHOW_MAP_OBJECT_GROUP = 0x1A,
    TRIGGER_COMMAND_HIDE_MAP_OBJECT_GROUP = 0x1B,
    TRIGGER_COMMAND_ENVIRONMENT = 0x1C,
    TRIGGER_COMMAND_SET_ITEM_AVAILABILITY = 0x1D,
    TRIGGER_COMMAND_SET_OTHER_MAP_ACT = 0x1E,
    TRIGGER_COMMAND_SAVE_POINT = 0x1F,
    TRIGGER_COMMAND_CHANGE_MAP_LAYER = 0x20,
    TRIGGER_COMMAND_TOGGLE_GAME_BIT_FIELD = 0x21,
    TRIGGER_COMMAND_TOGGLE_OBJECT_GROUP = 0x22,
    TRIGGER_COMMAND_RESTART_POINT = 0x23,
    TRIGGER_COMMAND_TRICKY = 0x26,
    TRIGGER_COMMAND_LOAD_MAP = 0x27,
    TRIGGER_COMMAND_UNLOAD_MAP = 0x28,
    TRIGGER_COMMAND_LOCK_LEVEL = 0x2A,
    TRIGGER_COMMAND_UNLOCK_LEVEL = 0x2B,
    TRIGGER_COMMAND_SET_SEQUENCE_SCALE = 0x2C,
    TRIGGER_COMMAND_DIALOGUE = 0x2D,
    TRIGGER_COMMAND_DEFRAG_TEXTURES = 0x2E,
    TRIGGER_COMMAND_ADD_TIMER_SECONDS = 0x2F,
} TriggerCommandOpcode;

static inline u32 triggerCommandGetArgument(TriggerCommand* command) {
    return (command->param1 << 8) | command->param2;
}

static inline void triggerBitsSet(u16 argument) {
    s32 gameBitId;
    u32 value;

    gameBitId = argument & 0x3fff;
    argument >>= 14;

    value = mainGetBit(gameBitId);
    if (argument == 0) {
        value = 0;
    } else if (argument == 1) {
        value = 0xffffffff;
    } else if (argument == 2) {
        value = ~value;
    }
    mainSetBits(gameBitId, value);
}

static inline void triggerBitsToggle(u16 argument) {
    s32 gameBitId;
    u32 value;

    gameBitId = argument & 0x1fff;
    argument >>= 13;

    value = mainGetBit(gameBitId);
    value ^= 1 << argument;
    mainSetBits(gameBitId, value);
}

static inline void triggerTextureLoad(u16 tableId) {
    s32* table;
    s32* textureId;
    s32 id;
    Texture* texture;

    table = getTablesBinEntry(tableId + 2);
    if (table != NULL) {
        for (textureId = table; (id = *textureId) != -1; textureId++) {
            texture = getLoadedTexture(id);
            if (texture == NULL) {
                crash(0x32, 3, 0, *textureId, 0, 0, 0, 0);
            }
        }
    }
}

static inline void triggerTextureFree(u16 tableId) {
    s32* table;
    s32* textureId;
    s32 id;
    Texture* texture;

    table = getTablesBinEntry(tableId + 2);
    if (table != NULL) {
        for (textureId = table; (id = *textureId) != -1; textureId++) {
            texture = getLoadedTexture(id);
            if (texture != NULL) {
                textureFree(texture);
            }
        }
    }
}

void objInterpretSeq(GameObject* obj, GameObject* seqObj, s8 legCode, int range) {
    char* desc = (char*)&gTriggerObjDescriptor;
    TriggerState* state = (TriggerState*)obj->extra;
    TriggerPlacement* placement = (TriggerPlacement*)obj->anim.placementData;
    TriggerCommand* command;
    u8 i;
    u8 flags;
    u8 status;

    command = placement->commands;
    i = 0;
    for (; i < ARRAY_SIZE(placement->commands); i++, command++) {
        if (command->id == 0) {
            continue;
        }
        status = state->status;
        if ((status & TRIGGER_SFLAG_DISABLED) != 0 && (command->condition & TRIGGER_CMD_OVERRIDE_DISABLED) == 0) {
            continue;
        }
        flags = command->condition;
        if ((flags & TRIGGER_CMD_UNCONDITIONAL) == 0) {
            if (legCode == 1) {
                if ((flags & TRIGGER_CMD_ON_ENTER) == 0) {
                    continue;
                }
                if ((status & TRIGGER_SFLAG_ENTERED) != 0 && (flags & TRIGGER_CMD_ONCE_ENTER) == 0) {
                    continue;
                }
            } else if (legCode == -1) {
                if ((flags & TRIGGER_CMD_ON_EXIT) == 0) {
                    continue;
                }
                if ((status & TRIGGER_SFLAG_EXITED) != 0 && (flags & TRIGGER_CMD_ONCE_EXIT) == 0) {
                    continue;
                }
            } else {
                continue;
            }
        } else if ((flags & TRIGGER_CMD_ON_ENTER) != 0) {
            if (legCode < 0) {
                continue;
            }
        } else if ((flags & TRIGGER_CMD_ON_EXIT) != 0 && legCode > 0) {
            continue;
        }
        switch (command->id) {
        case TRIGGER_COMMAND_PLAYER_STATE:
            switch (command->param1) {
            case 0:
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
                break;
            case 8: {
                GameObject* player = Obj_GetPlayerObject();
                if (player != NULL) {
                    playerSetStateValue(player, 1, 0.0f);
                }
                break;
            }
            case 9: {
                GameObject* player = Obj_GetPlayerObject();
                if (player != NULL) {
                    playerSetStateValue(player, 10, 0.0f);
                }
                break;
            }
            case 10: {
                GameObject* player = Obj_GetPlayerObject();
                if (player != NULL) {
                    playerSetStateValue(player, 0xb, 0.0f);
                }
                break;
            }
            case 0xb: {
                GameObject* player = Obj_GetPlayerObject();
                if (player != NULL) {
                    playerSetStateValue(player, 1, 14.0f);
                }
                break;
            }
            }
            break;
        case TRIGGER_COMMAND_SFX:
            if (legCode >= 0) {
                Sfx_PlayFromObject(obj, (u16)triggerCommandGetArgument(command));
            } else {
                Sfx_StopFromObject(obj, (u16)triggerCommandGetArgument(command));
            }
            break;
        case TRIGGER_COMMAND_CAMERA_ACTION:
            (*gCameraInterface)->loadTriggeredCamAction(command->param1, command->param2, 0);
            break;
        case TRIGGER_COMMAND_RENDER_CONTROL:
            switch (command->param1) {
            case 0:
                if (command->param2 > 1) {
                    command->param2 = 1;
                }
                setDrawCloudsAndLights(command->param2);
                break;
            case 1:
                if (command->param2 > 1) {
                    command->param2 = 1;
                }
                setDisableAntiAlias(command->param2);
                break;
            case 2:
                if (command->param2 > 1) {
                    command->param2 = 1;
                }
                setDrawLights(command->param2);
                break;
            case 3:
                if (command->param2 > 1) {
                    command->param2 = 1;
                }
                (*gCloudActionInterface)->func09Nop(command->param2);
                break;
            case 4:
                (*gPlayerShadowInterface)->setMode(command->param2);
                break;
            case 5:
                waterFxSetDisabled(command->param2);
                break;
            case 6:
                if (command->param2 != 0) {
                    skySetSlotFlag80(7, 1);
                } else {
                    skySetSlotFlag80(7, 0);
                }
                break;
            case 7:
                if (command->param2 != 0) {
                    setRenderFlag20000(1);
                } else {
                    setRenderFlag20000(0);
                }
                break;
            case 8:
                if (command->param2 != 0) {
                    Rcp_EnableHeatEffect();
                } else {
                    Rcp_DisableHeatEffect();
                }
                break;
            case 9:
                skySetLightIndex(skyGetCurrentLightIndex() ^ 1, (f32)(u32)command->param2);
                break;
            case 10:
                skySetLightIndex(0, (f32)(u32)command->param2);
                break;
            case 0xb:
                skySetLightIndex(1, (f32)(u32)command->param2);
                break;
            }
            break;
        case TRIGGER_COMMAND_UNUSED_05:
            if (!state->rangeSq) {
                break;
            }
            if (state->rangeSq) {
                break;
            }
            break;
        case TRIGGER_COMMAND_ENVFX_ACTION:
            getEnvfxAct(obj, seqObj, (u16)triggerCommandGetArgument(command), range);
            OSReport(desc + 0x68, (int)obj->anim.classId, triggerCommandGetArgument(command), range);
            break;
        case TRIGGER_COMMAND_LIGHTING_ACTION:
            getLActions(obj, seqObj, (u16)triggerCommandGetArgument(command), legCode, range, 0);
            break;
        case TRIGGER_COMMAND_SEQUENCE: {
            GameObject* target;

            switch (command->param1) {
            case 0:
            case 3:
                target = objGetNearestTypeTo(TARGET_OBJGROUP, obj, 0);
                if (target != NULL) {
                    (*gObjectTriggerInterface)->runSequence(command->param2, target, -1);
                }
                break;
            case 1:
                (*gObjectTriggerInterface)->setFlag(command->param2, 1);
                break;
            case 2:
                (*gObjectTriggerInterface)->setFlag(command->param2, 0);
                break;
            }
            break;
        }
        case TRIGGER_COMMAND_ACTIVATE_TRIGGER: {
            GameObject** objects;
            GameObject* trigger;
            TriggerPlacement* triggerPlacement;
            int count;
            int first;
            u16 triggerId;

            triggerId = triggerCommandGetArgument(command);
            objects = ObjList_GetObjects(&first, &count);
            for (; first < count; first++) {
                trigger = objects[first];
                triggerPlacement = (TriggerPlacement*)trigger->anim.placementData;
                if (triggerPlacement == NULL) {
                    continue;
                }
                switch (triggerPlacement->base.objectId) {
                case 0x4b:
                case 0x4c:
                case 0x4d:
                case 0x4e:
                case 0x4f:
                case 0x50:
                case 0x54:
                case 0x230:
                    if (triggerPlacement->triggerId == triggerId) {
                        objInterpretSeq(trigger, seqObj, legCode, range);
                    }
                    break;
                }
            }
            break;
        }
        case TRIGGER_COMMAND_SET_PLAYER_MODEL:
            Obj_SetActiveModelIndex(Obj_GetPlayerObject(), command->param1);
            break;
        case TRIGGER_COMMAND_UPDATE_GAME_BIT: {
            triggerBitsSet(triggerCommandGetArgument(command));
            break;
        }
        case TRIGGER_COMMAND_TOGGLE_GAME_BIT_FIELD: {
            triggerBitsToggle(triggerCommandGetArgument(command));
            break;
        }
        case TRIGGER_COMMAND_SHOW_OBJECT_GROUP:
            (*gMapEventInterface)
                ->setObjGroupStatus((int)obj->anim.mapEventSlot, triggerCommandGetArgument(command), 1);
            break;
        case TRIGGER_COMMAND_LOAD_MAP: {
            int mapId = triggerCommandGetArgument(command);

            mapLoadDataFiles(mapId);
            loadModelAndAnimTabs();
            OSReport(desc + 0xa8, mapId);
            break;
        }
        case TRIGGER_COMMAND_UNLOAD_MAP: {
            int mapId = triggerCommandGetArgument(command);

            mapUnload(mapId, 0x20000000);
            OSReport(desc + 0xc4, mapId);
            break;
        }
        case TRIGGER_COMMAND_DEFRAG_TEXTURES:
            defragMemory(0);
            break;
        case TRIGGER_COMMAND_LOCK_LEVEL:
            lockLevel(command->param1, command->param2);
            OSReport(desc + 0xe0, command->param1, command->param2);
            break;
        case TRIGGER_COMMAND_UNLOCK_LEVEL:
            unlockLevel(command->param1, command->param2, 0);
            OSReport(desc + 0x114, command->param1, command->param2);
            break;
        case TRIGGER_COMMAND_ADD_TIMER_SECONDS: {
            GameObject* timer = objGetNearestTypeTo(TIMER_OBJECT_GROUP, obj, 0);

            if (timer != NULL) {
                timer_addDuration(timer, command->param2 * 0x3c);
            }
            break;
        }
        case TRIGGER_COMMAND_HIDE_OBJECT_GROUP:
            (*gMapEventInterface)
                ->setObjGroupStatus((int)obj->anim.mapEventSlot, triggerCommandGetArgument(command), 0);
            break;
        case TRIGGER_COMMAND_TOGGLE_OBJECT_GROUP: {
            int groupId = triggerCommandGetArgument(command);
            u8 groupStatus = (u8)(*gMapEventInterface)->getObjGroupStatus((int)obj->anim.mapEventSlot, groupId);

            (*gMapEventInterface)->setObjGroupStatus((int)obj->anim.mapEventSlot, groupId, groupStatus ^ 1);
            break;
        }
        case TRIGGER_COMMAND_REQUIRE_TEXTURES: {
            triggerTextureLoad(triggerCommandGetArgument(command));
            break;
        }
        case TRIGGER_COMMAND_FREE_TEXTURES: {
            triggerTextureFree(triggerCommandGetArgument(command));
            break;
        }
        case TRIGGER_COMMAND_SET_MAP_ACT:
            (*gMapEventInterface)->setMapAct((int)obj->anim.mapEventSlot, triggerCommandGetArgument(command));
            break;
        case TRIGGER_COMMAND_SHOW_MAP_OBJECT_GROUP:
            (*gMapEventInterface)->setObjGroupStatus(command->param2, command->param1, 1);
            break;
        case TRIGGER_COMMAND_HIDE_MAP_OBJECT_GROUP:
            (*gMapEventInterface)->setObjGroupStatus(command->param2, command->param1, 0);
            break;
        case TRIGGER_COMMAND_SET_OTHER_MAP_ACT:
            (*gMapEventInterface)->setMapAct(command->param2, command->param1);
            break;
        case TRIGGER_COMMAND_SET_TRICKY_TALK:
            mainSetBits(GAMEBIT_TrickyTalk, triggerCommandGetArgument(command));
            break;
        case TRIGGER_COMMAND_SAVE_POINT: {
            GameObject* player = Obj_GetPlayerObject();
            s16 angleDiff = obj->anim.rotX - (u16)player->anim.rotX;
            int angle;

            if (angleDiff > 0x8000) {
                angleDiff = (angleDiff - 0x10000) + 1;
            }
            if (angleDiff < -0x8000) {
                angleDiff = (angleDiff + 0x10000) - 1;
            }
            if (angleDiff >= 0) {
                angle = angleDiff;
            } else {
                angle = -angleDiff;
            }
            if (angle > 0x4000) {
                (*gMapEventInterface)
                    ->savePoint(&obj->anim.localPosX, (int)(s16)(obj->anim.rotX + 0x8000), command->param2,
                                getCurMapLayer());
            } else {
                (*gMapEventInterface)
                    ->savePoint(&obj->anim.localPosX, (int)obj->anim.rotX, command->param2, getCurMapLayer());
            }
            break;
        }
        case TRIGGER_COMMAND_CHANGE_MAP_LAYER:
            if (command->param1 == 0) {
                goToNextMapLayer();
            } else {
                goToPrevMapLayer();
            }
            break;
        case TRIGGER_COMMAND_RESTART_POINT:
            switch (command->param1) {
            case 0:
                (*gMapEventInterface)
                    ->restartPoint((void*)&obj->anim.localPos, (int)obj->anim.rotX, getCurMapLayer(), 0);
                break;
            case 1:
                (*gMapEventInterface)->clearRestartPoint();
                break;
            case 2:
                (*gMapEventInterface)->gotoRestartPoint();
                break;
            case 3:
                (*gMapEventInterface)
                    ->restartPoint((void*)&obj->anim.localPos, (int)obj->anim.rotX, getCurMapLayer(), 1);
                break;
            }
            break;
        case TRIGGER_COMMAND_TRICKY: {
            GameObject* tricky = getTrickyObject();

            if (tricky != NULL) {
                switch (command->param1) {
                case 0:
                    TRICKY_INTERFACE(tricky)->requestRecall(tricky);
                    break;
                case 1:
                    Obj_FreeObject(getTrickyObject());
                    break;
                case 2: {
                    GameObject* target = objGetNearestTypeTo(TRICKY_TARGET_OBJGROUP, tricky, 0);
                    if (target == NULL) {
                        target = objGetNearestTypeTo(TRICKY_TARGET_OBJGROUP_FALLBACK, tricky, 0);
                    }
                    if (target != NULL) {
                        TRICKY_INTERFACE(tricky)->requestMoveToObject(tricky, target);
                    }
                    break;
                }
                case 3:
                    mainSetBits(GAMEBIT_NoBallsAllowed, 0);
                    break;
                case 4:
                    mainSetBits(GAMEBIT_NoBallsAllowed, 1);
                    break;
                }
            }
            break;
        }
        case TRIGGER_COMMAND_ENVIRONMENT:
            switch (command->param1) {
            case 0:
                mainSetBits(GAMEBIT_ENV_disableDayFX1, command->param2 == 0);
                break;
            case 1:
                mainSetBits(GAMEBIT_ENV_disableDayFX2, command->param2 == 0);
                break;
            case 2:
                mainSetBits(GAMEBIT_ENV_disableDayFX3, command->param2 == 0);
                break;
            case 3:
                switch (command->param2) {
                case 0:
                    mainSetBits(GAMEBIT_ENV_isOutdoor, 1);
                    getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), TRIGGER_ENVFX_A0, 0);
                    getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), TRIGGER_ENVFX_A1, 0);
                    getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), TRIGGER_ENVFX_A2, 0);
                    break;
                case 1:
                    mainSetBits(GAMEBIT_ENV_isOutdoor, 0);
                    getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), TRIGGER_ENVFX_A0, 0);
                    getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), TRIGGER_ENVFX_A1, 0);
                    getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), TRIGGER_ENVFX_A2, 0);
                    skyRefreshPlayerEnvFx();
                    break;
                case 2:
                    mainSetBits(GAMEBIT_ENV_isOutdoor, 1);
                    getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), TRIGGER_ENVFX_B0, 0);
                    getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), TRIGGER_ENVFX_B1, 0);
                    getEnvfxAct(Obj_GetPlayerObject(), Obj_GetPlayerObject(), TRIGGER_ENVFX_B2, 0);
                    break;
                }
                break;
            }
            break;
        case TRIGGER_COMMAND_SET_ITEM_AVAILABILITY:
            if (command->param1 != 0) {
                mainSetBits(GAMEBIT_ITEM_DinoHorn_Disabled, 0);
                mainSetBits(GAMEBIT_ITEM_Firefly_Disabled, 0);
                mainSetBits(GAMEBIT_Tricky_CantFeed, 0);
            } else {
                mainSetBits(GAMEBIT_ITEM_DinoHorn_Disabled, 1);
                mainSetBits(GAMEBIT_ITEM_Firefly_Disabled, 1);
                mainSetBits(GAMEBIT_Tricky_CantFeed, 1);
            }
            break;
        case TRIGGER_COMMAND_SET_SEQUENCE_SCALE:
            *(f32*)seqObj->extra = 0.1f * (f32)(s32)triggerCommandGetArgument(command);
            break;
        case TRIGGER_COMMAND_DIALOGUE:
            if (Obj_GetPlayerObject() != NULL) {
                (*gGameUIInterface)->showNpcDialogue(triggerCommandGetArgument(command), 0x14, 0x8c, 1);
            } else if ((void*)getArwing() != NULL) {
                headDisplayOpen(triggerCommandGetArgument(command));
            }
            break;
        }
    }
    if (legCode > 0) {
        state->status |= TRIGGER_SFLAG_ENTERED;
        mainSetBits(state->gameBit, 1);
    } else if (legCode < 0) {
        state->status |= TRIGGER_SFLAG_EXITED;
    }
}

int Trigger_getExtraSize(void) {
    return 0xac;
}
int Trigger_getObjectTypeId(void) {
    return 0x0;
}

void Trigger_free(GameObject* obj) {
    u8 i;
    TriggerPlacement* placement;
    TriggerCommand* command;

    placement = (TriggerPlacement*)obj->anim.placementData;
    command = placement->commands;
    i = 0;

    while (i < ARRAY_SIZE(placement->commands)) {
        if ((command->condition & (TRIGGER_CMD_ON_ENTER | TRIGGER_CMD_ON_EXIT)) != 0 &&
            command->id != TRIGGER_COMMAND_MUSIC_ACTION && command->id == TRIGGER_COMMAND_SFX) {
            Sfx_StopFromObject(obj, (u16)triggerCommandGetArgument(command));
        }
        i++;
        command++;
    }
}

/* group owned by another DLL, queried here */

/* Env-effect ids co-activated by the type-3 command (command->param2 sub-case); the A set
   runs for sub-cases 0/1, the B set for sub-case 2. Opaque distinct roles per index. */

/*
 * TriggerState+0 status byte (`state->status`). See objInterpretSeq / Trigger_hitDetect.
 */

/*
 * TriggerCommand.condition gates whether a command runs for a given activation leg.
 */

void Trigger_render(void) {
}

void Trigger_hitDetect(GameObject* obj) {
    u8* state = (obj)->extra;
    u8* def = (u8*)(obj)->anim.placementData;
    GameObject* triggerObj;
    GameObject* trickyObj;
    GameObject* target;
    int ok;
    int ok2;
    int inside;
    int wasInside;
    int i;
    u8 targetKind;
    f32 dist[1];

    dist[0] = 200.0f;
    if (((TriggerPlacement*)def)->triggerId <= 0 || ((TriggerPlacement*)def)->base.objectId == 0xf4) {
        triggerObj = Obj_GetPlayerObject();
        if (triggerObj != NULL) {
            inside = (int)playerGetFocusObject(triggerObj);
            if ((void*)inside != NULL) {
                triggerObj = (GameObject*)inside;
            }
        } else {
            triggerObj = getArwing();
        }
        trickyObj = getTrickyObject();
        if (triggerObj != NULL || trickyObj != NULL) {
            if ((*state & TRIGGER_SFLAG_DISABLED) != 0) {
                objInterpretSeq(obj, triggerObj, 1, 0);
                *state &= ~TRIGGER_SFLAG_DISABLED;
                *state |= TRIGGER_SFLAG_ENTERED;
            } else {
                ok = 1;
                targetKind = ((TriggerPlacement*)def)->target;
                if (targetKind > 2) {
                    target = objGetNearestTypeTo(targetKind - 1, obj, dist);
                    if (target == NULL) {
                        ok = 0;
                    }
                } else {
                    switch (targetKind) {
                    case 0:
                        target = triggerObj;
                        if (triggerObj == NULL) {
                            ok = 0;
                        }
                        break;
                    case 1:
                        target = trickyObj;
                        if (trickyObj == NULL) {
                            ok = 0;
                        }
                        break;
                    case 2:
                        target = (GameObject*)(*gCameraInterface)->getCamera();
                        break;
                    }
                }
                if (ok) {
                    if ((*state & TRIGGER_SFLAG_SEED_TARGET) != 0) {
                        switch (((TriggerPlacement*)def)->target) {
                        case 2:
                            ((TriggerState*)state)->targetPosX = target->anim.worldPosX;
                            ((TriggerState*)state)->targetPosY = target->anim.worldPosY;
                            ((TriggerState*)state)->targetPosZ = target->anim.worldPosZ;
                            break;
                        case 0:
                        case 1:
                            ((TriggerState*)state)->targetPosX = target->anim.previousWorldPosX;
                            ((TriggerState*)state)->targetPosY = target->anim.previousWorldPosY;
                            ((TriggerState*)state)->targetPosZ = target->anim.previousWorldPosZ;
                            break;
                        default:
                            ((TriggerState*)state)->targetPosX = target->anim.previousLocalPosX;
                            ((TriggerState*)state)->targetPosY = target->anim.previousLocalPosY;
                            ((TriggerState*)state)->targetPosZ = target->anim.previousLocalPosZ;
                            break;
                        }
                        *state &= ~TRIGGER_SFLAG_SEED_TARGET;
                    } else {
                        ((TriggerState*)state)->targetPosX = ((TriggerState*)state)->prevTargetPosX;
                        ((TriggerState*)state)->targetPosY = ((TriggerState*)state)->prevTargetPosY;
                        ((TriggerState*)state)->targetPosZ = ((TriggerState*)state)->prevTargetPosZ;
                    }
                    switch (((TriggerPlacement*)def)->target) {
                    case 0:
                    case 1:
                    case 2:
                        ((TriggerState*)state)->prevTargetPosX = target->anim.worldPosX;
                        ((TriggerState*)state)->prevTargetPosY = target->anim.worldPosY;
                        ((TriggerState*)state)->prevTargetPosZ = target->anim.worldPosZ;
                        break;
                    default:
                        ((TriggerState*)state)->prevTargetPosX = target->anim.localPosX;
                        ((TriggerState*)state)->prevTargetPosY = target->anim.localPosY;
                        ((TriggerState*)state)->prevTargetPosZ = target->anim.localPosZ;
                        break;
                    }
                }
                switch (((TriggerPlacement*)def)->base.objectId) {
                case 0x4b:
                    if (ok) {
                        ((void (*)(GameObject*, GameObject*))triggerEvalEndpointSpheres)(obj, target);
                    }
                    break;
                case 0x230:
                    if (ok) {
                        ((void (*)(GameObject*, GameObject*))triggerEvalEndpointCylinders)(obj, target);
                    }
                    break;
                case 0x4c:
                    ok2 = 1;
                    if (((TriggerState*)state)->gateBits[0] != -1 &&
                        mainGetBit(((TriggerState*)state)->gateBits[0]) == 0u) {
                        ok2 = 0;
                    }
                    if (ok2 && ok) {
                        triggerEvalPlaneCrossing(obj, target);
                    }
                    break;
                case 0x4e:
                    ((TriggerState*)state)->timer = *(int*)&((TriggerState*)state)->timer + framesThisStep;
                    if (((TriggerState*)state)->timer >= (u32)((TriggerPlacement*)def)->triggerDelayFrames) {
                        objInterpretSeq(obj, 0, 1, 0);
                    }
                    break;
                case 0x4d:
                    if (ok) {
                        TriggerState* st = (TriggerState*)(obj)->extra;
                        inside = ((int (*)(GameObject*, f32*))triggerPointInBox)(obj, &st->prevTargetPosX);
                        wasInside = ((int (*)(GameObject*, f32*))triggerPointInBox)(obj, &st->targetPosX);
                        if (inside != 0) {
                            if (wasInside == 0) {
                                objInterpretSeq(obj, target, 1, 0);
                            } else {
                                objInterpretSeq(obj, target, 2, 0);
                            }
                        } else if (wasInside != 0) {
                            objInterpretSeq(obj, target, -1, 0);
                        } else {
                            objInterpretSeq(obj, target, -2, 0);
                        }
                    }
                    break;
                case 0x50:
                    objInterpretSeq(obj, triggerObj, 1, 0);
                    if (TriggSetpShouldUnload() != 0) {
                        Obj_FreeObject(obj);
                    }
                    break;
                case 0x54:
                    ok = 1;
                    i = 0;
                    while (i < 4 && ok) {
                        s16 gate = ((TriggerState*)state)->gateBits[i];
                        if (gate != -1 && mainGetBit(gate) == 0u) {
                            ok = 0;
                        }
                        i++;
                    }
                    if (ok && ((TriggerState*)state)->flags8A.bit7 == 0) {
                        ((TriggerState*)state)->flags8A.bit7 = 1;
                        objInterpretSeq(obj, triggerObj, 1, 0);
                    }
                    if (!ok) {
                        ((TriggerState*)state)->flags8A.bit7 = 0;
                    }
                    break;
                case 0xf4:
                    if (ok) {
                        ((void (*)(GameObject*, GameObject*))triggerEvalCurveLoop)(obj, target);
                    }
                    break;
                }
            }
        }
    }
}

void Trigger_update(void) {
}

void Trigger_init(GameObject* obj, u8* params) {
    u8* state;
    f32 range;
    TriggerPlacement* placement = (TriggerPlacement*)params;

    objSetSlot(obj, 0x28);
    state = obj->extra;
    switch (((TriggerPlacement*)params)->base.objectId) {
    case 0x4b:
        range = (f32)(s32)(((TriggerPlacement*)params)->size[0] * 2);
        ((TriggerState*)state)->rangeSq = range * range;
        obj->anim.rotZ = 0;
        obj->anim.rotY = 0;
        obj->anim.rotX = (s16)(((TriggerPlacement*)params)->rot[0] << 8);
        obj->anim.rootMotionScale = triggerRangeToModelScale(range);
        break;
    case 0x4c:
        ((TriggerState*)state)->gateBits[0] = ((TriggerPlacement*)params)->gateBitSrc[0];
        MmpGyservent_setup(obj, (MMPTriggerGeyserPlacement*)params);
        break;
    case 0x230:
        ((TriggerState*)state)->rangeSq = (f32)(s32)(((TriggerPlacement*)params)->size[0] * 2);
        ((TriggerState*)state)->rangeSq = ((TriggerState*)state)->rangeSq * ((TriggerState*)state)->rangeSq;
        break;
    case 0x4d:
        obj->anim.rotX = (s16)(((TriggerPlacement*)params)->rot[0] << 8);
        obj->anim.rotY = (s16)(((TriggerPlacement*)params)->rot[1] << 8);
        obj->anim.rotZ = 0;
        break;
    case 0x54:
        ((TriggerState*)state)->gateBits[0] = ((TriggerPlacement*)params)->gateBitSrc[0];
        ((TriggerState*)state)->gateBits[1] = ((TriggerPlacement*)params)->gateBitSrc[1];
        ((TriggerState*)state)->gateBits[2] = ((TriggerPlacement*)params)->gateBitSrc[2];
        ((TriggerState*)state)->gateBits[3] = ((TriggerPlacement*)params)->gateBitSrc[3];
        ((TriggerState*)state)->flags8A.bit7 = 0;
        break;
    case 0x4e:
    case 0x4f:
    case 0x50:
        break;
    case 0xf4:
        break;
    default:
        break;
    }
    ((TriggerState*)state)->gameBit = ((TriggerPlacement*)params)->gameBitSrc;
    if ((int)mainGetBit(((TriggerState*)state)->gameBit) == 1) {
        state[0] = (u8)(state[0] | TRIGGER_SFLAG_DISABLED);
    }
    state[0] = (u8)(state[0] | TRIGGER_SFLAG_SEED_TARGET);
}

void Trigger_release(void) {
}

void Trigger_initialise(void) {
}
