#ifndef MAIN_OBJANIM_INTERNAL_H_
#define MAIN_OBJANIM_INTERNAL_H_

#include "global.h"
#include "ghidra_import.h"
#include "main/objanim.h"
#include "main/objhits_types.h"

typedef struct ObjHitReactState ObjHitReactState;
typedef struct ObjHitReactMoveEntry ObjHitReactMoveEntry;

extern const f32 gObjAnimProgressOne;
extern const f32 gObjAnimProgressZero;
extern const f32 gObjAnimEventStepScale;
extern const f32 gObjAnimEventFrameScale;
extern const f32 gObjAnimSetMoveProgressMax;
extern const f32 gObjAnimMoveStepScaleMin;

typedef struct ObjAnimHitReactRow {
  u8 pad00[0x16];
  s8 entryIndex;
  u8 pad17;
} ObjAnimHitReactRow;

typedef struct ObjAnimFrameCommand {
  u8 opcode;
  u8 frameLength;
} ObjAnimFrameCommand;

typedef s16 ObjAnimPackedEvent;

#define OBJANIM_DEF_FLAG_CACHED_MOVES 0x40
#define OBJANIM_DEF_FLAG_SKELETON_HITBOXES 0x1000
/* Object allocated & owns its own placementData copy (must free it). Set after
   mmAlloc+memcpy into placementData; gates the placementData mm_free in Obj_FreeObject. */
#define OBJANIM_FLAG_OWNS_PLACEMENT_DATA 0x2000
#define OBJANIM_FLAG_HIDDEN 0x4000
/* Bits copied from set-move flags into ObjAnimState during move advancement. */
#define OBJANIM_MOVE_CONTROL_HOLD_EVENT_COUNTDOWN 0x02
#define OBJANIM_MOVE_CONTROL_REFRESH_SAVED_STEP 0x08
#define OBJANIM_MOVE_CONTROL_SKIP_EVENT_COUNTDOWN 0x10
#define OBJANIM_MOVE_CACHE_SLOT_COUNT 2
#define OBJANIM_MISSING_MOVE_ID -1
#define OBJANIM_BLEND_MOVE_INDEX_INVALID -1
#define OBJANIM_CACHED_MOVE_DATA_OFFSET 0x80
#define OBJANIM_MOVE_ROOT_CURVE_OFFSET 4
#define OBJANIM_FRAME_COMMANDS_OFFSET 6
#define OBJANIM_FRAME_TYPE_CLAMPED 0
#define OBJANIM_FRAME_TYPE_MASK 0xF0
#define OBJANIM_FRAME_STEP_MASK 0x0F
#define OBJANIM_EVENT_COUNTDOWN_RESET 0x4000
#define OBJANIM_EVENT_FRAME_MASK 0x1FF
#define OBJANIM_EVENT_ID_SHIFT 9
#define OBJANIM_EVENT_ID_MASK 0x7F
#define OBJANIM_EVENT_ID_NONE 0x7F
#define OBJANIM_EVENT_TRIGGER_CAPACITY 8
/* Event-scan flags: wrapped progress and reverse playback combine as a bitfield. */
#define OBJANIM_EVENT_SCAN_FORWARD 0
#define OBJANIM_EVENT_SCAN_WRAPPED 0x01
#define OBJANIM_EVENT_SCAN_REVERSE 0x02
#define OBJANIM_EVENT_SCAN_REVERSE_WRAPPED \
  (OBJANIM_EVENT_SCAN_WRAPPED | OBJANIM_EVENT_SCAN_REVERSE)
#define OBJANIM_MOVE_GROUP_SHIFT 8
#define OBJANIM_MOVE_INDEX_MASK 0xFF
#define OBJANIM_MOVE_GROUP_BASE_COUNT 0x3E
#define OBJANIM_ROOT_CURVE_AXIS_DATA_OFFSET 6
#define OBJANIM_ROOT_CURVE_Z_AXIS_OFFSET 10
#define OBJANIM_ROOT_CURVE_AXIS_COUNT 6
#define OBJANIM_ROOT_CURVE_TRANSLATION_AXIS_COUNT 3
#define OBJANIM_ROOT_CURVE_AXIS_X 0
#define OBJANIM_ROOT_CURVE_AXIS_Y 1
#define OBJANIM_ROOT_CURVE_AXIS_Z 2
#define OBJANIM_ROOT_CURVE_AXIS_YAW 3
#define OBJANIM_ROOT_CURVE_AXIS_PITCH 4
#define OBJANIM_ROOT_CURVE_AXIS_ROLL 5
#define OBJANIM_DOUBLE_CONVERSION_HIGH_WORD 0x43300000
#define OBJANIM_S32_DOUBLE_BIAS_XOR 0x80000000
#define OBJANIM_U32_DOUBLE(value)                                                                  \
    ((double)((u64)(((u64)(u32)(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD) << 32) | (u32)((value)))))
#define OBJ_MODEL_STATE_SHADOW_VISIBLE 0x04
#define OBJ_MODEL_STATE_SHADOW_INIT_CALLBACK_RAN 0x08
#define OBJ_MODEL_STATE_SHADOW_FADE_OUT 0x1000
#define OBJ_MODEL_STATE_SHADOW_ALPHA_HOLD 0x10000

/*
 * Shared state used by the object-animation helpers around main/objanim.c.
 * These names are still partially provisional, but the layouts are stable
 * enough to carry meaning across the nearby animation and hit-reaction code.
 */
typedef struct ObjAnimDef {
  u8 pad00[2];
  u16 flags;
  u16 modNo;
  u8 pad06[0x20 - 6];
  s16 *eventMoveTable;
  ObjHitReactMoveEntry *hitReactMoveTable;
  u8 pad28[0x58 - 0x28];
  ObjAnimHitReactRow *hitReactTable;
  u8 pad5C[0x64 - 0x5C];
  u8 **moveData;
  u8 pad68[4];
  s16 *cachedAnimIds;
  s16 moveGroupBaseIndices[OBJANIM_MOVE_GROUP_BASE_COUNT];
  u16 moveCount;
} ObjAnimDef;

typedef struct ObjAnimState {
  u8 pad00[4];
  f32 framePhase;
  f32 prevFramePhase;
  f32 frameStep;
  f32 savedFrameStep;
  f32 frameLength;
  f32 prevFrameLength;
  u8 *moveCache[OBJANIM_MOVE_CACHE_SLOT_COUNT];
  u8 *blendMoveCache[OBJANIM_MOVE_CACHE_SLOT_COUNT];
  u8 pad2c[8];
  ObjAnimFrameCommand *moveFrameData;
  ObjAnimFrameCommand *prevMoveFrameData;
  ObjAnimFrameCommand *blendFrameData;
  ObjAnimFrameCommand *prevBlendFrameData;
  u16 moveCacheSlot;
  u16 prevMoveCacheSlot;
  u16 blendCacheSlot;
  u16 prevBlendCacheSlot;
  u8 pad4c[0x58 - 0x4C];
  u16 eventCountdown;
  u16 eventState;
  u16 prevEventState;
  u16 eventStep;
  s8 frameType;
  s8 prevFrameType;
  s8 blendToggle;
  s8 moveControlFlags;
  s16 lastBlendMoveIndex;
} ObjAnimState;

typedef struct ObjAnimRootCurveAxis {
  s16 firstSample;
  s16 samples[1];
} ObjAnimRootCurveAxis;

/*
 * Root curves are packed by axis after the scale/sample-count header.  An axis
 * with firstSample == 0 occupies only that first s16; otherwise it is followed
 * by sampleCount additional s16 samples. Translation axes emit scaled floats,
 * while rotation axes emit raw s16 deltas into ObjAnimEventList.
 */
typedef struct ObjAnimRootCurve {
  f32 scale;
  s16 sampleCount;
  ObjAnimRootCurveAxis axes[1];
} ObjAnimRootCurve;

#define OBJMODEL_FLAG_SKIP_RESET_UPDATE 0x40

typedef struct ObjDefHitVolume {
  s16 jointOffsetX;
  s16 jointOffsetY;
  s16 jointOffsetZ;
  s16 posX;
  s16 posY;
  s16 posZ;
  u8 bounds[4];
  u8 flags;
  s8 priority;
  s8 jointIndices[2];
  u8 pad14[0x18 - 0x14];
} ObjDefHitVolume;

typedef struct ObjHitVolumeRuntimeTransform {
  f32 jointX;
  f32 jointY;
  f32 jointZ;
  f32 centerX;
  f32 centerY;
  f32 centerZ;
} ObjHitVolumeRuntimeTransform;

typedef struct ObjHitVolumeRuntimeBounds {
  u8 bounds[4];
  u8 flags;
} ObjHitVolumeRuntimeBounds;

typedef struct ObjTextureSlotDef {
  u8 tag;
  u8 materialIndex;
} ObjTextureSlotDef;

typedef struct ObjTextureRuntimeSlot {
  s32 textureId;
  u8 pad04[4];
  s16 offsetS;
  s16 offsetT;
  u8 colorR;
  u8 colorG;
  u8 colorB;
  u8 pad0F;
} ObjTextureRuntimeSlot;

/*
 * Minimal recovered shape of the model pointer carried by ObjAnimComponent.
 * The named fields below are shared by root-motion sampling and hit-reaction
 * table loading; the rest of the object/model layout is still being mapped.
 */
typedef struct ObjDef {
  u8 pad00[4];
  f32 rootMotionScaleBase;
  u8 pad08[0x0C - 0x08];
  ObjTextureSlotDef *textureSlotDefs;
  s8 *jointData;
  u8 pad14[0x18 - 0x14];
  u8 *extraSetupData;
  s16 *sequenceMap;
  s16 *eventMoveTable;
  ObjHitReactMoveEntry *hitReactMoveTable;
  s16 *weaponDaTable;
  u8 pad2C[0x40 - 0x2C];
  ObjDefHitVolume *hitVolumes;
  u32 flags;
  s16 shadowType;
  s16 shadowTextureId;
  u8 pad4C[0x4E - 0x4C];
  s16 hitboxFlags;
  u8 pad50[0x55 - 0x50];
  s8 modelCount;
  s8 group8RegistrationCount;
  u8 pad57[0x59 - 0x57];
  u8 textureSlotCount;
  u8 jointCount;
  u8 pad5B[0x5E - 0x5B];
  u8 sequenceCount;
  u8 renderFlags;
  u8 hitboxStateIndex;
  u8 pad61;
  u8 primaryHitboxRadius;
  u8 lateralResponseWeight;
  u8 axialResponseWeight;
  u8 primaryHitboxShapeFlags;
  u8 pad66;
  u8 targetHitMask;
  s16 primaryCapsuleOffsetA;
  s16 primaryCapsuleOffsetB;
  s16 secondaryCapsuleOffsetA;
  s16 secondaryCapsuleOffsetB;
  u8 sourceHitMask;
  u8 runtimeSourceHitMask;
  u8 hitVolumeCount;
  u8 pad73;
  u8 fixedSortDepth;
  u8 pad75;
  u8 effectFlags;
  u8 secondaryHitboxRadius;
  s16 mapLoadObjectId;
  u8 pad7A[0x7C - 0x7A];
  s16 helpTextIds[8];
  u8 pad8C;
  u8 modelLightMaskIndex;
  u8 pad8E;
  u8 fallbackHitSphereRadius;
  u8 secondaryHitboxShapeFlags;
  u8 pad91[0x94 - 0x91];
} ObjDef;

typedef ObjDef ObjModelInstance;

typedef struct ObjAnimMoveData {
  u8 pad00;
  s8 frameControl;
  u8 pad02[OBJANIM_MOVE_ROOT_CURVE_OFFSET - 2];
  s16 rootCurveOffset;
  u8 frameCommands[1];
} ObjAnimMoveData;

typedef struct ObjAnimBank {
  ObjAnimDef *animDef;
  u8 pad04[0x2C - 4];
  ObjAnimState *currentState;
  ObjAnimState *activeState;
} ObjAnimBank;

typedef struct ObjModelState {
  f32 shadowScale;
  void *shadowTexture;
  void *shadowWorkBuffer;
  void *shadowCastSlot;
  void *shadowRenderResource;
  f32 shadowOffsetX;
  f32 shadowOffsetY;
  f32 shadowOffsetZ;
  f32 overrideWorldPosX;
  f32 overrideWorldPosY;
  f32 overrideWorldPosZ;
  f32 shadowModelScale;
  u32 flags;
  u8 pad34[0x36 - 0x34];
  s16 shadowAlphaStep;
  u8 pad38[0x3A - 0x38];
  u8 shadowTintA;
  u8 shadowTintB;
  u8 pad3C[0x40 - 0x3C];
  u8 shadowAlpha;
  u8 pad41[0x44 - 0x41];
} ObjModelState;

typedef struct ObjAnimComponent {
  s16 rotX;
  s16 rotY;
  s16 rotZ;
  s16 flags;
  f32 rootMotionScale;
  f32 localPosX;
  f32 localPosY;
  f32 localPosZ;
  f32 worldPosX;
  f32 worldPosY;
  f32 worldPosZ;
  f32 velocityX;
  f32 velocityY;
  f32 velocityZ;
  void *parent;
  u8 pad34[2]; /* +0x35 is the signed yaw transform-table index. */
  u8 alpha;
  u8 pad37[0x44 - 0x37];
  s16 classId;
  s16 seqId;
  s16 defId;
  u8 pad4A[0x4C - 0x4A];
  union {
    s16 *placementData; /* raw view - the s16* deref width is load-bearing
                           at placementData[i] sites; keep for those */
    struct ObjPlacement *placement; /* typed view of the common head */
  };
  ObjDef *modelInstance;
  ObjHitReactState *hitReactState;
  u8 pad58[0x5C - 0x58];
  struct ObjWeaponDaTable *weaponDaTable;
  struct ObjAnimEventTable *eventTable;
  ObjModelState *modelState;
  int **dll;
  u8 *jointPoseData;
  ObjTextureRuntimeSlot *textureSlots;
  ObjHitVolumeRuntimeTransform *hitVolumeTransforms;
  ObjHitVolumeRuntimeBounds *hitVolumeBounds;
  ObjAnimBank **banks;
  f32 previousLocalPosX;
  f32 previousLocalPosY;
  f32 previousLocalPosZ;
  f32 previousWorldPosX;
  f32 previousWorldPosY;
  f32 previousWorldPosZ;
  f32 currentMoveProgress;
  f32 activeMoveProgress;
  s16 currentMove;
  s16 activeMove;
  void *targetObj; /* attention/track target (GameObject*): camera focus/track
                     sites across CAM TUs + baddieControl.c 0xA4-as-pointer
                     census - general object field, not camera-specific */
  f32 hitboxScale;
  s8 mapEventSlot;
  s8 bankIndex;
  s8 activeHitboxMode;
  union {
    s8 resetHitboxMode;
    u8 resetHitboxFlags; /* unsigned view - INTERACT_FLAG_* bits; matched
                            code reads lbz/stb here where the s8 view would
                            emit extsb */
  };
} ObjAnimComponent;

/*
 * anim.resetHitboxFlags bits - the engine<->DLL interact-prompt handshake.
 * ACTIVATED and IN_RANGE are engine-written (DLL code only reads them:
 * 44/31 sites); DISABLED and PROMPT_SUPPRESSED are DLL-written. The
 * objhits system separately stores small mode VALUES in this same byte
 * via the s8 view (OBJHITS_RESET_HITBOX_MODE).
 */
#define INTERACT_FLAG_ACTIVATED 0x01 /* player triggered the prompt this frame */
#define INTERACT_FLAG_IN_RANGE 0x04  /* player close enough; DLLs show the A icon */
#define INTERACT_FLAG_DISABLED 0x08  /* interaction off (DLLs default-set, clear to enable) */
#define INTERACT_FLAG_PROMPT_SUPPRESSED 0x10 /* precondition unmet, hide the prompt */

typedef struct ObjAnimEventTable {
  s32 byteCount;
  ObjAnimPackedEvent *entries;
} ObjAnimEventTable;

typedef struct ObjWeaponDaTable {
  s32 byteCount;
  s16 *entries;
} ObjWeaponDaTable;

typedef struct ObjAnimEventList {
  f32 rootDeltaX;
  f32 rootDeltaY;
  f32 rootDeltaZ;
  s16 rootYaw;
  s16 rootPitch;
  s16 rootRoll;
  u8 rootCurveValid;
  s8 triggeredIds[OBJANIM_EVENT_TRIGGER_CAPACITY];
  s8 triggerCount;
} ObjAnimEventList;

STATIC_ASSERT(sizeof(ObjAnimHitReactRow) == 0x18);
STATIC_ASSERT(offsetof(ObjAnimHitReactRow, entryIndex) == 0x16);
STATIC_ASSERT(offsetof(ObjAnimFrameCommand, frameLength) == 0x01);

STATIC_ASSERT(sizeof(ObjAnimDef) == 0xF0);
STATIC_ASSERT(offsetof(ObjAnimDef, flags) == 0x02);
STATIC_ASSERT(offsetof(ObjAnimDef, modNo) == 0x04);
STATIC_ASSERT(offsetof(ObjAnimDef, eventMoveTable) == 0x20);
STATIC_ASSERT(offsetof(ObjAnimDef, hitReactMoveTable) == 0x24);
STATIC_ASSERT(offsetof(ObjAnimDef, hitReactTable) == 0x58);
STATIC_ASSERT(offsetof(ObjAnimDef, moveData) == 0x64);
STATIC_ASSERT(offsetof(ObjAnimDef, cachedAnimIds) == 0x6C);
STATIC_ASSERT(offsetof(ObjAnimDef, moveGroupBaseIndices) == 0x70);
STATIC_ASSERT(offsetof(ObjAnimDef, moveCount) == 0xEC);

STATIC_ASSERT(sizeof(ObjAnimState) == 0x68);
STATIC_ASSERT(offsetof(ObjAnimState, framePhase) == 0x04);
STATIC_ASSERT(offsetof(ObjAnimState, prevFramePhase) == 0x08);
STATIC_ASSERT(offsetof(ObjAnimState, frameStep) == 0x0C);
STATIC_ASSERT(offsetof(ObjAnimState, savedFrameStep) == 0x10);
STATIC_ASSERT(offsetof(ObjAnimState, frameLength) == 0x14);
STATIC_ASSERT(offsetof(ObjAnimState, prevFrameLength) == 0x18);
STATIC_ASSERT(offsetof(ObjAnimState, moveCache) == 0x1C);
STATIC_ASSERT(offsetof(ObjAnimState, blendMoveCache) == 0x24);
STATIC_ASSERT(offsetof(ObjAnimState, moveFrameData) == 0x34);
STATIC_ASSERT(offsetof(ObjAnimState, prevMoveFrameData) == 0x38);
STATIC_ASSERT(offsetof(ObjAnimState, blendFrameData) == 0x3C);
STATIC_ASSERT(offsetof(ObjAnimState, prevBlendFrameData) == 0x40);
STATIC_ASSERT(offsetof(ObjAnimState, moveCacheSlot) == 0x44);
STATIC_ASSERT(offsetof(ObjAnimState, prevMoveCacheSlot) == 0x46);
STATIC_ASSERT(offsetof(ObjAnimState, blendCacheSlot) == 0x48);
STATIC_ASSERT(offsetof(ObjAnimState, prevBlendCacheSlot) == 0x4A);
STATIC_ASSERT(offsetof(ObjAnimState, eventCountdown) == 0x58);
STATIC_ASSERT(offsetof(ObjAnimState, eventState) == 0x5A);
STATIC_ASSERT(offsetof(ObjAnimState, prevEventState) == 0x5C);
STATIC_ASSERT(offsetof(ObjAnimState, eventStep) == 0x5E);
STATIC_ASSERT(offsetof(ObjAnimState, frameType) == 0x60);
STATIC_ASSERT(offsetof(ObjAnimState, prevFrameType) == 0x61);
STATIC_ASSERT(offsetof(ObjAnimState, blendToggle) == 0x62);
STATIC_ASSERT(offsetof(ObjAnimState, moveControlFlags) == 0x63);
STATIC_ASSERT(offsetof(ObjAnimState, lastBlendMoveIndex) == 0x64);

STATIC_ASSERT(sizeof(ObjDefHitVolume) == 0x18);
STATIC_ASSERT(offsetof(ObjDefHitVolume, bounds) == 0x0C);
STATIC_ASSERT(offsetof(ObjDefHitVolume, flags) == 0x10);
STATIC_ASSERT(offsetof(ObjDefHitVolume, priority) == 0x11);
STATIC_ASSERT(offsetof(ObjDefHitVolume, jointIndices) == 0x12);
STATIC_ASSERT(sizeof(ObjHitVolumeRuntimeTransform) == 0x18);
STATIC_ASSERT(sizeof(ObjHitVolumeRuntimeBounds) == 0x05);
STATIC_ASSERT(sizeof(ObjTextureSlotDef) == 0x02);
STATIC_ASSERT(sizeof(ObjTextureRuntimeSlot) == 0x10);

STATIC_ASSERT(sizeof(ObjDef) == 0x94);
STATIC_ASSERT(offsetof(ObjDef, rootMotionScaleBase) == 0x04);
STATIC_ASSERT(offsetof(ObjDef, textureSlotDefs) == 0x0C);
STATIC_ASSERT(offsetof(ObjDef, jointData) == 0x10);
STATIC_ASSERT(offsetof(ObjDef, extraSetupData) == 0x18);
STATIC_ASSERT(offsetof(ObjDef, sequenceMap) == 0x1C);
STATIC_ASSERT(offsetof(ObjDef, eventMoveTable) == 0x20);
STATIC_ASSERT(offsetof(ObjDef, hitReactMoveTable) == 0x24);
STATIC_ASSERT(offsetof(ObjDef, weaponDaTable) == 0x28);
STATIC_ASSERT(offsetof(ObjDef, hitVolumes) == 0x40);
STATIC_ASSERT(offsetof(ObjDef, flags) == 0x44);
STATIC_ASSERT(offsetof(ObjDef, shadowType) == 0x48);
STATIC_ASSERT(offsetof(ObjDef, shadowTextureId) == 0x4A);
STATIC_ASSERT(offsetof(ObjDef, hitboxFlags) == 0x4E);
STATIC_ASSERT(offsetof(ObjDef, modelCount) == 0x55);
STATIC_ASSERT(offsetof(ObjDef, group8RegistrationCount) == 0x56);
STATIC_ASSERT(offsetof(ObjDef, textureSlotCount) == 0x59);
STATIC_ASSERT(offsetof(ObjDef, jointCount) == 0x5A);
STATIC_ASSERT(offsetof(ObjDef, sequenceCount) == 0x5E);
STATIC_ASSERT(offsetof(ObjDef, renderFlags) == 0x5F);

/*
 * ObjDef.renderFlags (ObjDef+0x5F, u8) bit names. These are baked into the
 * loaded model-def data and read (never set in code) across the render/shadow
 * paths; the roles are the cross-file consensus from how each bit gates
 * behavior. Field is u8, so a bare int constant folds identically for & tests.
 *  - 0x4 PROJECTED_SHADOW: the model's shadow is a dynamically rendered
 *    projected shadow (own 512 render target, textureAlloc512 in
 *    track_dolphin; freed via mm_free not textureFree in object.c; forces the
 *    front-cull z-write shadow pass in objprint_dolphin; shadow-slot mode 2 in
 *    newshadows). Consensus across object.c/newshadows.c/track_dolphin.c/
 *    objprint_dolphin.c (5+ read sites).
 *  - 0x10 DEFERRED_RENDER: routes the object through the deferred render queue
 *    and the extended (0x1f) shadow render mode; also triggers the special
 *    render setup in objprint_dolphin. Consensus across objprint_dolphin.c and
 *    lightmap.c (paired with modelInstance->flags 0x800 to the same path).
 */
#define OBJDEF_RENDERFLAG_PROJECTED_SHADOW 0x4
#define OBJDEF_RENDERFLAG_DEFERRED_RENDER  0x10
STATIC_ASSERT(offsetof(ObjDef, hitboxStateIndex) == 0x60);
STATIC_ASSERT(offsetof(ObjDef, primaryHitboxRadius) == 0x62);
STATIC_ASSERT(offsetof(ObjDef, lateralResponseWeight) == 0x63);
STATIC_ASSERT(offsetof(ObjDef, axialResponseWeight) == 0x64);
STATIC_ASSERT(offsetof(ObjDef, primaryHitboxShapeFlags) == 0x65);
STATIC_ASSERT(offsetof(ObjDef, targetHitMask) == 0x67);
STATIC_ASSERT(offsetof(ObjDef, primaryCapsuleOffsetA) == 0x68);
STATIC_ASSERT(offsetof(ObjDef, primaryCapsuleOffsetB) == 0x6A);
STATIC_ASSERT(offsetof(ObjDef, secondaryCapsuleOffsetA) == 0x6C);
STATIC_ASSERT(offsetof(ObjDef, secondaryCapsuleOffsetB) == 0x6E);
STATIC_ASSERT(offsetof(ObjDef, sourceHitMask) == 0x70);
STATIC_ASSERT(offsetof(ObjDef, runtimeSourceHitMask) == 0x71);
STATIC_ASSERT(offsetof(ObjDef, hitVolumeCount) == 0x72);
STATIC_ASSERT(offsetof(ObjDef, fixedSortDepth) == 0x74);
STATIC_ASSERT(offsetof(ObjDef, effectFlags) == 0x76);
STATIC_ASSERT(offsetof(ObjDef, secondaryHitboxRadius) == 0x77);
STATIC_ASSERT(offsetof(ObjDef, mapLoadObjectId) == 0x78);
STATIC_ASSERT(offsetof(ObjDef, helpTextIds) == 0x7C);
STATIC_ASSERT(offsetof(ObjDef, modelLightMaskIndex) == 0x8D);
STATIC_ASSERT(offsetof(ObjDef, fallbackHitSphereRadius) == 0x8F);
STATIC_ASSERT(offsetof(ObjDef, secondaryHitboxShapeFlags) == 0x90);

STATIC_ASSERT(sizeof(ObjAnimMoveData) == 0x08);
STATIC_ASSERT(offsetof(ObjAnimMoveData, frameControl) == 0x01);
STATIC_ASSERT(offsetof(ObjAnimMoveData, rootCurveOffset) == 0x04);
STATIC_ASSERT(offsetof(ObjAnimMoveData, frameCommands) == OBJANIM_FRAME_COMMANDS_OFFSET);

STATIC_ASSERT(sizeof(ObjAnimBank) == 0x34);
STATIC_ASSERT(offsetof(ObjAnimBank, animDef) == 0x00);
STATIC_ASSERT(offsetof(ObjAnimBank, currentState) == 0x2C);
STATIC_ASSERT(offsetof(ObjAnimBank, activeState) == 0x30);

STATIC_ASSERT(sizeof(ObjAnimComponent) == 0xB0);
STATIC_ASSERT(offsetof(ObjAnimComponent, textureSlots) == 0x70);
STATIC_ASSERT(offsetof(ObjAnimComponent, hitVolumeTransforms) == 0x74);
STATIC_ASSERT(offsetof(ObjAnimComponent, hitVolumeBounds) == 0x78);
STATIC_ASSERT(offsetof(ObjAnimComponent, targetObj) == 0xA4);
STATIC_ASSERT(offsetof(ObjAnimComponent, mapEventSlot) == 0xAC);
STATIC_ASSERT(offsetof(ObjAnimComponent, rotX) == 0x00);
STATIC_ASSERT(offsetof(ObjAnimComponent, rotY) == 0x02);
STATIC_ASSERT(offsetof(ObjAnimComponent, rotZ) == 0x04);
STATIC_ASSERT(offsetof(ObjAnimComponent, flags) == 0x06);
STATIC_ASSERT(offsetof(ObjAnimComponent, rootMotionScale) == 0x08);
STATIC_ASSERT(offsetof(ObjAnimComponent, localPosX) == 0x0C);
STATIC_ASSERT(offsetof(ObjAnimComponent, localPosY) == 0x10);
STATIC_ASSERT(offsetof(ObjAnimComponent, localPosZ) == 0x14);
STATIC_ASSERT(offsetof(ObjAnimComponent, worldPosX) == 0x18);
STATIC_ASSERT(offsetof(ObjAnimComponent, worldPosY) == 0x1C);
STATIC_ASSERT(offsetof(ObjAnimComponent, worldPosZ) == 0x20);
STATIC_ASSERT(offsetof(ObjAnimComponent, velocityX) == 0x24);
STATIC_ASSERT(offsetof(ObjAnimComponent, velocityY) == 0x28);
STATIC_ASSERT(offsetof(ObjAnimComponent, velocityZ) == 0x2C);
STATIC_ASSERT(offsetof(ObjAnimComponent, parent) == 0x30);
STATIC_ASSERT(offsetof(ObjAnimComponent, alpha) == 0x36);
STATIC_ASSERT(offsetof(ObjAnimComponent, classId) == 0x44);
STATIC_ASSERT(offsetof(ObjAnimComponent, seqId) == 0x46);
STATIC_ASSERT(offsetof(ObjAnimComponent, defId) == 0x48);
STATIC_ASSERT(offsetof(ObjAnimComponent, placementData) == 0x4C);
STATIC_ASSERT(offsetof(ObjAnimComponent, placement) == 0x4C);
STATIC_ASSERT(offsetof(ObjAnimComponent, modelInstance) == 0x50);
STATIC_ASSERT(offsetof(ObjAnimComponent, hitReactState) == 0x54);
STATIC_ASSERT(offsetof(ObjAnimComponent, weaponDaTable) == 0x5C);
STATIC_ASSERT(offsetof(ObjAnimComponent, eventTable) == 0x60);
STATIC_ASSERT(offsetof(ObjAnimComponent, modelState) == 0x64);
STATIC_ASSERT(offsetof(ObjAnimComponent, dll) == 0x68);
STATIC_ASSERT(offsetof(ObjAnimComponent, jointPoseData) == 0x6C);
STATIC_ASSERT(offsetof(ObjAnimComponent, banks) == 0x7C);
STATIC_ASSERT(offsetof(ObjAnimComponent, previousLocalPosX) == 0x80);
STATIC_ASSERT(offsetof(ObjAnimComponent, previousWorldPosX) == 0x8C);
STATIC_ASSERT(offsetof(ObjAnimComponent, currentMoveProgress) == 0x98);
STATIC_ASSERT(offsetof(ObjAnimComponent, activeMoveProgress) == 0x9C);
STATIC_ASSERT(offsetof(ObjAnimComponent, currentMove) == 0xA0);
STATIC_ASSERT(offsetof(ObjAnimComponent, activeMove) == 0xA2);
STATIC_ASSERT(offsetof(ObjAnimComponent, hitboxScale) == 0xA8);
STATIC_ASSERT(offsetof(ObjAnimComponent, bankIndex) == 0xAD);
STATIC_ASSERT(offsetof(ObjAnimComponent, activeHitboxMode) == 0xAE);
STATIC_ASSERT(offsetof(ObjAnimComponent, resetHitboxMode) == 0xAF);
STATIC_ASSERT(offsetof(ObjAnimComponent, resetHitboxFlags) == 0xAF);

STATIC_ASSERT(sizeof(ObjAnimEventTable) == 0x08);
STATIC_ASSERT(offsetof(ObjAnimEventTable, byteCount) == 0x00);
STATIC_ASSERT(offsetof(ObjAnimEventTable, entries) == 0x04);

STATIC_ASSERT(sizeof(ObjWeaponDaTable) == 0x08);
STATIC_ASSERT(offsetof(ObjWeaponDaTable, byteCount) == 0x00);
STATIC_ASSERT(offsetof(ObjWeaponDaTable, entries) == 0x04);

STATIC_ASSERT(sizeof(ObjAnimEventList) == 0x1C);
STATIC_ASSERT(offsetof(ObjAnimEventList, rootDeltaX) == 0x00);
STATIC_ASSERT(offsetof(ObjAnimEventList, rootYaw) == 0x0C);
STATIC_ASSERT(offsetof(ObjAnimEventList, rootCurveValid) == 0x12);
STATIC_ASSERT(offsetof(ObjAnimEventList, triggeredIds) == 0x13);
STATIC_ASSERT(offsetof(ObjAnimEventList, triggerCount) == 0x1B);

static inline ObjAnimBank *ObjAnim_GetActiveBank(ObjAnimComponent *objAnim) {
  return objAnim->banks[objAnim->bankIndex];
}

static inline ObjHitsPriorityState *ObjAnim_GetPriorityHitState(ObjAnimComponent *objAnim) {
  return (ObjHitsPriorityState *)objAnim->hitReactState;
}

static inline f64 ObjAnim_U32AsDouble(u32 value) {
  u64 bits = (u64)(((u64)(u32)(OBJANIM_DOUBLE_CONVERSION_HIGH_WORD) << 32) | (u32)(value));
  return *(f64 *)&bits;
}

static inline f64 ObjAnim_S32AsDouble(s32 value) {
  return ObjAnim_U32AsDouble((u32)(value ^ (s32)OBJANIM_S32_DOUBLE_BIAS_XOR));
}

static inline s32 ObjAnim_ResolveMoveIndex(ObjAnimDef *animDef, u32 moveId) {
  s32 moveIndex =
      animDef->moveGroupBaseIndices[(s32)moveId >> OBJANIM_MOVE_GROUP_SHIFT] +
      (moveId & OBJANIM_MOVE_INDEX_MASK);

  if (moveIndex >= animDef->moveCount) {
    moveIndex = animDef->moveCount - 1;
  }
  if (moveIndex < 0) {
    moveIndex = 0;
  }
  return moveIndex;
}

static inline ObjAnimDef *ObjAnim_GetAnimDef(ObjAnimComponent *objAnim) {
  return ObjAnim_GetActiveBank(objAnim)->animDef;
}

static inline ObjAnimState *ObjAnim_GetActiveState(ObjAnimComponent *objAnim) {
  return ObjAnim_GetActiveBank(objAnim)->activeState;
}

static inline ObjAnimState *ObjAnim_GetCurrentState(ObjAnimComponent *objAnim) {
  return ObjAnim_GetActiveBank(objAnim)->currentState;
}

static inline s32 ObjAnim_GetHitReactEntryIndex(ObjAnimDef *animDef, s32 sphereIndex) {
  return animDef->hitReactTable[sphereIndex].entryIndex;
}

static inline ObjAnimMoveData *ObjAnim_GetMoveData(ObjAnimDef *animDef, ObjAnimState *state,
                                                   u16 slot) {
  if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0) {
    return (ObjAnimMoveData *)(state->moveCache[slot] + OBJANIM_CACHED_MOVE_DATA_OFFSET);
  }
  return (ObjAnimMoveData *)animDef->moveData[slot];
}

static inline ObjAnimMoveData *ObjAnim_GetCurrentMoveData(ObjAnimDef *animDef,
                                                          ObjAnimState *state) {
  return ObjAnim_GetMoveData(animDef, state, state->moveCacheSlot);
}

static inline ObjAnimMoveData *ObjAnim_GetBlendMoveData(ObjAnimDef *animDef, ObjAnimState *state,
                                                        u16 slot) {
  if ((animDef->flags & OBJANIM_DEF_FLAG_CACHED_MOVES) != 0) {
    return (ObjAnimMoveData *)(state->blendMoveCache[slot] + OBJANIM_CACHED_MOVE_DATA_OFFSET);
  }
  return (ObjAnimMoveData *)animDef->moveData[slot];
}

static inline ObjAnimMoveData *ObjAnim_GetCurrentBlendMoveData(ObjAnimDef *animDef,
                                                               ObjAnimState *state) {
  return ObjAnim_GetBlendMoveData(animDef, state, state->blendCacheSlot);
}

static inline ObjAnimRootCurve *ObjAnim_GetMoveDataRootCurve(ObjAnimMoveData *moveData) {
  return (ObjAnimRootCurve *)((u8 *)moveData + moveData->rootCurveOffset);
}

static inline s16 *ObjAnim_GetRootCurveAxisData(ObjAnimRootCurve *curve) {
  return &curve->axes[0].firstSample;
}

static inline ObjAnimRootCurve *ObjAnim_GetMoveRootCurve(ObjAnimDef *animDef,
                                                         ObjAnimState *state) {
  ObjAnimMoveData *moveData;

  moveData = ObjAnim_GetCurrentMoveData(animDef, state);
  if (moveData->rootCurveOffset == 0) {
    return NULL;
  }
  return ObjAnim_GetMoveDataRootCurve(moveData);
}

static inline ObjAnimRootCurve *ObjAnim_GetBlendMoveRootCurve(ObjAnimDef *animDef,
                                                              ObjAnimState *state) {
  ObjAnimMoveData *moveData;

  moveData = ObjAnim_GetCurrentBlendMoveData(animDef, state);
  if (moveData->rootCurveOffset == 0) {
    return NULL;
  }
  return ObjAnim_GetMoveDataRootCurve(moveData);
}

static inline s32 ObjAnim_GetPackedEventFrame(ObjAnimPackedEvent eventEntry) {
  return eventEntry & OBJANIM_EVENT_FRAME_MASK;
}

static inline s32 ObjAnim_GetPackedEventId(ObjAnimPackedEvent eventEntry) {
  return (eventEntry >> OBJANIM_EVENT_ID_SHIFT) & OBJANIM_EVENT_ID_MASK;
}

#endif /* MAIN_OBJANIM_INTERNAL_H_ */
