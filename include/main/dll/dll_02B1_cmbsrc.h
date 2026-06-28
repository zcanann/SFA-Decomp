#ifndef MAIN_DLL_CMBSRC_H_
#define MAIN_DLL_CMBSRC_H_

#include "global.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"
#include "main/objanim_internal.h"

#define CMBSRC_DLL_ID 0x02B1
#define CMBSRC_DUSTMOTESOU_DLL_ID 0x02B2
#define CMBSRC_CLASS_ID 0x007E
#define CMBSRC_DEF_ID 0x059C
#define CMBSRCTPOLE_DEF_ID 0x059D
#define CMBSRCTWALL_DEF_ID 0x059E
#define CMBSRC_THUSTERSOUR_DEF_ID 0x059F
#define DUSTMOTESOU_DEF_ID 0x05A0
#define CMBSRC_OBJECT_DEF_BYTES 0xA0
#define CMBSRC_PLACEMENT_BYTES 0x30
#define CMBSRC_EXTRA_STATE_BYTES 0x28

#define CMBSRC_SEQ_DEFAULT 0x06E8
#define CMBSRC_SEQ_THUSTER_SOURCE 0x0758
#define CMBSRC_SEQ_TWALL 0x0853

#define CMBSRC_STATE_RENDERED 0x01
#define CMBSRC_STATE_EXTERNAL_ACTIVE 0x02
#define CMBSRC_STATE_THORNTAIL_GATE 0x04
#define CMBSRC_STATE_SUPPRESS_IDLE_EFFECT 0x08

#define CMBSRC_MAP_START_ACTIVE 0x01
#define CMBSRC_MAP_LOOP_SOUND 0x02
#define CMBSRC_MAP_ENABLE_HIT_VOLUME 0x04
#define CMBSRC_MAP_RENDER_MODEL 0x08
#define CMBSRC_MAP_CREATE_LIGHT 0x10
#define CMBSRC_MAP_AFFECTS_AABB_LIGHT 0x20
#define CMBSRC_MAP_GLOW 0x40
#define CMBSRC_MAP_GLOW_LARGE 0x80

#define CMBSRC_BEHAVIOR_THORNTAIL_GATE 0x01
#define CMBSRC_BEHAVIOR_ACTIVE_PARTICLES 0x02
#define CMBSRC_BEHAVIOR_DISABLE_FIELD4D 0x04
#define CMBSRC_BEHAVIOR_WIDE_ATTENUATION 0x08
#define CMBSRC_BEHAVIOR_HIT_MODE_MASK 0x30
#define CMBSRC_BEHAVIOR_SYNC_HIT_POSITION 0x40
#define CMBSRC_BEHAVIOR_SUPPRESS_IDLE_EFFECT 0x80

#define CMBSRC_HIT_TYPE_DAMAGE 0x10
#define CMBSRC_MAX_HIT_CHARGE 0x0F
#define CMBSRC_COLOR_CYCLE_COUNT 3
#define CMBSRC_MODE_COLOR_CYCLE 0x0F
#define CMBSRC_EFFECT_MODE_COUNT 9
#define CMBSRC_SUBMODE_COUNT 4
#define CMBSRC_LOOP_SOUND_CHANNEL 0x40
#define CMBSRC_HIT_VOLUME_SLOT 0x1F
#define CMBSRC_PARTICLE_EFFECT_ID 0x07CB
#define CMBSRC_DEFAULT_INACTIVE_FRAMES 0x0258

typedef struct CmbSrcMapData {
  ObjPlacement base;
  s8 rotZ;
  s8 rotY;
  s8 rotX;
  u8 colorIndex;
  u8 effectMode;
  u8 pulseSubMode;
  u8 pad1E[0x20 - 0x1E];
  f32 radius;
  s16 gameBit;
  u8 colorDistance;
  u8 effectDistance;
  u8 pulseDistance;
  u8 flags;
  u8 behaviorFlags;
  u8 inactiveSeconds;
  u8 glowProjectionMode;
  u8 pad2D[CMBSRC_PLACEMENT_BYTES - 0x2D];
} CmbSrcMapData;

typedef struct CmbSrcHitFlags {
  u8 disabled : 1;
} CmbSrcHitFlags;

/* Partial overlay onto the shared ModelLightStruct (defined in
 * main/model_light.h, which conflicts with the dll_80220608_shared.h
 * ModelLight = void typedef / signatures used by this DLL). Only the
 * enable flag and glow-pulse fields touched by cmbsrc are named here. */
typedef struct CmbSrcLight {
  u8 pad00[0x4C - 0x00];
  u8 enabled;
  u8 pad4D[0x2F8 - 0x4D];
  u8 glowType;
  u8 glowAlpha;
  s8 glowAlphaStep;
} CmbSrcLight;

STATIC_ASSERT(offsetof(CmbSrcLight, enabled) == 0x4C);
STATIC_ASSERT(offsetof(CmbSrcLight, glowType) == 0x2F8);
STATIC_ASSERT(offsetof(CmbSrcLight, glowAlpha) == 0x2F9);
STATIC_ASSERT(offsetof(CmbSrcLight, glowAlphaStep) == 0x2FA);

typedef struct CmbSrcState {
  void *light;
  f32 effectTimer;
  f32 pulseTimer;
  f32 particleTimer;
  f32 colorCycleTimer;
  f32 inactiveTimer;
  f32 radius;
  f32 hitRecoverTimer;
  u16 inactiveFrameCount;
  u8 flags;
  u8 colorCycleIndex;
  u8 priorityHitType;
  u8 active;
  s8 hitCharge;
  CmbSrcHitFlags hitFlags;
} CmbSrcState;

typedef struct CmbSrcObject {
  ObjAnimComponent objAnim;
  u16 objectFlags;
  u8 padB2[0xB8 - 0xB2];
  CmbSrcState *state;
  int (*updateCallback)(int obj);
} CmbSrcObject;

STATIC_ASSERT(sizeof(CmbSrcMapData) == CMBSRC_PLACEMENT_BYTES);
STATIC_ASSERT(offsetof(CmbSrcMapData, rotZ) == 0x18);
STATIC_ASSERT(offsetof(CmbSrcMapData, colorIndex) == 0x1B);
STATIC_ASSERT(offsetof(CmbSrcMapData, effectMode) == 0x1C);
STATIC_ASSERT(offsetof(CmbSrcMapData, radius) == 0x20);
STATIC_ASSERT(offsetof(CmbSrcMapData, gameBit) == 0x24);
STATIC_ASSERT(offsetof(CmbSrcMapData, flags) == 0x29);
STATIC_ASSERT(offsetof(CmbSrcMapData, behaviorFlags) == 0x2A);
STATIC_ASSERT(offsetof(CmbSrcMapData, inactiveSeconds) == 0x2B);
STATIC_ASSERT(offsetof(CmbSrcMapData, glowProjectionMode) == 0x2C);

STATIC_ASSERT(sizeof(CmbSrcState) == CMBSRC_EXTRA_STATE_BYTES);
STATIC_ASSERT(offsetof(CmbSrcState, light) == 0x00);
STATIC_ASSERT(offsetof(CmbSrcState, colorCycleTimer) == 0x10);
STATIC_ASSERT(offsetof(CmbSrcState, inactiveTimer) == 0x14);
STATIC_ASSERT(offsetof(CmbSrcState, radius) == 0x18);
STATIC_ASSERT(offsetof(CmbSrcState, inactiveFrameCount) == 0x20);
STATIC_ASSERT(offsetof(CmbSrcState, flags) == 0x22);
STATIC_ASSERT(offsetof(CmbSrcState, colorCycleIndex) == 0x23);
STATIC_ASSERT(offsetof(CmbSrcState, priorityHitType) == 0x24);
STATIC_ASSERT(offsetof(CmbSrcState, active) == 0x25);
STATIC_ASSERT(offsetof(CmbSrcState, hitCharge) == 0x26);
STATIC_ASSERT(offsetof(CmbSrcState, hitFlags) == 0x27);

STATIC_ASSERT(offsetof(CmbSrcObject, objAnim) == 0x00);
STATIC_ASSERT(offsetof(CmbSrcObject, objectFlags) == 0xB0);
STATIC_ASSERT(offsetof(CmbSrcObject, state) == 0xB8);
STATIC_ASSERT(offsetof(CmbSrcObject, updateCallback) == 0xBC);

extern ObjectDescriptor gCmbSrcObjDescriptor;

int cmbsrc_getExtraSize(void);
int cmbsrc_getObjectTypeId(void);
void cmbsrc_initialise(void);
void cmbsrc_release(void);
int cmbsrc_updateAndReturnZero(int obj);
int cmbsrc_getColorIndex(int obj);
void cmbsrc_setExternalActive(int obj,u8 active);
void cmbsrc_free(int obj);
void cmbsrc_render(int obj,int p2,int p3,int p4,int p5,s8 visible);
int cmbsrc_shouldActivate(int obj,int state,int setup);
int cmbsrc_shouldDeactivate(int obj,int state,int setup);
void cmbsrc_hitDetect(int obj);
int cmbsrc_cycleColor(int obj,int state);
void cmbsrc_updateVisuals(int obj,int state);
int cmbsrc_update(int obj);
void cmbsrc_init(int obj,u8 *setup);

#endif /* MAIN_DLL_CMBSRC_H_ */
