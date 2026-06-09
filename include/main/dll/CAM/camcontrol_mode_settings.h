#ifndef MAIN_DLL_CAM_CAMCONTROL_MODE_SETTINGS_H_
#define MAIN_DLL_CAM_CAMCONTROL_MODE_SETTINGS_H_

#include "global.h"

typedef struct CamcontrolModeFlagByte {
  u8 b7 : 1;
  u8 b6 : 1;
  u8 rest : 6;
} CamcontrolModeFlagByte;

typedef struct CamcontrolFirstPersonActionSettings {
  u8 pad00[2];
  s8 fov;
  u8 minDistance;
  u8 maxDistance;
  s8 targetHeight;
  u8 lowerHeightOffset;
  u8 flags;
  u8 upperHeightOffset;
  u8 slideRightAmount;
  u8 slideLeftAmount;
  u8 distanceAdjustRate;
  u8 heightAdjustRate;
} CamcontrolFirstPersonActionSettings;

STATIC_ASSERT(sizeof(CamcontrolFirstPersonActionSettings) == 0x0D);
STATIC_ASSERT(offsetof(CamcontrolFirstPersonActionSettings, fov) == 0x02);
STATIC_ASSERT(offsetof(CamcontrolFirstPersonActionSettings, minDistance) == 0x03);
STATIC_ASSERT(offsetof(CamcontrolFirstPersonActionSettings, maxDistance) == 0x04);
STATIC_ASSERT(offsetof(CamcontrolFirstPersonActionSettings, targetHeight) == 0x05);
STATIC_ASSERT(offsetof(CamcontrolFirstPersonActionSettings, lowerHeightOffset) == 0x06);
STATIC_ASSERT(offsetof(CamcontrolFirstPersonActionSettings, flags) == 0x07);
STATIC_ASSERT(offsetof(CamcontrolFirstPersonActionSettings, upperHeightOffset) == 0x08);
STATIC_ASSERT(offsetof(CamcontrolFirstPersonActionSettings, slideRightAmount) == 0x09);
STATIC_ASSERT(offsetof(CamcontrolFirstPersonActionSettings, slideLeftAmount) == 0x0A);
STATIC_ASSERT(offsetof(CamcontrolFirstPersonActionSettings, distanceAdjustRate) == 0x0B);
STATIC_ASSERT(offsetof(CamcontrolFirstPersonActionSettings, heightAdjustRate) == 0x0C);

typedef struct CamcontrolModeSettings {
  f32 minDistance;
  f32 maxDistance;
  f32 lowerHeightOffset;
  f32 upperHeightOffset;
  f32 distanceAdjustRate;
  f32 heightAdjustRate;
  f32 slideRightAmount;
  f32 slideLeftAmount;
  f32 pad20;
  f32 pad24;
  f32 pad28;
  f32 savedMinDistance;
  f32 targetMinDistance;
  f32 savedMaxDistance;
  f32 targetMaxDistance;
  f32 savedLowerHeightOffset;
  f32 targetLowerHeightOffset;
  f32 savedUpperHeightOffset;
  f32 targetUpperHeightOffset;
  f32 savedDistanceAdjustRate;
  f32 targetDistanceAdjustRate;
  f32 savedHeightAdjustRate;
  f32 targetHeightAdjustRate;
  f32 savedSlideRightAmount;
  f32 targetSlideRightAmount;
  f32 savedSlideLeftAmount;
  f32 targetSlideLeftAmount;
  f32 savedFov;
  f32 fov;
  f32 savedWorldX;
  f32 savedWorldY;
  f32 savedWorldZ;
  s16 pitchOffset;
  s16 transitionTimer;
  s16 transitionDuration;
  s16 savedRotX;
  s16 savedRotY;
  s16 savedRotZ;
  f32 targetHeight;
  f32 savedTargetHeight;
  f32 targetTargetHeight;
  f32 baseLowerHeightOffset;
  f32 baseUpperHeightOffset;
  f32 verticalLowerBound;
  f32 verticalUpperBound;
  u8 padA8[0xAC - 0xA8];
  s32 slideAngle;
  u8 padB0[0xBC - 0xB0];
  f32 heightLockLimit;
  u8 padC0;
  u8 initialized;
  u8 yawResponseFrames;
  u8 collisionProbeTimer;
  u8 collisionState;
  u8 targetActionFlags;
  CamcontrolModeFlagByte wallAvoidanceFlags;
  u8 wallAvoidanceTimer;
  CamcontrolModeFlagByte distanceClampFlags;
  u8 padC9[0xCC - 0xC9];
} CamcontrolModeSettings;

STATIC_ASSERT(sizeof(CamcontrolModeSettings) == 0xCC);
STATIC_ASSERT(offsetof(CamcontrolModeSettings, targetHeight) == 0x8C);
STATIC_ASSERT(offsetof(CamcontrolModeSettings, verticalLowerBound) == 0xA0);
STATIC_ASSERT(offsetof(CamcontrolModeSettings, verticalUpperBound) == 0xA4);
STATIC_ASSERT(offsetof(CamcontrolModeSettings, slideAngle) == 0xAC);
STATIC_ASSERT(offsetof(CamcontrolModeSettings, heightLockLimit) == 0xBC);
STATIC_ASSERT(offsetof(CamcontrolModeSettings, yawResponseFrames) == 0xC2);
STATIC_ASSERT(offsetof(CamcontrolModeSettings, wallAvoidanceFlags) == 0xC6);
STATIC_ASSERT(offsetof(CamcontrolModeSettings, distanceClampFlags) == 0xC8);

extern CamcontrolModeSettings *cameraMtxVar57;

#endif /* MAIN_DLL_CAM_CAMCONTROL_MODE_SETTINGS_H_ */
