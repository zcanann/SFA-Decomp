#ifndef MAIN_DLL_OBJFSA_ROMCURVE_H_
#define MAIN_DLL_OBJFSA_ROMCURVE_H_

#include "global.h"

typedef struct ObjfsaRomCurveDef {
  u8 pad00[4];
  u8 linkSelectors[4]; /* 0x4: per-link selector byte, parallels linkIds[4] */
  f32 x;
  f32 y;
  f32 z;
  u32 id;
  s8 action;
  s8 type;
  s8 unk1A; /* 0x1A */
  s8 blockedLinkMask;
  s32 linkIds[4];
  s8 rotZ;   /* 0x2C, aka tangentYaw in DrakorCurveNode's per-node overlay */
  s8 rotY;   /* 0x2D, aka tangentPitch */
  u8 rotX;   /* 0x2E, aka tangentMag */
  u8 pad2F;
  s16 requiredBit;
  s16 forbiddenBit;
} ObjfsaRomCurveDef;

STATIC_ASSERT(offsetof(ObjfsaRomCurveDef, linkSelectors) == 0x4);
STATIC_ASSERT(offsetof(ObjfsaRomCurveDef, x) == 0x8);
STATIC_ASSERT(offsetof(ObjfsaRomCurveDef, type) == 0x19);
STATIC_ASSERT(offsetof(ObjfsaRomCurveDef, unk1A) == 0x1A);
STATIC_ASSERT(offsetof(ObjfsaRomCurveDef, blockedLinkMask) == 0x1B);
STATIC_ASSERT(offsetof(ObjfsaRomCurveDef, linkIds) == 0x1C);
STATIC_ASSERT(offsetof(ObjfsaRomCurveDef, requiredBit) == 0x30);
STATIC_ASSERT(sizeof(ObjfsaRomCurveDef) == 0x34);

#endif
