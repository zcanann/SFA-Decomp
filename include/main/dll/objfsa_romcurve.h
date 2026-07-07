#ifndef MAIN_DLL_OBJFSA_ROMCURVE_H_
#define MAIN_DLL_OBJFSA_ROMCURVE_H_

#include "global.h"

typedef struct ObjfsaRomCurveDef {
  u8 pad00[0x08];
  f32 x;
  f32 y;
  f32 z;
  u32 id;
  s8 action;
  s8 type;
  u8 pad1A;
  s8 blockedLinkMask;
  s32 linkIds[4];
  s8 rotZ;   /* 0x2C, aka tangentYaw in DrakorCurveNode's per-node overlay */
  s8 rotY;   /* 0x2D, aka tangentPitch */
  u8 rotX;   /* 0x2E, aka tangentMag */
  u8 pad2F;
  s16 requiredBit;
  s16 forbiddenBit;
} ObjfsaRomCurveDef;

#endif
