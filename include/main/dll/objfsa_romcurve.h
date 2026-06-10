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
} ObjfsaRomCurveDef;

#endif
