#ifndef MAIN_DLL_ROM_CURVE_INTERFACE_H_
#define MAIN_DLL_ROM_CURVE_INTERFACE_H_

#include "global.h"

typedef struct RomCurveDef RomCurveDef;
typedef struct RomCurveWalker RomCurveWalker;

#define ROM_CURVE_PATH_LINK_COUNT 5

typedef struct RomCurvePathNode
{
  u8 pad00[0x08];
  f32 x;
  f32 y;
  f32 z;
  s32 selfId;
  u8 pad18;
  s8 type;
  u8 pad1A;
  s8 directionMask;
  s32 links[ROM_CURVE_PATH_LINK_COUNT];
  u8 pad30;
  u8 tag0;
  u8 tag1;
  u8 tag2;
  s16 sampleA;
  s16 sampleB;
  s16 sampleC;
  s8 sampleD;
} RomCurvePathNode;

STATIC_ASSERT(offsetof(RomCurvePathNode, x) == 0x08);
STATIC_ASSERT(offsetof(RomCurvePathNode, selfId) == 0x14);
STATIC_ASSERT(offsetof(RomCurvePathNode, directionMask) == 0x1B);
STATIC_ASSERT(offsetof(RomCurvePathNode, links) == 0x1C);
STATIC_ASSERT(offsetof(RomCurvePathNode, tag0) == 0x31);
STATIC_ASSERT(offsetof(RomCurvePathNode, sampleA) == 0x34);

typedef void (*RomCurveVoidFn)(void);
typedef RomCurveDef **(*RomCurveGetCurvesFn)(int *outCount);
typedef int (*RomCurveFindFn)(int *types,int typeCount,int action,f32 x,f32 y,f32 z);
typedef RomCurveDef *(*RomCurveGetByIdFn)(int curveId);
typedef u8 (*RomCurveInitWalkerFn)(void *walker,void *obj,f32 scale,int *curveParam,int arg);
typedef u8 (*RomCurveGoNextPointFn)(void *walker);
typedef int (*RomCurveSetClosedFn)(void *walker,int closed);
typedef u8 (*RomCurveGoNextPointIndexedFn)(void *walker,int pickIdx);

typedef struct RomCurveInterface {
  RomCurveVoidFn release;
  RomCurveVoidFn initialise;
  void (*remove)(RomCurveDef *curve);
  void (*addCurveDef)(RomCurveDef *curve);
  RomCurveGetCurvesFn getCurves;
  RomCurveFindFn find;
  void *slot18;
  RomCurveGetByIdFn getById;
  void *slot20;
  void *slot24;
  void *slot28;
  void *slot2C;
  void *slot30;
  void *slot34;
  void *slot38;
  void *slot3C;
  void *slot40;
  void *slot44;
  void *slot48;
  void *slot4C;
  void *slot50;
  void *slot54;
  void *slot58;
  void *slot5C;
  void *slot60;
  void *slot64;
  void *slot68;
  void *slot6C;
  void *slot70;
  void *slot74;
  void *slot78;
  void *slot7C;
  void *slot80;
  void *slot84;
  void *slot88;
  RomCurveInitWalkerFn initCurve;
  RomCurveGoNextPointFn goNextPoint;
  RomCurveSetClosedFn setClosed;
  void *slot98;
  RomCurveGoNextPointIndexedFn goNextPointIndexed;
  void *slotA0;
  void *slotA4;
  void *slotA8;
} RomCurveInterface;

extern RomCurveInterface **gRomCurveInterface;

STATIC_ASSERT(offsetof(RomCurveInterface, getCurves) == 0x10);
STATIC_ASSERT(offsetof(RomCurveInterface, find) == 0x14);
STATIC_ASSERT(offsetof(RomCurveInterface, getById) == 0x1C);
STATIC_ASSERT(offsetof(RomCurveInterface, initCurve) == 0x8C);
STATIC_ASSERT(offsetof(RomCurveInterface, goNextPoint) == 0x90);
STATIC_ASSERT(offsetof(RomCurveInterface, setClosed) == 0x94);
STATIC_ASSERT(offsetof(RomCurveInterface, goNextPointIndexed) == 0x9C);
STATIC_ASSERT(offsetof(RomCurveInterface, slotA8) == 0xA8);

#endif /* MAIN_DLL_ROM_CURVE_INTERFACE_H_ */
