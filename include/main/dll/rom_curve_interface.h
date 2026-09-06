#ifndef MAIN_DLL_ROM_CURVE_INTERFACE_H_
#define MAIN_DLL_ROM_CURVE_INTERFACE_H_

#include "global.h"

typedef struct RomCurveDef RomCurveDef;
typedef struct RomCurveWalker RomCurveWalker;
typedef struct RomCurveInterface RomCurveInterface;
struct GameObject;

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
  u8 cameraFlags;
} RomCurvePathNode;

STATIC_ASSERT(offsetof(RomCurvePathNode, x) == 0x08);
STATIC_ASSERT(offsetof(RomCurvePathNode, selfId) == 0x14);
STATIC_ASSERT(offsetof(RomCurvePathNode, directionMask) == 0x1B);
STATIC_ASSERT(offsetof(RomCurvePathNode, links) == 0x1C);
STATIC_ASSERT(offsetof(RomCurvePathNode, tag0) == 0x31);
STATIC_ASSERT(offsetof(RomCurvePathNode, sampleA) == 0x34);
STATIC_ASSERT(offsetof(RomCurvePathNode, cameraFlags) == 0x3B);
STATIC_ASSERT(sizeof(RomCurvePathNode) == 0x3C);

typedef void (*RomCurveVoidFn)(void);
typedef RomCurveDef **(*RomCurveGetCurvesFn)(int *outCount);
typedef int (*RomCurveFindFn)(f32 x,f32 y,f32 z,int *types,int typeCount,int action);
typedef RomCurveDef *(*RomCurveGetByIdFn)(u32 curveId);
typedef f32 (*RomCurveFindPositionFn)(int type,int action,f32 x,f32 y,f32 z,f32 *outX,f32 *outY,f32 *outZ);
typedef f32 (*RomCurveDistanceToObjectFn)(struct GameObject *obj,u32 curveId);
typedef int (*RomCurveFindByActionFn)(int action);
typedef int (*RomCurveGetLinkedCurveFn)(RomCurveDef *curve,int excludeLinkId);
typedef int (*RomCurveFindShortestPathLinkFn)(RomCurveDef *startCurve,int unused1,int unused2,
                                              int *previousCurveId);
typedef int (*RomCurveIsPointInsideLoopFn)(int curveId,f32 x,f32 y,f32 z,f32 *outDistance);
typedef int (*RomCurveCountRandomPointsFn)(RomCurveDef *curve);
typedef int (*RomCurveBuildRandomPointsFn)(RomCurveDef *curve,f32 *outX,f32 *outY,f32 *outZ,s8 *outTypes);
typedef int (*RomCurveInitFromCurveIdFn)(RomCurveWalker *walker,struct GameObject *obj,int startCurveId,
                                         RomCurveInterface *interface);
typedef u8 (*RomCurveInitWalkerFn)(void *walker,void *obj,f32 scale,int *curveParam,int arg);
typedef u8 (*RomCurveGoNextPointFn)(void *walker);
typedef int (*RomCurveSetClosedFn)(void *walker,int closed);
typedef u8 (*RomCurveGoNextPointIndexedFn)(void *walker,int pickIdx);

struct RomCurveInterface {
  RomCurveVoidFn release;
  RomCurveVoidFn initialise;
  void (*addCurveDef)(RomCurveDef *curve);
  void (*remove)(RomCurveDef *curve);
  RomCurveGetCurvesFn getCurves;
  RomCurveFindFn find;
  void *slot18;
  RomCurveGetByIdFn getById;
  RomCurveFindPositionFn findPosition;
  RomCurveDistanceToObjectFn distanceToObject;
  void *slot28;
  void *slot2C;
  void *slot30;
  void *slot34;
  void *slot38;
  void *slot3C;
  RomCurveFindByActionFn findByAction;
  void *slot44;
  void *slot48;
  RomCurveIsPointInsideLoopFn isPointInsideLoop;
  void *slot50;
  RomCurveGetLinkedCurveFn getRandomForwardLink;
  void *slot58;
  void *slot5C;
  RomCurveGetLinkedCurveFn getRandomBackwardLink;
  void *slot64;
  RomCurveFindShortestPathLinkFn findShortestPathLink;
  void *slot6C;
  void *slot70;
  RomCurveCountRandomPointsFn countRandomPoints;
  RomCurveBuildRandomPointsFn buildRandomPoints;
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
  RomCurveInitFromCurveIdFn initFromCurveId;
};

extern RomCurveInterface **gRomCurveInterface;

STATIC_ASSERT(offsetof(RomCurveInterface, getCurves) == 0x10);
STATIC_ASSERT(offsetof(RomCurveInterface, find) == 0x14);
STATIC_ASSERT(offsetof(RomCurveInterface, getById) == 0x1C);
STATIC_ASSERT(offsetof(RomCurveInterface, getRandomForwardLink) == 0x54);
STATIC_ASSERT(offsetof(RomCurveInterface, getRandomBackwardLink) == 0x60);
STATIC_ASSERT(offsetof(RomCurveInterface, findShortestPathLink) == 0x68);
STATIC_ASSERT(offsetof(RomCurveInterface, initCurve) == 0x8C);
STATIC_ASSERT(offsetof(RomCurveInterface, goNextPoint) == 0x90);
STATIC_ASSERT(offsetof(RomCurveInterface, setClosed) == 0x94);
STATIC_ASSERT(offsetof(RomCurveInterface, goNextPointIndexed) == 0x9C);
STATIC_ASSERT(offsetof(RomCurveInterface, initFromCurveId) == 0xA8);

#endif /* MAIN_DLL_ROM_CURVE_INTERFACE_H_ */
