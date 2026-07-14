#ifndef MAIN_DLL_WM_DLL_0211_WMWALLCRAWLER_H_
#define MAIN_DLL_WM_DLL_0211_WMWALLCRAWLER_H_

#include "main/game_object.h"
#include "main/dll/path_control_interface.h"
#include "main/obj_placement.h"
#include "main/vecmath.h"

typedef struct WmwallcrawlerState
{
    u8 pathState[0x268];    /* 0x000: PathControlInterface state block */
    f32 triggerRadius;      /* 0x268: aggro radius, from placement; rescaled after each dive */
    f32 fleeChaseThreshold; /* 0x26C: distance threshold; >thr+eps -> CHASE, <thr -> FLEE drains lifeTimer */
    f32 homeX;              /* 0x270: home position, from placement */
    f32 homeY;              /* 0x274 */
    f32 homeZ;              /* 0x278 */
    u8 pad27C[0x284 - 0x27C];
    f32 animSpeed;      /* 0x284: ObjAnim_AdvanceCurrentMove rate */
    s16 attackTimer;    /* 0x288: strike cooldown (float-param, timerCountDown) */
    s16 explodeTimer;   /* 0x28A: TIMED_EXPLODE countdown to the particle burst */
    s16 despawnTimer;   /* 0x28C: post-burst countdown; render gates on 0 */
    s16 heightOffset;   /* 0x28E: from placement, added to homeY for the perch */
    s16 lifeTimer;      /* 0x290: frames until the crawler retreats/expires */
    s16 counterGameBit; /* 0x292: incremented when the death anim completes (0/-1 = none) */
    u16 flags;          /* 0x294: WMWALLCRAWLER_FLAG_*, from gWallCrawlerVariantFlags[variant] */
    s8 mode;            /* 0x296: WMWALLCRAWLER_MODE_* */
    u8 pad297;
    u8 variant; /* 0x298: placement byte indexing the flag table */
    u8 hitBits; /* 0x299: bit 0 = hit recorded, consumed by hitDetect (WcHitBits) */
    u8 pad29A[0x29C - 0x29A];
} WmwallcrawlerState;

STATIC_ASSERT(offsetof(WmwallcrawlerState, triggerRadius) == 0x268);
STATIC_ASSERT(offsetof(WmwallcrawlerState, homeX) == 0x270);
STATIC_ASSERT(offsetof(WmwallcrawlerState, animSpeed) == 0x284);
STATIC_ASSERT(offsetof(WmwallcrawlerState, attackTimer) == 0x288);
STATIC_ASSERT(offsetof(WmwallcrawlerState, despawnTimer) == 0x28C);
STATIC_ASSERT(offsetof(WmwallcrawlerState, lifeTimer) == 0x290);
STATIC_ASSERT(offsetof(WmwallcrawlerState, counterGameBit) == 0x292);
STATIC_ASSERT(offsetof(WmwallcrawlerState, flags) == 0x294);
STATIC_ASSERT(offsetof(WmwallcrawlerState, mode) == 0x296);
STATIC_ASSERT(offsetof(WmwallcrawlerState, variant) == 0x298);
STATIC_ASSERT(offsetof(WmwallcrawlerState, hitBits) == 0x299);
STATIC_ASSERT(sizeof(WmwallcrawlerState) == 0x29C);

typedef struct WmwallcrawlerMapData
{
    ObjPlacement base;
    s8 rotXByte;        /* 0x18: rotX in 1/256 turns */
    u8 variant;         /* 0x19: index into the flag table gWallCrawlerVariantFlags */
    s16 triggerRadius;  /* 0x1A */
    s16 heightOffset;   /* 0x1C */
    s16 counterGameBit; /* 0x1E */
} WmwallcrawlerMapData;

STATIC_ASSERT(offsetof(WmwallcrawlerMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(WmwallcrawlerMapData, variant) == 0x19);
STATIC_ASSERT(offsetof(WmwallcrawlerMapData, triggerRadius) == 0x1A);
STATIC_ASSERT(offsetof(WmwallcrawlerMapData, heightOffset) == 0x1C);
STATIC_ASSERT(offsetof(WmwallcrawlerMapData, counterGameBit) == 0x1E);
STATIC_ASSERT(sizeof(WmwallcrawlerMapData) == 0x20);

extern f32 lbl_803E5FB4;

int wmwallcrawler_animEventCallback(GameObject* obj);
void wmwallcrawler_alignToFloorNormal(GameObject* obj, f32* floorData);
int wmwallcrawler_getExtraSize(void);
int wmwallcrawler_getObjectTypeId(void);
void wmwallcrawler_free(GameObject* obj);
void wmwallcrawler_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wmwallcrawler_hitDetect(GameObject* obj);
void wmwallcrawler_update(GameObject* obj);
void wmwallcrawler_init(GameObject* obj, WmwallcrawlerMapData* mapData);
void wmwallcrawler_release(void);
void wmwallcrawler_initialise(void);

#endif
