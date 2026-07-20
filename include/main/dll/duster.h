#ifndef MAIN_DLL_DUSTER_H_
#define MAIN_DLL_DUSTER_H_

#include "ghidra_import.h"
#include "main/game_object.h"

void rachnopUpdateApproach(int* obj, int state);
void rachnopUpdateAttack(int* obj, int state);
void rachnopUpdateIdle(int* obj, int state);
void spittingEbaUpdateIdle(GameObject* obj, int state);
void spittingEbaUpdateEngaged(u32 obj, int state);

void FUN_80155b6c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int *param_9,int param_10);
void FUN_80155cac(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int *param_9,int param_10);
void FUN_80155e00(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int *param_9,int param_10);
void rachnopInit(u32 param_1,int param_2);
void spittingEbaSpawnPollen(u32 param_9,int param_10);
void spittingEbaUpdateTimeOfDay(int param_9,int param_10);
void FUN_8015666c(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 int param_9,int param_10);
void FUN_80156978(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,int param_10);
void spittingEbaInit(u32 param_1,int param_2);
void FUN_80156eb8(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9,int param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void FUN_80157220(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u16 *param_9,u32 *param_10,u32 param_11,u32 param_12,
                 u32 param_13,u32 param_14,u32 param_15,u32 param_16);
void wbInit(u32 param_1,int param_2);
void FUN_801579f4(u64 param_1,double param_2,double param_3,u64 param_4,
                 u64 param_5,u64 param_6,u64 param_7,u64 param_8,
                 u32 param_9,int param_10);

/*
 * DusterState - shared overlay naming the PER-FAMILY scratch that
 * baddie_state.h leaves raw for the duster creatures. phaseTimer/decoyTimer
 * are f32 per-frame countdown timers; turnDelta is the hooded-zyck per-frame
 * rotY step.
 */
typedef struct DusterState
{
    u8 pad00[0x2F8];
    u16 moveEventFired; /* 0x2F8 nonzero = current move fired its progress event this frame */
    u8 pad2FA[0x324 - 0x2FA];
    f32 phaseTimer; /* 0x324 */
    f32 decoyTimer; /* 0x328 */
    u8 pad32C[0x338 - 0x32C];
    u16 turnDelta; /* 0x338 hooded-zyck per-frame rotY step */
    /*
     * 0x344..0x364: the wall/plane block rachnopFindWallPlane writes from a bbox probe
     * hit and the crawl helpers read back. planeNormal (0x344) is passed by
     * address to the PSVEC helpers, so it stays raw; the rest are scalar-only.
     */
    u8 pad33A[0x350 - 0x33A];
    f32 planeNormalW;   /* 0x350 4th probe component (hit[10]) */
    f32 planeAxisRatio; /* 0x354 anchor->plane projection ratio */
    f32 planeAnchorY;   /* 0x358 max(hit[3],hit[4]) */
    f32 planeBoundMin;  /* 0x35C min(hit[15],hit[16]) */
    f32 planeAnchorX;   /* 0x360 hit[1] */
    f32 planeAnchorZ;   /* 0x364 hit[5] */
} DusterState;

#endif /* MAIN_DLL_DUSTER_H_ */
