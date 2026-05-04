#ifndef MAIN_OBJHITS_H_
#define MAIN_OBJHITS_H_

#include "ghidra_import.h"

#define OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT 5

extern int gObjHitsActiveHitVolumeObjects[OBJHITS_ACTIVE_HIT_VOLUME_OBJECT_COUNT];

typedef struct ObjHitsSweepEntry {
  float minX;
  float maxX;
  int obj;
} ObjHitsSweepEntry;

void ObjHits_CollectSkeletonHitsXZ(undefined8 param_1,double param_2,double param_3,
                                   undefined4 param_4,undefined4 param_5,int *param_6,
                                   int *param_7,int *param_8,float *param_9);
void ObjHits_CollectSkeletonHits3D(undefined4 param_1,undefined4 param_2,int *param_3,
                                   int *param_4,int *param_5,float *param_6);
void ObjHits_CalcSkeletonResponseXZ(undefined8 param_1,double param_2,double param_3,
                                    undefined4 param_4,undefined4 param_5,int param_6,
                                    int param_7,undefined4 param_8,int param_9,float *param_10);
void ObjHits_CalcSkeletonResponse3D(undefined8 param_1,undefined8 param_2,double param_3,
                                    undefined4 param_4,undefined4 param_5,int param_6,
                                    int param_7,undefined4 param_8,int param_9,float *param_10);
float *ObjHits_ProjectPointToTaperedCapsuleXZ(double param_1,double param_2,double param_3,
                                              double param_4,double param_5,float *param_6,
                                              float *param_7,float *param_8,float *param_9);
float *ObjHits_ProjectPointToTaperedCapsule3D(double param_1,double param_2,double param_3,
                                              double param_4,double param_5,float *param_6,
                                              float *param_7,float *param_8,float *param_9);
float *ObjHits_CalcTaperedCapsuleNormal(double param_1,double param_2,double param_3,
                                        double param_4,float *param_5,float *param_6,
                                        float *param_7,float *param_8);
uint ObjHits_TestTaperedCapsuleXZ(double param_1,double param_2,double param_3,double param_4,
                                  float *param_5,float *param_6,float *param_7,float *param_8,
                                  float *param_9,float *param_10,float *param_11);
uint ObjHits_TestTaperedCapsule3D(double param_1,double param_2,double param_3,double param_4,
                                  float *param_5,float *param_6,float *param_7,float *param_8,
                                  float *param_9,float *param_10,float *param_11);
void ObjHits_SortSweepEntries(int sweepPtrs,int entryCount);
void ObjHits_TickPriorityHitCooldowns(void);
void ObjHitbox_UpdateRotatedBounds(ushort *param_1,int param_2);
u8 ObjHits_CheckHitVolumes(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                           undefined8 param_5,undefined8 param_6,undefined8 param_7,
                           undefined8 param_8,undefined4 param_9,undefined4 param_10,
                           int param_11,undefined4 param_12,undefined4 param_13,uint param_14,
                           uint param_15,undefined4 param_16);
void FUN_80033358(void);
void ObjHits_CheckObjectHitVolumes(undefined8 param_1,double param_2,undefined8 param_3,
                                   undefined8 param_4,undefined8 param_5,undefined8 param_6,
                                   undefined8 param_7,undefined8 param_8,undefined4 param_9,
                                   undefined4 param_10,int param_11,int param_12);
void ObjHits_RegisterActiveHitVolumeObject(int obj);
void ObjHits_ApplyPairResponse(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                               undefined4 param_5,int param_6);
void ObjHits_DetectObjectPair(void);
void ObjHits_CheckSkeletonPair(undefined4 param_1,undefined4 param_2,int *param_3);
void ObjHits_CheckTrackContact(void);
void ObjHits_Update(undefined8 param_1,double param_2,undefined8 param_3,undefined8 param_4,
                    undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8);

#endif /* MAIN_OBJHITS_H_ */
