#ifndef MAIN_DLL_DLL_0282_BARRELGENER_H
#define MAIN_DLL_DLL_0282_BARRELGENER_H

#include "main/dll/barrelgener_state.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"

struct ModelLightStruct;

extern ObjectDescriptor gBarrelGenerObjDescriptor;

int barrelgener_getLinkId(GameObject* obj);
void barrelgener_queueObjectRelease(GameObject* obj, GameObject* queuedObj, int releaseFrame);
int barrelgener_getExtraSize(void);
int barrelgener_getObjectTypeId(void);
void barrelgener_free(GameObject* obj);
void barrelgener_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void barrelgener_hitDetect(void);
void barrelgener_init(GameObject* obj);
void barrelgener_update(GameObject* obj);
void barrelgener_release(void);
void barrelgener_initialise(void);

/* Shared movement/effect helpers emitted by this translation unit. */
void Obj_SteerVelocityTowardVector(int out, f32* currentVel, f32* desiredDir, f32 maxSpeed, f32 maxSpeedDelta,
                                   f32 turnRate);
int Obj_UpdateRomCurveFollowVelocity(GameObject* obj, int routePtr, f32 advanceStep, f32 arriveRadius, f32 speed,
                                     int flag);
int Obj_UpdateRomCurveFollowVelocityIndexed(GameObject* obj, int routePtr, f32 advanceStep, f32 arriveRadius,
                                            f32 speed, int flag, int* pickIdx);
void Obj_SpawnHitLightAndFade(int obj, f32* pos);
int Obj_UpdateLightningCluster(int obj, void** entries, int count, f32 intensity, struct ModelLightStruct** light);
void Obj_SmoothTurnAnglesTowardVelocity(GameObject* obj, int velVec, int turnFrames, f32 rollFactor,
                                        f32 pitchFactor);
int Obj_PredictInterceptPoint(GameObject* obj, f32 dt, int targetPos, int outPos);
int voxmaps_traceWorldLine(void* startPos, void* endPos);
void voxmaps_traceScaledVectorEnd(f32* out, void* origin, f32* dir, f32 scale);

#endif
