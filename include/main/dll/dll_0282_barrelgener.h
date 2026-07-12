#ifndef MAIN_DLL_DLL_0282_BARRELGENER_H
#define MAIN_DLL_DLL_0282_BARRELGENER_H

#include "main/dll/barrelgener_state.h"
#include "main/dll/curve_walker.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/vec_types.h"
#include "main/lightningeffect.h"

struct ModelLightStruct;

extern ObjectDescriptor gBarrelGenerObjDescriptor;
extern int lbl_803DC398;
extern f32 lbl_803DC3A0;
extern f32 lbl_803DC3A4;
extern f32 lbl_803DC3A8;
extern u16 lbl_803DC3AC;
extern f32 lbl_803E6C20;
extern f32 lbl_803E6C24;
extern f32 lbl_803E6C28;
extern f32 lbl_803E6C2C;
extern f32 lbl_803E6C30;
extern f32 lbl_803E6C34;
extern f32 lbl_803E6C38;
extern f32 lbl_803E6C3C;
extern f32 lbl_803E6C40;
extern f32 lbl_803E6C44;
extern f32 lbl_803E6C58;
extern f32 lbl_803E6C5C;
extern f32 gBarrelGenPi;
extern f32 gBarrelGenAngleHalfRange;
extern f32 lbl_803E6C68;
extern f32 lbl_803E6C6C;
extern f32 lbl_803E6C70;
extern f32 lbl_803E6C74;
extern f32 lbl_803E6C78;
extern f32 lbl_803E6C7C;
extern f32 lbl_803E6C80;
extern f32 gBarrelGenAngleWrapNeg;
extern f32 gBarrelGenAngleWrapPos;
extern f32 gBarrelGenAngleWrapThreshold;
extern f32 gBarrelGenTurnRateClampMin;
extern f32 gBarrelGenTurnRateClampMax;
extern f32 lbl_803E6C98;

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
void Obj_SteerVelocityTowardVector(GameObject* obj, Vec3f* currentVelocity, Vec3f* desiredDirection, f32 maxSpeed,
                                   f32 maxSpeedDelta, f32 turnRate);
int Obj_UpdateRomCurveFollowVelocity(GameObject* obj, RomCurveWalker* route, f32 advanceStep, f32 arriveRadius,
                                     f32 speed, int flag);
int Obj_UpdateRomCurveFollowVelocityIndexed(GameObject* obj, RomCurveWalker* route, f32 advanceStep,
                                            f32 arriveRadius, f32 speed, int flag, int* pickIdx);
void Obj_SpawnHitLightAndFade(GameObject* obj, const Vec3f* pos, f32 scale);
int Obj_UpdateLightningCluster(GameObject* obj, LightningEffect** entries, int count, f32 intensity,
                               struct ModelLightStruct** light);
void Obj_SmoothTurnAnglesTowardVelocity(GameObject* obj, const Vec3f* velocity, int turnFrames, f32 rollFactor,
                                        f32 pitchFactor);
int Obj_PredictInterceptPoint(GameObject* obj, f32 dt, const Vec3f* targetPos, Vec3f* outPos);
int voxmaps_traceWorldLine(void* startPos, void* endPos);
void voxmaps_traceScaledVectorEnd(f32* out, void* origin, f32* dir, f32 scale);

#endif
