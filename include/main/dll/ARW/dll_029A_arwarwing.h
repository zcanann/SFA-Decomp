#ifndef MAIN_DLL_ARW_DLL_029A_ARWARWING_H
#define MAIN_DLL_ARW_DLL_029A_ARWARWING_H

#include "global.h"
#include "game/objects/object.h"
#include "dlls/object_descriptor.h"
#include "main/objseq.h"
#include "main/vec_types.h"
#include "main/dll/ARW/arwing_state.h"

extern ObjectDescriptor gARWArwingObjDescriptor;

typedef struct ArwInitCfg
{
    int a;
    int b;
    u16 c;
    int d;
} ArwInitCfg;

STATIC_ASSERT(sizeof(ArwInitCfg) == 0x10);

extern GameObject* gArwing;
extern f32 sDamageStickBlendRamp[30];
extern f32 gArwingDeathSpinRate;
extern f32 gArwingMaxLateralSpeed;
extern f32 gArwingLateralResponse;
extern f32 gArwingMaxVerticalSpeed;
extern f32 gArwingVerticalResponse;
extern f32 gArwingMaxForwardAccel;
extern f32 gArwingMinForwardAccel;
extern f32 gArwingYawRange;
extern f32 gArwingPitchRange;
extern f32 gArwingRollRange;
extern f32 gArwingRollGain;
extern f32 gArwingRollTrimRange;
extern f32 gArwingRollTrimGain;
extern f32 gArwingRollBlendThreshold;
extern f32 gArwingBlendRate;
extern f32 gArwingBarrelRollSpeed;
extern f32 gArwingBarrelRollDecelRange;
extern f32 gArwingRootMotionScale;
extern f32 gArwingBarrelRollMaxSpeedScale;
extern f32 gArwingBarrelRollAccelScale;
extern f32 gArwingLeftRollSpeedScale;
extern f32 gArwingEscortSearchRadius;
extern f32 gArwingLightOffsetY;
extern f32 gArwingLightOffsetZ;
extern f32 gArwingLightNearDistance;
extern f32 gArwingLightFarDistance;
extern f32 gArwingLeftRollAccel;
extern f32 gArwingNeutralForwardAccel;
extern f32 gArwingRollCooldown;
extern f32 gArwingRollEnergyMax;
extern f32 gArwingBobRollAmplitude;
extern f32 gArwingBobYRate;
extern f32 gArwingFlightHalfWidth;
extern f32 gArwingFlightUpperHeight;
extern f32 gArwingHitShakeAmplitude;
extern f32 gArwingAimCameraParameter;
extern f32 gArwingThrusterFadeInRate;
extern f32 gArwingThrusterAlphaMax;
extern u8 gArwingCourseMapIds[8];
extern const ArwInitCfg gArwingInitConfig;
extern f32 gArwingPathSetupData[10][3];
extern f32 sArwingPathSpeeds[10];

GameObject* getArwing(void);
int arwarwing_getExtraSize(void);
int arwarwing_getObjectTypeId(void);
void arwarwing_free(GameObject* obj);
void arwarwing_release(void);
void arwarwing_initialise(void);
void arwarwing_render(GameObject* obj, int p2, int p3, int p4, int p5);
void arwarwing_hitDetect(GameObject* obj);
void arwarwing_setFlightHalfWidth(GameObject* arwing, f32 width);
int arwarwing_getRotY(GameObject* arwing);
void arwarwing_setRotY(GameObject* arwing, int rotY);
void arwarwing_getVelocity(Vec3f* out, GameObject* arwing);
void arwarwing_setVelocity(GameObject* arwing, const Vec3f* velocity);
void arwarwing_addVelocity(GameObject* arwing, const Vec3f* velocity);
void arwarwing_clearActiveBomb(GameObject* arwing);
int arwarwing_getRequiredRingCount(GameObject* arwing);
int arwarwing_getCollectedRingCount(GameObject* arwing);
void arwarwing_addScore(GameObject* arwing, u8 amount);
int arwarwing_getScore(GameObject* arwing);
int arwarwing_getBombCount(GameObject* arwing);
int arwarwing_getMaxHealth(GameObject* arwing);
int arwarwing_getHealth(GameObject* arwing);
int arwarwing_incrementPickup6DACount(GameObject* arwing);
int arwarwing_incrementPickup6DBCount(GameObject* arwing);
int arwarwing_incrementPickup6D9Count(GameObject* arwing);
int arwarwing_incrementPickup6D8Count(GameObject* arwing);
int arwarwing_incrementCollectedRingCount(GameObject* arwing);
void arwarwing_addMaxHealth(GameObject* arwing, int amount);
void arwarwing_addHealth(GameObject* arwing, int amount);
void arwarwing_clampToFlightBounds(GameObject* obj, ArwingState* state);
void arwarwing_updateFlightPhysics(GameObject* obj, ArwingState* state);
void arwarwing_updateBombFire(GameObject* obj, ArwingState* state);
void arwarwing_emitDamageEffects(void* obj, ArwingState* state);
void arwarwing_warpByCourse(GameObject* obj);
void arwarwing_updateWeaponFire(GameObject* obj, ArwingState* state);
void arwarwing_update(GameObject* obj);
void arwarwing_spawnLaserShot(GameObject* obj, ArwingState* state, int side, int level, int linkEffect);
void arwarwing_addBomb(GameObject* arwing);
void arwarwing_upgradeLaserLevel(GameObject* arwing);
int arwarwing_isExplodingOrWarping(GameObject* arwing);
int arwarwing_isBarrelRolling(GameObject* arwing);
int arwarwing_isDead(GameObject* arwing);
void arwarwing_updateRollAndEngine(GameObject* obj, ArwingState* state);
void arwarwing_clearAimSnapshot(GameObject* obj);
void arwarwing_initAttachments(GameObject* obj, ArwingState* state);
void arwarwing_spawnBomb(GameObject* obj, ArwingState* state, int side);
void arwarwing_resetFlightState(GameObject* obj);
void arwarwing_updateThrusters(GameObject* obj, ArwingState* state);
void arwarwing_handlePathDamage(GameObject* obj, ArwingState* state);
void arwarwing_handleObjectDamage(GameObject* obj, ArwingState* state);
int arwarwing_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate);
void arwarwing_init(GameObject* obj);
void arwarwing_readControls(GameObject* obj, ArwingState* state);
void arwarwing_updateBarrelRoll(GameObject* obj, ArwingState* state);

#endif /* MAIN_DLL_ARW_DLL_029A_ARWARWING_H */
