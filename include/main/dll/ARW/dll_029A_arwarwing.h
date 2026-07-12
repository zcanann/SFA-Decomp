#ifndef MAIN_DLL_ARW_DLL_029A_ARWARWING_H
#define MAIN_DLL_ARW_DLL_029A_ARWARWING_H

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"
#include "main/vec_types.h"
#include "main/dll/ARW/arwing_state.h"

extern ObjectDescriptor gARWArwingObjDescriptor;

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
void arwarwing_setVelocity(GameObject* arwing, int velocity);
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
void arwarwing_clampToFlightBounds(GameObject* obj, int state);
void arwarwing_updateFlightPhysics(GameObject* obj, int state);
void arwarwing_updateBombFire(GameObject* obj, int state);
void arwarwing_emitDamageEffects(int obj, int state);
void arwarwing_warpByCourse(GameObject* obj);
void arwarwing_updateWeaponFire(GameObject* obj, int state);
void arwarwing_update(GameObject* obj);
void arwarwing_spawnLaserShot(GameObject* obj, int state, int side, int level, int linkEffect);
void arwarwing_addBomb(int arwing);
void arwarwing_upgradeLaserLevel(int arwing);
int arwarwing_isExplodingOrWarping(int arwing);
int arwarwing_isBarrelRolling(int arwing);
int arwarwing_isDead(int arwing);
void arwarwing_updateRollAndEngine(int obj, int state);
void arwarwing_clearAimSnapshot(GameObject* obj);
void arwarwing_initAttachments(GameObject* obj, int state);
void arwarwing_spawnBomb(GameObject* obj, int state, int side);
void arwarwing_resetFlightState(GameObject* obj);
void arwarwing_updateThrusters(GameObject* obj, int state);
void arwarwing_handlePathDamage(GameObject* obj, int state);
void arwarwing_handleObjectDamage(GameObject* obj, int state);
int arwarwing_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void arwarwing_init(GameObject* obj);
void arwarwing_readControls(GameObject* obj, int state);
void arwarwing_updateBarrelRoll(GameObject* obj, int state);

#endif /* MAIN_DLL_ARW_DLL_029A_ARWARWING_H */
