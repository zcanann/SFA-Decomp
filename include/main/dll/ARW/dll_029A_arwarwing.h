#ifndef MAIN_DLL_ARW_DLL_029A_ARWARWING_H
#define MAIN_DLL_ARW_DLL_029A_ARWARWING_H

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/objanim_update.h"
#include "main/vec_types.h"
#include "main/dll/ARW/arwing_state.h"

extern ObjectDescriptor gARWArwingObjDescriptor;

typedef struct Arw339Flags
{
    u8 scoreFlag : 1;
} Arw339Flags;

typedef struct ArwInitCfg
{
    int a;
    int b;
    u16 c;
    int d;
} ArwInitCfg;

STATIC_ASSERT(sizeof(ArwInitCfg) == 0x10);

extern GameObject* gArwing;
extern f32 lbl_803E6ECC;
extern f32 lbl_803E6ED0;
extern f32 lbl_803E6EF0;
extern f32 lbl_803E6EF4;
extern f32 lbl_803E6EF8;
extern f32 lbl_803E6EFC;
extern f32 lbl_803E6F00;
extern f32 lbl_803E6F08;
extern f32 lbl_803E6F0C;
extern f32 lbl_803E6F10;
extern f32 lbl_803E6F14;
extern f32 lbl_803E6F18;
extern f32 lbl_803E6F1C;
extern f32 lbl_803E6F20;
extern f32 lbl_803E6F28;
extern f32 lbl_803E6F2C;
extern f32 lbl_803E6F30;
extern f32 lbl_803E6F34;
extern f32 lbl_803E6F38;
extern f32 lbl_803E6F3C;
extern f32 lbl_803E6F40;
extern double lbl_803E6F48;
extern double lbl_803E6F50;
extern f32 lbl_803E6F58;
extern f32 lbl_803E6F5C;
extern f32 lbl_803E6F60;
extern f32 lbl_803E6F64;
extern f32 lbl_803E6F68;
extern f32 lbl_803E6F6C;
extern f32 lbl_803E6F70;
extern f32 lbl_803E6F74;
extern f32 lbl_803E6F78;
extern f32 lbl_803E6F7C;
extern f32 lbl_803E6F80;
extern f32 lbl_803E6F84;
extern f32 lbl_803E6F88;
extern f32 lbl_803E6F8C;
extern f32 lbl_803E6F90;
extern f32 lbl_803E6F94;
extern f32 lbl_803E6F98;
extern f32 lbl_803E6F9C;
extern f32 lbl_803E6FA0;
extern f32 lbl_803E6FA4;
extern f32 lbl_803E6FA8;
extern f32 lbl_803E6FAC;
extern f32 lbl_803E6FB0;
extern f32 lbl_803E6FB4;
extern f32 lbl_803E6FB8;
extern f32 lbl_803E6FBC;
extern f32 gArwingEscortSearchRadius;
extern f32 lbl_803E6FC4;
extern f32 lbl_803E6FC8;
extern f32 lbl_803E6FCC;
extern f32 lbl_803E6FD0;
extern f32 lbl_803E6FD4;
extern f32 lbl_803E6FD8;
extern f32 lbl_803E6FDC;
extern f32 lbl_803E6FE0;
extern f32 lbl_803E6FE4;
extern f32 lbl_803E6FE8;
extern f32 lbl_803E6FEC;
extern f32 lbl_803E6FF0;
extern f32 lbl_803E6FF4;
extern f32 lbl_803E6FF8;
extern f32 lbl_803E6FFC;
extern f32 lbl_803E7000;
extern f32 gArwingFireTimerReset;
extern f32 gArwingExplodeModeTime;
extern u8 gArwingCourseMapIds[8];
extern const ArwInitCfg gArwingInitConfig;
extern int gArwingPathSetupData[];
extern int sArwingPathName[];

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
void arwarwing_clampToFlightBounds(GameObject* obj, ArwingState* state);
void arwarwing_updateFlightPhysics(GameObject* obj, ArwingState* state);
void arwarwing_updateBombFire(GameObject* obj, ArwingState* state);
void arwarwing_emitDamageEffects(int obj, ArwingState* state);
void arwarwing_warpByCourse(GameObject* obj);
void arwarwing_updateWeaponFire(GameObject* obj, ArwingState* state);
void arwarwing_update(GameObject* obj);
void arwarwing_spawnLaserShot(GameObject* obj, ArwingState* state, int side, int level, int linkEffect);
void arwarwing_addBomb(GameObject* arwing);
void arwarwing_upgradeLaserLevel(GameObject* arwing);
int arwarwing_isExplodingOrWarping(GameObject* arwing);
int arwarwing_isBarrelRolling(GameObject* arwing);
int arwarwing_isDead(GameObject* arwing);
void arwarwing_updateRollAndEngine(int obj, ArwingState* state);
void arwarwing_clearAimSnapshot(GameObject* obj);
void arwarwing_initAttachments(GameObject* obj, ArwingState* state);
void arwarwing_spawnBomb(GameObject* obj, ArwingState* state, int side);
void arwarwing_resetFlightState(GameObject* obj);
void arwarwing_updateThrusters(GameObject* obj, ArwingState* state);
void arwarwing_handlePathDamage(GameObject* obj, ArwingState* state);
void arwarwing_handleObjectDamage(GameObject* obj, ArwingState* state);
int arwarwing_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void arwarwing_init(GameObject* obj);
void arwarwing_readControls(GameObject* obj, ArwingState* state);
void arwarwing_updateBarrelRoll(GameObject* obj, ArwingState* state);

#endif /* MAIN_DLL_ARW_DLL_029A_ARWARWING_H */
