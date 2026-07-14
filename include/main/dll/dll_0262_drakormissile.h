#ifndef MAIN_DLL_DLL_0262_DRAKORMISSILE_H_
#define MAIN_DLL_DLL_0262_DRAKORMISSILE_H_

#include "main/game_object.h"
#include "main/modellight_api.h"

#define DRAKORMISSILE_RENDER_TRAIL_COUNT 5

typedef struct DrakorMissileSetup
{
    u8 pad00[0x08];
    f32 posX;
    f32 posY;
    f32 posZ;
    u8 pad14[0x18 - 0x14];
    u8 velocityX;
    u8 velocityY;
    u8 velocityZ;
} DrakorMissileSetup;

typedef struct DrakorMissileState
{
    ModelLightStruct* light;
    u8 state;
    u8 flags;
    u8 pad06[2];
    int timer;
    f32 fadeTime;
    u16 trailYaw[DRAKORMISSILE_RENDER_TRAIL_COUNT];
    u16 trailYawStep[DRAKORMISSILE_RENDER_TRAIL_COUNT];
    u16 trailPitch[DRAKORMISSILE_RENDER_TRAIL_COUNT];
    u16 trailPitchStep[DRAKORMISSILE_RENDER_TRAIL_COUNT];
} DrakorMissileState;

STATIC_ASSERT(offsetof(DrakorMissileSetup, posX) == 0x08);
STATIC_ASSERT(offsetof(DrakorMissileSetup, velocityX) == 0x18);
STATIC_ASSERT(sizeof(DrakorMissileState) == 0x38);

void drakormissile_startActiveLaunch(GameObject* obj);
void drakormissile_startStraightLaunch(GameObject* obj, GameObject* from, GameObject* target, f32 speed);
int drakormissile_getExtraSize(void);
int drakormissile_getObjectTypeId(void);
void drakormissile_hitDetect(void);
void drakormissile_initialise(void);
void drakormissile_release(void);
void drakormissile_update(int obj);
int drakormissile_setScale(GameObject* obj);
void drakormissile_abortStraightFlight(GameObject* obj);
void drakormissile_modelMtxFn(GameObject* obj);
void drakormissile_free(GameObject* obj);
void drakormissile_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, s8 visible);
void drakormissile_init(GameObject* obj, DrakorMissileSetup* setup);

extern f32 lbl_803E6940;
extern f32 lbl_803E6944;
extern f32 lbl_803E6948;
extern f32 lbl_803E694C;
extern f32 lbl_803E6950;
extern f32 lbl_803E6954;
extern f32 lbl_803E6958;
extern f32 lbl_803E6964;
extern f32 lbl_803E6960;
extern f32 lbl_803DC2B0;
extern f32 lbl_803DC2B4;
extern f32 lbl_803DC2B8;
extern f32 gDrakorMissileProximityDetonateDist;
extern f32 gDrakorMissileFadeOutDuration;
extern f32 lbl_803E695C;

#endif /* MAIN_DLL_DLL_0262_DRAKORMISSILE_H_ */
