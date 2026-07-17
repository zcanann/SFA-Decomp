#ifndef MAIN_DLL_DR_DLL_027E_DRMUSICCONT_H_
#define MAIN_DLL_DR_DLL_027E_DRMUSICCONT_H_

#include "main/game_object.h"
#include "main/dll/SH/dll_01AE_shlevelcontrol.h"
#include "global.h"

extern const f32 lbl_803E6BC8;
extern const f32 gDrMusicControlCloudOverridePosX;
extern const f32 gDrMusicControlCloudOverridePosY;
extern const f32 gDrMusicControlCloudOverridePosZ;
extern const f32 lbl_803E6BD8;
extern const f32 gDrMusicControlStingerTimerDuration;
extern const f32 gDrMusicControlRestartPointX;
extern const f32 gDrMusicControlRestartPointY;
extern const f32 gDrMusicControlRestartPointZ;

typedef struct DrMusicContFlags
{
    u8 b_state : 1;
    u8 pad8_lo : 1;
    u8 b_e30 : 1;
    u8 b_e31 : 1;
    u8 b_e32 : 1;
    u8 b_e33 : 1;
    u8 b_e9c : 1;
    u8 b_e38 : 1;
    u8 b_e3c : 1;
    u8 b_e3d : 1;
    u8 b_e3e : 1;
    u8 b_e39 : 1;
    u8 b_9e0 : 1;
    u8 b_9e1 : 1;
    u8 b_9e2 : 1;
    u8 b_9e7 : 1;
} DrMusicContFlags;

typedef struct DrmusiccontState
{
    SCGameBitLatchState gameBitLatch;
    f32 stingerTimer;
    DrMusicContFlags flags;
} DrmusiccontState;

STATIC_ASSERT(offsetof(DrmusiccontState, gameBitLatch) == 0x0);
STATIC_ASSERT(offsetof(DrmusiccontState, stingerTimer) == 0x4);
STATIC_ASSERT(offsetof(DrmusiccontState, flags) == 0x8);

int drmusiccont_getExtraSize(void);
int drmusiccont_getObjectTypeId(void);
void drmusiccont_free(int obj);
void drmusiccont_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void drmusiccont_hitDetect(void);
void drmusiccont_release(void);
void drmusiccont_initialise(void);
void drmusiccont_init(GameObject* obj);
void drmusiccont_update(GameObject* obj);

#endif /* MAIN_DLL_DR_DLL_027E_DRMUSICCONT_H_ */
