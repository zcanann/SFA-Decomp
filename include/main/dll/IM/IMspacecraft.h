#ifndef MAIN_DLL_IM_IMSPACECRAFT_H_
#define MAIN_DLL_IM_IMSPACECRAFT_H_

#include "ghidra_import.h"
#include "main/objanim_update.h"
#include "main/dll/curve_walker.h"

#define SPIRITDOORLOCK_EXTRA_SIZE 0x14
#define ROLLINGBARREL_EXTRA_SIZE 0x118

/* SPIRITDOORLOCK_GAMEBIT_PLAYER_APPROACHED moved to GameBitId in gamebits.h
 * as GAMEBIT_K1_SPIRITDOORLOCK_PLAYER_APPROACHED (0xab9). */
#define SPIRITDOORLOCK_ORBIT_OBJECT_GROUP 0x4e
#define SPIRITDOORLOCK_LOOP_SFX 0x423

#define ROLLINGBARREL_GROUP_ID 0x2f
#define ROLLINGBARREL_SPECIAL_DESCRIPTOR_TYPE 0x72a

#define ROLLINGBARREL_STATE_ROLLING 0
#define ROLLINGBARREL_STATE_EXPLODED_WAIT 1
#define ROLLINGBARREL_STATE_RESPAWN_WAIT 2
#define ROLLINGBARREL_STATE_CLEANUP 3

typedef struct SpiritDoorLockState {
    int light;
    int spinAngle;
    int active;
    int orbitCount;
    u8 flags;
    u8 pad11[SPIRITDOORLOCK_EXTRA_SIZE - 0x11];
} SpiritDoorLockState;

typedef struct SpiritDoorLockMapData {
    u8 pad00[0x18];
    s8 yaw;
    s8 scale;
    s16 orbitCount;
    u8 pad1C[0x1E - 0x1C];
    s16 doneGameBit;
    s16 activeGameBit;
} SpiritDoorLockMapData;

typedef struct RollingBarrelState {
    RomCurveWalker curve;
    f32 curveSpeed;
    f32 verticalSpeed;
    f32 timer;
    u8 state;
    u8 pitchRising;
    u8 hitVolumeSlot;
    u8 pad117;
} RollingBarrelState;

typedef struct RollingBarrelMapData {
    s16 objectDefId;
    u8 pad02[0x08 - 0x02];
    f32 x;
    f32 y;
    f32 z;
    s32 respawnParam;
    u8 pad18[0x1A - 0x18];
    s16 verticalSpeed;
    s16 curveSpeed;
} RollingBarrelMapData;

STATIC_ASSERT(sizeof(SpiritDoorLockState) == SPIRITDOORLOCK_EXTRA_SIZE);
STATIC_ASSERT(offsetof(SpiritDoorLockState, light) == 0x00);
STATIC_ASSERT(offsetof(SpiritDoorLockState, spinAngle) == 0x04);
STATIC_ASSERT(offsetof(SpiritDoorLockState, active) == 0x08);
STATIC_ASSERT(offsetof(SpiritDoorLockState, orbitCount) == 0x0C);
STATIC_ASSERT(offsetof(SpiritDoorLockState, flags) == 0x10);

STATIC_ASSERT(offsetof(SpiritDoorLockMapData, yaw) == 0x18);
STATIC_ASSERT(offsetof(SpiritDoorLockMapData, scale) == 0x19);
STATIC_ASSERT(offsetof(SpiritDoorLockMapData, orbitCount) == 0x1A);
STATIC_ASSERT(offsetof(SpiritDoorLockMapData, doneGameBit) == 0x1E);
STATIC_ASSERT(offsetof(SpiritDoorLockMapData, activeGameBit) == 0x20);

STATIC_ASSERT(sizeof(RollingBarrelState) == ROLLINGBARREL_EXTRA_SIZE);
STATIC_ASSERT(offsetof(RollingBarrelState, curveSpeed) == 0x108);
STATIC_ASSERT(offsetof(RollingBarrelState, verticalSpeed) == 0x10C);
STATIC_ASSERT(offsetof(RollingBarrelState, timer) == 0x110);
STATIC_ASSERT(offsetof(RollingBarrelState, state) == 0x114);
STATIC_ASSERT(offsetof(RollingBarrelState, pitchRising) == 0x115);
STATIC_ASSERT(offsetof(RollingBarrelState, hitVolumeSlot) == 0x116);

STATIC_ASSERT(offsetof(RollingBarrelMapData, x) == 0x08);
STATIC_ASSERT(offsetof(RollingBarrelMapData, y) == 0x0C);
STATIC_ASSERT(offsetof(RollingBarrelMapData, z) == 0x10);
STATIC_ASSERT(offsetof(RollingBarrelMapData, respawnParam) == 0x14);
STATIC_ASSERT(offsetof(RollingBarrelMapData, verticalSpeed) == 0x1A);
STATIC_ASSERT(offsetof(RollingBarrelMapData, curveSpeed) == 0x1C);

int SpiritDoorLock_getExtraSize(void);
int SpiritDoorLock_getObjectTypeId(void);
void SpiritDoorLock_free(int obj);
void SpiritDoorLock_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void SpiritDoorLock_hitDetect(void);
void SpiritDoorLock_update(int obj);
void SpiritDoorLock_init(int obj, SpiritDoorLockMapData *params, int mode);
void SpiritDoorLock_release(void);
void SpiritDoorLock_initialise(void);
void fn_801A5D88(int obj, int explosionVariant);
int RollingBarrel_getExtraSize(void);
int RollingBarrel_getObjectTypeId(void);
void RollingBarrel_free(int obj);
void RollingBarrel_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
void RollingBarrel_hitDetect(void);
void RollingBarrel_update(int obj);
void RollingBarrel_init(int obj, RollingBarrelMapData *params);
void RollingBarrel_release(void);
void RollingBarrel_initialise(void);
int MMP_LevelControl_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate);
int MMP_levelcontrol_getExtraSize(void);
int MMP_levelcontrol_getObjectTypeId(void);
void MMP_levelcontrol_free(int obj);
void MMP_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void MMP_levelcontrol_hitDetect(void);

#endif /* MAIN_DLL_IM_IMSPACECRAFT_H_ */
