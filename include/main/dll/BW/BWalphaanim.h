#ifndef MAIN_DLL_BW_BWALPHAANIM_H_
#define MAIN_DLL_BW_BWALPHAANIM_H_

#include "ghidra_import.h"
#include "global.h"

/* Per-object extra state for the rideable SnowBike / CloudRunner bike.
 * Offsets recovered from SnowBike_init/SnowBike_update derefs; the
 * 0x178..0x3DC block is the gPathControlInterface curves-collision state
 * and the 0x428 byte carries the SnowBikeFlags bitfield overlay. */
typedef struct SnowBikeState {
    u8 pad000[0xc];
    f32 posSnapshotX;       /* 0x00c: position snapshot X */
    f32 posSnapshotY;       /* 0x010: position snapshot Y */
    f32 posSnapshotZ;       /* 0x014: position snapshot Z */
    f32 unk018;             /* 0x018 */
    f32 unk01C;             /* 0x01c */
    f32 unk020;             /* 0x020 */
    f32 unk024;             /* 0x024 */
    u8 pad028[0x4];
    s16 riderYawOnFree;             /* 0x02c: rider yaw on free */
    s16 riderPitchOnFree;             /* 0x02e: rider pitch on free */
    u8 pad030[0x4];
    f32 unk034;             /* 0x034 */
    int checkpointIndexA;             /* 0x038 */
    int checkpointIndexB;             /* 0x03c */
    int checkpointIndexC;             /* 0x040 */
    int unk044;             /* 0x044 */
    u8 pad048[0x4];
    f32 riderPosX;             /* 0x04c: rider pos X on free */
    f32 riderPosY;             /* 0x050: rider pos Y on free */
    f32 riderPosZ;             /* 0x054: rider pos Z on free */
    u8 unk058;              /* 0x058 */
    u8 pad059[0x3];
    u8 unk05C;              /* 0x05c */
    u8 unk05D;              /* 0x05d */
    u8 pad05E[0x2];
    char *gameBitPtr;       /* 0x060: base+0xa4+bikeType*6; points to a pair of s16 GameBit ids (GameBit_Get at +0/+2) */
    u8 pad064[0x1];
    s8 collisionHitType;    /* 0x065: path-collision secondaryHitType (-1 = use plain non-Ex setup) */
    u8 pad066[0x2];
    f32 pathProgress;             /* 0x068 */
    u8 pad06C[0x100];       /* 0x178: path-control block lives in here */
    f32 refPosX;             /* 0x16c: position reference X */
    f32 refPosY;             /* 0x170: position reference Y */
    f32 refPosZ;             /* 0x174: position reference Z */
    u8 pad178[0xB8];
    u8 dampPresetModeRaw;   /* 0x230: un-latched preset selector copied into dampPresetMode */
    u8 pad231[0xDF];
    s16 unk310;             /* 0x310 */
    s16 unk312;             /* 0x312 */
    u8 pad314[0xC2];
    u8 unk3D6;              /* 0x3d6 */
    u8 pad3D7[0x2];
    s8 unk3D9;              /* 0x3d9 */
    u8 pad3DA[0x6];
    f32 collisionFxDamping;             /* 0x3e0 */
    f32 collisionFxTimer;             /* 0x3e4 */
    u8 pad3E8[0xc];
    f32 unk3F4;             /* 0x3f4 */
    f32 unk3F8;             /* 0x3f8 */
    u8 pad3FC[0x10];
    s16 yawCurrent;             /* 0x40c: yaw current */
    s16 yaw;             /* 0x40e: yaw target */
    int unk410;             /* 0x410 */
    u8 pad414[0x8];
    s16 savedRotY;             /* 0x41c: saved anim.rotY (restored after temp halo modify) */
    s16 savedRotZ;             /* 0x41e: saved anim.rotZ (restored after temp halo modify) */
    u8 unk420;              /* 0x420 */
    s8 riderMode;              /* 0x421: rider mode */
    s8 unk422;              /* 0x422 */
    u8 pad423;
    f32 impactShakeTimer;   /* 0x424: accumulates timeDelta while grounded; drives doRumble + CameraShake_SetAllMagnitudes */
    u8 flags428;            /* 0x428: SnowBikeFlags overlay byte */
    u8 pad429[0x3];
    int linkedObj;             /* 0x42c: linked object */
    f32 unk430;             /* 0x430 */
    u8 bikeType;              /* 0x434: bike kind */
    u8 bikeVariant;              /* 0x435: variant */
    u8 pad436[0x2];
    f32 unk438;             /* 0x438 */
    f32 timer;              /* 0x43c: countdown timer (decays by timeDelta, fires+resets at floor) */
    s16 modelId;             /* 0x440: model id */
    u8 pad442[0x6];
    s16 unk448;             /* 0x448 */
    s16 gameBitId;             /* 0x44a: gamebit id */
    s16 steerAngleDeg;      /* 0x44c: stick steering angle in deg (getAngle/gSnowBikeBamToDeg); gates partfx in angle bands */
    u8 pad44E[0x2];
    u32 buttonsJustPressed;             /* 0x450 */
    u32 buttonsJustPressedIfNotBusy;             /* 0x454 */
    u32 buttonsHeld;             /* 0x458 */
    f32 stickX;             /* 0x45c */
    s8 stickY;              /* 0x460 */
    u8 pad461[0x3];
    f32 velLimitX;             /* 0x464 */
    f32 velLimitY;             /* 0x468 */
    f32 velLimitZ;             /* 0x46c */
    f32 baseVelLimitX;             /* 0x470: persistent base velocity limit; copied into velLimit*+localVel*Limit on reset */
    f32 baseVelLimitY;             /* 0x474 */
    f32 baseVelLimitZ;             /* 0x478 */
    f32 localVelXLimit;             /* 0x47c */
    f32 localVelYLimit;             /* 0x480 */
    f32 distanceScaleLimit; /* 0x484: symmetric clamp bound applied to distanceScale */
    u8 pad488[0xc];
    f32 localVelX;             /* 0x494 */
    f32 localVelY;             /* 0x498 */
    f32 distanceScale;             /* 0x49c */
    u8 pad4A0[0xC];
    f32 collisionBounceScale; /* 0x4ac: collision velocity-retention scalar (localVel *= dot*collisionBounceScale + K on hit) */
    f32 liftAccel;          /* 0x4b0: vertical accel integrated into localVelY (localVelY += liftAccel*dt); also scales turn force */
    u8 dampPresetMode;      /* 0x4b4: latched mode (copied from unk230) selecting the spring-target preset in the damp update switch */
    u8 pad4B5[0x3];
    f32 airMeterMax;             /* 0x4b8 */
    f32 airMeterCurrent;             /* 0x4bc */
    f32 airDrainRate;             /* 0x4c0 */
    f32 airMeterRefillTimer; /* 0x4c4: counts down by rate*timeDelta (clamped [0,K]); while non-zero, refills airMeterCurrent */
    u8 pad4C8[0x54];        /* 0x4c8: 9 path allocation slots (stride 8) */
    f32 homePosX;             /* 0x51c: home X */
    f32 homePosY;             /* 0x520: home Y */
    f32 homePosZ;             /* 0x524: home Z */
    u8 pad528[0x4];
    f32 unk52C;             /* 0x52c */
    f32 unk530;             /* 0x530 */
    f32 unk534;             /* 0x534 */
    f32 unk538;             /* 0x538 */
    f32 unk53C;             /* 0x53c */
    f32 turnVelScale;       /* 0x540: smoothed scale on the strafe/turn velocity delta */
    f32 turnForceGain;      /* 0x544: smoothed gain (* unk4B0) on the strafe/turn force input */
    f32 localVelXDamp;      /* 0x548: smoothed base of powfBitEstimate(.,dt) damping localVelX */
    f32 distanceScaleDamp;  /* 0x54c: smoothed base of powfBitEstimate(.,dt) damping distanceScale */
    f32 unk550;             /* 0x550 */
    f32 unk554;             /* 0x554 */
    f32 unk558;             /* 0x558 */
    u8 pad55C[0x10];
    f32 unk56C;             /* 0x56c */
    f32 unk570;             /* 0x570 */
    f32 unk574;             /* 0x574 */
    f32 unk578;             /* 0x578 */
    f32 localVelXDampTarget;     /* 0x57c: held target for localVelXDamp (riding-paused state) */
    f32 distanceScaleDampTarget; /* 0x580: held target for distanceScaleDamp (riding-paused state) */
    f32 unk584;             /* 0x584 */
    s16 haloDriftPhaseA;    /* 0x588: integrated phase, fed to mathSinf for halo-light drift */
    s16 haloDriftPhaseB;    /* 0x58a: integrated phase, fed to mathSinf for halo-light drift */
    f32 haloYawDrift;             /* 0x58c */
    f32 haloDriftAmpB;      /* 0x590: halo drift channel-B amplitude (decays via powfBitEstimate) */
    f32 haloPitchDrift;             /* 0x594: halo-light yaw drift */
    f32 haloDriftB;         /* 0x598: halo drift channel-B output (haloDriftAmpB * sin(phaseB)); added to anim.rotZ */
} SnowBikeState; /* extends to at least 0x59C (DRhightop/DRhalolight tail) */
STATIC_ASSERT(offsetof(SnowBikeState, refPosX) == 0x16C);
STATIC_ASSERT(offsetof(SnowBikeState, unk3D6) == 0x3D6);
STATIC_ASSERT(offsetof(SnowBikeState, collisionFxDamping) == 0x3E0);
STATIC_ASSERT(offsetof(SnowBikeState, impactShakeTimer) == 0x424);
STATIC_ASSERT(offsetof(SnowBikeState, flags428) == 0x428);
STATIC_ASSERT(offsetof(SnowBikeState, collisionBounceScale) == 0x4AC);
STATIC_ASSERT(offsetof(SnowBikeState, unk530) == 0x530);
STATIC_ASSERT(offsetof(SnowBikeState, haloPitchDrift) == 0x594);

void SnowBike_update(int obj);

#endif /* MAIN_DLL_BW_BWALPHAANIM_H_ */
