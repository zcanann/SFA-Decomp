#ifndef MAIN_DLL_DR_CLOUDRUNNER_STATE_H_
#define MAIN_DLL_DR_CLOUDRUNNER_STATE_H_

#include "global.h"
#include "main/dll/baddie_state.h"

typedef struct CloudRunnerState {
    BaddieState baddie;
    u8 pad35C[0x3c4 - 0x35c];
    f32 posX; /* 0x3c4: copied into the object's anim.localPos */
    f32 posY;
    f32 posZ;
    f32 pathPointX;
    f32 pathPointY;
    f32 pathPointZ;
    u8 pad3DC[0x464 - 0x3dc];
    u8 unk464;
    u8 pad465[0xad5 - 0x465];
    u8 moveFlags;
    u8 padAD6[0xae8 - 0xad6];
    f32 spawnPosX; /* 0xae8: stored position fed to a spawned object's ObjPlacement.pos */
    f32 spawnPosY;
    f32 spawnPosZ;
    f32 lastPosX;
    f32 lastPosY;
    f32 lastPosZ;
    u8 padB00[4];
    int unkB04;
    u8 padB08[0xb50 - 0xb08];
    f32 pathFollowSpeed;
    u8 padB54[0xbae - 0xb54];
    s16 unkBAE;
    s16 airTimeRemaining;
    u8 flightState;
    u8 padBB3;
    u8 spawnVariant; /* 0xbb4: variant selector from spawn-setup byte +0x19; gates init (case 0 = early-out) */
    u8 padBB5;
    u8 flagsBB6; /* 0xbb6: bit flags (|=4, &=~8) */
    u8 unkBB7;
    u8 unkBB8;
    u8 padBB9;
    s16 headingAngle; /* 0xbba: yaw; loaded from/stored to anim.rotX, turned toward target by moveInputX */
    s16 pitchAngle;
    s16 rollAngle;
    u8 flagsBC0; /* ByteFlags */
    u8 flagsBC1; /* ByteFlags */
    u8 padBC2;
    s8 cooldownTimer;
    s8 sequenceIndex;
    u8 padBC5[3];
} CloudRunnerState;

#endif
