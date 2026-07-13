#ifndef MAIN_DLL_DLL_014C_BABYCLOUDRUNNER_H_
#define MAIN_DLL_DLL_014C_BABYCLOUDRUNNER_H_

#include "main/game_object.h"
#include "main/objanim_update.h"

typedef struct BabyCloudRunnerState
{
    f32 unk00;
    u8 pad04[0x38]; /* 0x18: position used for the sandworm handoff */
    u8 lookBlock[0x30]; /* 0x3c: fn_8003ADC4 head-track block */
    u8 audioBlock[0x3c]; /* 0x6c: objAudioFn block */
    f32 animSpeed;
    f32 scale; /* 0xac: copied to the linked object's scale */
    int unkB0;
    int unkB4;
    int unkB8;
    int unkBC;
    int turnLatch; /* 0xc0: sandworm_turnTowardTargetAnim turn/idle move latch */
    int behaviourState; /* 0xc4: def[0x1c]; SeqFn 0..0xb dispatch */
    u8 padC8[4];
    int unkCC;
    s16 roostYaw; /* 0xd0: heading captured at init */
    u8 padD2[0x42];
    void* linkedObj; /* 0x114 */
    u8 pad118[0xc];
    u8 curveWalker[0x108]; /* 0x124: rom-curve follow block */
    u8 flags22C; /* 1 = alive/active */
    u8 pad22D[3];
    int runnerState; /* 0x230: 0 curve-seek, 1 follow, 2 chased, 3 freed */
    int runnerIndex; /* 0x234: gamebit base index, -1 keyed off */
    f32 countdownTimer; /* 0x238 */
    f32 curveSpeed; /* 0x23c */
    void* mutterSfxTable; /* 0x240 */
    u8 spitFlags; /* 0x244: BabyCloudrunnerFlags / WormSpitByte overlay */
    u8 pad245[3];
} BabyCloudRunnerState;

int babycloudrunner_getExtraSize(void);
int babycloudrunner_getObjectTypeId(void);
void babycloudrunner_free(int* obj);
void babycloudrunner_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void babycloudrunner_hitDetect(void);
void babycloudrunner_update(int* obj);
void babycloudrunner_init(int* obj, u8* def);
void babycloudrunner_release(void);
void babycloudrunner_initialise(void);
int babycloudrunner_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate);

#endif /* MAIN_DLL_DLL_014C_BABYCLOUDRUNNER_H_ */
