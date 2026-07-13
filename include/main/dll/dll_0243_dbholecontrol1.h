#ifndef MAIN_DLL_DLL_0243_DBHOLECONTROL1_H_
#define MAIN_DLL_DLL_0243_DBHOLECONTROL1_H_

#include "types.h"
#include "main/objanim_update.h"

typedef struct Dbholecontrol1Placement
{
    u8 pad0[0x8 - 0x0];
    f32 posX;
    f32 posY;
    f32 posZ;
    s32 mapId;
    u8 unk18;
    s8 triggerSeqId; /* 0x19: run as an object sequence when triggerGameBit is set */
    s16 gameBitA; /* copied into DbHoleControl1State.gameBitA */
    s16 gameBitB; /* copied into DbHoleControl1State.gameBitB */
    s16 hideGameBit;
    s16 triggerGameBit;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} Dbholecontrol1Placement;

void DBstealerwo_setFuncPtrs_80203c78(void);

int dbholecontrol1_getExtraSize(void);
int dbholecontrol1_getObjectTypeId(void);
void dbholecontrol1_free(int obj);
void dbholecontrol1_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void dbholecontrol1_hitDetect(void);
void dbholecontrol1_update(int* obj);
void dbholecontrol1_init(int* obj, u8* params);
int dbholecontrol1_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
void dbholecontrol1_release(void);
void dbholecontrol1_initialise(void);

#endif
