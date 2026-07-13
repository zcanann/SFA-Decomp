#ifndef MAIN_DLL_PLAYER_H_
#define MAIN_DLL_PLAYER_H_

#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/objfx.h"
#include "main/screen_transition.h"
#include "main/dll/player_api.h"
#include "main/dll/player_data.h"
#include "main/dll/player_state.h"

typedef struct
{
    u8 pad[0x7ac];
    s16 moves[8];
    f32 blend[8];
    f32 angles[8];
} MoveTable;
STATIC_ASSERT(sizeof(MoveTable) == 0x7fc);

typedef struct
{
    f32 nx;
    f32 ny;
    f32 nz;
    f32 d;
} EmitPlane;
STATIC_ASSERT(sizeof(EmitPlane) == 0x10);

typedef struct
{
    u8 pad00[0x60];
    s16 anims[14];
    f32 blends[25];
    u16 bits[8];
    f32 scales[16];
} EmitCtrlTbl;
STATIC_ASSERT(sizeof(EmitCtrlTbl) == 0x130);

int fn_802AD2F4(GameObject* obj, int inner, int state);
void playerItemGetAnimFn(int obj, int inner, int state);
void fn_802AFB0C(int obj, int inner, int state);
void playerDoHitDetection(int obj);
int fn_802AC7DC(int obj, int state, int inner, f32 fv);

s8 playerCheckIfClimbingOntoWall(int obj, int state, int state2, void* out, f32 fv, u32 mask);
int playerStateMoving(int obj, int state);
int playerStateOnLadder(int obj, int state);
int playerStateClimbWall(GameObject* obj, int state);
int playerStateAimStaff(int obj, int state);
int playerStateAttack(GameObject* obj, int state, f32 fv);
int playerState1D(int obj, int state, f32 fv);
int playerStateIdle(int obj, int state, f32 fv);
int playerState08(GameObject* obj, int state, f32 fv);

#endif
