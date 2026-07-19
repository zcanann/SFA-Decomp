/* DLL 0xE1 - battle droid baddie behaviour [8014FEF8-8014FFB4) */
#include "main/dll/baddie_state.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/game_object.h"

void battleDroidUpdateWhileFrozen(int obj, int* state, int arg, int code, int wpad0, int wpad1, void* wpad2, int wpad3)
{
    if (code == 0x10)
    {
        ((BaddieState*)state)->reactionFlags |= 0x20;
    }
    else
    {
        ((BaddieState*)state)->reactionFlags |= 0x8;
    }
}

void battleDroidUpdate(int obj, int state)
{
}

void battleDroidUpdateAttack(int obj, int state)
{
    f32* pos = (f32*)((BaddieState*)state)->trackedObj;
    baddieTurnTowardPoint((GameObject*)obj, state, pos[3], pos[5], 0xf, 0);
}

void battleDroidInit(int unused, char* p)
{
    f32 v1c;
    ((BaddieState*)p)->speedScale = 60.0f;
    ((BaddieState*)p)->unk2E4 = 1;
    ((BaddieState*)p)->unk2E4 |= 0x80;
    ((BaddieState*)p)->unk308 = 0.005f;
    ((BaddieState*)p)->animDeltaScale = 0.17f;
    ((BaddieState*)p)->unk304 = 0.97f;
    ((BaddieState*)p)->unk320 = 0;
    v1c = 3.0f;
    *(f32*)&((BaddieState*)p)->eventFlags = v1c;
    ((BaddieState*)p)->unk321 = 0;
    ((BaddieState*)p)->unk318 = 1.25f;
    ((BaddieState*)p)->unk322 = 0;
    ((BaddieState*)p)->unk31C = v1c;
}
