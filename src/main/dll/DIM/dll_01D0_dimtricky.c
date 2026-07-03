/* DLL 0x1D0 — DIM Tricky companion object.
 * A simple 1-byte state machine (states 0-3) that watches game bit 0xA1B to
 * trigger a Tricky companion-pickup sequence: clears bits 0x4E4/0x4E5, then
 * dispatches a vtable call (slot 14 of Tricky's object type at offset
 * 0x68+0x38) to link the companion. */
#include "main/dll/dimmagicbridge_state.h"
#include "main/dll/dimwooddoor2state_struct.h"
#include "main/dll/fbwgpipe_struct.h"
#include "main/dll/dll1cestate_struct.h"
#include "main/dll/explosionpartfxsource_struct.h"
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/dll/explosion_state.h"
#include "main/objseq.h"

STATIC_ASSERT(sizeof(DimWoodDoor2State) == 0xC);
STATIC_ASSERT(sizeof(Dll1CEState) == 0xC);
STATIC_ASSERT(sizeof(DimMagicBridgeState) == 0x68);

STATIC_ASSERT(sizeof(ExplosionPartfxSource) == 0x38);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, rootMotionScale) == 0x08);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, localPosX) == 0x0C);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, worldPosX) == 0x18);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, velocityX) == 0x24);

STATIC_ASSERT(sizeof(ExplosionState) == 0xA60);
STATIC_ASSERT(offsetof(ExplosionState, driftYSpeed) == 0xA3C);

FbWGPipe GXWGFifo : (0xCC008000);

#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

extern f32 lbl_803E4A38;

static inline int* DIM2snowball_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

void dll_1CF_free(void);

void dim_tricky_free(void)
{
}

void dim_tricky_hitDetect(void)
{
}

void dim2conveyor_hitDetect(void);

int dim_tricky_getExtraSize(void) { return 0x1; }
int dim_tricky_getObjectTypeId(void) { return 0x0; }
int dimtruthhornice_getExtraSize(void);

void dim_tricky_init(int* obj)
{
    u8 v = 0x0;
    *((u8*)(int*)((GameObject*)obj)->extra + 0x0) = v;
}

void dim_tricky_render(void) { extern void objRenderFn_8003b8f4(f32); objRenderFn_8003b8f4(lbl_803E4A38); }

void dim2conveyor_free(int x);

void dim_tricky_update(int* obj)
{
    int* state = ((GameObject*)obj)->extra;
    int* trickyObj = getTrickyObject();
    if (trickyObj == NULL) return;
    switch (*(u8*)state)
    {
    case 0:
        if (GameBit_Get(0xa1b) != 0)
        {
            GameBit_Set(0x4e4, 0);
            GameBit_Set(0x4e5, 0);
            *(s8*)state = 1;
        }
        break;
    case 1:
        *(s8*)state = 2;
        break;
    case 2:
        ((void(*)(int*, int*))((void**)*(*(int***)((char*)trickyObj + 104)))[14])(trickyObj, obj);
        *(s8*)state = 3;
        break;
    case 3:
        break;
    }
}
