/* DLL 0x1D1 — DIM Truth Horn Ice: a breakable ice target in Snowhorn Wastes 2.
 * Hit-count tracked in extra->hitsLeft; when depleted sets gameBit and starts a
 * particle-burst death animation (spawn loop in phase 1, freeze-hide in phase 2).
 * Tricky can deliver fire hits via vtable dispatch (slot 0x28 of Tricky's type at
 * offset 0x68). Also contains fn_801B6D40 (generic byte-damage helper shared by
 * this DLL group). */
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

#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/dll/DR/dr_802bbc10_shared.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"

#define DIMTRUTHHORNICE_OBJFLAG_HIDDEN 0x4000

typedef struct DimtruthhorniceObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 hitsLeft;
    s16 unk1C;
    s16 gameBit;
} DimtruthhorniceObjectDef;

typedef enum TruthHornIcePhase
{
    TRUTHHORNICE_PHASE_INTACT = 0,     /* takes hits; on break sets game bit, disables hits */
    TRUTHHORNICE_PHASE_SHATTERING = 1, /* delay timer, then spawns the ice-shard burst */
    TRUTHHORNICE_PHASE_SHATTERED = 2,  /* hidden */
} TruthHornIcePhase;

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);


extern f32 lbl_803E4A40;
extern f32 lbl_803E4A44;

static inline int* DIM2snowball_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

void dll_1CF_free(void);

int dimtruthhornice_getExtraSize(void) { return 0x8; }
int dim2conveyor_getExtraSize(void);

int fn_801B6D40(int* obj, int v)
{
    u8* state = ((GameObject*)obj)->extra;
    *(s8*)(state + 2) = (s8)(state[2] - v);
    return *(s8*)(state + 2) <= 0;
}

u8 dim2pathgenerator_getCurveVals(int* obj, int** p1, int** p2, int** p3, int** p4);

void dimtruthhornice_init(int* obj, int* def)
{
    TruthHornIceState* state = ((GameObject*)obj)->extra;
    state->hitsLeft = (s8)((DimtruthhorniceObjectDef*)def)->hitsLeft;
    state->gameBit = ((DimtruthhorniceObjectDef*)def)->gameBit;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | DIMTRUTHHORNICE_OBJFLAG_HIDDEN);
    {
        s16 slot = state->gameBit;
        if (slot != -1 && GameBit_Get(slot) != 0u)
        {
            ObjHits_DisableObject(obj);
            state->phase = TRUTHHORNICE_PHASE_SHATTERED;
            ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        }
    }
}

void dim2snowball_init(int* obj, int* def);

void dimtruthhornice_update(int* obj)
{

    TruthHornIceState* extra = ((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
    switch (extra->phase)
    {
    case TRUTHHORNICE_PHASE_INTACT:
        if (extra->hitsLeft <= 0)
        {
            if (extra->gameBit != -1)
            {
                GameBit_Set(extra->gameBit, 1);
                ObjHits_DisableObject(obj);
                extra->phase = TRUTHHORNICE_PHASE_SHATTERING;
                extra->timer = lbl_803E4A40;
            }
        }
        else
        {
            int* tricky = getTrickyObject();
            if (tricky != NULL)
            {
                if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0)
                {
                    (*(void (**)(int*, int*, int, int))(**(int**)((char*)tricky + 0x68) + 0x28))(tricky, obj, 1, 4);
                }
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            }
        }
        break;
    case TRUTHHORNICE_PHASE_SHATTERING:
        {
            f32 desc[6];
            extra->timer = extra->timer + timeDelta;
            if (extra->timer > lbl_803E4A44)
            {
                int i;
                extra->phase = TRUTHHORNICE_PHASE_SHATTERED;
                Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
                Sfx_PlayFromObject((int)obj, SFXTRIG_barrel_bounce1);
                for (i = 30; i != 0; i--)
                {
                    desc[3] = 0.1f * (f32)(int)
                    randomGetRange(-100, 100);
                    desc[4] = 0.1f * (f32)(int)
                    randomGetRange(0, 350);
                    desc[5] = 0.1f * (f32)(int)
                    randomGetRange(-100, 100);
                    desc[2] = 1.0f;
                    (*gPartfxInterface)->spawnObject(obj, 2043, desc, 2, -1, NULL);
                    (*gPartfxInterface)->spawnObject(obj, 2044, desc, 2, -1, NULL);
                }
            }
            desc[3] = 0.1f * (f32)(int)
            randomGetRange(-100, 100);
            desc[4] = 0.1f * (f32)(int)
            randomGetRange(0, 350);
            desc[5] = 0.1f * (f32)(int)
            randomGetRange(-100, 100);
            desc[2] = 1.0f;
            (*gPartfxInterface)->spawnObject(obj, 2044, desc, 2, -1, NULL);
            break;
        }
    case TRUTHHORNICE_PHASE_SHATTERED:
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        break;
    }
}
