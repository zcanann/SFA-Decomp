/*
 * dimlavaball (DLL 0x1BF) - DIM lava-ball cannon proxy; manages the spawned
 * 0x18D lava-ball sub-object, controls its fire period and game-bit gate,
 * and relaunches it on each fire cycle.
 */
#include "main/dll/linklevcontrolstate_struct.h"
#include "main/dll/lavaball1bfstate_struct.h"
#include "main/dll/imspacethrusterstate_struct.h"
#include "main/dll/lavaball1bestate_struct.h"
#include "main/dll/imanimspacecraftstate_struct.h"
#include "main/dll/dll16cstate_struct.h"
#include "main/dll/magiclightstate_struct.h"
#include "main/dll/crrockfall_types.h"
#include "main/objseq.h"

#define DIMLAVABALL_OBJFLAG_HITDETECT_DISABLED 0x2000
#define DIMLAVABALL_OBJFLAG_HIDDEN 0x4000

/*
 * Per-object extra state for the IM ice-mountain event controller
 * (imicemountain_getExtraSize == 0x14).
 */
typedef struct IMIceMountainState
{
    u8 eventState; /* 0..7 event machine (imicemountain_updateEventState) */
    u8 pad01[3];
    s32 latchFlags; /* SCGameBitLatch record; bit 1 = latch fired this frame */
    s8 warpCountdown; /* state 6: frames until warpToMap(0x1A) */
    u8 pad09;
    s16 musicTrack; /* -1 or 26; Music_Trigger edge latch */
    u8 mapEventState; /* MEVT_QUERY result at init (1/2/5) */
    u8 pad0D[3];
    f32 warningTextTimer; /* shows text 0x351 while above the floor value */
} IMIceMountainState;

STATIC_ASSERT(sizeof(IMIceMountainState) == 0x14);

STATIC_ASSERT(sizeof(MagicLightState) == 0x14);
STATIC_ASSERT(sizeof(Dll16CState) == 0x24);
STATIC_ASSERT(sizeof(CrRockfallState) == 0x14);

extern int randomGetRange(int lo, int hi);

void imicepillar_free(void);

int imicepillar_getExtraSize(void);
int imicepillar_getObjectTypeId(void);

extern void objRenderFn_8003b8f4(f32);

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int kind, int id);
extern void Music_Trigger(int id, int arg);
extern f32 timeDelta;
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMcannon.h"
#include "main/gamebits.h"
#include "main/sfa_shared_decls.h"

typedef struct Lavaball1bfPlacement
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1E - 0x19];
    s16 triggerGameBit;
    u8 pad20[0x24 - 0x20];
    s16 stateGameBit;
    u8 pad26[0x28 - 0x26];
} Lavaball1bfPlacement;

STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

STATIC_ASSERT(sizeof(ImSpaceThrusterState) == 0xC);

STATIC_ASSERT(sizeof(LinkLevControlState) == 0x10);

STATIC_ASSERT(sizeof(Lavaball1beState) == 0x14);

STATIC_ASSERT(sizeof(Lavaball1bfState) == 0x1C);

extern f32 lbl_803E4810;
extern int Obj_AllocObjectSetup(int extraSize, int id);
extern f32 lbl_803E4814;

static inline int* DIMcannon_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

#pragma scheduling on
#pragma peephole on
void imicepillar_hitDetect(void);

void imicepillar_update(void);

void imicepillar_init(void);

void imicepillar_release(void);

void imicepillar_initialise(void);

ObjectDescriptor gIMIcePillarObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)imicepillar_initialise,
    (ObjectDescriptorCallback)imicepillar_release,
    0,
    (ObjectDescriptorCallback)imicepillar_init,
    (ObjectDescriptorCallback)imicepillar_update,
    (ObjectDescriptorCallback)imicepillar_hitDetect,
    (ObjectDescriptorCallback)imicepillar_render,
    (ObjectDescriptorCallback)imicepillar_free,
    (ObjectDescriptorCallback)imicepillar_getObjectTypeId,
    imicepillar_getExtraSize,
};

#pragma scheduling off
#pragma peephole off
void lavaball1bf_hitDetect(void)
{
}

void lavaball1bf_release(void)
{
}

void lavaball1bf_initialise(void)
{
}

int lavaball1bf_getExtraSize(void) { return 0x1c; }
int lavaball1bf_getObjectTypeId(void) { return 0x0; }
int dimlogfire_getExtraSize(void);

void lavaball1bf_func11(int* obj)
{
    Lavaball1bfState* p = (Lavaball1bfState*)(int*)((GameObject*)obj)->extra;
    if (p->gateA == 0) return;
    if (p->pending == 0) return;
    p->pending = 0;
}

int lavaball1bf_setScale(int* obj)
{
    Lavaball1bfState* p;
    obj = (int*)(int*)((GameObject*)obj)->extra;
    p = (Lavaball1bfState*)obj;
    if (p->gateA == 0) return 0;
    if (p->pending == 0)
    {
        p->pending = 1;
        return 1;
    }
    return 0;
}

void lavaball1bf_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4810);
}

void lavaball1bf_init(s16* obj, u8* p)
{
    Lavaball1bfState* inner;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)p[0x1c] << 8);
    inner = ((GameObject*)obj)->extra;
    inner->firePeriod = (f32) * (s16*)(p + 0x18);
    inner->fireTimer = lbl_803E4814;
    inner->gateA = p[0x1d];
    inner->gateB = GameBit_Get((int)*(s16*)(p + 0x22));
    if (*(s16*)(p + 0x24) == -1 && inner->gateB == 0)
    {
        inner->soloLatch = 1;
    }
    ((GameObject*)obj)->objectFlags |= (DIMLAVABALL_OBJFLAG_HIDDEN | DIMLAVABALL_OBJFLAG_HITDETECT_DISABLED);
}

void lavaball1bf_free(int obj, int mode)
{
    extern void Obj_FreeObject(void* o); /* #57 */
    Lavaball1bfState* inner = ((GameObject*)obj)->extra;
    if (mode == 0 && inner->spawnedObj != 0)
    {
        Obj_FreeObject(inner->spawnedObj);
    }
}

void lavaball1bf_update(int* obj)
{
    extern void* Obj_SetupObject(int a, int b, int c, int d, int e); /* #57 */
    u8* setup;
    Lavaball1bfState* state;
    int* spawned;
    f32 t;

    state = ((GameObject*)obj)->extra;
    setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    state->gbState = GameBit_Get(((Lavaball1bfPlacement*)setup)->stateGameBit);
    if (state->soloLatch != 0)
    {
        if (GameBit_Get(((Lavaball1bfPlacement*)setup)->triggerGameBit) != 0)
        {
            state->gbState = 1;
            state->soloLatch = 0;
            state->fireTimer = lbl_803E4814;
        }
        else
        {
            state->gbState = 0;
        }
    }
    if (*(void**)&state->spawnedObj == NULL && Obj_IsLoadingLocked() != 0)
    {
        int s = Obj_AllocObjectSetup(0x24, 0x18d);
        ObjPlacement* sp = (ObjPlacement*)s;
        *(u8*)(s + 2) = 9;
        sp->color[0] = 2;
        sp->color[2] = 0xff;
        sp->color[1] = 4;
        sp->color[3] = 0x50;
        sp->posX = ((GameObject*)obj)->anim.localPosX;
        sp->posY = ((GameObject*)obj)->anim.localPosY;
        sp->posZ = ((GameObject*)obj)->anim.localPosZ;
        *(s8*)(s + 0x18) = setup[0x1c];
        *(s16*)(s + 0x1a) = setup[0x1a];
        *(s16*)(s + 0x1c) = setup[0x1b];
        sp->mapId = ((ObjPlacement*)setup)->mapId;
        *(int*)&state->spawnedObj = ((int (*)(int, int, int, int, int))Obj_SetupObject)(
            s, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
    }
    spawned = state->spawnedObj;
    t = state->fireTimer - timeDelta;
    state->fireTimer = t;
    if (t <= lbl_803E4814 && ((int (*)(int*))((void**)*(void**)*(int*)&((GameObject*)spawned)->anim.dll)[9])(spawned) != 0)
    {
        if (state->gbState != 0)
        {
            int a;
            if (GameBit_Get(((Lavaball1bfPlacement*)setup)->triggerGameBit) != 0 && state->gateB == 0)
            {
                a = setup[0x20];
                state->gateB = 1;
            }
            else
            {
                a = setup[0x1a];
            }
            ((void (*)(int*, int, int))((void**)*(void**)*(int*)&((GameObject*)spawned)->anim.dll)[8])(spawned, a, setup[0x1b]);
        }
        state->fireTimer = state->firePeriod + (f32)(int)
        randomGetRange(0, 0x3c);
    }
}
