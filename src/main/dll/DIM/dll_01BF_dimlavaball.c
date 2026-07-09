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
#include "main/dll/imicemountainstate_struct.h"

#define DIMLAVABALL_OBJFLAG_HITDETECT_DISABLED 0x2000
#define DIMLAVABALL_OBJFLAG_HIDDEN             0x4000

/* Lava-ball sub-object id spawned by lavaball1bf_update (docblock: "the 0x18D lava-ball sub-object"). */
#define DIMLAVABALL_SUBOBJ_ID 0x18d

/*
 * Per-object extra state for the IM ice-mountain event controller
 * (IMIceMountain_getExtraSize == 0x14).
 */

STATIC_ASSERT(sizeof(IMIceMountainState) == 0x14);

STATIC_ASSERT(sizeof(MagicLightState) == 0x14);
STATIC_ASSERT(sizeof(Dll16CState) == 0x24);
STATIC_ASSERT(sizeof(CrRockfallState) == 0x14);

extern int randomGetRange(int lo, int hi);

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);

extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int kind, int id);
extern f32 timeDelta;
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/dll/DIM/DIMcannon.h"
#include "main/gamebits.h"
#include "main/sfa_shared_decls.h"

typedef struct Lavaball1bfPlacement
{
    u8 pad0[0x18 - 0x0];
    s8 firePeriod; /* 0x18 read raw as s16 (p+0x18) into state.firePeriod */
    u8 pad19[0x1E - 0x19];
    s16 triggerGameBit;
    u8 pad20[0x24 - 0x20];
    s16 stateGameBit;
    u8 pad26[0x28 - 0x26];
} Lavaball1bfPlacement;

/* 0x24-byte Obj_AllocObjectSetup(0x24, 0x18D) buffer built in
 * lavaball1bf_update to launch the 0x18D lava-ball sub-object. */
typedef struct Lavaball18dSetup
{
    ObjPlacement head; /* 0x00..0x17 */
    s8 unk18;          /* 0x18: copied from placement[0x1C] */
    u8 pad19;
    s16 childRot; /* 0x1A rotation region; copied from placement[0x1A] */
    s16 unk1C;    /* 0x1C: copied from placement[0x1B] */
    u8 pad1E[0x24 - 0x1E];
} Lavaball18dSetup;

STATIC_ASSERT(offsetof(Lavaball18dSetup, unk18) == 0x18);
STATIC_ASSERT(offsetof(Lavaball18dSetup, childRot) == 0x1A);
STATIC_ASSERT(offsetof(Lavaball18dSetup, unk1C) == 0x1C);
STATIC_ASSERT(sizeof(Lavaball18dSetup) == 0x24);

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

void lavaball1bf_clearPending(int* obj)
{
    Lavaball1bfState* p = (Lavaball1bfState*)(int*)((GameObject*)obj)->extra;
    if (p->gateA == 0)
        return;
    if (p->pending == 0)
        return;
    p->pending = 0;
}

int lavaball1bf_trySetPending(int* obj)
{
    Lavaball1bfState* p;
    obj = (int*)(int*)((GameObject*)obj)->extra;
    p = (Lavaball1bfState*)obj;
    if (p->gateA == 0)
        return 0;
    if (p->pending == 0)
    {
        p->pending = 1;
        return 1;
    }
    return 0;
}

int lavaball1bf_getExtraSize(void)
{
    return 0x1c;
}
int lavaball1bf_getObjectTypeId(void)
{
    return 0x0;
}

void lavaball1bf_free(struct GameObject* obj, int mode)
{
    extern void Obj_FreeObject(void* o);
    Lavaball1bfState* inner = (obj)->extra;
    if (mode == 0 && inner->spawnedObj != 0)
    {
        Obj_FreeObject(inner->spawnedObj);
    }
}

void lavaball1bf_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E4810);
}

void lavaball1bf_hitDetect(void)
{
}

void lavaball1bf_update(int* obj)
{
    extern void* Obj_SetupObject(int a, int b, int c, int d, int e);
    u8* setup;
    Lavaball1bfState* state;
    int* spawned;
    f32 timer;

    state = ((GameObject*)obj)->extra;
    setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    state->gbState = mainGetBit(((Lavaball1bfPlacement*)setup)->stateGameBit);
    if (state->soloLatch != 0)
    {
        if (mainGetBit(((Lavaball1bfPlacement*)setup)->triggerGameBit) != 0)
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
        int s = Obj_AllocObjectSetup(0x24, DIMLAVABALL_SUBOBJ_ID);
        Lavaball18dSetup* sp = (Lavaball18dSetup*)s;
        *(u8*)(s + 2) = 9;
        sp->head.color[0] = 2;
        sp->head.color[2] = 0xff;
        sp->head.color[1] = 4;
        sp->head.color[3] = 0x50;
        sp->head.posX = ((GameObject*)obj)->anim.localPosX;
        sp->head.posY = ((GameObject*)obj)->anim.localPosY;
        sp->head.posZ = ((GameObject*)obj)->anim.localPosZ;
        sp->unk18 = setup[0x1c];
        sp->childRot = setup[0x1a];
        sp->unk1C = setup[0x1b];
        sp->head.mapId = ((ObjPlacement*)setup)->mapId;
        *(int*)&state->spawnedObj =
            ((int (*)(int, int, int, int, int))Obj_SetupObject)(s, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
    }
    spawned = state->spawnedObj;
    timer = state->fireTimer - timeDelta;
    state->fireTimer = timer;
    if (timer <= lbl_803E4814 &&
        ((int (*)(int*))((void**)*(void**)*(int*)&((GameObject*)spawned)->anim.dll)[9])(spawned) != 0)
    {
        if (state->gbState != 0)
        {
            int rot;
            if (mainGetBit(((Lavaball1bfPlacement*)setup)->triggerGameBit) != 0 && state->gateB == 0)
            {
                rot = setup[0x20];
                state->gateB = 1;
            }
            else
            {
                rot = setup[0x1a];
            }
            ((void (*)(int*, int, int))((void**)*(void**)*(int*)&((GameObject*)spawned)->anim.dll)[8])(spawned, rot,
                                                                                                       setup[0x1b]);
        }
        state->fireTimer = state->firePeriod + (f32)(int)randomGetRange(0, 0x3c);
    }
}

void lavaball1bf_init(s16* obj, u8* p)
{
    Lavaball1bfState* inner;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)p[0x1c] << 8);
    inner = ((GameObject*)obj)->extra;
    inner->firePeriod = (f32) * (s16*)(p + 0x18);
    inner->fireTimer = lbl_803E4814;
    inner->gateA = p[0x1d];
    inner->gateB = mainGetBit((int)*(s16*)(p + 0x22));
    if (*(s16*)(p + 0x24) == -1 && inner->gateB == 0)
    {
        inner->soloLatch = 1;
    }
    ((GameObject*)obj)->objectFlags |= (DIMLAVABALL_OBJFLAG_HIDDEN | DIMLAVABALL_OBJFLAG_HITDETECT_DISABLED);
}

void lavaball1bf_release(void)
{
}

void lavaball1bf_initialise(void)
{
}
