/*
 * dim2pathgenerator (DLL 0x1D8) — snowball path-generator for Snowhorn Wastes 2.
 * Finds and loads a RomCurve spline near its placement position (curve group 21),
 * then periodically spawns dim2snowball objects (DLL type in spawnTypes[]) from a
 * free pool (object group 47) or via Obj_AllocObjectSetup, alternating between two
 * snowball types per spawn. Spawn rate and type are set from the placement data.
 */

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

#include "main/dll/rom_curve_interface.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/dll/DR/dr_802bbc10_shared.h"

#define DIM2PATHGENERATOR_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct Dim2pathgeneratorObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s16 spawnPeriod;
    s16 unk1A;
    s16 unk1C;
    u16 spawnType0; /* 0x1E primary spawn object type -> state->spawnTypes[0] */
    s16 spawnType1; /* 0x20 secondary spawn type (-1 = reuse spawnType0) -> spawnTypes[1] */
    u8 pad22[0x28 - 0x22];
} Dim2pathgeneratorObjectDef;

/* RomCurve definition record (subset) returned by gRomCurveInterface->getById. */
typedef struct Dim2RomCurveDef
{
    u8 pad0[0x8 - 0x0];
    f32 originX;
    f32 originY;
    f32 originZ;
} Dim2RomCurveDef;

/* Object spawn-setup descriptor written before Obj_SetupObject. */
typedef struct Dim2SpawnSetup
{
    u8 pad0[0x3 - 0x0];
    u8 unk3;
    u8 colorR;
    u8 colorG;
    u8 colorB;
    u8 colorA;
    f32 posX;
    f32 posY;
    f32 posZ;
    s32 mapId;
    s8 unk18;
    u8 pad19;
    s16 childRot; /* 0x1A rotation region of spawned child placement */
    s16 unk1C;
} Dim2SpawnSetup;

typedef struct Dim2pathgeneratorPlacement
{
    u8 pad0[0x3 - 0x0];
    u8 unk3;
    u8 colorR; /* 0x4 -> spawn setup head.unk04[0] */
    u8 colorG; /* 0x5 -> spawn setup head.unk04[1] */
    u8 colorB; /* 0x6 -> spawn setup head.unk04[2] */
    u8 colorA; /* 0x7 -> spawn setup head.unk04[3] (forced 0xff) */
    u8 pad8[0x14 - 0x8];
    s32 mapId;
    s16 spawnPeriod; /* 0x18 */
    s16 unk1A;
    s16 unk1C;
    u16 spawnType0; /* 0x1E */
    s16 spawnType1; /* 0x20 */
    s16 activeGameBit;
    u8 pad24[0x28 - 0x24];
} Dim2pathgeneratorPlacement;

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

#define CURVE_GROUP_SNOWBALL_PATH   21
#define OBJ_GROUP_SNOWBALL_POOL     47


extern int** ObjGroup_GetObjects(int group, int* countOut);

static inline int* DIM2snowball_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}


void dim2pathgenerator_free(void)
{
}

void dim2pathgenerator_render(void)
{
}

void dim2pathgenerator_hitDetect(void)
{
}

void dim2pathgenerator_release(void)
{
}

void dim2pathgenerator_initialise(void)
{
}

int dim2pathgenerator_getExtraSize(void) { return 0x9a8; }
int dim2pathgenerator_getObjectTypeId(void) { return 0x0; }


u8 dim2pathgenerator_getCurveVals(int* obj, int** p1, int** p2, int** p3, int** p4)
{
    int* state = ((GameObject*)obj)->extra;
    *p1 = (int*)((char*)state + 12);
    *p2 = (int*)((char*)state + 812);
    *p3 = (int*)((char*)state + 1612);
    if (p4 != NULL)
    {
        *p4 = (int*)((char*)state + 2412);
    }
    return ((Dim2PathGeneratorState*)state)->curveValid;
}


void dim2pathgenerator_init(int* obj, int* def)
{
    Dim2PathGeneratorState* state;
    *(s16*)obj = (s16)((u32) * (u8*)((char*)def + 28) << 8);
    state = ((GameObject*)obj)->extra;
    state->spawnPeriod = ((Dim2pathgeneratorObjectDef*)def)->spawnPeriod;
    state->spawnTimer = (s16) * (u8*)((char*)def + 29);
    state->spawnTypes[0] = (s16)((Dim2pathgeneratorObjectDef*)def)->spawnType0;
    {
        s16 v = ((Dim2pathgeneratorObjectDef*)def)->spawnType1;
        if (v == -1)
        {
            state->spawnTypes[1] = (s16)((Dim2pathgeneratorObjectDef*)def)->spawnType0;
        }
        else
        {
            state->spawnTypes[1] = v;
        }
    }
    state->flags = (u8)(state->flags | 4);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | DIM2PATHGENERATOR_OBJFLAG_HITDETECT_DISABLED);
}


void dim2pathgenerator_update(int* obj)
{
    int* def;
    int* extra = ((GameObject*)obj)->extra;
    int toggle;
    int** objs;
    int i;
    int n;
    int count;

    def = *(int**)&((GameObject*)obj)->anim.placementData;
    if (GameBit_Get(((Dim2pathgeneratorPlacement*)def)->activeGameBit) == 0)
    {
        return;
    }
    if ((((Dim2PathGeneratorState*)extra)->flags & 4) != 0)
    {
        if ((((Dim2PathGeneratorState*)extra)->flags & 2) == 0)
        {
            int found;
            n = CURVE_GROUP_SNOWBALL_PATH;
            found = ((int (*)(f32, f32, f32, int*, int, int))(*gRomCurveInterface)->find)(
                ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                ((GameObject*)obj)->anim.localPosZ, &n, 1, 10);
            if (found != -1)
            {
                int* cv = (int*)(*gRomCurveInterface)->getById(found);
                ((void (*)(int))(*gRomCurveInterface)->slot74)((int)cv);
                ((Dim2PathGeneratorState*)extra)->curveValid =
                    ((int (*)(int*, void*, void*, void*, void*))(*gRomCurveInterface)->slot78)(
                        cv, (char*)extra + 0xc, (char*)extra + 0x32c, (char*)extra + 0x64c,
                        (char*)extra + 0x96c);
                ((Dim2PathGeneratorState*)extra)->flags |= 2;
                ((Dim2PathGeneratorState*)extra)->originX = ((Dim2RomCurveDef*)cv)->originX;
                ((Dim2PathGeneratorState*)extra)->originY = ((Dim2RomCurveDef*)cv)->originY;
                ((Dim2PathGeneratorState*)extra)->originZ = ((Dim2RomCurveDef*)cv)->originZ;
            }
        }
    }
    else
    {
        ((Dim2PathGeneratorState*)extra)->originX = ((GameObject*)obj)->anim.localPosX;
        ((Dim2PathGeneratorState*)extra)->originY = ((GameObject*)obj)->anim.localPosY;
        ((Dim2PathGeneratorState*)extra)->originZ = ((GameObject*)obj)->anim.localPosZ;
    }
    if ((((Dim2PathGeneratorState*)extra)->spawnTimer -= framesThisStep) > 0)
    {
        return;
    }
    toggle = ((Dim2PathGeneratorState*)extra)->flags & 1;
    ((Dim2PathGeneratorState*)extra)->spawnTimer = ((Dim2PathGeneratorState*)extra)->spawnPeriod;
    ((Dim2PathGeneratorState*)extra)->flags &= ~1;
    objs = ObjGroup_GetObjects(OBJ_GROUP_SNOWBALL_POOL, &count);
    for (i = 0; i < count; i++)
    {
        if (((Dim2PathGeneratorState*)extra)->spawnTypes[toggle] == ((GameObject*)objs[i])->anim.seqId)
        {
            int* p = *(int**)((char*)objs[i] + 0x4c);
            int j;
            int** o2;
            ((Dim2SpawnSetup*)p)->posX = ((Dim2PathGeneratorState*)extra)->originX;
            ((Dim2SpawnSetup*)p)->posY = ((Dim2PathGeneratorState*)extra)->originY;
            ((Dim2SpawnSetup*)p)->posZ = ((Dim2PathGeneratorState*)extra)->originZ;
            ((Dim2SpawnSetup*)p)->mapId = ((Dim2pathgeneratorPlacement*)def)->mapId;
            (*(void (**)(int*, int*, int))(**(int**)((char*)objs[i] + 0x68) + 4))(objs[i], p, 1);
            ObjGroup_RemoveObject(objs[i], OBJ_GROUP_SNOWBALL_POOL);
            o2 = ObjGroup_GetObjects(OBJ_GROUP_SNOWBALL_POOL, &count);
            for (j = 0; j < count; j++)
            {
            }
            ((Dim2PathGeneratorState*)extra)->flags |= (toggle ^ 1) & 1;
            return;
        }
    }
    if (Obj_IsLoadingLocked())
    {
        int* np = (int*)Obj_AllocObjectSetup(36, ((s16*)((Dim2PathGeneratorState*)extra)->spawnTypes)[toggle]);
        ((Dim2SpawnSetup*)np)->posX = ((Dim2PathGeneratorState*)extra)->originX;
        ((Dim2SpawnSetup*)np)->posY = ((Dim2PathGeneratorState*)extra)->originY;
        ((Dim2SpawnSetup*)np)->posZ = ((Dim2PathGeneratorState*)extra)->originZ;
        ((Dim2SpawnSetup*)np)->colorR = ((Dim2pathgeneratorPlacement*)def)->colorR;
        ((Dim2SpawnSetup*)np)->colorB = ((Dim2pathgeneratorPlacement*)def)->colorB;
        ((Dim2SpawnSetup*)np)->colorG = ((Dim2pathgeneratorPlacement*)def)->colorG;
        ((Dim2SpawnSetup*)np)->colorA = ((Dim2pathgeneratorPlacement*)def)->colorA;
        ((Dim2SpawnSetup*)np)->colorA = 255;
        ((Dim2SpawnSetup*)np)->unk3 = ((Dim2pathgeneratorPlacement*)def)->unk3;
        ((Dim2SpawnSetup*)np)->unk18 = (s8) * (u8*)((char*)def + 0x1c);
        ((Dim2SpawnSetup*)np)->childRot = *(u8*)((char*)def + 0x1a);
        ((Dim2SpawnSetup*)np)->unk1C = *(u8*)((char*)def + 0x1b);
        ((Dim2SpawnSetup*)np)->mapId = ((Dim2pathgeneratorPlacement*)def)->mapId;
        Obj_SetupObject((int)np, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
        ((Dim2PathGeneratorState*)extra)->flags |= (toggle ^ 1) & 1;
    }
}
