/*
 * dimsnowball1c2 (DLL 0x1C2) — timed snowball spawner for Dinosaur Island
 * Mission.  On each timer expiry, if loading is not locked and the player
 * is clear, allocates a rolling-snowball object (kind 36, id 406) seeded
 * from the placement params and resets the spawn countdown.
 */
#include "main/dll/dimicewallstate_struct.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#define DIMSNOWBALL1C2_OBJFLAG_HITDETECT_DISABLED 0x2000
#define DIMSNOWBALL1C2_OBJFLAG_HIDDEN 0x4000

typedef struct Dimsnowball1c2State
{
    s8 countdown;
    u8 pad1[0x2 - 0x1];
    s16 spawnPeriod;
    u8 pad4[0x8 - 0x4];
} Dimsnowball1c2State;

typedef struct Dimsnowball1c2Placement
{
    u8 pad0[0x4 - 0x0];
    u8 colorR; /* 0x4 -> spawn setup head.unk04[0] */
    u8 colorG; /* 0x5 -> spawn setup head.unk04[1] */
    u8 colorB; /* 0x6 -> spawn setup head.unk04[2] */
    u8 colorA; /* 0x7 -> spawn setup head.unk04[3] */
    u8 pad8[0x14 - 0x8];
    s32 mapId;
    s16 initialCountdown; /* init: copied to extra (DimicewallState.unk2 + word 0) */
    u8 childRot; /* copied to spawned child placement 0x1A (rotation) */
    u8 childZOffset; /* base for spawned child placement 0x1C (+random) */
    s8 rotByte; /* 0x1C rotation byte; also -> child placement 0x18 */
    u8 pad1D[0x1E - 0x1D];
    s16 unk1E;
} Dimsnowball1c2Placement;

extern int randomGetRange(int lo, int hi);
extern f32 lbl_803E4860;
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern u8 framesThisStep;
extern u8 Obj_IsLoadingLocked(void);
extern u32 fn_802972A8(int player);
extern void* Obj_AllocObjectSetup(int size, int b);
extern void* Obj_SetupObject(int a, int b, int c, int d, int e);
extern f32 lbl_803E4864;

int dimsnowball1c2_getExtraSize(void)
{
    return 4;
}

void dimsnowball1c2_free(void)
{
}

void dimsnowball1c2_hitDetect(void)
{
}

void dimsnowball1c2_release(void)
{
}

void dimsnowball1c2_initialise(void)
{
}


int dimsnowball1c2_getObjectTypeId(void) { return 0x0; }

void dimsnowball1c2_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E4860);
}


void dimsnowball1c2_init(int obj, u8* p)
{
    Dimsnowball1c2Placement* def = (Dimsnowball1c2Placement*)p;
    char* inner;
    ((GameObject*)obj)->anim.rotX = (s16)((u32)p[0x1c] << 8);
    inner = ((GameObject*)obj)->extra;
    ((DimicewallState*)inner)->unk2 = def->initialCountdown;
    *(s16*)inner = def->initialCountdown;
    ((GameObject*)obj)->objectFlags |= (DIMSNOWBALL1C2_OBJFLAG_HIDDEN | DIMSNOWBALL1C2_OBJFLAG_HITDETECT_DISABLED);
}


void dimsnowball1c2_update(int* obj)
{
    if (Obj_IsLoadingLocked())
    {
        int* extra = ((GameObject*)obj)->extra;
        if ((*(s16*)extra -= framesThisStep) <= 0)
        {
            if (fn_802972A8(Obj_GetPlayerObject()) == 0)
            {
                ObjPlacement* np;
                Dimsnowball1c2Placement* def;
                def = *(Dimsnowball1c2Placement**)&((GameObject*)obj)->anim.placementData;
                np = (ObjPlacement*)Obj_AllocObjectSetup(36, 406);
                np->color[0] = def->colorR;
                np->color[2] = def->colorB;
                np->color[1] = def->colorG;
                np->color[3] = def->colorA;
                np->posX = ((GameObject*)obj)->anim.localPosX;
                np->posY = ((GameObject*)obj)->anim.localPosY;
                np->posZ = ((GameObject*)obj)->anim.localPosZ;
                np->mapId = def->mapId;
                {
                    int t1c = def->rotByte;
                    *(s8*)((char*)np + 0x18) = t1c;
                }
                *(s16*)((char*)np + 0x1a) = def->childRot;
                *(s16*)((char*)np + 0x1c) =
                    (f32)(u32)def->childZOffset +
                    (f32)(int)randomGetRange(0, 100) / lbl_803E4864;
                Obj_SetupObject((int)np, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
                *(s16*)extra = ((Dimsnowball1c2State*)extra)->spawnPeriod;
            }
        }
    }
}
