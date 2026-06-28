/*
 * dimsnowball1c2 (DLL 0x1C2) — timed snowball spawner for Dinosaur Island
 * Mission.  On each timer expiry, if loading is not locked and the player
 * is clear, allocates a rolling-snowball object (kind 36, id 406) seeded
 * from the placement params and resets the spawn countdown.
 */
#include "main/dll/dimicewallstate_struct.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

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
    s32 unk14;
    s16 unk18; /* init: copied to extra (DimicewallState.unk2 + word 0) */
    u8 unk1A;
    u8 unk1B;
    s8 unk1C;
    u8 pad1D[0x1E - 0x1D];
    s16 unk1E;
} Dimsnowball1c2Placement;

extern int randomGetRange(int lo, int hi);
extern f32 lbl_803E4860;
extern void objRenderFn_8003b8f4(f32);
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

void dimgate_free(void);

int dimsnowball1c2_getObjectTypeId(void) { return 0x0; }
int dimgate_SeqFn(void);

void dimsnowball1c2_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4860);
}

void dimgate_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dimsnowball1c2_init(int obj, u8* p)
{
    Dimsnowball1c2Placement* def = (Dimsnowball1c2Placement*)p;
    char* inner;
    ((GameObject*)obj)->anim.rotX = (s16)((u32)p[0x1c] << 8);
    inner = ((GameObject*)obj)->extra;
    ((DimicewallState*)inner)->unk2 = def->unk18;
    *(s16*)inner = def->unk18;
    ((GameObject*)obj)->objectFlags |= 0x6000;
}

void dimicewall_init(int obj, s8* p);

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
                np->mapId = def->unk14;
                {
                    int t1c = def->unk1C;
                    *(s8*)((char*)np + 0x18) = t1c;
                }
                *(s16*)((char*)np + 0x1a) = def->unk1A;
                *(s16*)((char*)np + 0x1c) =
                    (f32)(u32)def->unk1B +
                    (f32)(int)randomGetRange(0, 100) / lbl_803E4864;
                Obj_SetupObject((int)np, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
                *(s16*)extra = ((Dimsnowball1c2State*)extra)->spawnPeriod;
            }
        }
    }
}
