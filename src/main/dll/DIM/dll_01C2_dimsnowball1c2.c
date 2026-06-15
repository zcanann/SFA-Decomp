/*
 * dimsnowball1c2 (DLL 0x1C2) — timed snowball spawner for Dinosaur Island
 * Mission.  On each timer expiry, if loading is not locked and the player
 * is clear, allocates a rolling-snowball object (kind 36, id 406) seeded
 * from the placement params and resets the spawn countdown.
 */
#include "main/dll/dimicewallstate_struct.h"
#include "main/game_object.h"

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
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    u8 pad8[0x14 - 0x8];
    s32 unk14;
    u8 pad18[0x19 - 0x18];
    s8 unk19;
    u8 unk1A;
    u8 unk1B;
    s8 unk1C;
    u8 pad1D[0x1E - 0x1D];
    s16 unk1E;
} Dimsnowball1c2Placement;

extern u32 randomGetRange(int min, int max);
extern f32 lbl_803E4860;
extern void objRenderFn_8003b8f4(f32);
extern u8 framesThisStep;
extern u8 Obj_IsLoadingLocked(void);
extern uint fn_802972A8(int player);
extern int Obj_AllocObjectSetup(int kind, int id);
extern int Obj_SetupObject(int handle, int a, int b, int c, int d);
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
    char* inner;
    *(s16*)obj = (s16)((u32)p[0x1c] << 8);
    inner = ((GameObject*)obj)->extra;
    ((DimicewallState*)inner)->unk2 = *(s16*)(p + 0x18);
    *(s16*)inner = *(s16*)(p + 0x18);
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
                int* np;
                int* def;
                def = *(int**)&((GameObject*)obj)->anim.placementData;
                np = (int*)Obj_AllocObjectSetup(36, 406);
                *(u8*)((char*)np + 4) = ((Dimsnowball1c2Placement*)def)->unk4;
                *(u8*)((char*)np + 6) = ((Dimsnowball1c2Placement*)def)->unk6;
                *(u8*)((char*)np + 5) = ((Dimsnowball1c2Placement*)def)->unk5;
                *(u8*)((char*)np + 7) = ((Dimsnowball1c2Placement*)def)->unk7;
                *(f32*)((char*)np + 8) = ((GameObject*)obj)->anim.localPosX;
                *(f32*)((char*)np + 0xc) = ((GameObject*)obj)->anim.localPosY;
                *(f32*)&((ObjDef*)np)->jointData = ((GameObject*)obj)->anim.localPosZ;
                *(int*)((char*)np + 0x14) = ((Dimsnowball1c2Placement*)def)->unk14;
                {
                    int t1c = ((Dimsnowball1c2Placement*)def)->unk1C;
                    *(s8*)((char*)np + 0x18) = t1c;
                }
                *(s16*)((char*)np + 0x1a) = ((Dimsnowball1c2Placement*)def)->unk1A;
                *(s16*)((char*)np + 0x1c) =
                    (f32)(u32)((Dimsnowball1c2Placement*)def)->unk1B +
                    (f32)(int)randomGetRange(0, 100) / lbl_803E4864;
                Obj_SetupObject((int)np, 5, ((GameObject*)obj)->anim.mapEventSlot, -1, 0);
                *(s16*)extra = ((Dimsnowball1c2State*)extra)->spawnPeriod;
            }
        }
    }
}
