#include "main/dll/cfforcefield.h"
#include "main/dll/explodable.h"
#include "main/game_object.h"
#include "main/dll/cfforcefield_state.h"
#include "main/resource.h"


extern uint GameBit_Get(int eventId);
extern void ObjHits_DisableObject(u32 obj);
extern u32 randomGetRange(int min, int max);
extern void hitDetect_calcSweptSphereBounds(u32* boundsOut, f32* startPoints, f32* endPoints, f32* radii,
                                            int pointCount);
extern void hitDetectFn_800691c0(int obj, void* bounds, uint mask, int flags);
extern u8 hitDetectFn_80067958(int obj, f32* startPoints, f32* endPoints, int pointCount,
                               void* outHits, int flags);

extern f32 lbl_803AC7A0[4];
extern void* lbl_803DDAC8;
extern f32 lbl_803E39AC;
extern f32 lbl_803E39E8;
extern f32 lbl_803E39F4;

typedef union LargeCrateVariantRemap
{
    s16 entries[6];
    int words[3];
} LargeCrateVariantRemap;

extern LargeCrateVariantRemap lbl_802C2280;
extern LargeCrateVariantRemap lbl_802C228C;

/*
 * --INFO--
 *
 * Function: largecrate_init
 * EN v1.0 Address: 0x80184180
 * EN v1.0 Size: 568b
 * EN v1.1 Address: 0x801841F4
 * EN v1.1 Size: 568b
 */
void largecrate_init(int obj, u8* initData)
{
    int state;
    u32 r3rand;
    f32 fr;
    LargeCrateVariantRemap constArrA;
    LargeCrateVariantRemap constArrB;
    short id;

    /* copy two constant blobs to stack (used as lookup arrays) */
    constArrA = lbl_802C2280;
    constArrB = lbl_802C228C;

    state = *(int*)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)LargeCrate_SeqFn;
    *(short*)obj = (short)((int)(signed char)initData[0x18] << 8);
    ((CfForcefieldState*)state)->enableGameBit = *(short*)(initData + 0x1e);

    id = *(short*)(initData + 0x1c);
    if (id == LARGECRATE_TIMER_SENTINEL_DISABLED)
    {
        *(int*)state = LARGECRATE_TIMER_SENTINEL_DISABLED;
    }
    else if (id == LARGECRATE_TIMER_SENTINEL_FOREVER)
    {
        *(int*)state = -1;
    }
    else
    {
        *(int*)state = (int)id * LARGECRATE_TIMER_SCALE_FRAMES;
    }

    if (GameBit_Get((int)((CfForcefieldState*)state)->enableGameBit) != 0)
    {
        *(float*)(state + 4) = lbl_803E39AC;
        ObjHits_DisableObject((u32)obj);
    }

    ((CfForcefieldState*)state)->unk11 = initData[0x19];
    lbl_803DDAC8 = Resource_Acquire(LARGECRATE_RESOURCE_ID, LARGECRATE_RESOURCE_MODE);
    r3rand = randomGetRange(LARGECRATE_RANDOM_DELAY_MIN, LARGECRATE_RANDOM_DELAY_MAX);
    ((CfForcefieldState*)state)->randomTimer = (short)(r3rand + LARGECRATE_RANDOM_DELAY_BASE);
    ((CfForcefieldState*)state)->countdown = LARGECRATE_DEFAULT_COUNTDOWN;
    ((CfForcefieldState*)state)->unk12 = (u8) * (short*)(initData + 0x1a);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | LARGECRATE_OBJECT_FLAGS);
    *(short*)obj = (short)((int)(signed char)initData[0x18] << 8);

    id = ((GameObject*)obj)->anim.seqId;
    if (id == LARGECRATE_VARIANT_A)
    {
        ((CfForcefieldState*)state)->unk11 = (u8)constArrA.entries[((CfForcefieldState*)state)->unk11];
        ((CfForcefieldState*)state)->sfxIdA = LARGECRATE_VARIANT_A_SFX_A;
        ((CfForcefieldState*)state)->sfxIdB = LARGECRATE_VARIANT_A_SFX_B;
    }
    else if (id == LARGECRATE_VARIANT_B || id == LARGECRATE_VARIANT_C)
    {
        ((CfForcefieldState*)state)->unk11 = (u8)constArrB.entries[((CfForcefieldState*)state)->unk11];
        ((CfForcefieldState*)state)->sfxIdA = LARGECRATE_VARIANT_B_SFX_A;
        ((CfForcefieldState*)state)->sfxIdB = LARGECRATE_VARIANT_B_SFX_B;
    }

    ((CfForcefieldState*)state)->unk20 = 0;
    r3rand = randomGetRange(LARGECRATE_RANDOM_DELAY_MIN, LARGECRATE_RANDOM_BOB_MAX);
    fr = (float)(int)r3rand;
    fr = lbl_803E39E8 + fr;
    *(float*)(state + 0x1c) = fr;
    *(float*)(state + 0x24) = ((GameObject*)obj)->anim.localPosX;

    if (((GameObject*)obj)->anim.seqId == LARGECRATE_VARIANT_C)
    {
        ((CfForcefieldState*)state)->unk28 = 0;
    }
    else
    {
        ((CfForcefieldState*)state)->unk28 = 2;
    }
}

/*
 * --INFO--
 *
 * Function: largecrate_release
 * EN v1.0 Address: 0x801843B8
 * EN v1.0 Size: 4b
 */
void largecrate_release(void)
{
}

/*
 * --INFO--
 *
 * Function: largecrate_initialise
 * EN v1.0 Address: 0x801843BC
 * EN v1.0 Size: 4b
 */
void largecrate_initialise(void)
{
}

