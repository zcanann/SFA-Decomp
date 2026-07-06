/* DLL 0x01CD — DIM level-control object for Snowhorn Wastes 2.
 * Manages time-of-day music (day=0xC5, night=0xE2), map-event latching via
 * SCGameBitLatch_Update (8 latch bits controlling music triggers), environment
 * fx for the lava area, an NPC dialogue trigger (game bits 0x3E2/0x3E3), and
 * initial level unlock. */
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
#include "main/audio/sfx_ids.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/sky_interface.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx.h"
#include "main/audio/music_trigger_ids.h"

#define DIMLEVELCONTROL_OBJFLAG_HITDETECT_DISABLED 0x2000
#define DIMLEVELCONTROL_OBJFLAG_HIDDEN 0x4000

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


extern f32 lbl_803E4A20;
extern void timeOfDayFn_80055000(void);
STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);
STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);
STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);
STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);
STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);
#define DIMLEVELCONTROL_MUSIC_DAY   0xc5
#define DIMLEVELCONTROL_MUSIC_NIGHT 0xe2

extern int getEnvfxActImmediately(int a, int b, u16 idx, int d);
extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern void gameTextSetColor(u8 r, u8 g, u8 b, u8 a);
extern void gameTextShow(int a);
extern void SCGameBitLatch_Update(int* state, int mask, int a, int b, int bit, int value);
extern f32 lbl_803E4A24;
extern f32 lbl_803E4A28;
extern int getSaveGameLoadStatus(void);
extern void gameBitFn_800ea2e0(u8 id);
extern int unlockLevel(s32 val, int idx, int flag);

int dim_levelcontrol_getExtraSize(void) { return 0x10; }

void dim_levelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderModelAndHitVolumes(int p1, int p2, int p3, int p4, int p5, f32 v);
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E4A20);
}

void dim_levelcontrol_free(int p1)
{
    extern void Music_Trigger(int id, int arg);
    Music_Trigger(MUSICTRIG_drako_1, 0);
    Music_Trigger(MUSICTRIG_citytombs_ed, 0);
    timeOfDayFn_80055000();
}

#pragma dont_inline on
#pragma dont_inline reset

FbWGPipe GXWGFifo : (0xCC008000);

static inline int* DIM2snowball_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

typedef struct DimLevelControlState
{
    f32 timer;
    int latch;
    u8 saveState;
    u8 unk9;
    s16 musicTrack;
    u8 dialogueFired;
    u8 groupStatus;
    u8 b7 : 1;
    u8 b6 : 1;
    u8 b5 : 1;
    u8 b4 : 1;
    u8 b3 : 1;
} DimLevelControlState;

void dim_levelcontrol_update(int obj)
{
    extern void Music_Trigger(int id, int arg);

    u8 a;
    u8 b;
    u8 c;
    u8 d;
    DimLevelControlState* st;
    u32 t;
    u32 t2;

    a = GameBit_Get(0xd0b);
    b = GameBit_Get(0xd0c);
    c = GameBit_Get(0xd0d);
    d = GameBit_Get(0xd0e);
    st = ((GameObject*)obj)->extra;
    if ((a && !st->b7) || (b && !st->b6) || (c && !st->b5) || (d && !st->b4))
    {
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
    }
    st->b7 = a;
    st->b6 = b;
    st->b5 = c;
    st->b4 = d;
    if (!st->b3 && GameBit_Get(0xa21) != 0)
    {
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
        st->b3 = 1;
    }
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if ((u32)GameBit_Get(0xa82) == 0 ||
            ((u32)GameBit_Get(0x17) != 0 && GameBit_Get(0xead) == 0))
        {
            if (((GameObject*)obj)->unkF4 == 2)
            {
                getEnvfxActImmediately(0, 0, 0x160, 0);
                getEnvfxActImmediately(0, 0, 0x15a, 0);
                getEnvfxActImmediately(0, 0, 0x15c, 0);
                getEnvfxActImmediately(0, 0, 0x15f, 0);
            }
            else
            {
                getEnvfxAct(0, 0, 0x160, 0);
                getEnvfxAct(0, 0, 0x15a, 0);
                getEnvfxAct(0, 0, 0x15c, 0);
                getEnvfxAct(0, 0, 0x15f, 0);
            }
        }
        ((GameObject*)obj)->unkF4 = 0;
    }
    if (st->groupStatus != 0)
    {
        if ((u32)GameBit_Get(0x651) == 0)
        {
            (*gMapEventInterface)->setObjGroupStatus(0x13, 0xd, 0);
            st->groupStatus = 0;
        }
    }
    else
    {
        if ((u32)GameBit_Get(0x651) != 0)
        {
            (*gMapEventInterface)->setObjGroupStatus(0x13, 0xd, 1);
            st->groupStatus = 1;
        }
    }
    if (st->timer > lbl_803E4A24)
    {
        gameTextSetColor(0xff, 0xff, 0xff, 0xff);
        gameTextShow(0x430);
        st->timer = st->timer - timeDelta;
        if (st->timer < *(f32*)&lbl_803E4A24)
        {
            st->timer = lbl_803E4A24;
        }
    }
    if (st->dialogueFired == 0)
    {
        t = GameBit_Get(0x3e2);
        t2 = GameBit_Get(0x3e3);
        st->dialogueFired = (u8)(t2 & t);
        if (st->dialogueFired != 0)
        {
            (*gGameUIInterface)->showNpcDialogue(0x4ba, 0x14, 0x8c, 1);
        }
    }
    t = GameBit_Get(0x3e2);
    {
        int gb = !GameBit_Get(0x3e3);
        t = gb & t;
    }
    t2 = t & 0xff;
    if (t2 != st->saveState)
    {
        GameBit_Set(0x3e8, t2);
        st->saveState = t2;
    }
    if (!(u8)GameBit_Get(0x8a5) && GameBit_Get(0x89d) != 0)
    {
        GameBit_Set(0x8a4, 1);
    }
    if ((*gSkyInterface)->getSunPosition(0) == 0)
    {
        if (st->musicTrack != DIMLEVELCONTROL_MUSIC_NIGHT)
        {
            st->musicTrack = DIMLEVELCONTROL_MUSIC_NIGHT;
            if (st->latch & 4)
            {
                Music_Trigger(DIMLEVELCONTROL_MUSIC_DAY, 0);
                Music_Trigger(DIMLEVELCONTROL_MUSIC_NIGHT, 1);
            }
        }
    }
    else
    {
        if (st->musicTrack != DIMLEVELCONTROL_MUSIC_DAY)
        {
            st->musicTrack = DIMLEVELCONTROL_MUSIC_DAY;
            if (st->latch & 4)
            {
                Music_Trigger(DIMLEVELCONTROL_MUSIC_NIGHT, 0);
                Music_Trigger(DIMLEVELCONTROL_MUSIC_DAY, 1);
            }
        }
    }
    SCGameBitLatch_Update(&st->latch, 1, 0x1a7, 0x64b, 0xc1e, 0xa1);
    SCGameBitLatch_Update(&st->latch, 2, 0x1a8, 0xc0, 0xc1f, 0xcf);
    SCGameBitLatch_Update(&st->latch, 4, 0x1ba, 0x1b9, 0xc20, st->musicTrack);
    SCGameBitLatch_Update(&st->latch, 8, -1, -1, 0xd8f, 0xdc);
    SCGameBitLatch_Update(&st->latch, 0x10, 0x1a7, 0x64b, 0xc1e, 0xed);
    SCGameBitLatch_Update(&st->latch, 0x20, 0x1a8, 0xc0, 0xc1f, 0x36);
    SCGameBitLatch_Update(&st->latch, 0x40, 0x1ba, 0x1b9, 0xc20, 0x35);
    SCGameBitLatch_Update(&st->latch, 0x100, -1, -1, 0x3e2, 0x2b);
}


void dim_levelcontrol_init(int obj)
{
    DimLevelControlState* st;
    u8 i;

    randomGetRange(0, 11);
    st = ((GameObject*)obj)->extra;
    st->saveState = 0;
    st->timer = lbl_803E4A28;
    if (getSaveGameLoadStatus() != 0)
    {
        ((GameObject*)obj)->unkF4 = 2;
    }
    else
    {
        ((GameObject*)obj)->unkF4 = 1;
    }
    for (i = 1; i <= 38; i++)
    {
        gameBitFn_800ea2e0(i);
    }
    st->dialogueFired = GameBit_Get(0xdc);
    GameBit_Set(0xf0a, 0);
    if ((u32)GameBit_Get(0x89d) != 0 && GameBit_Get(0x8a5) == 0)
    {
        GameBit_Set(0x89d, 0);
    }
    st->b7 = GameBit_Get(0xd0b);
    st->b6 = GameBit_Get(0xd0c);
    st->b5 = GameBit_Get(0xd0d);
    st->b4 = GameBit_Get(0xd0e);
    st->b3 = GameBit_Get(0xa21);
    (*gMapEventInterface)->setMapAct(((GameObject*)obj)->anim.mapEventSlot, 1);
    ((GameObject*)obj)->objectFlags |= (DIMLEVELCONTROL_OBJFLAG_HIDDEN | DIMLEVELCONTROL_OBJFLAG_HITDETECT_DISABLED);
    unlockLevel(0, 0, 1);
}

