/*
 * msplantings (DLL 0x25B) - moon-seed planting spots.
 *
 * Each spot is a placeable object identified by its placement mapId; init maps
 * that id to a pair of game bits: one tracking whether a seed has been planted
 * here (sub+8), the other whether the grown plant has been harvested (sub+0xa).
 * The object walks a small state machine in update (phase byte at extra+0):
 * INIT -> EMPTY (alpha fades in, posY raised) -> GROWN/idle (pulses colour,
 * spawns directional fx, accepts a priority hit of type 0x1a to be cut) -> CUT
 * -> HARVESTED. The shared "seeds carried" counter is game bit 0x86A; planting
 * decrements it and runs object sequence 0. render tints the model per phase;
 * setScale is the trigger-volume callback that cuts/harvests.
 */
#include "main/dll/DIM/dimlogfire.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objseq.h"

/* shared "moon seeds carried" counter game bit */
#define GAMEBIT_MOONSEED_COUNT 0x86A
/* object-group id the planting spots register into */
#define MSPLANTING_OBJ_GROUP 0x2E

/* phase byte values (state byte at extra[0]) */
#define MSPLANTING_PHASE_INIT 0
#define MSPLANTING_PHASE_EMPTY 1
#define MSPLANTING_PHASE_GROWN 2
#define MSPLANTING_PHASE_CUT 3
#define MSPLANTING_PHASE_HARVESTED 4

/* state->flags bits */
#define MSPLANTING_FLAG_PLANTED 1
#define MSPLANTING_FLAG_VISIBLE 2
#define MSPLANTING_FLAG_BURST 4

/* ObjHits priority-hit result that cuts the plant */
#define MSPLANTING_HIT_CUT 0x1A

typedef struct MoonSeedPlantingSpotPlacement
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
} MoonSeedPlantingSpotPlacement;

typedef struct MoonSeedPlantingSpotState
{
    u8 pad0[0x1 - 0x0];
    u8 flags;
    u8 pad2[0x8 - 0x2];
    s16 plantedGameBit;
    s16 harvestedGameBit;
    s16 colorPhase;
    u8 padE[0x10 - 0xE];
    f32 unk10;
    f32 unk14;
} MoonSeedPlantingSpotState;

STATIC_ASSERT(sizeof(MoonSeedPlantingSpotState) == 0x18);

extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern u32 randomGetRange(int min, int max);
extern int ObjHits_GetPriorityHit();
extern void ObjGroup_RemoveObject(int obj, int group);
extern void ObjGroup_AddObject(int obj, int group);

extern void objRenderFn_8003b8f4(f32);
extern f32 timeDelta;
extern int Obj_GetPlayerObject(void);
extern void Sfx_PlayFromObject(int obj, int id);
extern f32 getXZDistance(f32 * a, f32 * b);
extern int getTrickyObject(void);
extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f);
extern f32 lbl_803E45DC;
extern f32 lbl_803E45F0;
extern f32 lbl_803E45F4;
extern f32 lbl_803E45F8;
extern f32 lbl_803E45FC;
extern f32 lbl_803E4600;
extern f32 lbl_803E4604;
extern f32 lbl_803E4608;
extern f32 lbl_803E45D8;
extern f32 lbl_803E45E0;
extern f32 lbl_803E45E4;
extern f32 mathSinf(f32 x);
extern void fn_8003B608(int r, int g, int b);

void MoonSeedPlantingSpot_hitDetect(void)
{
}

void MoonSeedPlantingSpot_release(void)
{
}

void MoonSeedPlantingSpot_initialise(void)
{
}

#pragma scheduling off
#pragma peephole off
void MoonSeedPlantingSpot_init(int* obj, u8* init)
{
    u8* sub;
    int mapId;

    sub = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = MoonSeedPlantingSpot_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)(init[0x1f] << 8);
    sub[0] = MSPLANTING_PHASE_INIT;
    ObjGroup_AddObject((int)obj, MSPLANTING_OBJ_GROUP);
    mapId = *(int*)(init + 0x14);
    switch (mapId)
    {
    case 0x41a5b:
        ((MoonSeedPlantingSpotState*)sub)->plantedGameBit = 0x866;
        ((MoonSeedPlantingSpotState*)sub)->harvestedGameBit = 0x856;
        break;
    case 0x41a59:
        ((MoonSeedPlantingSpotState*)sub)->plantedGameBit = 0x867;
        ((MoonSeedPlantingSpotState*)sub)->harvestedGameBit = 0x858;
        break;
    case 0x41a5c:
        ((MoonSeedPlantingSpotState*)sub)->plantedGameBit = 0x868;
        ((MoonSeedPlantingSpotState*)sub)->harvestedGameBit = 0x85a;
        break;
    case 0x41a5d:
        ((MoonSeedPlantingSpotState*)sub)->plantedGameBit = 0x869;
        ((MoonSeedPlantingSpotState*)sub)->harvestedGameBit = 0x864;
        break;
    case 0x43e04:
        ((MoonSeedPlantingSpotState*)sub)->plantedGameBit = 0x9a2;
        ((MoonSeedPlantingSpotState*)sub)->harvestedGameBit = 0x99a;
        break;
    case 0x43e1f:
        ((MoonSeedPlantingSpotState*)sub)->plantedGameBit = 0x9a3;
        ((MoonSeedPlantingSpotState*)sub)->harvestedGameBit = 0x99c;
        break;
    case 0x43e20:
        ((MoonSeedPlantingSpotState*)sub)->plantedGameBit = 0x9a4;
        ((MoonSeedPlantingSpotState*)sub)->harvestedGameBit = 0x99e;
        break;
    case 0x43e21:
        ((MoonSeedPlantingSpotState*)sub)->plantedGameBit = 0x9a5;
        ((MoonSeedPlantingSpotState*)sub)->harvestedGameBit = 0x9a0;
        break;
    case 0x476ae:
        ((MoonSeedPlantingSpotState*)sub)->plantedGameBit = 0x3d5;
        ((MoonSeedPlantingSpotState*)sub)->harvestedGameBit = 0x3d2;
        break;
    case 0x4b26e:
        ((MoonSeedPlantingSpotState*)sub)->plantedGameBit = 0xd4d;
        ((MoonSeedPlantingSpotState*)sub)->harvestedGameBit = 0xd4b;
        break;
    case 0x4bea3:
        ((MoonSeedPlantingSpotState*)sub)->plantedGameBit = 0xe21;
        ((MoonSeedPlantingSpotState*)sub)->harvestedGameBit = 0xe10;
        break;
    }
    sub[1] = 0;
}

int MoonSeedPlantingSpot_render2(void) { return 0x2; }
int MoonSeedPlantingSpot_modelMtxFn(void) { return 0x0; }
int MoonSeedPlantingSpot_func0B(void) { return 0x0; }
int MoonSeedPlantingSpot_getExtraSize(void) { return sizeof(MoonSeedPlantingSpotState); }
int MoonSeedPlantingSpot_getObjectTypeId(void) { return 0x1; }

void MoonSeedPlantingSpot_free(int x) { ObjGroup_RemoveObject(x, MSPLANTING_OBJ_GROUP); }

int MoonSeedPlantingSpot_SeqFn(int obj)
{
    obj = *(int*)&((GameObject*)obj)->extra;
    ((MoonSeedPlantingSpotState*)obj)->flags = (u8)((u32)((MoonSeedPlantingSpotState*)obj)->flags | MSPLANTING_FLAG_PLANTED);
    return 0;
}

void MoonSeedPlantingSpot_update(int obj)
{
    int ex = *(int*)&((GameObject*)obj)->extra;
    int setup = *(int*)&((GameObject*)obj)->anim.placementData;
    if (((MoonSeedPlantingSpotState*)ex)->flags & MSPLANTING_FLAG_PLANTED)
    {
        *(u8*)ex = MSPLANTING_PHASE_GROWN;
        GameBit_Set(((MoonSeedPlantingSpotState*)ex)->plantedGameBit, 1);
        ((MoonSeedPlantingSpotState*)ex)->flags = ((MoonSeedPlantingSpotState*)ex)->flags & ~MSPLANTING_FLAG_PLANTED;
        ((GameObject*)obj)->anim.alpha = 0xff;
    }
    if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 4) && !(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 8))
    {
        if (GameBit_Get(GAMEBIT_MOONSEED_COUNT) != 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x10;
        }
        else
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
        }
    }
    ((MoonSeedPlantingSpotState*)ex)->flags |= MSPLANTING_FLAG_VISIBLE;
    switch (*(u8*)ex)
    {
    case MSPLANTING_PHASE_INIT:
        *(u8*)ex = MSPLANTING_PHASE_EMPTY;
        ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY - lbl_803E45F0;
        if (GameBit_Get(((MoonSeedPlantingSpotState*)ex)->plantedGameBit) != 0)
        {
            *(u8*)ex = MSPLANTING_PHASE_GROWN;
            ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY;
            ((GameObject*)obj)->anim.alpha = 0xff;
        }
        if (GameBit_Get(((MoonSeedPlantingSpotState*)ex)->harvestedGameBit) != 0)
        {
            int setup2;
            int ex2;
            ex2 = *(int*)&((GameObject*)obj)->extra;
            setup2 = *(int*)&((GameObject*)obj)->anim.placementData;
            if (GameBit_Get(((MoonSeedPlantingSpotState*)ex2)->plantedGameBit) != 0)
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
                GameBit_Set(((MoonSeedPlantingSpotState*)ex2)->harvestedGameBit, 1);
                *(u8*)ex2 = MSPLANTING_PHASE_HARVESTED;
                ((GameObject*)obj)->anim.localPosY = ((MoonSeedPlantingSpotPlacement*)setup2)->unkC;
            }
        }
        break;
    case MSPLANTING_PHASE_EMPTY:
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & 1) &&
            (*gGameUIInterface)->isEventReady(GAMEBIT_MOONSEED_COUNT) != 0)
        {
            int cnt = GameBit_Get(GAMEBIT_MOONSEED_COUNT);
            if (cnt != 0)
            {
                ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY;
                ((GameObject*)obj)->anim.alpha = 0;
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                GameBit_Set(GAMEBIT_MOONSEED_COUNT, cnt - 1);
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            }
        }
        break;
    case MSPLANTING_PHASE_GROWN:
        {
            int tricky = getTrickyObject();
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            if (((MoonSeedPlantingSpotState*)ex)->flags & MSPLANTING_FLAG_VISIBLE)
            {
                void* player;
                if (((MoonSeedPlantingSpotState*)ex)->flags & MSPLANTING_FLAG_BURST)
                {
                    ((GameObject*)obj)->anim.localPosY =
                        ((ObjPlacement*)setup)->posY + (f32)(int)
                    randomGetRange(-1, 1);
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x70f, NULL, 2, -1, NULL);
                }
                ((MoonSeedPlantingSpotState*)ex)->unk14 = ((MoonSeedPlantingSpotState*)ex)->unk14 - timeDelta;
                if (((MoonSeedPlantingSpotState*)ex)->unk14 <= lbl_803E45F4)
                {
                    if ((int)randomGetRange(0, 1) != 0)
                    {
                        ((MoonSeedPlantingSpotState*)ex)->unk14 = lbl_803E45F8;
                        ((MoonSeedPlantingSpotState*)ex)->flags |= MSPLANTING_FLAG_BURST;
                        Sfx_PlayFromObject(obj, 0x438);
                    }
                    else
                    {
                        ((MoonSeedPlantingSpotState*)ex)->unk14 = (f32)(int)
                        randomGetRange(0x32, 200);
                        ((MoonSeedPlantingSpotState*)ex)->flags &= ~MSPLANTING_FLAG_BURST;
                    }
                }
                player = (void*)Obj_GetPlayerObject();
                if (player != NULL && getXZDistance(&((GameObject*)player)->anim.worldPosX,
                                                    &((GameObject*)obj)->anim.worldPosX) <= lbl_803E45FC)
                {
                    objfx_spawnDirectionalBurst(obj, 5, lbl_803E45DC, 5, 1, 0x28, lbl_803E4600, 0, 0);
                    (*(void (*)(int, int, int, int))(*(int*)(*(int*)(*(int*)((char*)tricky + 0x68)) + 0x28)))(
                        tricky, obj, 1, 4);
                }
                else
                {
                    objfx_spawnDirectionalBurst(obj, 5, lbl_803E45DC, 6, 1, 0x28, lbl_803E4604, 0, 0);
                }
                if (ObjHits_GetPriorityHit(obj, 0, 0, 0) == MSPLANTING_HIT_CUT)
                {
                    *(u8*)ex = MSPLANTING_PHASE_CUT;
                    ((MoonSeedPlantingSpotState*)ex)->colorPhase = 0;
                    ((MoonSeedPlantingSpotState*)ex)->unk10 = lbl_803E4608;
                }
            }
            break;
        }
    case MSPLANTING_PHASE_CUT:
        {
            int tricky = getTrickyObject();
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
            ((GameObject*)obj)->anim.localPosY = ((ObjPlacement*)setup)->posY;
            if (getXZDistance((f32*)(tricky + 0x18), &((GameObject*)obj)->anim.worldPosX) <= lbl_803E45FC)
            {
                objfx_spawnDirectionalBurst(obj, 5, lbl_803E45DC, 5, 1, 0x28, lbl_803E4600, 0, 0);
            }
            else
            {
                objfx_spawnDirectionalBurst(obj, 5, lbl_803E45DC, 6, 1, 0x28, lbl_803E4604, 0, 0);
            }
            if (((MoonSeedPlantingSpotState*)ex)->unk10 <= lbl_803E45F4 && GameBit_Get(((MoonSeedPlantingSpotState*)ex)->plantedGameBit) != 0 &&
                GameBit_Get(((MoonSeedPlantingSpotState*)ex)->harvestedGameBit) == 0)
            {
                int setup2;
                int ex2;
                ex2 = *(int*)&((GameObject*)obj)->extra;
                setup2 = *(int*)&((GameObject*)obj)->anim.placementData;
                if (GameBit_Get(((MoonSeedPlantingSpotState*)ex2)->plantedGameBit) != 0)
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
                    GameBit_Set(((MoonSeedPlantingSpotState*)ex2)->harvestedGameBit, 1);
                    *(u8*)ex2 = MSPLANTING_PHASE_HARVESTED;
                    ((GameObject*)obj)->anim.localPosY = ((MoonSeedPlantingSpotPlacement*)setup2)->unkC;
                }
            }
            ((MoonSeedPlantingSpotState*)ex)->unk10 = ((MoonSeedPlantingSpotState*)ex)->unk10 - timeDelta;
            if (((MoonSeedPlantingSpotState*)ex)->unk10 < lbl_803E45F4)
            {
                ((MoonSeedPlantingSpotState*)ex)->unk10 = *(f32*)&lbl_803E45F4;
            }
            break;
        }
    }
}

#pragma optimization_level 2
int MoonSeedPlantingSpot_setScale(int* obj, int arg)
{
    int* sub;
    u8* inner;
    int ret;

    inner = ((GameObject*)obj)->extra;
    ret = 0;
    if (arg == 0)
    {
        if ((((MoonSeedPlantingSpotState*)inner)->flags & MSPLANTING_FLAG_VISIBLE) != 0)
        {
            inner[0] = MSPLANTING_PHASE_CUT;
            ((MoonSeedPlantingSpotState*)inner)->colorPhase = 0;
        }
        ret = 1;
    }
    else if (arg == 1)
    {
        if (inner[0] == MSPLANTING_PHASE_CUT)
        {
            ret = 1;
            if (GameBit_Get(((MoonSeedPlantingSpotState*)inner)->plantedGameBit) != 0 && GameBit_Get(((MoonSeedPlantingSpotState*)inner)->harvestedGameBit) == 0)
            {
                inner = ((GameObject*)obj)->extra;
                sub = *(int**)&((GameObject*)obj)->anim.placementData;
                if (GameBit_Get(((MoonSeedPlantingSpotState*)inner)->plantedGameBit) != 0)
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
                    GameBit_Set(((MoonSeedPlantingSpotState*)inner)->harvestedGameBit, 1);
                    inner[0] = MSPLANTING_PHASE_HARVESTED;
                    ((GameObject*)obj)->anim.localPosY = *(f32*)((char*)sub + 0xc);
                }
            }
        }
    }
    return ret;
}
#pragma optimization_level reset

void MoonSeedPlantingSpot_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    u8* inner = ((GameObject*)p1)->extra;
    s32 v = visible;
    if (v != 0)
    {
        if (inner[0] == MSPLANTING_PHASE_GROWN)
        {
            if ((((MoonSeedPlantingSpotState*)inner)->flags & MSPLANTING_FLAG_VISIBLE) != 0)
            {
                f32 s;
                int iv;
                ((MoonSeedPlantingSpotState*)inner)->colorPhase += 0x1000;
                s = mathSinf(lbl_803E45E0 * (f32)((MoonSeedPlantingSpotState*)inner)->colorPhase / lbl_803E45E4);
                s = lbl_803E45DC + s;
                iv = (int)(lbl_803E45D8 * s);
                fn_8003B608((u8)(iv + 0x7f), 0xff, 0xff);
            }
        }
        else if (inner[0] == MSPLANTING_PHASE_CUT)
        {
            if (((MoonSeedPlantingSpotState*)inner)->colorPhase < 0x7d00)
            {
                ((MoonSeedPlantingSpotState*)inner)->colorPhase += 0xff;
            }
            fn_8003B608((s16)(((MoonSeedPlantingSpotState*)inner)->colorPhase >> 7), 0xff, 0xff);
        }
        else
        {
            fn_8003B608(0xff, 0xff, 0xff);
        }
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(p1, p2, p3, p4, p5, lbl_803E45DC);
    }
}
