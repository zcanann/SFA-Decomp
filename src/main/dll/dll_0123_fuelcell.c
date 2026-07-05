/* DLL 0x0123 — fuelcell (fuel cell collectible). TU: 0x8018C000–0x8018C7D8. */
#include "main/objseq.h"
extern f32 timeDelta;
extern void Sfx_PlayFromObject(int* obj, int sfxId);
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/sfa_shared_decls.h"
#include "main/audio/sfx_trigger_ids.h"

#define FUELCELL_OBJGROUP 0x4f
extern int randomGetRange(int lo, int hi);
extern void* ObjGroup_GetObjects();
extern u64 ObjGroup_RemoveObject();
extern int ObjMsg_Pop();
extern u32 ObjMsg_SendToObject();
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern void GXSetAlphaCompare(int comp0, int ref0, int op, int comp1, int ref1);
extern void GXSetBlendMode(int type, int srcFactor, int dstFactor, int op);

#define GX_BM_NONE 0
#define GX_BM_BLEND 1
#define GX_BL_ZERO 0
#define GX_BL_ONE 1
#define GX_BL_SRCALPHA 4
#define GX_LO_NOOP 5
#define GX_LEQUAL 3
#define GX_ALWAYS 7
#define GX_AOP_AND 0

#define FUELCELL_MSG_IN_RANGE 0x7000a  /* sent to player when grab is offered */
#define FUELCELL_MSG_RELEASE 0x7000b   /* player dropped/deposited the cell */
#define FUELCELL_GAMEBIT_CARRIED 0xe97 /* global: a fuel cell is currently held */
extern void gxSetPeControl_ZCompLoc_(u32 zCompLoc);
extern void gxSetZMode_(u32 compareEnable, int compareFunc, u32 updateEnable);
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void ObjModel_SetPostRenderCallback(u8* model, void* callback);
extern void mm_free_(void* ptr);
extern f32 Vec_distance(f32* a, f32* b);

extern void Sfx_AddLoopedObjectSound(int* obj, int soundId);
extern void Sfx_RemoveLoopedObjectSound(int* obj, int soundId);
extern void Sfx_PlayFromObject(int* obj, int soundId);
extern f32 getXZDistance(void* a, void* b);
extern f32 lbl_803E3D08;
extern f32 lbl_803E3D0C;
extern f32 lbl_803E3D10;
extern void objfx_spawnDirectionalBurst(int* obj, int idx, f32 scale, int b, int c, int d, f32 speed, int e, int f);
extern int ObjModel_GetRenderOp(int model, int idx);
extern void lightningRender(void* state);

extern int lightningCreate(float* start, float* end, f32 radiusX, f32 radiusY, int delay, int c, int d);
extern f32 lbl_803E3CC8;
extern f32 lbl_803E3CCC;
extern f32 lbl_803E3CD0;
extern f32 lbl_803E3CD4;
extern f32 lbl_803E3CD8;
extern f32 gFuelCellMaxLinkDistSq;
extern f32 lbl_803E3CE0;
extern f32 lbl_803E3CE4;
extern f32 lbl_803E3CE8;
extern f32 lbl_803E3CEC;
extern f32 lbl_803E3CF0;
extern f32 lbl_803E3CF4;
extern f32 lbl_803E3CF8;

int fuelcell_getExtraSize(void) { return 0x60; }

typedef struct
{
    u16 msg; // 0x0
    u8 pad[0x5a];
    u8 lit : 1; // 0x5c bit 7
    u8 grabbed : 1; // bit 6
    u8 unkBit5 : 1; // bit 5
    u8 resetPos : 1; // bit 4
} FuelcellState;

typedef struct
{
    u8 pad[8];
    f32 homeX; // 0x8
    f32 homeY; // 0xc
    f32 homeZ; // 0x10
    u8 pad2[0xa];
    s16 offBit; // 0x1e
    s16 onBit; // 0x20
} FuelcellSetup;

int fuelcell_func0B(int* obj)
{
    FuelcellState* state = ((GameObject*)obj)->extra;
    state->unkBit5 = 1;
    state->resetPos = 1;
    return 0;
}

void fuelcell_modelMtxFn(u8* model)
{
    if (model[0x37] == 0xff)
    {
        GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
    }
    else
    {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    }
    gxSetZMode_(1, GX_LEQUAL, 0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void fuelcell_free(int* obj)
{
    u8* state = ((GameObject*)obj)->extra;
    u8 i;

    for (i = 0; i < 10; i++)
    {
        void* slot = *(void**)(state + 8 + i * 4);
        if (slot != NULL)
        {
            mm_free_(slot);
        }
    }

    if (((u32)state[0x5c] >> 7) & 1)
    {
        ObjGroup_RemoveObject(obj, FUELCELL_OBJGROUP);
    }
}

void fuelcell_init(int* obj)
{
    extern void* Obj_GetActiveModel(int* obj);
    ((GameObject*)obj)->animEventCallback = fuelcell_func0B;
    ObjModel_SetPostRenderCallback(Obj_GetActiveModel(obj), fuelcell_modelMtxFn);
    ObjMsg_AllocQueue(obj, 2);
}

void fuelcell_update(int* obj)
{
    extern void* Obj_GetPlayerObject(void);
    extern u32 ObjGroup_AddObject();

    FuelcellSetup* setup = *(FuelcellSetup**)&((GameObject*)obj)->anim.placementData;
    FuelcellState* state = ((GameObject*)obj)->extra;
    int* player;
    int msgId;
    int msgParam;

    player = Obj_GetPlayerObject();
    if (state->grabbed)
    {
        while (ObjMsg_Pop(obj, &msgId, &msgParam, 0) != 0)
        {
            if (msgId == FUELCELL_MSG_RELEASE)
            {
                state->grabbed = 0;
                GameBit_Set(setup->offBit, 1);
                gameBitIncrement(0x3f5);
                GameBit_Set(FUELCELL_GAMEBIT_CARRIED, 0);
            }
        }
    }
    else
    {
        int bit = setup->offBit;
        if (bit != -1 && GameBit_Get(bit) == 0)
        {
            bit = setup->onBit;
            if (bit == -1 || GameBit_Get(bit) != 0)
            {
                f32 dy;
                if (!state->lit)
                {
                    Sfx_AddLoopedObjectSound(obj, SFXTRIG_pk_fuelcell_fizz);
                    state->lit = 1;
                    ObjGroup_AddObject(obj, FUELCELL_OBJGROUP);
                }
                else if (state->resetPos)
                {
                    ((GameObject*)obj)->anim.localPosX = setup->homeX;
                    ((GameObject*)obj)->anim.localPosY = setup->homeY;
                    ((GameObject*)obj)->anim.localPosZ = setup->homeZ;
                    ((GameObject*)obj)->anim.alpha = 0xff;
                    state->resetPos = 0;
                }
                dy = ((GameObject*)obj)->anim.localPosY - ((GameObject*)player)->anim.localPosY;
                if (dy > lbl_803E3D08 && dy < lbl_803E3D0C
                    && GameBit_Get(FUELCELL_GAMEBIT_CARRIED) == 0
                    && getXZDistance(&((GameObject*)obj)->anim.worldPosX,
                                     &((GameObject*)player)->anim.worldPosX) < lbl_803E3D10)
                {
                    state->msg = 0xcbe;
                    ObjMsg_SendToObject(player, FUELCELL_MSG_IN_RANGE, obj, state);
                    state->grabbed = 1;
                    GameBit_Set(FUELCELL_GAMEBIT_CARRIED, 1);
                    Sfx_PlayFromObject(obj, SFXTRIG_lockoff22);
                }
            }
        }
        else if (state->lit)
        {
            state->lit = 0;
            Sfx_RemoveLoopedObjectSound(obj, SFXTRIG_pk_fuelcell_fizz);
            ObjGroup_RemoveObject(obj, FUELCELL_OBJGROUP);
        }
    }
}

typedef struct
{
    u8 pad0[0xc];
    f32 pos[3]; // 0xc
    f32 pos2[3]; // 0x18
} GameObjPos;

#pragma opt_loop_invariants off
void fuelcell_render(int* obj, int p2, int p3, int p4, int p5)
{
    extern f32 vec3f_distanceSquared(f32* a, f32* b);
    extern void* Obj_GetActiveModel(int* obj);
    int** list;
    u8* slot;
    FuelcellState* state;
    u8 mode;
    u8 i;
    u8 j;
    u8 pickCount;
    u8 spawned;
    f32 angle;
    f32 scale;
    int* candidates[9];
    f32 pos[3];
    int objCount;

    state = ((GameObject*)obj)->extra;
    angle = lbl_803E3CC8;
    objCount = 0;
    mode = 0x40;
    pickCount = 0;
    spawned = 0;
    if (state->lit)
    {
        if (state->unkBit5)
        {
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E3CCC, 1, 1, 0x14, lbl_803E3CD0, 0, 0);
        }
        else
        {
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E3CCC, 1, 1, 0x14, lbl_803E3CD4, 0, 0);
        }
        {
            int op = ObjModel_GetRenderOp(*(int*)Obj_GetActiveModel(obj), 0);
            *(u8*)(op + 0x43) = 0x7f;
        }
        ((void(*)(int*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E3CCC);

        for (i = 0; i < 10; i++)
        {
            slot = (u8*)state + i * 4;
            if (*(void**)(slot + 8) != NULL)
            {
                lightningRender(*(void**)(slot + 8));
                if (getHudHiddenFrameCount() == 0)
                {
                    *(f32*)(slot + 0x34) += timeDelta;
                    *(u16*)(*(char**)(slot + 8) + 0x20) = (int)(lbl_803E3CD8 + *(f32*)(slot + 0x34));
                    if (*(u16*)(*(char**)(slot + 8) + 0x20) > 0x14)
                    {
                        mm_free_(*(void**)(slot + 8));
                        *(void**)(slot + 8) = NULL;
                    }
                }
            }
            else if (!spawned && getHudHiddenFrameCount() == 0)
            {
                int* target;
                if ((int)randomGetRange(0, 9) == 0 && !state->unkBit5)
                {
                    list = ObjGroup_GetObjects(0x4f, &objCount);
                    for (j = 0; j < objCount; j++)
                    {
                        int ofs = (int)(u16)j * 4;
                        int* other = *(int**)((char*)list + ofs);
                        u8 ok;
                        if (other != obj)
                        {
                            if (((GameObject*)other)->extra != NULL &&
                                ((FuelcellState*)((GameObject*)other)->extra)->unkBit5)
                            {
                                ok = 0;
                            }
                            else
                            {
                                ok = 1;
                            }
                            if (ok && vec3f_distanceSquared(((GameObjPos*)other)->pos2, ((GameObjPos*)obj)->pos2) <
                                gFuelCellMaxLinkDistSq)
                            {
                                candidates[pickCount++] = *(int**)((char*)list + ofs);
                            }
                        }
                    }
                }
                if (pickCount != 0)
                {
                    pickCount--;
                    pickCount = randomGetRange(0, pickCount);
                    angle = -(lbl_803E3CE8 * (Vec_distance(((GameObjPos*)candidates[pickCount])->pos2,
                                                           ((GameObjPos*)obj)->pos2) / lbl_803E3CE0) - lbl_803E3CE4);
                    mode = 0xff;
                }
                else
                {
                    candidates[0] = obj;
                }
                target = candidates[pickCount];
                pos[0] = ((GameObjPos*)target)->pos[0];
                pos[1] = ((GameObjPos*)target)->pos[1];
                pos[2] = ((GameObjPos*)target)->pos[2];
                if (target == obj)
                {
                    if (state->unkBit5)
                    {
                        scale = lbl_803E3CEC;
                    }
                    else
                    {
                        scale = lbl_803E3CF0;
                    }
                    pos[0] = scale * (f32)((int)randomGetRange(0, 2000) - 1000) + pos[0];
                    pos[1] = scale * (f32)((int)randomGetRange(0, 2000) - 1000) + pos[1];
                    pos[2] = scale * (f32)((int)randomGetRange(0, 2000) - 1000) + pos[2];
                }
                *(int*)(slot + 8) = lightningCreate(((GameObjPos*)obj)->pos, pos, angle, lbl_803E3CF4, 0x14, mode, 0);
                *(f32*)(slot + 0x34) = lbl_803E3CF8;
                spawned = 1;
            }
        }
    }
}
#pragma opt_loop_invariants reset
