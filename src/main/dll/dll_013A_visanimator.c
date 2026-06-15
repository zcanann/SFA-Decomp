/* DLL 0x013A (visanimator) — Visibility animator object [0x8019423C-0x80194408). */
#include "main/dll/mmp_moonrock.h"
#include "main/dll/waveanimatorobjectdef_struct.h"
#include "main/dll/waveanimatorstate_struct.h"
#include "main/dll/alphaanimatorstate_struct.h"
#include "main/dll/visanimatorstate_struct.h"

extern uint GameBit_Get(int eventId);

extern void* mapGetBlock(int idx);

#include "main/dll/groundanimator_state.h"

/* waveanimator_getExtraSize == 0x3c (also the shared wave-grid config fed
 * to fn_801923F8; the grid/color/phase tables live in the lbl_803DDAEC/F0/F4
 * globals). */

STATIC_ASSERT(sizeof(WaveAnimatorState) == 0x3C);

STATIC_ASSERT(sizeof(AlphaAnimatorState) == 0x1C);

STATIC_ASSERT(sizeof(GroundAnimatorState) == 0x30);

STATIC_ASSERT(sizeof(VisAnimatorState) == 0x5);

extern int FUN_80017af0();
extern int FUN_8005337c();
extern undefined4 FUN_80056418();
extern int FUN_80056448();
extern int FUN_8005af70();
extern int FUN_8005b398();
extern int FUN_800600e4();
extern undefined8 FUN_8028682c();
extern undefined4 FUN_80286878();

extern void* lbl_803DDAEC;

void FUN_80192488(void)
{
    int texV;
    int ctxHi;
    int block;
    int polyIdx;
    int cell;
    uint gameBit;
    int texU;
    int ctxLo;
    int mapId;
    int placement;
    int vtxIdx;
    int vtx;
    undefined8 pair;

    pair = FUN_8028682c();
    ctxHi = (int)((ulonglong)pair >> 0x20);
    ctxLo = (int)pair;
    placement = *(int*)(ctxHi + 0x4c);
    block = FUN_8005b398((double)*(float*)(ctxHi + 0xc), (double)*(float*)(ctxHi + 0x10));
    block = FUN_8005af70(block);
    if (block == 0)
    {
        *(undefined*)(ctxLo + 0x10) = 1;
    }
    else
    {
        polyIdx = FUN_80017af0(0xe);
        if ((polyIdx != 0) &&
            (placement = FUN_8005337c(-*(int*)(polyIdx + *(short*)(placement + 0x18) * 4)), placement != 0))
        {
            for (polyIdx = 0; polyIdx < (int)(uint) * (byte*)(block + 0xa2); polyIdx = polyIdx + 1)
            {
                cell = FUN_800600e4(block, polyIdx);
                vtx = cell;
                for (vtxIdx = 0; vtxIdx < (int)(uint) * (byte*)(cell + 0x41); vtxIdx = vtxIdx + 1)
                {
                    if (*(int*)(vtx + 0x24) == placement)
                    {
                        texU = (uint) * (ushort*)(placement + 10) << 6;
                        texV = (uint) * (ushort*)(placement + 0xc) << 6;
                        if (*(byte*)(vtx + 0x2a) == 0xff)
                        {
                            texU = FUN_80056448((int)*(char*)(ctxLo + 0x11), (int)*(char*)(ctxLo + 0x12), texU,
                                                 texV);
                            *(char*)(vtx + 0x2a) = (char)texU;
                        }
                        else
                        {
                            mapId = *(int*)(*(int*)(ctxHi + 0x4c) + 0x14);
                            if ((mapId == 0x49b2f) || (mapId == 0x49b67))
                            {
                                gameBit = GameBit_Get(*(uint*)(ctxLo + 8));
                                if (gameBit != 0)
                                {
                                    FUN_80056418((uint) * (byte*)(vtx + 0x2a), (int)*(char*)(ctxLo + 0x11),
                                                 (int)*(char*)(ctxLo + 0x12), texU, texV);
                                }
                            }
                            else
                            {
                                FUN_80056418((uint) * (byte*)(vtx + 0x2a), (int)*(char*)(ctxLo + 0x11),
                                             (int)*(char*)(ctxLo + 0x12), texU, texV);
                            }
                        }
                    }
                    vtx = vtx + 8;
                }
            }
        }
    }
    FUN_80286878();
    return;
}

void waveanimator_update(void);

void visanimator_free(void)
{
}

void visanimator_render(void)
{
}

void visanimator_hitDetect(void)
{
}

void visanimator_release(void)
{
}

void visanimator_initialise(void)
{
}

int waveanimator_getExtraSize(void);
int visanimator_getExtraSize(void) { return 0x5; }
int visanimator_getObjectTypeId(void) { return 0x0; }

u8 groundanimator_modelMtxFn(int* obj);

#pragma scheduling off
#pragma peephole off
void visanimator_init(int* obj, int* desc)
{
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
    VisAnimatorState* vstate;
    u32 gate;
    u8 tmp;
    int sv;
    ((GameObject*)obj)->objectFlags |= 0x6000;
    vstate = (VisAnimatorState*)((int**)obj)[0xB8 / 4];
    sv = *(s8*)((char*)desc + 0x1B);
    vstate->visBit = (s8)sv;
    vstate->gateMask = (u8)(1 << *(u8*)&((WaveanimatorObjectDef*)desc)->spanX);
    gate = (u32)GameBit_Get(((WaveanimatorObjectDef*)desc)->originX);
    if ((vstate->gateMask & gate) != 0)
    {
        vstate->visBit = vstate->visBit ^ 1;
    }
    mapGetBlock(objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                    (double)((GameObject*)obj)->anim.localPosY,
                                    (double)((GameObject*)obj)->anim.localPosZ));
    gate = (u32)GameBit_Get(((WaveanimatorObjectDef*)desc)->originX);
    tmp = (u8)(vstate->gateMask & gate);
    vstate->gateNow = tmp;
    vstate->gatePrev = tmp;
    vstate->flags |= 1;
}

void visanimator_update(int* obj)
{
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
    int* state = ((int**)obj)[0x4C / 4];
    VisAnimatorState* vstate = (VisAnimatorState*)((int**)obj)[0xB8 / 4];
    int idx = objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                  (double)((GameObject*)obj)->anim.localPosY,
                                  (double)((GameObject*)obj)->anim.localPosZ);
    if (mapGetBlock(idx) == NULL)
    {
        vstate->flags |= 1;
        return;
    }
    {
        int gate = GameBit_Get(*(s16*)((char*)state + 0x18));
        vstate->gateNow = (u8)(vstate->gateMask & gate);
        if (vstate->gatePrev != vstate->gateNow)
        {
            vstate->visBit = (s8)(vstate->visBit ^ 1);
            vstate->flags |= 1;
        }
        vstate->gatePrev = vstate->gateNow;
        if (vstate->flags & 1)
        {
            vstate->flags &= ~1;
        }
    }
}
