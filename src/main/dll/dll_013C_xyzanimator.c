/*
 * xyzanimator (DLL 0x13C) - drives a smooth offset animation of a map
 * block's vertices/edges along the X/Y/Z axes.
 *
 * On first update the object copies the source map block's vertex and
 * edge positions into a freshly mmAlloc'd buffer (fn_80194964), then on
 * each tick walks an offset vec toward the placement's per-axis targets
 * and writes the displaced positions back into the live block
 * (fn_80194C40). The placement animation mode selects the drive style:
 *   0/4 = one-shot toward target (sets the completion game bit),
 *   1   = looping (per-axis wrap), 2 = game-bit gated forward/reverse.
 * A game bit gates whether the animation runs.
 */
#include "main/audio/sfx.h"
#include "main/game_object.h"
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/gamebits.h"
#include "main/objlib.h"
#include "main/dll/VF/vf_shared.h"
extern int mmAlloc(int size, int pool, int tag);
extern asm void DCStoreRange(register void* addr, register u32 nBytes);
extern int return0_80060B90(void);
extern void* fn_800606DC(int* obj, int idx);
extern void* fn_800606FC(int* obj, int idx);
extern void* fn_8006070C(int* obj, int idx);
extern void* Shader_getLayer(char* base, int idx);
extern f32 timeDelta;

/* .sdata2 float constants owned by this TU: lbl_803E4000 = 0.0 default;
 * lbl_803E4008 = per-axis offset scale; lbl_803E4018 = per-tick step multiplier;
 * lbl_803E4004 value unconfirmed. */
extern f32 lbl_803E4000;
extern f32 lbl_803E4004;
extern f32 lbl_803E4008;
extern f32 lbl_803E4018;

f32 objFn_801948c0(u8* obj, u8 coord)
{
    XyzAnimatorState* state;

    if (obj == NULL || (state = (XyzAnimatorState*)((GameObject*)obj)->extra, state == NULL))
    {
        return lbl_803E4000;
    }
    switch (coord)
    {
    case 1:
        return ((GameObject*)obj)->anim.localPosX + state->unk40;
    case 2:
        return state->unk40;
    case 3:
        return ((GameObject*)obj)->anim.localPosY + state->unk44;
    case 4:
        return state->unk44;
    case 5:
        return ((GameObject*)obj)->anim.localPosZ + state->unk48;
    case 6:
        return state->unk48;
    }
    return lbl_803E4000;
}

typedef struct MapBlockHdr
{
    u16 start;
    u16 pad1[2];
    s16 posA;
    s16 posB;
} MapBlockHdr;

typedef struct VertexS16
{
    s16 x;
    s16 y;
    s16 z;
} VertexS16;

typedef struct EdgeVerts
{
    u8 pad[6];
    s16 a;
    s16 b;
    s16 c;
    s16 d;
    s16 e;
    s16 f;
} EdgeVerts;

void fn_80194964(XyzAnimatorPlacement* setup, XyzAnimatorState* state, int block)
{
    extern u32 mapBlockFn_80060678(int* block); /* #57 */
    extern void* mapBlockFn_800606ec(int* obj, int idx); /* #57 */
    u16 blockEnd;
    u16* mapBlock;
    int blockLayer;
    int coordOffset;
    VertexS16* vtx;
    u32 triangle;
    int triangleOffset;
    int edge;
    int edgeOffset;
    int blockIndex;

    triangleOffset = 0;
    coordOffset = 0;
    edgeOffset = 0;
    for (blockIndex = 0; blockIndex < (int)(u32) * (u16*)(block + 0x9a); blockIndex++)
    {
        mapBlock = mapBlockFn_800606ec((int*)block, blockIndex);
        blockLayer = mapBlockFn_80060678((int*)mapBlock);
        if ((int)setup->unk28 == blockLayer)
        {
            *(s16*)(state->unk10 + coordOffset) = ((MapBlockHdr*)mapBlock)->posA;
            *(s16*)(state->unk14 + coordOffset) = ((MapBlockHdr*)mapBlock)->posB;
            coordOffset += 2;
            blockEnd = mapBlock[10];
            triangle = (u32) * mapBlock;
            edgeOffset = triangleOffset;
            for (; triangle < (int)(u32)blockEnd; triangle++)
            {
                mapBlock = fn_800606DC((int*)block, triangle);
                vtx = (VertexS16*)(*(int*)(block + 0x58) + (u32) * mapBlock * 6);
                *(s16*)(state->dataBuffer + edgeOffset) = vtx->x;
                *(s16*)(state->dataBuffer + edgeOffset + 2) = vtx->y;
                *(s16*)(state->dataBuffer + edgeOffset + 4) = vtx->z;
                vtx = (VertexS16*)(*(int*)(block + 0x58) + mapBlock[1] * 6);
                *(s16*)(state->dataBuffer + edgeOffset + 6) = vtx->x;
                *(s16*)(state->dataBuffer + edgeOffset + 8) = vtx->y;
                *(s16*)(state->dataBuffer + edgeOffset + 10) = vtx->z;
                vtx = (VertexS16*)(*(int*)(block + 0x58) + mapBlock[2] * 6);
                *(s16*)(state->dataBuffer + edgeOffset + 0xc) = vtx->x;
                *(s16*)(state->dataBuffer + edgeOffset + 0xe) = vtx->y;
                *(s16*)(state->dataBuffer + edgeOffset + 0x10) = vtx->z;
                edgeOffset += 0x12;
                triangleOffset += 0x12;
            }
        }
    }
    edge = 0;
    for (edgeOffset = 0; edgeOffset < (int)(u32) * (u8*)(block + 0xa1); edgeOffset++)
    {
        blockIndex = (int)fn_800606FC((int*)block, edgeOffset);
        *(s16*)(state->unk28 + edge) = ((EdgeVerts*)blockIndex)->a;
        *(s16*)(state->unk2C + edge) = ((EdgeVerts*)blockIndex)->d;
        *(s16*)(state->unk30 + edge) = ((EdgeVerts*)blockIndex)->b;
        *(s16*)(state->unk34 + edge) = ((EdgeVerts*)blockIndex)->e;
        *(s16*)(state->unk38 + edge) = ((EdgeVerts*)blockIndex)->c;
        *(s16*)(state->unk3C + edge) = ((EdgeVerts*)blockIndex)->f;
        edge += 2;
    }
}

void fn_80194C40(XyzAnimatorPlacement* def, XyzAnimatorState* state, int block)
{
    extern u32 mapBlockFn_80060678(int* block); /* #57 */
    extern void* mapBlockFn_800606ec(int* obj, int idx); /* #57 */
    u16 blockEnd;
    f32 scale;
    int edgeData;
    u16* mapBlock;
    int blockLayer;
    void* shader;
    VertexS16* vtx;
    u32 triangle;
    int triangleOffset;
    int vertexOffset;
    int coordOffset;
    int blockIndex;
    int edgeIndex;
    int edgeOffset;
    int vertexIndex;

    triangleOffset = 0;
    coordOffset = triangleOffset;
    vertexOffset = coordOffset;
    for (blockIndex = 0; blockIndex < (int)(u32) * (u16*)(block + 0x9a); blockIndex++)
    {
        mapBlock = mapBlockFn_800606ec((int*)block, blockIndex);
        blockLayer = mapBlockFn_80060678((int*)mapBlock);
        if ((int)def->unk28 == blockLayer)
        {
            ((MapBlockHdr*)mapBlock)->posA = (s16)(state->unk44 +
                (f32) * (s16*)(state->unk10 + coordOffset));
            ((MapBlockHdr*)mapBlock)->posB = (s16)(state->unk44 +
                (f32) * (s16*)(state->unk14 + coordOffset));
            coordOffset += 2;
            blockEnd = mapBlock[10];
            scale = lbl_803E4008;
            triangle = (u32) * mapBlock;
            edgeOffset = vertexOffset;
            for (; triangle < (int)(u32)blockEnd; triangle++)
            {
                mapBlock = fn_800606DC((int*)block, triangle);
                vertexIndex = edgeOffset;
                for (edgeIndex = 3; edgeIndex != 0; edgeIndex--)
                {
                    vtx = (VertexS16*)(*(int*)(block + 0x58) + (u32) * mapBlock * 6);
                    vtx->x = (s16)(scale * state->unk40 +
                        (f32) * (s16*)(state->dataBuffer + edgeOffset));
                    vtx->y = (s16)(scale * state->unk44 +
                        (f32) * (s16*)(state->dataBuffer + edgeOffset + 2));
                    vtx->z = (s16)(scale * state->unk48 +
                        (f32) * (s16*)(state->dataBuffer + edgeOffset + 4));
                    edgeOffset += 6;
                    vertexIndex += 6;
                    vertexOffset += 6;
                    mapBlock++;
                }
                edgeOffset = vertexIndex;
            }
        }
    }
    DCStoreRange(*(void**)(block + 0x58), (u32) * (u16*)(block + 0x90) * 6);
    edgeData = 0;
    for (edgeOffset = 0; edgeOffset < (int)(u32) * (u8*)(block + 0xa1); edgeOffset++)
    {
        vertexOffset = (int)fn_800606FC((int*)block, edgeOffset);
        shader = fn_8006070C((int*)block, *(u8*)(vertexOffset + 0x13));
        shader = Shader_getLayer(shader, 0);
        scale = lbl_803E4008;
        if ((int) * (u8*)((int)shader + 5) == def->unk28)
        {
            ((EdgeVerts*)vertexOffset)->a = (s16)(scale * state->unk40 +
                (f32) * (s16*)(state->unk28 + edgeData));
            ((EdgeVerts*)vertexOffset)->d = (s16)(scale * state->unk40 +
                (f32) * (s16*)(state->unk2C + edgeData));
            ((EdgeVerts*)vertexOffset)->b = (s16)(scale * state->unk44 +
                (f32) * (s16*)(state->unk30 + edgeData));
            ((EdgeVerts*)vertexOffset)->e = (s16)(scale * state->unk44 +
                (f32) * (s16*)(state->unk34 + edgeData));
            ((EdgeVerts*)vertexOffset)->c = (s16)(scale * state->unk48 +
                (f32) * (s16*)(state->unk38 + edgeData));
            ((EdgeVerts*)vertexOffset)->f = (s16)(scale * state->unk48 +
                (f32) * (s16*)(state->unk3C + edgeData));
        }
        edgeData += 2;
    }
    *(int*)block = return0_80060B90();
}

int xyzanimator_getExtraSize(void)
{
    return 0x50;
}

void xyzanimator_free(int obj, int param_2)
{
    extern int mapGetBlock(int blockIdx); /* #57 */
    extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z); /* #57 */
    int block;
    XyzAnimatorState* state;
    XyzAnimatorPlacement* setup;
    f32 zero;

    state = (XyzAnimatorState*)((GameObject*)obj)->extra;
    setup = *(XyzAnimatorPlacement**)&((GameObject*)obj)->anim.placementData;
    zero = lbl_803E4000;
    state->unk40 = zero;
    state->unk44 = zero;
    state->unk48 = zero;
    if (param_2 == 0)
    {
        block = objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                    (double)((GameObject*)obj)->anim.localPosY,
                                    (double)((GameObject*)obj)->anim.localPosZ);
        block = mapGetBlock(block);
        if (((void*)block != NULL) && (state->unk4 != 0))
        {
            fn_80194C40(setup, state, block);
        }
    }
    if (*(void**)&state->dataBuffer != NULL)
    {
        mm_free(*(void**)&state->dataBuffer);
    }
    ObjGroup_RemoveObject(obj, 0x51);
}

void xyzanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible; /* s32 widening for matching cmpwi */
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4004);
}

void xyzanimator_update(int obj)
{
    extern void fn_80194C40(u8* setup, u8* state, int block); /* #57 */
    extern void fn_80194964(u8* setup, u8* state, int block); /* #57 */
    extern int mapBlockFn_80060678(void); /* #57 */
    extern u8* mapBlockFn_800606ec(int block, int idx); /* #57 */
    extern int* mapGetBlock(int idx); /* #57 */
    extern int objPosToMapBlockIdx(f32 x, f32 y, f32 z); /* #57 */
    u8* setup = *(u8**)&((GameObject*)obj)->anim.placementData;
    u8* state = ((GameObject*)obj)->extra;
    int block;
    u8* row;
    int i;
    int done;
    int alloc, stride;
    int t;

    block = (int)mapGetBlock(objPosToMapBlockIdx(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                                 ((GameObject*)obj)->anim.localPosZ));
    if ((u32)block == 0)
    {
        ((XyzAnimatorState*)state)->unk4D = 0;
        goto no_update;
    }
    if ((*(u16*)(block + 4) & 8) == 0)
    {
        goto no_update;
    }
    if (((XyzAnimatorState*)state)->unk4 == 0)
    {
        for (i = 0; i < *(u16*)(block + 0x9a); i++)
        {
            row = mapBlockFn_800606ec(block, i);
            t = mapBlockFn_80060678();
            if (((XyzAnimatorPlacement*)setup)->unk28 == t)
            {
                ((XyzAnimatorState*)state)->rowCount++;
                ((XyzAnimatorState*)state)->unk4 += (*(u16*)(row + 0x14) - *(u16*)(row + 0));
            }
        }
        if (((XyzAnimatorState*)state)->unk4 == 0)
        {
            goto no_update;
        }
        ((XyzAnimatorState*)state)->unk4 *= 3;
        if (((XyzAnimatorPlacement*)setup)->unk18 == -1)
        {
            ((XyzAnimatorState*)state)->gameBitValue = 1;
        }
        else
        {
            ((XyzAnimatorState*)state)->gameBitValue = GameBit_Get(((XyzAnimatorPlacement*)setup)->unk18);
        }
        ((XyzAnimatorState*)state)->unk8 = *(u8*)(block + 0xa1);
        ((XyzAnimatorState*)state)->unk40 = (f32)((XyzAnimatorPlacement*)setup)->unk1C;
        ((XyzAnimatorState*)state)->unk44 = (f32)((XyzAnimatorPlacement*)setup)->unk1E;
        ((XyzAnimatorState*)state)->unk48 = (f32)((XyzAnimatorPlacement*)setup)->unk20;
        if (((XyzAnimatorPlacement*)setup)->unk1A != -1 && GameBit_Get(((XyzAnimatorPlacement*)setup)->unk1A) != 0)
        {
            ((XyzAnimatorState*)state)->unk40 = (f32)((XyzAnimatorPlacement*)setup)->unk22;
            ((XyzAnimatorState*)state)->unk44 = (f32)((XyzAnimatorPlacement*)setup)->unk24;
            ((XyzAnimatorState*)state)->unk48 = (f32)((XyzAnimatorPlacement*)setup)->unk26;
            ((XyzAnimatorState*)state)->gameBitValue = 1;
        }
        t = ((XyzAnimatorState*)state)->unk4 * 6 + ((XyzAnimatorState*)state)->rowCount * 0xc;
        t = t + ((XyzAnimatorState*)state)->unk8 * 0xc;
        alloc = mmAlloc(t, 5, 0);
        ((XyzAnimatorState*)state)->dataBuffer = alloc;
        stride = ((XyzAnimatorState*)state)->rowCount * 2;
        alloc = alloc + ((XyzAnimatorState*)state)->unk4 * 6;
        ((XyzAnimatorState*)state)->unk18 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->unk1C = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->unk10 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->unk14 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->unk20 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->unk24 = alloc;
        alloc = alloc + stride;
        stride = ((XyzAnimatorState*)state)->unk8 * 2;
        ((XyzAnimatorState*)state)->unk28 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->unk2C = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->unk30 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->unk34 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->unk38 = alloc;
        alloc = alloc + stride;
        ((XyzAnimatorState*)state)->unk3C = alloc;
        fn_80194964(setup, state, block);
        if (((XyzAnimatorPlacement*)setup)->unk2C != 4)
        {
            fn_80194C40(setup, state, block);
            *(u16*)(block + 4) = *(u16*)(block + 4) ^ 1;
            fn_80194C40(setup, state, block);
            *(u16*)(block + 4) = *(u16*)(block + 4) ^ 1;
        }
    }
    if (((XyzAnimatorPlacement*)setup)->unk2C == 2)
    {
        t = GameBit_Get(((XyzAnimatorPlacement*)setup)->unk18);
        if (((XyzAnimatorState*)state)->gameBitValue != t)
        {
            ((XyzAnimatorState*)state)->gameBitValue = t;
            if (t == 0)
            {
                if (((XyzAnimatorPlacement*)setup)->unk1A > -1)
                {
                    GameBit_Set(((XyzAnimatorPlacement*)setup)->unk1A, 0);
                }
            }
            if (((XyzAnimatorState*)state)->unk4D > 2)
            {
                ((XyzAnimatorState*)state)->unk4D = 0;
            }
        }
        if (((XyzAnimatorState*)state)->unk4D > 2)
        {
            goto no_update;
        }
        if (((XyzAnimatorState*)state)->loopSfxId != 0)
        {
            Sfx_KeepAliveLoopedObjectSound((u32)obj, ((XyzAnimatorState*)state)->loopSfxId);
        }
    }
    else
    {
        if (((XyzAnimatorState*)state)->unk4D > 2)
        {
            goto no_update;
        }
        if (((XyzAnimatorState*)state)->gameBitValue == 0)
        {
            ((XyzAnimatorState*)state)->gameBitValue = GameBit_Get(((XyzAnimatorPlacement*)setup)->unk18);
            if (((XyzAnimatorState*)state)->gameBitValue == 0)
            {
                goto no_update;
            }
        }
    }
    switch (((XyzAnimatorPlacement*)setup)->unk2C)
    {
    case 0:
    case 4:
        done = 0;
        if (((XyzAnimatorPlacement*)setup)->unk1C > ((XyzAnimatorPlacement*)setup)->unk22)
        {
            ((XyzAnimatorState*)state)->unk40 =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk29 * timeDelta) - ((XyzAnimatorState*)
                    state)->unk40);
            if (((XyzAnimatorState*)state)->unk40 <= (f32)((XyzAnimatorPlacement*)setup)->unk22)
            {
                ((XyzAnimatorState*)state)->unk40 = (f32)((XyzAnimatorPlacement*)setup)->unk22;
                done = 1;
            }
        }
        else
        {
            ((XyzAnimatorState*)state)->unk40 =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk29 * timeDelta) + ((XyzAnimatorState*)
                    state)->unk40;
            if (((XyzAnimatorState*)state)->unk40 >= (f32)((XyzAnimatorPlacement*)setup)->unk22)
            {
                ((XyzAnimatorState*)state)->unk40 = (f32)((XyzAnimatorPlacement*)setup)->unk22;
                done = 1;
            }
        }
        if (((XyzAnimatorPlacement*)setup)->unk1E > ((XyzAnimatorPlacement*)setup)->unk24)
        {
            ((XyzAnimatorState*)state)->unk44 =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2A * timeDelta) - ((XyzAnimatorState*)
                    state)->unk44);
            if (((XyzAnimatorState*)state)->unk44 <= (f32)((XyzAnimatorPlacement*)setup)->unk24)
            {
                ((XyzAnimatorState*)state)->unk44 = (f32)((XyzAnimatorPlacement*)setup)->unk24;
                done += 1;
            }
        }
        else
        {
            ((XyzAnimatorState*)state)->unk44 =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2A * timeDelta) + ((XyzAnimatorState*)
                    state)->unk44;
            if (((XyzAnimatorState*)state)->unk44 >= (f32)((XyzAnimatorPlacement*)setup)->unk24)
            {
                ((XyzAnimatorState*)state)->unk44 = (f32)((XyzAnimatorPlacement*)setup)->unk24;
                done += 1;
            }
        }
        if (((XyzAnimatorPlacement*)setup)->unk20 > ((XyzAnimatorPlacement*)setup)->unk26)
        {
            ((XyzAnimatorState*)state)->unk48 =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2B * timeDelta) - ((XyzAnimatorState*)
                    state)->unk48);
            if (((XyzAnimatorState*)state)->unk48 <= (f32)((XyzAnimatorPlacement*)setup)->unk26)
            {
                ((XyzAnimatorState*)state)->unk48 = (f32)((XyzAnimatorPlacement*)setup)->unk26;
                done += 1;
            }
        }
        else
        {
            ((XyzAnimatorState*)state)->unk48 =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2B * timeDelta) + ((XyzAnimatorState*)
                    state)->unk48;
            if (((XyzAnimatorState*)state)->unk48 >= (f32)((XyzAnimatorPlacement*)setup)->unk26)
            {
                ((XyzAnimatorState*)state)->unk48 = (f32)((XyzAnimatorPlacement*)setup)->unk26;
                done += 1;
            }
        }
        if (done == 3)
        {
            if (((XyzAnimatorPlacement*)setup)->unk1A != -1)
            {
                GameBit_Set(((XyzAnimatorPlacement*)setup)->unk1A, 1);
            }
            ((XyzAnimatorState*)state)->unk4D += 1;
        }
        break;
    case 1:
        if (((XyzAnimatorPlacement*)setup)->unk1C > ((XyzAnimatorPlacement*)setup)->unk22)
        {
            ((XyzAnimatorState*)state)->unk40 =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk29 * timeDelta) - ((XyzAnimatorState*)
                    state)->unk40);
            if (((XyzAnimatorState*)state)->unk40 < (f32)((XyzAnimatorPlacement*)setup)->unk22)
            {
                ((XyzAnimatorState*)state)->unk40 =
                    (f32)(((XyzAnimatorPlacement*)setup)->unk1C -
                        (int)((f32)((XyzAnimatorPlacement*)setup)->unk22 - ((XyzAnimatorState*)state)->unk40));
            }
        }
        else
        {
            ((XyzAnimatorState*)state)->unk40 =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk29 * timeDelta) + ((XyzAnimatorState*)
                    state)->unk40;
            if (((XyzAnimatorState*)state)->unk40 > (f32)((XyzAnimatorPlacement*)setup)->unk1C)
            {
                ((XyzAnimatorState*)state)->unk40 =
                    (f32)(((XyzAnimatorPlacement*)setup)->unk22 +
                        (int)(((XyzAnimatorState*)state)->unk40 - (f32)((XyzAnimatorPlacement*)setup)->unk22));
            }
        }
        if (((XyzAnimatorPlacement*)setup)->unk1E > ((XyzAnimatorPlacement*)setup)->unk24)
        {
            ((XyzAnimatorState*)state)->unk44 =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2A * timeDelta) - ((XyzAnimatorState*)
                    state)->unk44);
            if (((XyzAnimatorState*)state)->unk44 < (f32)((XyzAnimatorPlacement*)setup)->unk24)
            {
                ((XyzAnimatorState*)state)->unk44 =
                    -(lbl_803E4018 *
                        (f32)(int)((f32)((XyzAnimatorPlacement*)setup)->unk24 - ((XyzAnimatorState*)state)->unk44) -
                        (f32)((XyzAnimatorPlacement*)setup)->unk1E);
            }
        }
        else
        {
            ((XyzAnimatorState*)state)->unk44 =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2A * timeDelta) + ((XyzAnimatorState*)
                    state)->unk44;
            if (((XyzAnimatorState*)state)->unk44 > (f32)((XyzAnimatorPlacement*)setup)->unk1E)
            {
                ((XyzAnimatorState*)state)->unk44 =
                    (f32)(((XyzAnimatorPlacement*)setup)->unk24 +
                        (int)(((XyzAnimatorState*)state)->unk44 - (f32)((XyzAnimatorPlacement*)setup)->unk24));
            }
        }
        if (((XyzAnimatorPlacement*)setup)->unk20 > ((XyzAnimatorPlacement*)setup)->unk26)
        {
            ((XyzAnimatorState*)state)->unk48 =
                -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2B * timeDelta) - ((XyzAnimatorState*)
                    state)->unk48);
            if (((XyzAnimatorState*)state)->unk48 < (f32)((XyzAnimatorPlacement*)setup)->unk26)
            {
                ((XyzAnimatorState*)state)->unk48 =
                    (f32)(((XyzAnimatorPlacement*)setup)->unk20 -
                        (int)((f32)((XyzAnimatorPlacement*)setup)->unk26 - ((XyzAnimatorState*)state)->unk48));
            }
        }
        else
        {
            ((XyzAnimatorState*)state)->unk48 =
                lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2B * timeDelta) + ((XyzAnimatorState*)
                    state)->unk48;
            if (((XyzAnimatorState*)state)->unk48 > (f32)((XyzAnimatorPlacement*)setup)->unk20)
            {
                ((XyzAnimatorState*)state)->unk48 =
                    (f32)(((XyzAnimatorPlacement*)setup)->unk26 +
                        (int)(((XyzAnimatorState*)state)->unk48 - (f32)((XyzAnimatorPlacement*)setup)->unk26));
            }
        }
        break;
    case 2:
        done = 0;
        if (((XyzAnimatorState*)state)->gameBitValue != 0)
        {
            if (((XyzAnimatorPlacement*)setup)->unk1C > ((XyzAnimatorPlacement*)setup)->unk22)
            {
                ((XyzAnimatorState*)state)->unk40 =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk29 * timeDelta) -
                        ((XyzAnimatorState*)state)->unk40);
                if (((XyzAnimatorState*)state)->unk40 <= (f32)((XyzAnimatorPlacement*)setup)->unk22)
                {
                    ((XyzAnimatorState*)state)->unk40 = (f32)((XyzAnimatorPlacement*)setup)->unk22;
                    done = 1;
                }
            }
            else
            {
                ((XyzAnimatorState*)state)->unk40 =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk29 * timeDelta) + ((XyzAnimatorState*)
                        state)->unk40;
                if (((XyzAnimatorState*)state)->unk40 >= (f32)((XyzAnimatorPlacement*)setup)->unk22)
                {
                    ((XyzAnimatorState*)state)->unk40 = (f32)((XyzAnimatorPlacement*)setup)->unk22;
                    done = 1;
                }
            }
            if (((XyzAnimatorPlacement*)setup)->unk1E > ((XyzAnimatorPlacement*)setup)->unk24)
            {
                ((XyzAnimatorState*)state)->unk44 =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2A * timeDelta) -
                        ((XyzAnimatorState*)state)->unk44);
                if (((XyzAnimatorState*)state)->unk44 <= (f32)((XyzAnimatorPlacement*)setup)->unk24)
                {
                    ((XyzAnimatorState*)state)->unk44 = (f32)((XyzAnimatorPlacement*)setup)->unk24;
                    done += 1;
                }
            }
            else
            {
                ((XyzAnimatorState*)state)->unk44 =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2A * timeDelta) + ((XyzAnimatorState*)
                        state)->unk44;
                if (((XyzAnimatorState*)state)->unk44 >= (f32)((XyzAnimatorPlacement*)setup)->unk24)
                {
                    ((XyzAnimatorState*)state)->unk44 = (f32)((XyzAnimatorPlacement*)setup)->unk24;
                    done += 1;
                }
            }
            if (((XyzAnimatorPlacement*)setup)->unk20 > ((XyzAnimatorPlacement*)setup)->unk26)
            {
                ((XyzAnimatorState*)state)->unk48 =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2B * timeDelta) -
                        ((XyzAnimatorState*)state)->unk48);
                if (((XyzAnimatorState*)state)->unk48 <= (f32)((XyzAnimatorPlacement*)setup)->unk26)
                {
                    ((XyzAnimatorState*)state)->unk48 = (f32)((XyzAnimatorPlacement*)setup)->unk26;
                    done += 1;
                }
            }
            else
            {
                ((XyzAnimatorState*)state)->unk48 =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2B * timeDelta) + ((XyzAnimatorState*)
                        state)->unk48;
                if (((XyzAnimatorState*)state)->unk48 >= (f32)((XyzAnimatorPlacement*)setup)->unk26)
                {
                    ((XyzAnimatorState*)state)->unk48 = (f32)((XyzAnimatorPlacement*)setup)->unk26;
                    done += 1;
                }
            }
            if (done == 3)
            {
                if (((XyzAnimatorPlacement*)setup)->unk1A != -1)
                {
                    GameBit_Set(((XyzAnimatorPlacement*)setup)->unk1A, 1);
                }
                ((XyzAnimatorState*)state)->unk4D += 1;
            }
        }
        else
        {
            if (((XyzAnimatorPlacement*)setup)->unk1C > ((XyzAnimatorPlacement*)setup)->unk22)
            {
                ((XyzAnimatorState*)state)->unk40 =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk29 * timeDelta) + ((XyzAnimatorState*)
                        state)->unk40;
                if (((XyzAnimatorState*)state)->unk40 >= (f32)((XyzAnimatorPlacement*)setup)->unk1C)
                {
                    ((XyzAnimatorState*)state)->unk40 = (f32)((XyzAnimatorPlacement*)setup)->unk1C;
                    done = 1;
                }
            }
            else
            {
                ((XyzAnimatorState*)state)->unk40 =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk29 * timeDelta) -
                        ((XyzAnimatorState*)state)->unk40);
                if (((XyzAnimatorState*)state)->unk40 <= (f32)((XyzAnimatorPlacement*)setup)->unk1C)
                {
                    ((XyzAnimatorState*)state)->unk40 = (f32)((XyzAnimatorPlacement*)setup)->unk1C;
                    done = 1;
                }
            }
            if (((XyzAnimatorPlacement*)setup)->unk1E > ((XyzAnimatorPlacement*)setup)->unk24)
            {
                ((XyzAnimatorState*)state)->unk44 =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2A * timeDelta) + ((XyzAnimatorState*)
                        state)->unk44;
                if (((XyzAnimatorState*)state)->unk44 >= (f32)((XyzAnimatorPlacement*)setup)->unk1E)
                {
                    ((XyzAnimatorState*)state)->unk44 = (f32)((XyzAnimatorPlacement*)setup)->unk1E;
                    done += 1;
                }
            }
            else
            {
                ((XyzAnimatorState*)state)->unk44 =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2A * timeDelta) -
                        ((XyzAnimatorState*)state)->unk44);
                if (((XyzAnimatorState*)state)->unk44 <= (f32)((XyzAnimatorPlacement*)setup)->unk1E)
                {
                    ((XyzAnimatorState*)state)->unk44 = (f32)((XyzAnimatorPlacement*)setup)->unk1E;
                    done += 1;
                }
            }
            if (((XyzAnimatorPlacement*)setup)->unk20 > ((XyzAnimatorPlacement*)setup)->unk26)
            {
                ((XyzAnimatorState*)state)->unk48 =
                    lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2B * timeDelta) + ((XyzAnimatorState*)
                        state)->unk48;
                if (((XyzAnimatorState*)state)->unk48 >= (f32)((XyzAnimatorPlacement*)setup)->unk20)
                {
                    ((XyzAnimatorState*)state)->unk48 = (f32)((XyzAnimatorPlacement*)setup)->unk20;
                    done += 1;
                }
            }
            else
            {
                ((XyzAnimatorState*)state)->unk48 =
                    -(lbl_803E4018 * ((f32)(int)((XyzAnimatorPlacement*)setup)->unk2B * timeDelta) -
                        ((XyzAnimatorState*)state)->unk48);
                if (((XyzAnimatorState*)state)->unk48 <= (f32)((XyzAnimatorPlacement*)setup)->unk20)
                {
                    ((XyzAnimatorState*)state)->unk48 = (f32)((XyzAnimatorPlacement*)setup)->unk20;
                    done += 1;
                }
            }
            if (done == 3)
            {
                ((XyzAnimatorState*)state)->unk4D += 1;
            }
        }
        break;
    }
    fn_80194C40(setup, state, block);
no_update:
    return;
}

void xyzanimator_init(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    int id;
    ObjGroup_AddObject(obj, 0x51);
    id = *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
    switch (id)
    {
    case 0x46406:
    case 0x4BAB1:
        ((XyzAnimatorState*)inner)->loopSfxId = 0x7d;
        break;
    case 0x49275:
    case 0x49CB7:
    case 0x4C797:
        ((XyzAnimatorState*)inner)->loopSfxId = 0x4b7;
        break;
    }
}
