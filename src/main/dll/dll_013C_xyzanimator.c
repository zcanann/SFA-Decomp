/* === moved from main/dll/MMP/mmp_levelcontrol.c [801948C0-80195008) (TU re-split, docs/boundary_audit.md) === */
#include "main/effect_interfaces.h"
#include "main/game_object.h"







extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern void* fn_800606DC(int* obj, int idx);
extern void* fn_800606FC(int* obj, int idx);
extern void* fn_8006070C(int* obj, int idx);
extern void mm_free(void* ptr);
extern void DCStoreRange(void* addr, u32 nBytes);
extern int return0_80060B90(void);
extern void* Shader_getLayer(void* shader, int idx);

extern f32 lbl_803E4000;
extern f32 lbl_803E4008;

/*
 * --INFO--
 *
 * Function: wallanimator_setScale
 * EN v1.0 Address: 0x8019443C
 * EN v1.0 Size: 264b
 * EN v1.1 Address: 0x80194688
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_80194544
 * EN v1.0 Address: 0x80194544
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x801947D4
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: objFn_801948c0
 * EN v1.0 Address: 0x801948C0
 * EN v1.0 Size: 164b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
f32 objFn_801948c0(u8* obj, u8 coord)
{
    u8* state;

    if (obj == NULL || (state = ((GameObject*)obj)->extra, state == NULL))
    {
        return lbl_803E4000;
    }
    switch (coord)
    {
    case 1:
        return ((GameObject*)obj)->anim.localPosX + *(f32*)(state + 0x40);
    case 2:
        return *(f32*)(state + 0x40);
    case 3:
        return ((GameObject*)obj)->anim.localPosY + *(f32*)(state + 0x44);
    case 4:
        return *(f32*)(state + 0x44);
    case 5:
        return ((GameObject*)obj)->anim.localPosZ + *(f32*)(state + 0x48);
    case 6:
        return *(f32*)(state + 0x48);
    }
    return lbl_803E4000;
}

/*
 * --INFO--
 *
 * Function: FUN_80194a70
 * EN v1.0 Address: 0x80194A70
 * EN v1.0 Size: 160b
 * EN v1.1 Address: 0x80194E3C
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_80194b10
 * EN v1.0 Address: 0x80194B10
 * EN v1.0 Size: 512b
 * EN v1.1 Address: 0x80194EE0
 * EN v1.1 Size: 504b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


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

#pragma scheduling off
#pragma peephole off
void fn_80194964(int obj, int state, int block)
{
    extern uint mapBlockFn_80060678(int* block); /* #57 */
    extern void* mapBlockFn_800606ec(int* obj, int idx); /* #57 */
    ushort blockEnd;
    ushort* mapBlock;
    int blockLayer;
    int coordOffset;
    VertexS16* vtx;
    uint triangle;
    int triangleOffset;
    int edge;
    int edgeOffset;
    int blockIndex;

    triangleOffset = 0;
    coordOffset = 0;
    edgeOffset = 0;
    for (blockIndex = 0; blockIndex < (int)(uint) * (ushort*)(block + 0x9a); blockIndex++)
    {
        mapBlock = (ushort*)mapBlockFn_800606ec((int*)block, blockIndex);
        blockLayer = mapBlockFn_80060678((int*)mapBlock);
        if ((int)*(char*)(obj + 0x28) == blockLayer)
        {
            *(s16*)(*(int*)(state + 0x10) + coordOffset) = ((MapBlockHdr*)mapBlock)->posA;
            *(s16*)(*(int*)(state + 0x14) + coordOffset) = ((MapBlockHdr*)mapBlock)->posB;
            coordOffset += 2;
            blockEnd = mapBlock[10];
            triangle = (uint) * mapBlock;
            edgeOffset = triangleOffset;
            for (; (int)triangle < (int)(uint)blockEnd; triangle++)
            {
                mapBlock = (ushort*)fn_800606DC((int*)block, triangle);
                vtx = (VertexS16*)(*(int*)(block + 0x58) + (uint) * mapBlock * 6);
                *(s16*)(*(int*)(state + 0xc) + edgeOffset) = vtx->x;
                *(s16*)(*(int*)(state + 0xc) + edgeOffset + 2) = vtx->y;
                *(s16*)(*(int*)(state + 0xc) + edgeOffset + 4) = vtx->z;
                vtx = (VertexS16*)(*(int*)(block + 0x58) + (uint)mapBlock[1] * 6);
                *(s16*)(*(int*)(state + 0xc) + edgeOffset + 6) = vtx->x;
                *(s16*)(*(int*)(state + 0xc) + edgeOffset + 8) = vtx->y;
                *(s16*)(*(int*)(state + 0xc) + edgeOffset + 10) = vtx->z;
                vtx = (VertexS16*)(*(int*)(block + 0x58) + (uint)mapBlock[2] * 6);
                *(s16*)(*(int*)(state + 0xc) + edgeOffset + 0xc) = vtx->x;
                *(s16*)(*(int*)(state + 0xc) + edgeOffset + 0xe) = vtx->y;
                *(s16*)(*(int*)(state + 0xc) + edgeOffset + 0x10) = vtx->z;
                edgeOffset += 0x12;
                triangleOffset += 0x12;
            }
        }
    }
    edge = 0;
    for (edgeOffset = 0; edgeOffset < (int)(uint) * (byte*)(block + 0xa1); edgeOffset++)
    {
        blockIndex = (int)fn_800606FC((int*)block, edgeOffset);
        *(s16*)(*(int*)(state + 0x28) + edge) = ((EdgeVerts*)blockIndex)->a;
        *(s16*)(*(int*)(state + 0x2c) + edge) = ((EdgeVerts*)blockIndex)->d;
        *(s16*)(*(int*)(state + 0x30) + edge) = ((EdgeVerts*)blockIndex)->b;
        *(s16*)(*(int*)(state + 0x34) + edge) = ((EdgeVerts*)blockIndex)->e;
        *(s16*)(*(int*)(state + 0x38) + edge) = ((EdgeVerts*)blockIndex)->c;
        *(s16*)(*(int*)(state + 0x3c) + edge) = ((EdgeVerts*)blockIndex)->f;
        edge += 2;
    }
}

void fn_80194C40(undefined4 def, int state, int block)
{
    extern uint mapBlockFn_80060678(int* block); /* #57 */
    extern void* mapBlockFn_800606ec(int* obj, int idx); /* #57 */
    ushort blockEnd;
    f32 scale;
    int edgeData;
    ushort* mapBlock;
    int blockLayer;
    void* shader;
    VertexS16* vtx;
    uint triangle;
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
    for (blockIndex = 0; blockIndex < (int)(uint) * (ushort*)(block + 0x9a); blockIndex++)
    {
        mapBlock = (ushort*)mapBlockFn_800606ec((int*)block, blockIndex);
        blockLayer = mapBlockFn_80060678((int*)mapBlock);
        if ((int)*(char*)(def + 0x28) == blockLayer)
        {
            ((MapBlockHdr*)mapBlock)->posA = (int)(*(float*)(state + 0x44) +
                (f32) * (s16*)(*(int*)(state + 0x10) + coordOffset));
            ((MapBlockHdr*)mapBlock)->posB = (int)(*(float*)(state + 0x44) +
                (f32) * (s16*)(*(int*)(state + 0x14) + coordOffset));
            coordOffset += 2;
            blockEnd = mapBlock[10];
            scale = lbl_803E4008;
            triangle = (uint) * mapBlock;
            edgeOffset = vertexOffset;
            for (; (int)triangle < (int)(uint)blockEnd; triangle++)
            {
                mapBlock = (ushort*)fn_800606DC((int*)block, triangle);
                vertexIndex = edgeOffset;
                for (edgeIndex = 3; edgeIndex != 0; edgeIndex--)
                {
                    vtx = (VertexS16*)(*(int*)(block + 0x58) + (uint) * mapBlock * 6);
                    vtx->x = (int)(scale * *(float*)(state + 0x40) +
                        (f32) * (s16*)(*(int*)(state + 0xc) + edgeOffset));
                    vtx->y = (int)(scale * *(float*)(state + 0x44) +
                        (f32) * (s16*)(*(int*)(state + 0xc) + edgeOffset + 2));
                    vtx->z = (int)(scale * *(float*)(state + 0x48) +
                        (f32) * (s16*)(*(int*)(state + 0xc) + edgeOffset + 4));
                    edgeOffset += 6;
                    vertexIndex += 6;
                    vertexOffset += 6;
                    mapBlock++;
                }
                edgeOffset = vertexIndex;
            }
        }
    }
    DCStoreRange(*(void**)(block + 0x58), (uint) * (ushort*)(block + 0x90) * 6);
    edgeData = 0;
    for (edgeOffset = 0; edgeOffset < (int)(uint) * (byte*)(block + 0xa1); edgeOffset++)
    {
        vertexOffset = (int)fn_800606FC((int*)block, edgeOffset);
        shader = fn_8006070C((int*)block, *(byte*)(vertexOffset + 0x13));
        shader = Shader_getLayer(shader, 0);
        scale = lbl_803E4008;
        if ((uint) * (byte*)((int)shader + 5) == (int)*(char*)(def + 0x28))
        {
            ((EdgeVerts*)vertexOffset)->a = (int)(scale * *(float*)(state + 0x40) +
                (f32) * (s16*)(*(int*)(state + 0x28) + edgeData));
            ((EdgeVerts*)vertexOffset)->d = (int)(scale * *(float*)(state + 0x40) +
                (f32) * (s16*)(*(int*)(state + 0x2c) + edgeData));
            ((EdgeVerts*)vertexOffset)->b = (int)(scale * *(float*)(state + 0x44) +
                (f32) * (s16*)(*(int*)(state + 0x30) + edgeData));
            ((EdgeVerts*)vertexOffset)->e = (int)(scale * *(float*)(state + 0x44) +
                (f32) * (s16*)(*(int*)(state + 0x34) + edgeData));
            ((EdgeVerts*)vertexOffset)->c = (int)(scale * *(float*)(state + 0x48) +
                (f32) * (s16*)(*(int*)(state + 0x38) + edgeData));
            ((EdgeVerts*)vertexOffset)->f = (int)(scale * *(float*)(state + 0x48) +
                (f32) * (s16*)(*(int*)(state + 0x3c) + edgeData));
        }
        edgeData += 2;
    }
    *(int*)block = return0_80060B90();
}

/*
 * --INFO--
 *
 * Function: wallanimator_getExtraSize
 * EN v1.0 Address: 0x8019469C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: xyzanimator_getExtraSize
 * EN v1.0 Address: 0x80194B5C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int xyzanimator_getExtraSize(void)
{
    return 0x50;
}

void xyzanimator_free(int obj, int param_2)
{
    extern int mapGetBlock(int blockIdx); /* #57 */
    extern int objPosToMapBlockIdx(double x, double y, double z); /* #57 */
    int block;
    int state;
    undefined4 def;
    f32 zero;

    zero = lbl_803E4000;
    state = *(int*)&((GameObject*)obj)->extra;
    def = *(undefined4*)&((GameObject*)obj)->anim.placementData;
    *(float*)(state + 0x40) = lbl_803E4000;
    *(float*)(state + 0x44) = zero;
    *(float*)(state + 0x48) = zero;
    if (param_2 == 0)
    {
        block = objPosToMapBlockIdx((double)((GameObject*)obj)->anim.localPosX,
                                    (double)((GameObject*)obj)->anim.localPosY,
                                    (double)((GameObject*)obj)->anim.localPosZ);
        block = mapGetBlock(block);
        if ((block != 0) && (*(int*)(state + 4) != 0))
        {
            fn_80194C40(def, state, block);
        }
    }
    if (*(int*)(state + 0xc) != 0)
    {
        mm_free(*(void**)(state + 0xc));
    }
    ObjGroup_RemoveObject(obj, 0x51);
    return;
}

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3FF8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E4004;


void xyzanimator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4004);
}




/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/map_block.h"
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/path_control_interface.h"
#include "main/game_object.h"













/*
 * --INFO--
 *
 * Function: xyzanimator_update
 * EN v1.0 Address: 0x80195008
 * EN v1.0 Size: 164b
 * EN v1.1 Address: 0x801950E0
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern int mmAlloc(int size, int pool, int tag);
extern void Sfx_KeepAliveLoopedObjectSound(int obj);
extern f32 timeDelta;
extern f32 lbl_803E4018;

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
        goto done_lbl;
    }
    if ((*(u16*)(block + 4) & 8) == 0)
    {
        goto done_lbl;
    }
    if (((XyzAnimatorState*)state)->unk4 == 0)
    {
        for (i = 0; i < *(u16*)(block + 0x9a); i++)
        {
            row = mapBlockFn_800606ec(block, i);
            t = mapBlockFn_80060678();
            if (((XyzAnimatorPlacement*)setup)->unk28 == t)
            {
                ((XyzAnimatorState*)state)->rowCount = ((XyzAnimatorState*)state)->rowCount + 1;
                ((XyzAnimatorState*)state)->unk4 =
                    ((XyzAnimatorState*)state)->unk4 + (*(u16*)(row + 0x14) - *(u16*)(row + 0));
            }
        }
        if (((XyzAnimatorState*)state)->unk4 == 0)
        {
            goto done_lbl;
        }
        ((XyzAnimatorState*)state)->unk4 = ((XyzAnimatorState*)state)->unk4 * 3;
        if (((XyzAnimatorPlacement*)setup)->unk18 == -1)
        {
            ((XyzAnimatorState*)state)->gameBitValue = 1;
        }
        else
        {
            ((XyzAnimatorState*)state)->gameBitValue = (s8)GameBit_Get(((XyzAnimatorPlacement*)setup)->unk18);
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
        alloc = mmAlloc(t + ((XyzAnimatorState*)state)->unk8 * 0xc, 5, 0);
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
        ((XyzAnimatorState*)state)->unk3C = alloc + stride;
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
            ((XyzAnimatorState*)state)->gameBitValue = (s8)t;
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
            goto done_lbl;
        }
        if (((XyzAnimatorState*)state)->unk4E != 0)
        {
            Sfx_KeepAliveLoopedObjectSound(obj);
        }
    }
    else
    {
        if (((XyzAnimatorState*)state)->unk4D > 2)
        {
            goto done_lbl;
        }
        if (((XyzAnimatorState*)state)->gameBitValue == 0)
        {
            ((XyzAnimatorState*)state)->gameBitValue = (s8)GameBit_Get(((XyzAnimatorPlacement*)setup)->unk18);
            if (((XyzAnimatorState*)state)->gameBitValue == 0)
            {
                goto done_lbl;
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
done_lbl:
    return;
}

/*
 * --INFO--
 *
 * Function: FUN_801950ac
 * EN v1.0 Address: 0x801950AC
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8019518C
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801954f0
 * EN v1.0 Address: 0x801954F0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80195584
 * EN v1.1 Size: 4624b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801954f4
 * EN v1.0 Address: 0x801954F4
 * EN v1.0 Size: 176b
 * EN v1.1 Address: 0x80196794
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_80195b40
 * EN v1.0 Address: 0x80195B40
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80196EA8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_80195b74
 * EN v1.0 Address: 0x80195B74
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x80196ED8
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void explodeanimator_render(void);


















/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */



/* ObjGroup_RemoveObject(x, N) wrappers. */

/* state encode: ((obj->_X)->_Y << shift) | const. */

/* Drift-recovery: add new fns with v1.0 names. */










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
        *(s16*)(inner + 0x4e) = 0x7d;
        break;
    case 0x49275:
    case 0x49CB7:
    case 0x4C797:
        *(s16*)(inner + 0x4e) = 0x4b7;
        break;
    }
}

extern f32 sqrtf(f32);

/* EN v1.0 0x80196990  size: 1752b  dimbossicesmash_update: gate on the
 * trigger gamebit, integrate velocity/rotation with per-axis gravity
 * clamps, run the path-control hooks with surface bounce, fade alpha over
 * the lifetime window, and emit the two trail particles. */


/* EN v1.0 0x80196520  size: 1008b  fn_80196520: seed the icesmash launch
 * state from the setup record: spawn position/rotation, launch velocity
 * (optionally homing on the target point), rotation velocities and the
 * gravity/clamp direction flags. */

/* EN v1.0 0x80197068  size: 284b  dimbossicesmash_init. */


/* EN v1.0 0x80197474  size: 648b  fogcontrol_update: ramp the fog blend
 * toward the gamebit-selected target and feed the heavy fog params. */
