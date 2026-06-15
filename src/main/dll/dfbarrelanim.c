#include "main/game_object.h"
#include "main/dll/DF/dfropenode.h"

extern f32 sqrtf(f32 x);
extern void* mmAlloc(int size, int heap, int flags);

extern f32 lbl_803E4DF8;
extern f32 lbl_803E4DFC;
extern f32 lbl_803E4E00;
extern f32 lbl_803E4E04;
extern f32 lbl_803E4E08;
extern f32 lbl_803E4E0C;
extern f32 lbl_803E4E10;
extern f32 lbl_803E4E14;
extern f32 lbl_803E4E18;

DFRope* DFRope_Create(s32 count, f32 startX, f32 startY, f32 startZ, f32 endX, f32 endY, f32 endZ,
                      f32 unused, f32 tickScale)
{
    DFRope* rope;
    DFRopeNode* node;
    DFRopeLink* link;
    DFRopeNode* nextNode;
    s32 linkCount;
    s32 i;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 length;
    f32 zero;

    dx = endX - startX;
    dy = endY - startY;
    dz = endZ - startZ;
    length = sqrtf(dz * dz + (dx * dx + dy * dy));

    dx = dx / (f32)(count - 1);
    dy = dy / (f32)(count - 1);
    dz = dz / (f32)(count - 1);

    {
        s32 nodesSize = count * sizeof(DFRopeNode);
        rope = (DFRope*)mmAlloc(nodesSize + (count - 1) * sizeof(DFRopeLink) + sizeof(DFRope),
                                0xFF, 0);
        rope->nodes = (DFRopeNode*)((u8*)rope + sizeof(DFRope));
        rope->links = (DFRopeLink*)((u8*)rope + nodesSize + sizeof(DFRope));
    }
    rope->count = (u8)count;
    rope->totalLength = length;
    rope->start[0] = startX;
    rope->start[1] = startY;
    rope->start[2] = startZ;
    rope->end[0] = endX;
    rope->end[1] = endY;
    rope->end[2] = endZ;
    rope->sway = 0;
    rope->direction = 1;
    rope->damping = lbl_803E4E00;
    rope->enabled = 1;
    rope->step = lbl_803E4DF8;
    if (lbl_803E4E04 < rope->step * length)
    {
        rope->step = lbl_803E4E04 / length;
    }
    rope->maxSlack = lbl_803E4E08;
    rope->stepPerTick = rope->step / tickScale;
    rope->inverseTicks = lbl_803E4E0C / tickScale;

    zero = lbl_803E4DFC;
    node = rope->nodes;
    for (i = 0; i < count; i++, node++)
    {
        node->pos[0] = (f32)i * dx + rope->start[0];
        node->pos[1] = (f32)i * dy + rope->start[1];
        node->pos[2] = (f32)i * dz + rope->start[2];
        node->velocity[2] = zero;
        node->velocity[1] = zero;
        node->velocity[0] = zero;
        node->force[2] = zero;
        node->force[1] = zero;
        node->force[0] = zero;
        node->locked = 0;
        if ((i == 0) || (i == count - 1))
        {
            node->linkCount = 1;
        }
        else if ((i == 1) || (i == count - 2))
        {
            node->linkCount = 2;
        }
        else
        {
            node->linkCount = 2;
        }
        {
            s32 j;
            for (j = 0; j < node->linkCount; j++)
            {
                node->links[j] = NULL;
            }
        }
    }

    rope->nodes[count - 1].locked = 1;
    rope->nodes[0].locked = 1;

    link = rope->links;
    node = rope->nodes;
    linkCount = count - 1;
    for (i = 0; i < linkCount; i++)
    {
        link->restLength = rope->totalLength / (f32)linkCount;
        link->stiffness = lbl_803E4E10;
        link->force[2] = zero;
        link->force[1] = zero;
        link->force[0] = zero;
        link->maxLength = lbl_803E4E14 * link->restLength;
        nextNode = (DFRopeNode*)((u8*)rope->nodes + (i + 1) * sizeof(DFRopeNode));
        DFRopeLink_AttachNodes(link, node, nextNode);
        link++;
        node++;
    }
    return rope;
}

void dfropenode_func12(int obj, float value)
{
    ((DFropenodeExtra*)*(int*)&((GameObject*)obj)->extra)->minY = value;
}

int dfropenode_func11(int obj)
{
    DFropenodeExtra* extra = (DFropenodeExtra*)*(int*)&((GameObject*)obj)->extra;

    return (s16)(extra->hidden == 0);
}

void dfropenode_func10(int obj, int value)
{
    u32 bit;
    u8 bitByte;
    DFropenodeExtra* extra;
    void* linkedObj;

    extra = (DFropenodeExtra*)*(int*)&((GameObject*)obj)->extra;
    bit = (value == 0);
    bitByte = bit;
    extra->hidden = bitByte;
    linkedObj = (void*)extra->linkedObj;
    if (linkedObj != NULL)
    {
        extra = (DFropenodeExtra*)*(int*)((u8*)linkedObj + 0xb8);
        extra->hidden = bitByte;
    }
}

void dfropenode_func13(int obj)
{
    ((DFropenodeExtra*)*(int*)&((GameObject*)obj)->extra)->linkedObj = 0;
}

int dfropenode_func0F(int obj)
{
    return ((DFropenodeExtra*)*(int*)&((GameObject*)obj)->extra)->angle;
}

f32 fn_801C1698(f32 startX, f32 startY, f32 startZ, f32 endX, f32 endY, f32 endZ, f32* x, f32* y,
                f32* z)
{
    f32 dx;
    f32 dy;
    f32 dz;
    f32 t;

    dx = endX - startX;
    dy = endY - startY;
    dz = endZ - startZ;
    if ((lbl_803E4DFC == dx) && (lbl_803E4DFC == dz))
    {
        t = lbl_803E4DFC;
    }
    else
    {
        t = (dx * (*x - startX) + dz * (*z - startZ)) / (dx * dx + dz * dz);
    }
    if (t < *(f32*)&lbl_803E4DFC)
    {
        *x = startX;
        *y = startY;
        *z = startZ;
    }
    else if (t >= lbl_803E4E18)
    {
        *x = endX;
        *y = endY;
        *z = endZ;
    }
    else
    {
        *x = t * dx + startX;
        *y = t * dy + startY;
        *z = t * dz + startZ;
    }
    return t;
}
