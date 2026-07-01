/*
 * dfbarrelanim - rope/chain physics construction and helpers for the
 * DragonRock (DF) rope-node objects (dll_0175_dfropenode).
 *
 * DFRope_Create lays out a single mmAlloc block holding the DFRope header,
 * its per-node array and the inter-node link array, seeds node positions
 * evenly between the start and end points, pins the two endpoint nodes
 * (locked), and wires each link to its node pair via DFRopeLink_AttachNodes.
 * The lbl_803E4DF8..803E4E18 constants tune the simulation (rest step,
 * damping, slack, link stiffness/max-length scale).
 *
 * The dfropenode_func0F..func13 accessors read/write the DFropenodeExtra
 * state (angle, hidden flag with its linked-object mirror, ground minY,
 * linked object). fn_801C1698 projects a point onto the start->end segment
 * (clamped to the endpoints) and returns the projection parameter t.
 */
#include "main/game_object.h"
#include "main/dll/DF/dfropenode.h"
#include "main/mm.h"
#include "main/dll/fx_800944A0_shared.h"

extern f32 lbl_803E4DF8;
extern const f32 lbl_803E4DFC;
extern const f32 lbl_803E4E00;
extern f32 lbl_803E4E04;
extern const f32 lbl_803E4E08;
extern const f32 lbl_803E4E0C;
extern const f32 lbl_803E4E10;
extern const f32 lbl_803E4E14;
extern f32 lbl_803E4E18;

DFRope* DFRope_Create(f32 startX, f32 startY, f32 startZ, f32 endX, f32 endY, f32 endZ, f32 unused,
                      s32 count, f32 tickScale)
{
    DFRope* rope;
    DFRopeNode* nodes;
    DFRopeNode* node;
    DFRopeLink* link;
    DFRopeNode* nextNode;
    s32 linkCount;
    s32 i;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 length;

    dx = endX - startX;
    dy = endY - startY;
    dz = endZ - startZ;
    length = sqrtf(dz * dz + (dx * dx + dy * dy));

    dx = dx / (f32)(count - 1);
    dy = dy / (f32)(count - 1);
    dz = dz / (f32)(count - 1);

    {
        s32 nodesSize = count * sizeof(DFRopeNode);
        s32 allocSize = (count - 1) * sizeof(DFRopeLink) + sizeof(DFRope) + nodesSize;
        rope = (DFRope*)mmAlloc(allocSize, 0xFF, 0);
        rope->nodes = (DFRopeNode*)((u8*)rope + sizeof(DFRope));
        rope->links = (DFRopeLink*)((u8*)rope + nodesSize + sizeof(DFRope));
    }
    rope->count = count;
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
    if (rope->step * length > lbl_803E4E04)
    {
        rope->step = *(f32*)&lbl_803E4E04 / length;
    }
    rope->maxSlack = lbl_803E4E08;
    rope->stepPerTick = rope->step / tickScale;
    rope->inverseTicks = lbl_803E4E0C / tickScale;

    nodes = rope->nodes;
    node = nodes;
    for (i = 0; i < count; node++, i++)
    {
        node->pos[0] = i * dx + rope->start[0];
        node->pos[1] = i * dy + rope->start[1];
        node->pos[2] = i * dz + rope->start[2];
        node->velocity[2] = lbl_803E4DFC;
        node->velocity[1] = lbl_803E4DFC;
        node->velocity[0] = lbl_803E4DFC;
        node->force[2] = lbl_803E4DFC;
        node->force[1] = lbl_803E4DFC;
        node->force[0] = lbl_803E4DFC;
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

    nodes[count - 1].locked = 1;
    nodes[0].locked = 1;

    i = 0;
    link = rope->links;
    node = nodes;
    linkCount = count - 1;
    for (; i < linkCount; i++)
    {
        link->restLength = rope->totalLength / linkCount;
        link->stiffness = lbl_803E4E10;
        link->force[2] = lbl_803E4DFC;
        link->force[1] = lbl_803E4DFC;
        link->force[0] = lbl_803E4DFC;
        link->maxLength = lbl_803E4E14 * link->restLength;
        nextNode = (DFRopeNode*)((u8*)nodes + (i + 1) * sizeof(DFRopeNode));
        DFRopeLink_AttachNodes(link, node, nextNode);
        link++;
        node++;
    }
    return rope;
}

void dfropenode_func12(int obj, float value)
{
    ((DFropenodeObject*)obj)->extra->minY = value;
}

int dfropenode_func11(int obj)
{
    DFropenodeExtra* extra = ((DFropenodeObject*)obj)->extra;

    return (s16)(extra->hidden == 0);
}

void dfropenode_func10(int obj, int value)
{
    u32 bit;
    u8 bitByte;
    DFropenodeExtra* extra;
    void* linkedObj;

    extra = ((DFropenodeObject*)obj)->extra;
    bit = (value == 0);
    bitByte = bit;
    extra->hidden = bitByte;
    linkedObj = extra->linkedObj;
    if (linkedObj != NULL)
    {
        extra = ((DFropenodeObject*)linkedObj)->extra;
        extra->hidden = bitByte;
    }
}

void dfropenode_func13(int obj)
{
    ((DFropenodeObject*)obj)->extra->linkedObj = 0;
}

int dfropenode_func0F(int obj)
{
    return ((DFropenodeObject*)obj)->extra->angle;
}

f32 fn_801C1698(f32* x, f32* y, f32* z, f32 startX, f32 startY, f32 startZ, f32 endX, f32 endY,
                f32 endZ)
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
