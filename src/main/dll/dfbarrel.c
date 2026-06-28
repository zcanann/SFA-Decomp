/*
 * dfbarrel - rope/pulley physics simulation for the DF (Dinosaur Forest) area.
 * DFRope_UpdateSimulation applies sway to mid-rope nodes, then iterates
 * spring-constraint integration via DFPulley_integrateLinks, and finally
 * zeroes each node's accumulated force.
 * DFRopeLink_AttachNodes wires a link between two nodes, storing back-pointers
 * in both nodes' link arrays.
 */
#include "main/dll/DF/DFbarrel.h"
#include "main/game_object.h"
#include "dolphin/mtx.h"

extern f32 lbl_803E4DF8;
extern f32 lbl_803E4DFC;

extern void DFPulley_integrateLinks(u8 * self);

#define DFBARREL_ROPE_PART_SIZE 0x34
#define DFBARREL_ROPE_LINK_SIZE 0x24

#define DFBARREL_SWAY_LIMIT 0x32
#define DFBARREL_SWAY_DIR_INCREASING 1
#define DFBARREL_SWAY_DIR_DECREASING 2

#define DFBARREL_NODE_LINKS_OFFSET 0x28

void DFRope_UpdateSimulation(DFRope* self)
{
    int j;
    DFRopeLink* link;
    int k;
    DFRopeNode* parts;
    int i;
    DFRopeNode* partIter;
    Vec tmp;
    f32 zero;
    DFRopeNode* partsInit;

    partsInit = self->nodes;
    parts = partsInit;

    if ((s8)self->sway < -DFBARREL_SWAY_LIMIT)
    {
        self->direction = DFBARREL_SWAY_DIR_INCREASING;
    }
    if ((s8)self->sway > DFBARREL_SWAY_LIMIT)
    {
        self->direction = DFBARREL_SWAY_DIR_DECREASING;
    }
    if ((s8)self->direction == DFBARREL_SWAY_DIR_DECREASING)
    {
        self->sway--;
    }
    else
    {
        self->sway++;
    }

    i = 1;
    partIter = partsInit + 1;
    {
        f32 rate = lbl_803E4DF8;
        for (; i < self->count - 1; i++)
        {
            partIter->force[0] =
                partIter->force[0] + rate * (f32)(int)(s8)self->sway;
            partIter++;
        }
    }

    k = 0;
    zero = lbl_803E4DFC;
    for (; k < self->enabled; k++)
    {
        link = self->links;
        for (j = 0; j < self->count - 1; j++, link++)
        {
            PSVECSubtract((Vec*)link->a, (Vec*)link->b, &tmp);
            link->length = PSVECMag(&tmp);
            if (link->length > link->maxLength)
            {
                link->restLength = lbl_803E4DFC;
            }
            if (zero == link->restLength)
            {
                link->force[2] = zero;
                link->force[1] = zero;
                link->force[0] = zero;
            }
            else
            {
                PSVECScale(&tmp, (Vec*)link->force,
                           -link->stiffness * (link->length - link->restLength));
            }
        }
        DFPulley_integrateLinks((u8*)self);
    }

    i = 0;
    {
        f32 cleanZero = lbl_803E4DFC;
        for (; i < self->count; i++, parts++)
        {
            parts->force[0] = cleanZero;
            parts->force[1] = cleanZero;
            parts->force[2] = cleanZero;
        }
    }
}

void DFRopeLink_AttachNodes(DFRopeLink* linkSelf, DFRopeNode* firstNode, DFRopeNode* secondNode)
{
    u8* nodeLinkIter;
    int firstLinkIndex;
    int secondLinkIndex;

    firstLinkIndex = 0;
    secondLinkIndex = 0;
    nodeLinkIter = (u8*)firstNode;
    while (*(u32*)(nodeLinkIter + DFBARREL_NODE_LINKS_OFFSET) != 0)
    {
        nodeLinkIter += 4;
        firstLinkIndex++;
    }
    nodeLinkIter = (u8*)secondNode;
    while (*(u32*)(nodeLinkIter + DFBARREL_NODE_LINKS_OFFSET) != 0)
    {
        nodeLinkIter += 4;
        secondLinkIndex++;
    }
    if (firstLinkIndex > firstNode->linkCount || secondLinkIndex > secondNode->linkCount) return;
    firstNode->links[firstLinkIndex] = linkSelf;
    secondNode->links[secondLinkIndex] = linkSelf;
    linkSelf->a = firstNode;
    linkSelf->b = secondNode;
}
