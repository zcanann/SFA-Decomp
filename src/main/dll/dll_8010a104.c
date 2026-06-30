/*
 * Path-camera ROM-curve graph navigation (DLL 0x5B, CameraModeStatic
 * family). Operates on the ROM curve-node graph reached through
 * gRomCurveInterface->getById: each node holds up to five neighbour
 * node IDs (int[5] at +0x1C) and a direction bitmask (+0x1B) splitting
 * them into "forward"/"backward" links, plus three path-tag bytes
 * (+0x31..+0x33) used to keep a walk on the path selected by `tag`.
 *
 * fn_8010A104 advances the camera's near/far node pair (*p1/*p2) along
 * the tagged path: it nudges *p1 to the matching neighbour, then slides
 * it by world distance through the node window from
 * pathcam_findTaggedNodeWindow (near/far thresholds lbl_803E1888 /
 * lbl_803E188C), counts the tagged span with fn_8010A47C, and walks *p2
 * the same number of steps so the pair stays a fixed span apart.
 *
 * fn_8010A47C walks a node along its forward tagged links until it hits
 * an endpoint (node type 0x1A/0x1B at +0x19), returning the final node
 * and the number of steps taken.
 */
#include "main/dll/CAM/camshipbattle5C.h"
#include "main/dll/CAM/dll_5B.h"
#include "main/dll/rom_curve_interface.h"

#define PATHCURVE_NODE_LINK_COUNT 5

/*
 * Local view of the ROM curve-node graph as walked by this DLL. Mirrors the
 * sibling camshipbattle5C node but exposes the five-way neighbour array and the
 * three path-tag bytes this unit relies on.
 */
typedef struct PathCurveNode {
    u8 pad00[0x08];
    f32 x;
    f32 y;
    f32 z;
    s32 selfId;
    u8 pad18;
    s8 type;
    u8 pad1a;
    s8 directionMask;
    s32 links[PATHCURVE_NODE_LINK_COUNT];
    u8 pad30;
    u8 tag0;
    u8 tag1;
    u8 tag2;
} PathCurveNode;

extern f32 lbl_803E1888; /* near distance threshold */
extern f32 lbl_803E188C; /* far distance threshold */
extern f32 fn_8010AC48(f32 px, f32 py, f32 pz, int* obj);

#define PATHCAM_NEAR_THRESHOLD lbl_803E1888
#define PATHCAM_FAR_THRESHOLD lbl_803E188C

void fn_8010A104(int* p1, int* p2, f32 x, f32 y, f32 z, int tag)
{
    int node;
    int linked;
    int noForwardExit;
    int slot;
    int slot2;
    int step;
    int window[4];
    int span;
    int farSpan;
    int settled;
    f32 dist;
    f32 nearThresh;

    node = (int)(*gRomCurveInterface)->getById(*p1);
    noForwardExit = 1;
    for (slot = 0; slot < PATHCURVE_NODE_LINK_COUNT; slot++)
    {
        if (((PathCurveNode*)node)->links[slot] > -1 &&
            (((PathCurveNode*)node)->directionMask & (1 << slot)) == 0)
        {
            linked = (int)(*gRomCurveInterface)->getById(((PathCurveNode*)node)->links[slot]);
            if ((u32)linked != 0 &&
                (((PathCurveNode*)linked)->tag0 == tag || ((PathCurveNode*)linked)->tag1 == tag ||
                    ((PathCurveNode*)linked)->tag2 == tag))
            {
                noForwardExit = 0;
                slot = PATHCURVE_NODE_LINK_COUNT;
            }
        }
    }
    if (noForwardExit != 0)
    {
        for (slot = 0; slot < PATHCURVE_NODE_LINK_COUNT; slot++)
        {
            if (((PathCurveNode*)node)->links[slot] > -1 &&
                (((PathCurveNode*)node)->directionMask & (1 << slot)) != 0)
            {
                linked = (int)(*gRomCurveInterface)->getById(((PathCurveNode*)node)->links[slot]);
                if ((u32)linked != 0 &&
                    (((PathCurveNode*)linked)->tag0 == tag || ((PathCurveNode*)linked)->tag1 == tag ||
                        ((PathCurveNode*)linked)->tag2 == tag))
                {
                    *p1 = ((PathCurveNode*)node)->links[slot];
                    slot = PATHCURVE_NODE_LINK_COUNT;
                }
            }
        }
    }
    settled = 0;
    nearThresh = PATHCAM_NEAR_THRESHOLD;
    while (settled == 0)
    {
        settled = 1;
        node = (int)(*gRomCurveInterface)->getById(*p1);
        pathcam_findTaggedNodeWindow((u8*)node, window, tag);
        dist = fn_8010AC48(x, y, z, window);
        if (dist < nearThresh)
        {
            if (window[0] > -1)
            {
                *p1 = window[0];
                settled = 0;
            }
        }
        else if (dist > PATHCAM_FAR_THRESHOLD)
        {
            if (window[2] > -1 && window[3] > -1)
            {
                *p1 = window[2];
                settled = 0;
            }
        }
    }
    node = (int)(*gRomCurveInterface)->getById(*p1);
    fn_8010A47C(node, &span, tag);
    node = (int)(*gRomCurveInterface)->getById(*p2);
    *p2 = ((PathCurveNode*)fn_8010A47C(node, &farSpan, tag))->selfId;
    for (step = 0; step < span; step++)
    {
        node = (int)(*gRomCurveInterface)->getById(*p2);
        for (slot2 = 0; slot2 < PATHCURVE_NODE_LINK_COUNT; slot2++)
        {
            if (((PathCurveNode*)node)->links[slot2] > -1 &&
                (((PathCurveNode*)node)->directionMask & (1 << slot2)) == 0)
            {
                linked = (int)(*gRomCurveInterface)->getById(((PathCurveNode*)node)->links[slot2]);
                if ((u32)linked != 0 &&
                    (((PathCurveNode*)linked)->tag0 == tag || ((PathCurveNode*)linked)->tag1 == tag ||
                        ((PathCurveNode*)linked)->tag2 == tag))
                {
                    *p2 = ((PathCurveNode*)node)->links[slot2];
                    slot2 = PATHCURVE_NODE_LINK_COUNT;
                }
            }
        }
    }
}

int fn_8010A47C(int curve, int* count, int tag)
{
    int slot;
    int done;
    int linked;

    done = 0;
    *count = 0;
    while (done == 0)
    {
        done = 1;
        if ((((PathCurveNode*)curve)->type != 0x1b) && (((PathCurveNode*)curve)->type != 0x1a))
        {
            for (slot = 0; slot < PATHCURVE_NODE_LINK_COUNT; slot++)
            {
                if ((((PathCurveNode*)curve)->links[slot] > -1) &&
                    ((((PathCurveNode*)curve)->directionMask & (1 << slot)) != 0))
                {
                    linked = (int)(*gRomCurveInterface)->getById(((PathCurveNode*)curve)->links[slot]);
                    if (((u32)linked != 0) &&
                        ((((PathCurveNode*)linked)->tag0 == tag || (((PathCurveNode*)linked)->tag1 == tag)) ||
                            (((PathCurveNode*)linked)->tag2 == tag)))
                    {
                        curve = linked;
                        done = 0;
                        slot = PATHCURVE_NODE_LINK_COUNT;
                    }
                }
            }
        }
        if (done == 0)
        {
            (*count)++;
        }
    }
    return curve;
}
