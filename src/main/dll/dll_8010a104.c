/*
 * Path-camera ROM-curve graph navigation (DLL 0x5B, CameraModeStatic
 * family). Operates on the ROM curve-node graph reached through
 * gRomCurveInterface->getById: each node holds up to five neighbour
 * node IDs (int[5] at +0x1C) and a direction bitmask (+0x1B) splitting
 * them into "forward"/"backward" links, plus three path-tag bytes
 * (+0x31..+0x33) used to keep a walk on the path selected by `tag`.
 *
 * fn_8010A104 advances the camera's near/far node pair
 * (*nodeId/*leadNodeId) along the tagged path: it nudges *nodeId to the
 * matching neighbour, then slides it by world distance through the node
 * window from pathcam_findTaggedNodeWindow (near/far thresholds
 * lbl_803E1888 / lbl_803E188C), counts the tagged span with fn_8010A47C,
 * and walks *leadNodeId the same number of steps so the pair stays a
 * fixed span apart.
 *
 * fn_8010A47C walks a node along its forward tagged links until it hits
 * an endpoint (node type 0x1A/0x1B at +0x19), returning the final node
 * and the number of steps taken.
 */
#include "main/dll/CAM/camshipbattle5C.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_8010a104.h"

#define PATHCAM_NEAR_THRESHOLD lbl_803E1888
#define PATHCAM_FAR_THRESHOLD  lbl_803E188C

extern f32 lbl_803E1888; /* near distance threshold */
extern f32 lbl_803E188C; /* far distance threshold */
extern f32 fn_8010AC48(f32 px, f32 py, f32 pz, int* obj);

void fn_8010A104(int* nodeId, int* leadNodeId, f32 x, f32 y, f32 z, int tag)
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

    node = (int)(*gRomCurveInterface)->getById(*nodeId);
    noForwardExit = 1;
    for (slot = 0; slot < ROM_CURVE_PATH_LINK_COUNT; slot++)
    {
        if (((RomCurvePathNode*)node)->links[slot] > -1 && (((RomCurvePathNode*)node)->directionMask & (1 << slot)) == 0)
        {
            linked = (int)(*gRomCurveInterface)->getById(((RomCurvePathNode*)node)->links[slot]);
            if ((u32)linked != 0 && (((RomCurvePathNode*)linked)->tag0 == tag || ((RomCurvePathNode*)linked)->tag1 == tag ||
                                     ((RomCurvePathNode*)linked)->tag2 == tag))
            {
                noForwardExit = 0;
                slot = ROM_CURVE_PATH_LINK_COUNT;
            }
        }
    }
    if (noForwardExit != 0)
    {
        for (slot = 0; slot < ROM_CURVE_PATH_LINK_COUNT; slot++)
        {
            if (((RomCurvePathNode*)node)->links[slot] > -1 && (((RomCurvePathNode*)node)->directionMask & (1 << slot)) != 0)
            {
                linked = (int)(*gRomCurveInterface)->getById(((RomCurvePathNode*)node)->links[slot]);
                if ((u32)linked != 0 &&
                    (((RomCurvePathNode*)linked)->tag0 == tag || ((RomCurvePathNode*)linked)->tag1 == tag ||
                     ((RomCurvePathNode*)linked)->tag2 == tag))
                {
                    *nodeId = ((RomCurvePathNode*)node)->links[slot];
                    slot = ROM_CURVE_PATH_LINK_COUNT;
                }
            }
        }
    }
    settled = 0;
    nearThresh = PATHCAM_NEAR_THRESHOLD;
    while (settled == 0)
    {
        settled = 1;
        node = (int)(*gRomCurveInterface)->getById(*nodeId);
        pathcam_findTaggedNodeWindow((u8*)node, window, tag);
        dist = fn_8010AC48(x, y, z, window);
        if (dist < nearThresh)
        {
            if (window[0] > -1)
            {
                *nodeId = window[0];
                settled = 0;
            }
        }
        else if (dist > PATHCAM_FAR_THRESHOLD)
        {
            if (window[2] > -1 && window[3] > -1)
            {
                *nodeId = window[2];
                settled = 0;
            }
        }
    }
    node = (int)(*gRomCurveInterface)->getById(*nodeId);
    fn_8010A47C(node, &span, tag);
    node = (int)(*gRomCurveInterface)->getById(*leadNodeId);
    *leadNodeId = ((RomCurvePathNode*)fn_8010A47C(node, &farSpan, tag))->selfId;
    for (step = 0; step < span; step++)
    {
        node = (int)(*gRomCurveInterface)->getById(*leadNodeId);
        for (slot2 = 0; slot2 < ROM_CURVE_PATH_LINK_COUNT; slot2++)
        {
            if (((RomCurvePathNode*)node)->links[slot2] > -1 &&
                (((RomCurvePathNode*)node)->directionMask & (1 << slot2)) == 0)
            {
                linked = (int)(*gRomCurveInterface)->getById(((RomCurvePathNode*)node)->links[slot2]);
                if ((u32)linked != 0 &&
                    (((RomCurvePathNode*)linked)->tag0 == tag || ((RomCurvePathNode*)linked)->tag1 == tag ||
                     ((RomCurvePathNode*)linked)->tag2 == tag))
                {
                    *leadNodeId = ((RomCurvePathNode*)node)->links[slot2];
                    slot2 = ROM_CURVE_PATH_LINK_COUNT;
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
        if ((((RomCurvePathNode*)curve)->type != 0x1b) && (((RomCurvePathNode*)curve)->type != 0x1a))
        {
            for (slot = 0; slot < ROM_CURVE_PATH_LINK_COUNT; slot++)
            {
                if ((((RomCurvePathNode*)curve)->links[slot] > -1) &&
                    ((((RomCurvePathNode*)curve)->directionMask & (1 << slot)) != 0))
                {
                    linked = (int)(*gRomCurveInterface)->getById(((RomCurvePathNode*)curve)->links[slot]);
                    if (((u32)linked != 0) &&
                        ((((RomCurvePathNode*)linked)->tag0 == tag || (((RomCurvePathNode*)linked)->tag1 == tag)) ||
                         (((RomCurvePathNode*)linked)->tag2 == tag)))
                    {
                        curve = linked;
                        done = 0;
                        slot = ROM_CURVE_PATH_LINK_COUNT;
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
