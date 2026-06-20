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
extern f32 lbl_803E1888; /* near distance threshold */
extern f32 lbl_803E188C; /* far distance threshold */
extern f32 fn_8010AC48(int* obj, f32 px, f32 unused, f32 pz);

#define PATHCAM_NEAR_THRESHOLD lbl_803E1888
#define PATHCAM_FAR_THRESHOLD lbl_803E188C

void fn_8010A104(int* p1, int* p2, f32 x, f32 y, f32 z, int tag)
{
    int node;
    int linked;
    int noForwardExit;
    int slot;
    int step;
    int window[4];
    int span;
    int farSpan;
    int settled;
    f32 dist;
    f32 nearThresh;

    node = (int)(*gRomCurveInterface)->getById(*p1);
    noForwardExit = 1;
    for (slot = 0; slot < 5; slot++)
    {
        if (*(int*)(node + slot * 4 + 0x1C) > -1 &&
            (*(s8*)(node + 0x1B) & (1 << slot)) == 0)
        {
            linked = (int)(*gRomCurveInterface)->getById(*(int*)(node + slot * 4 + 0x1C));
            if ((u32)linked != 0 &&
                (*(u8*)(linked + 0x31) == tag || *(u8*)(linked + 0x32) == tag ||
                    *(u8*)(linked + 0x33) == tag))
            {
                noForwardExit = 0;
                slot = 5;
            }
        }
    }
    if (noForwardExit != 0)
    {
        for (slot = 0; slot < 5; slot++)
        {
            if (*(int*)(node + slot * 4 + 0x1C) > -1 &&
                (*(s8*)(node + 0x1B) & (1 << slot)) != 0)
            {
                linked = (int)(*gRomCurveInterface)->getById(*(int*)(node + slot * 4 + 0x1C));
                if ((u32)linked != 0 &&
                    (*(u8*)(linked + 49) == tag || *(u8*)(linked + 50) == tag ||
                        *(u8*)(linked + 51) == tag))
                {
                    *p1 = *(int*)(node + slot * 4 + 0x1C);
                    slot = 5;
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
        dist = fn_8010AC48(window, x, y, z);
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
    *p2 = *(int*)(fn_8010A47C(node, &farSpan, tag) + 0x14);
    for (step = 0; step < span; step++)
    {
        node = (int)(*gRomCurveInterface)->getById(*p2);
        for (slot = 0; slot < 5; slot++)
        {
            if (*(int*)(node + slot * 4 + 0x1C) > -1 &&
                (*(s8*)(node + 0x1B) & (1 << slot)) == 0)
            {
                linked = (int)(*gRomCurveInterface)->getById(*(int*)(node + slot * 4 + 0x1C));
                if ((u32)linked != 0 &&
                    (*(u8*)(linked + 49) == tag || *(u8*)(linked + 50) == tag ||
                        *(u8*)(linked + 51) == tag))
                {
                    *p2 = *(int*)(node + slot * 4 + 0x1C);
                    slot = 5;
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
        if ((*(char*)(curve + 0x19) != 0x1b) && (*(char*)(curve + 0x19) != 0x1a))
        {
            for (slot = 0; slot < 5; slot++)
            {
                if ((*(int*)(curve + slot * 4 + 0x1c) > -1) &&
                    ((*(s8*)(curve + 0x1b) & (1 << slot)) != 0))
                {
                    linked = (int)(*gRomCurveInterface)->getById(*(int*)(curve + slot * 4 + 0x1c));
                    if (((u32)linked != 0) &&
                        ((*(u8*)(linked + 0x31) == tag || (*(u8*)(linked + 0x32) == tag)) ||
                            (*(u8*)(linked + 0x33) == tag)))
                    {
                        curve = linked;
                        done = 0;
                        slot = 5;
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
