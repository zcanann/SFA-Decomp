/*
 * tricky_rollroute - Tricky (DLL 0x00C4) rom-curve route-walker sub-TU; Tricky
 * cluster code sharing gTrickyObjDescriptor-adjacent data. tricky_updateBallRoll is the
 * per-frame update that rolls the object along its rom-curve route.
 *
 * Before init (init-done byte 0x0a == 0): the ball homes onto its curve
 * (CANNONBALL_CURVE). Once the owner and the ball share a walk group it
 * picks the route direction by comparing owner-to-endpoint distances,
 * binds the route walker to the chosen segment, steps it, seeds the sfx
 * timer and marks init done.
 *
 * After init: at each segment end it gathers the valid branch nodes
 * (gated by the node-set's per-branch mask byte), picks the nearest to
 * the current owner, retargets the walker, then accelerates/decays the
 * roll speed toward CANNONBALL_SFX_TIMER limits, advances and moves the
 * ball. Off the walk grid it sets CANNONBALL_HIDE_FLAG. The sfx timer
 * periodically plays the rolling sound (0x29b) on object channel 0x10
 * when the current move is outside the 0x29..0x2f window.
 */
#include "main/audio/sfx.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/dll/skeetla_route_api.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/objfsa.h"
#include "main/dll/skeetla.h"
#include "main/dll/baddie/trickyfollow.h"
#include "main/dll/tricky_state.h"
#include "main/frame_timing.h"
#include "main/objprint_sound_api.h"
#include "main/dll/tricky_rollroute.h"

/* The "ball" is the Tricky cannonball's TrickyState extra block: substate is
 * the init-done byte, speed the roll speed, stateFlags the flag word, route the
 * embedded RomCurveWalker, followObj/playerObj the owner links, scratch700 the
 * curve link and scratch708 the rolling-sfx countdown. */
#define CANNONBALL_HIDE_FLAG        0x10
#define CANNONBALL_SPEED_DECAY_FLAG 0x10000000

/* lbl_803E2*: this DLL's f32 route/speed constants. */
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E0;
extern f32 lbl_803E23F4;
extern f32 lbl_803E241C;
extern f32 lbl_803E2420;
extern f32 lbl_803E2488;
extern f32 lbl_803E2508;
extern f32 lbl_803E250C;

void tricky_updateBallRoll(int obj, int ball)
{
    TrickyState* ts = (TrickyState*)ball;
    int toNode;
    u8 nodeCount;
    int node;
    int nodeSet;
    u32 mask;
    int bit;
    int i;
    int curve;
    int fromNode;
    int nodeIds[4];
    void* curveArg;
    int nextNode;
    int candidateNode;
    int targetNode;
    int walkGroup;
    int sfxState;
    float speed;
    double distance;
    double bestDistance;

    nodeCount = 0;
    if (ts->substate != 0)
    {
        if (ts->route.reverse == 0)
        {
            if (ts->route.atSegmentEnd != 0)
            {
                nodeSet = (int)ts->route.nodeA4;
                mask = 1;
                for (bit = 0; bit < 4; bit++)
                {
                    node = *(int*)(nodeSet + 0x1c + bit * 4);
                    if (node > -1 && ((*(s8*)(nodeSet + 0x1b) & mask) == 0))
                    {
                        nodeIds[nodeCount++] = node;
                    }
                    mask <<= 1;
                }
            }
        }
        else if (ts->route.atSegmentEnd == 0)
        {
            int node2;
            int nodeSet2;
            u32 mask2;
            nodeSet2 = (int)ts->route.nodeA4;
            mask2 = 1;
            for (bit = 0; bit < 4; bit++)
            {
                node2 = *(int*)(nodeSet2 + 0x1c + bit * 4);
                if (node2 > -1 && ((*(s8*)(nodeSet2 + 0x1b) & mask2) != 0))
                {
                    nodeIds[nodeCount++] = node2;
                }
                mask2 <<= 1;
            }
        }

        if (nodeCount != 0)
        {
            targetNode = (int)(*gRomCurveInterface)->getById(nodeIds[0]);
            bestDistance = getXZDistance((float*)((int)ts->followObj + 0x18), (float*)(targetNode + 8));

            for (i = 1; i < nodeCount; i++)
            {
                candidateNode = (int)(*gRomCurveInterface)->getById(nodeIds[i]);
                distance = getXZDistance((float*)((int)ts->followObj + 0x18), (float*)(candidateNode + 8));
                if (distance < bestDistance)
                {
                    targetNode = candidateNode;
                    bestDistance = distance;
                }
            }

            curveFn_800da23c(&ts->route, (void*)targetNode);
        }

        speed = ts->speed;
        if ((u8)(ts->stateFlags & CANNONBALL_SPEED_DECAY_FLAG) != 0)
        {
            speed += lbl_803E23F4 * timeDelta;
            if (speed < lbl_803E23DC)
            {
                speed = lbl_803E23DC;
            }
        }
        else if (speed > lbl_803E2508)
        {
            speed += lbl_803E241C * timeDelta;
            if (speed < lbl_803E2508)
            {
                speed = lbl_803E2508;
            }
        }
        else
        {
            speed += lbl_803E2420 * timeDelta;
            if (speed > lbl_803E2508)
            {
                speed = lbl_803E2508;
            }
        }

        ts->speed = speed;
        trickyAdvanceRouteTargetAhead(obj, &ts->route, ts->speed);
        trickyMove((GameObject*)obj, &ts->route.posX);

        if (Objfsa_GetWalkGroupIndexAtPoint((float*)&((GameObject*)obj)->anim.worldPosX, NULL) != 0)
        {
            ts->stateFlags &= ~(u64)CANNONBALL_HIDE_FLAG;
        }
        else
        {
            ts->stateFlags |= CANNONBALL_HIDE_FLAG;
        }

        ts->scratch708.f -= timeDelta;
        if (ts->scratch708.f < lbl_803E23DC)
        {
            ts->scratch708.f = (f32)(int)randomGetRange(200, 600);

            sfxState = *(int*)&((GameObject*)obj)->extra;
            if (((u32)(*(u8*)(sfxState + 0x58) >> 6 & 1) == 0) &&
                ((((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29) &&
                 !Sfx_IsPlayingFromObjectChannel(obj, 0x10)))
            {
                objAudioFn_800393f8((GameObject*)obj, &((TrickyState*)sfxState)->soundState, 0x29b, 0x1000, -1, 0);
            }
        }
    }
    else
    {
        trickyFn_8013b368((GameObject*)obj, lbl_803E2488, (TrickyState*)ball);
        if (Objfsa_GetWalkGroupIndexAtPoint((float*)&((GameObject*)obj)->anim.worldPosX, NULL) ==
            (walkGroup = Objfsa_GetWalkGroupIndexAtPoint((float*)((int)ts->scratch700.ptr + 8), NULL)))
        {
            curve = (int)ts->scratch700.ptr;

            nextNode = (*gRomCurveInterface)->getRandomUnblockedLink((RomCurveDef*)curve, 0);
            fromNode = (int)(*gRomCurveInterface)->getById(nextNode);

            nextNode = (*gRomCurveInterface)->getRandomBlockedLink((RomCurveDef*)curve, 0);
            toNode = (int)(*gRomCurveInterface)->getById(nextNode);

            bestDistance = getXZDistance((float*)(ts->playerObj + 0x18), (float*)(fromNode + 8));
            distance = getXZDistance((float*)(ts->playerObj + 0x18), (float*)(toNode + 8));

            curveArg = (void*)curve;
            if (bestDistance > distance)
            {
                nextNode = (*gRomCurveInterface)->getRandomUnblockedLink((RomCurveDef*)fromNode, 0);
                targetNode = (int)(*gRomCurveInterface)->getById(nextNode);
                ts->route.reverse = 0;
            }
            else
            {
                fromNode = toNode;
                nextNode = (*gRomCurveInterface)->getRandomBlockedLink((RomCurveDef*)toNode, 0);
                targetNode = (int)(*gRomCurveInterface)->getById(nextNode);
                ts->route.reverse = 1;
            }

            RomCurve_setupHermiteSegment(&ts->route, curveArg, (void*)fromNode, (void*)targetNode);
            if (ts->route.reverse != 0)
            {
                RomCurve_stepClamped(&ts->route, lbl_803E250C);
            }
            else
            {
                RomCurve_stepClamped(&ts->route, lbl_803E23E0);
            }

            ts->scratch708.f = lbl_803E23DC;
            ts->substate = 1;
        }
    }
}

void fn_8014187C(void)
{
}
