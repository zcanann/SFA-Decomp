/*
 * tricky_rollroute - Tricky (DLL 0x00C4) rom-curve route-walker sub-TU; Tricky
 * cluster code sharing gTrickyObjDescriptor-adjacent data. trickyFn_80141290 is the
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
#include "main/game_object.h"
#include "main/dll/baddie/skeetla.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/objfsa.h"
#include "main/dll/tricky_state.h"
#include "main/gameplay_runtime.h"

/* The "ball" is the Tricky cannonball's TrickyState extra block: substate is
 * the init-done byte, speed the roll speed, stateFlags the flag word, route the
 * embedded RomCurveWalker, followObj/playerObj the owner links, unk700 the
 * curve link and unk708 (read as f32) the rolling-sfx countdown. */
#define CANNONBALL_HIDE_FLAG 0x10
#define CANNONBALL_SPEED_DECAY_FLAG 0x10000000

/* getXZDistance/randomGetRange: util; objAudioFn_800393f8: audio;
   Objfsa_GetWalkGroupIndexAtPoint: objfsa; trickyMove: skeetla (Tricky).
   trickyFn_8013b368: trickyfollow (block-scope signature override of
   trickyfollow.h's int(u8*,f32,u8*) for this TU's codegen, recipe #57).
   lbl_803E2*: this DLL's f32 route/speed constants. */
extern f32 getXZDistance(f32* a, f32* b);
extern void objAudioFn_800393f8(int obj, void* audio, int soundId, int volume, int param5, int param6);
extern int Objfsa_GetWalkGroupIndexAtPoint(float* pos, void* flag);
extern void trickyMove(int obj, void* moveState);
extern void trickyFn_8013b368(int obj1, int obj2, float arg);
extern f32 timeDelta;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E0;
extern f32 lbl_803E23F4;
extern f32 lbl_803E241C;
extern f32 lbl_803E2420;
extern f32 lbl_803E2488;
extern f32 lbl_803E2508;
extern f32 lbl_803E250C;

void trickyFn_80141290(int obj, int ball)
{
    TrickyState *ts = (TrickyState *)ball;
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
            bestDistance = getXZDistance((float*)((int)ts->followObj + 0x18),
                                         (float*)(targetNode + 8));

            for (i = 1; i < nodeCount; i++)
            {
                candidateNode = (int)(*gRomCurveInterface)->getById(nodeIds[i]);
                distance = getXZDistance((float*)((int)ts->followObj + 0x18),
                                         (float*)(candidateNode + 8));
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
        trickyMove(obj, (void*)&ts->route.posX);

        if (Objfsa_GetWalkGroupIndexAtPoint((float*)&((GameObject*)obj)->anim.worldPosX, NULL) != 0)
        {
            ts->stateFlags &= ~(u64)CANNONBALL_HIDE_FLAG;
        }
        else
        {
            ts->stateFlags |= CANNONBALL_HIDE_FLAG;
        }

        *(float*)&ts->unk708 -= timeDelta;
        if (*(float*)&ts->unk708 < lbl_803E23DC)
        {
            *(float*)&ts->unk708 = (f32)(int)randomGetRange(200, 600);

            sfxState = *(int*)&((GameObject*)obj)->extra;
            if (((u32)(*(u8*)(sfxState + 0x58) >> 6 & 1) == 0) &&
                ((((GameObject*)obj)->anim.currentMove >= 0x30 || ((GameObject*)obj)->anim.currentMove < 0x29) &&
                 !Sfx_IsPlayingFromObjectChannel(obj, 0x10)))
            {
                objAudioFn_800393f8(obj, (void*)(sfxState + 0x3a8), 0x29b, 0x1000, -1, 0);
            }
        }
    }
    else
    {
        trickyFn_8013b368(obj, ball, lbl_803E2488);
        walkGroup = Objfsa_GetWalkGroupIndexAtPoint((float*)((int)ts->unk700 + 8), NULL);

        if (Objfsa_GetWalkGroupIndexAtPoint((float*)&((GameObject*)obj)->anim.worldPosX, NULL) == walkGroup)
        {
            curve = (int)ts->unk700;

            nextNode = ((int (*)(int, int))(*gRomCurveInterface)->slot54)(curve, 0);
            fromNode = (int)(*gRomCurveInterface)->getById(nextNode);

            nextNode = ((int (*)(int, int))(*gRomCurveInterface)->slot60)(curve, 0);
            toNode = (int)(*gRomCurveInterface)->getById(nextNode);

            bestDistance = getXZDistance((float*)(ts->playerObj + 0x18),
                                         (float*)(fromNode + 8));
            distance = getXZDistance((float*)(ts->playerObj + 0x18),
                                     (float*)(toNode + 8));

            if (bestDistance > distance)
            {
                nextNode = ((int (*)(int, int))(*gRomCurveInterface)->slot54)(fromNode, 0);
                targetNode = (int)(*gRomCurveInterface)->getById(nextNode);
                ts->route.reverse = 0;
            }
            else
            {
                fromNode = toNode;
                nextNode = ((int (*)(int, int))(*gRomCurveInterface)->slot60)(toNode, 0);
                targetNode = (int)(*gRomCurveInterface)->getById(nextNode);
                ts->route.reverse = 1;
            }

            fn_800DA980(&ts->route, (void*)curve, (void*)fromNode, (void*)targetNode);
            if (ts->route.reverse != 0)
            {
                RomCurve_stepClamped(&ts->route, lbl_803E250C);
            }
            else
            {
                RomCurve_stepClamped(&ts->route, lbl_803E23E0);
            }

            *(float*)&ts->unk708 = lbl_803E23DC;
            ts->substate = 1;
        }
    }
}

void fn_8014187C(void)
{
}
