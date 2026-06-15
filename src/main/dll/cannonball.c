#include "main/audio/sfx.h"
#include "main/game_object.h"
#include "main/dll/baddie/skeetla.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/objfsa.h"

#define CANNONBALL_INIT_DONE 0x0a
#define CANNONBALL_SPEED 0x14
#define CANNONBALL_FLAGS 0x54
#define CANNONBALL_OWNER_LINK 0x4
#define CANNONBALL_CURRENT_OWNER 0x24
#define CANNONBALL_ROUTE 0x420
#define CANNONBALL_MOVE_STATE 0x488
#define CANNONBALL_CURVE 0x700
#define CANNONBALL_SFX_TIMER 0x708

#define CANNONBALL_HIDE_FLAG 0x10
#define CANNONBALL_SPEED_DECAY_FLAG 0x10000000

extern double getXZDistance(float* a, float* b);
extern u32 randomGetRange(int min, int max);
extern void objAudioFn_800393f8(int obj, void *audio, int soundId, int volume, int param5, int param6);
extern int Objfsa_GetWalkGroupIndexAtPoint(float *pos, void *flag);
extern void trickyMove(int obj, void *moveState);
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
    int nodeIds[4];
    u8 nodeCount;
    int node;
    int nodeSet;
    u32 mask;
    int bit;
    int i;
    int curve;
    int fromNode;
    int toNode;
    int nextNode;
    int candidateNode;
    int targetNode;
    int walkGroup;
    int sfxState;
    float speed;
    double distance;
    double bestDistance;

    nodeCount = 0;
    if (*(u8*)(ball + CANNONBALL_INIT_DONE) != 0)
    {
        if (((RomCurveWalker*)(ball + CANNONBALL_ROUTE))->reverse == 0)
        {
            if (((RomCurveWalker*)(ball + CANNONBALL_ROUTE))->atSegmentEnd != 0)
            {
                nodeSet = (int)((RomCurveWalker*)(ball + CANNONBALL_ROUTE))->nodeA4;
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
        else if (((RomCurveWalker*)(ball + CANNONBALL_ROUTE))->atSegmentEnd == 0)
        {
            int node2;
            int nodeSet2;
            u32 mask2;
            nodeSet2 = (int)((RomCurveWalker*)(ball + CANNONBALL_ROUTE))->nodeA4;
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
            bestDistance = getXZDistance((float*)(*(int*)(ball + CANNONBALL_CURRENT_OWNER) + 0x18),
                                         (float*)(targetNode + 8));

            for (i = 1; i < nodeCount; i++)
            {
                candidateNode = (int)(*gRomCurveInterface)->getById(nodeIds[i]);
                distance = getXZDistance((float*)(*(int*)(ball + CANNONBALL_CURRENT_OWNER) + 0x18),
                                         (float*)(candidateNode + 8));
                if (distance < bestDistance)
                {
                    targetNode = candidateNode;
                    bestDistance = distance;
                }
            }

            curveFn_800da23c(((RomCurveWalker*)(ball + CANNONBALL_ROUTE)), (void *)targetNode);
        }

        speed = *(float*)(ball + CANNONBALL_SPEED);
        if ((u8)(*(u32*)(ball + CANNONBALL_FLAGS) & CANNONBALL_SPEED_DECAY_FLAG) != 0)
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

        *(float*)(ball + CANNONBALL_SPEED) = speed;
        trickyAdvanceRouteTargetAhead(obj, ((RomCurveWalker*)(ball + CANNONBALL_ROUTE)), *(float*)(ball + CANNONBALL_SPEED));
        trickyMove(obj, (void*)(ball + CANNONBALL_MOVE_STATE));

        if (Objfsa_GetWalkGroupIndexAtPoint((float*)&((GameObject*)obj)->anim.worldPosX, (void*)0) != 0)
        {
            *(u32*)(ball + CANNONBALL_FLAGS) &= ~CANNONBALL_HIDE_FLAG;
        }
        else
        {
            *(u32*)(ball + CANNONBALL_FLAGS) |= CANNONBALL_HIDE_FLAG;
        }

        *(float*)(ball + CANNONBALL_SFX_TIMER) -= timeDelta;
        if (*(float*)(ball + CANNONBALL_SFX_TIMER) < lbl_803E23DC)
        {
            *(float*)(ball + CANNONBALL_SFX_TIMER) = (f32)(int)
            randomGetRange(200, 600);

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
        walkGroup = Objfsa_GetWalkGroupIndexAtPoint((float*)(*(int*)(ball + CANNONBALL_CURVE) + 8), (void*)0);

        if (Objfsa_GetWalkGroupIndexAtPoint((float*)&((GameObject*)obj)->anim.worldPosX, (void*)0) == walkGroup)
        {
            curve = *(int*)(ball + CANNONBALL_CURVE);

            nextNode = ((int (*)(int, int))(*gRomCurveInterface)->slot54)(curve, 0);
            fromNode = (int)(*gRomCurveInterface)->getById(nextNode);

            nextNode = ((int (*)(int, int))(*gRomCurveInterface)->slot60)(curve, 0);
            toNode = (int)(*gRomCurveInterface)->getById(nextNode);

            bestDistance = getXZDistance((float*)(*(int*)(ball + CANNONBALL_OWNER_LINK) + 0x18),
                                         (float*)(fromNode + 8));
            distance = getXZDistance((float*)(*(int*)(ball + CANNONBALL_OWNER_LINK) + 0x18),
                                     (float*)(toNode + 8));

            if (bestDistance > distance)
            {
                nextNode = ((int (*)(int, int))(*gRomCurveInterface)->slot54)(fromNode, 0);
                targetNode = (int)(*gRomCurveInterface)->getById(nextNode);
                ((RomCurveWalker*)(ball + CANNONBALL_ROUTE))->reverse = 0;
            }
            else
            {
                fromNode = toNode;
                nextNode = ((int (*)(int, int))(*gRomCurveInterface)->slot60)(toNode, 0);
                targetNode = (int)(*gRomCurveInterface)->getById(nextNode);
                ((RomCurveWalker*)(ball + CANNONBALL_ROUTE))->reverse = 1;
            }

            fn_800DA980(((RomCurveWalker*)(ball + CANNONBALL_ROUTE)), (void *)curve, (void *)fromNode, (void *)targetNode);
            if (((RomCurveWalker*)(ball + CANNONBALL_ROUTE))->reverse != 0) {
                RomCurve_stepClamped(((RomCurveWalker*)(ball + CANNONBALL_ROUTE)), lbl_803E250C);
            }
            else
            {
                RomCurve_stepClamped(((RomCurveWalker*)(ball + CANNONBALL_ROUTE)), lbl_803E23E0);
            }

            *(float*)(ball + CANNONBALL_SFX_TIMER) = lbl_803E23DC;
            *(u8*)(ball + CANNONBALL_INIT_DONE) = 1;
        }
    }
}

void fn_8014187C(void)
{
}
