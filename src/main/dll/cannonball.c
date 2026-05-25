#include "ghidra_import.h"
#include "main/dll/cannonball.h"

#pragma peephole off
#pragma scheduling off

#define CANNONBALL_INIT_DONE 0x0a
#define CANNONBALL_SPEED 0x14
#define CANNONBALL_FLAGS 0x54
#define CANNONBALL_OWNER_LINK 0x4
#define CANNONBALL_CURRENT_OWNER 0x24
#define CANNONBALL_ROUTE 0x420
#define CANNONBALL_ROUTE_ACTIVE 0x430
#define CANNONBALL_ROUTE_REVERSING 0x4a0
#define CANNONBALL_ROUTE_NODE_SET 0x4c4
#define CANNONBALL_MOVE_STATE 0x488
#define CANNONBALL_CURVE 0x700
#define CANNONBALL_SFX_TIMER 0x708

#define CANNONBALL_HIDE_FLAG 0x10
#define CANNONBALL_SPEED_DECAY_FLAG 0x10000000

extern bool Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern double getXZDistance(float *a, float *b);
extern u32 randomGetRange(int min, int max);
extern void objAudioFn_800393f8(int obj, void *audio, int soundId, int volume, int param5, int param6);
extern void curveFn_800da23c(void *route, int node);
extern void fn_800DA928(float *route, float speed);
extern void fn_800DA980(void *route, int curve, int fromNode, int toNode);
extern int fn_800DBCFC(float *pos, void *flag);
extern void fn_80139834(int obj, void *route, float speed);
extern void trickyMove(int obj, void *moveState);
extern void trickyFn_8013b368(int obj1, int obj2, float arg);

extern void *gRomCurveInterface;
extern f32 timeDelta;
extern f64 lbl_803E2460;
extern f32 lbl_803E23DC;
extern f32 lbl_803E23E0;
extern f32 lbl_803E23F4;
extern f32 lbl_803E241C;
extern f32 lbl_803E2420;
extern f32 lbl_803E2488;
extern f32 lbl_803E2508;
extern f32 lbl_803E250C;

/*
 * --INFO--
 *
 * Function: trickyFn_80141290
 * EN v1.0 Address: 0x80141290
 * EN v1.0 Size: 1520b
 * EN v1.1 Address: 0x80141618
 * EN v1.1 Size: 1520b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void trickyFn_80141290(int obj, int ball)
{
    int nodeIds[6];
    int nodeCount;
    int nodeSet;
    int mask;
    int node;
    int i;
    int curve;
    int fromNode;
    int toNode;
    int targetNode;
    int candidateNode;
    int sfxState;
    float speed;
    double distance;
    double bestDistance;

    nodeCount = 0;
    if (*(u8 *)(ball + CANNONBALL_INIT_DONE) != 0) {
        if (*(int *)(ball + CANNONBALL_ROUTE_REVERSING) == 0) {
            if (*(int *)(ball + CANNONBALL_ROUTE_ACTIVE) != 0) {
                nodeSet = *(int *)(ball + CANNONBALL_ROUTE_NODE_SET);
                mask = 1;

                node = *(int *)(nodeSet + 0x1c);
                if (node > -1 && ((*(s8 *)(nodeSet + 0x1b) & mask) == 0)) {
                    nodeIds[nodeCount] = node;
                    nodeCount++;
                }

                mask <<= 1;
                node = *(int *)(nodeSet + 0x20);
                if (node > -1 && ((*(s8 *)(nodeSet + 0x1b) & mask) == 0)) {
                    nodeIds[nodeCount] = node;
                    nodeCount++;
                }

                mask <<= 1;
                node = *(int *)(nodeSet + 0x24);
                if (node > -1 && ((*(s8 *)(nodeSet + 0x1b) & mask) == 0)) {
                    nodeIds[nodeCount] = node;
                    nodeCount++;
                }

                mask <<= 1;
                node = *(int *)(nodeSet + 0x28);
                if (node > -1 && ((*(s8 *)(nodeSet + 0x1b) & mask) == 0)) {
                    nodeIds[nodeCount] = node;
                    nodeCount++;
                }
            }
        } else if (*(int *)(ball + CANNONBALL_ROUTE_ACTIVE) == 0) {
            nodeSet = *(int *)(ball + CANNONBALL_ROUTE_NODE_SET);
            mask = 1;

            node = *(int *)(nodeSet + 0x1c);
            if (node > -1 && ((*(s8 *)(nodeSet + 0x1b) & mask) != 0)) {
                nodeIds[nodeCount] = node;
                nodeCount++;
            }

            mask <<= 1;
            node = *(int *)(nodeSet + 0x20);
            if (node > -1 && ((*(s8 *)(nodeSet + 0x1b) & mask) != 0)) {
                nodeIds[nodeCount] = node;
                nodeCount++;
            }

            mask <<= 1;
            node = *(int *)(nodeSet + 0x24);
            if (node > -1 && ((*(s8 *)(nodeSet + 0x1b) & mask) != 0)) {
                nodeIds[nodeCount] = node;
                nodeCount++;
            }

            mask <<= 1;
            node = *(int *)(nodeSet + 0x28);
            if (node > -1 && ((*(s8 *)(nodeSet + 0x1b) & mask) != 0)) {
                nodeIds[nodeCount] = node;
                nodeCount++;
            }
        }

        if (nodeCount != 0) {
            targetNode = (*(int (**)(int))(*(int *)gRomCurveInterface + 0x1c))(nodeIds[0]);
            bestDistance = getXZDistance((float *)(*(int *)(ball + CANNONBALL_CURRENT_OWNER) + 0x18),
                                         (float *)(targetNode + 8));

            for (i = 1; i < nodeCount; i++) {
                candidateNode = (*(int (**)(int))(*(int *)gRomCurveInterface + 0x1c))(nodeIds[i]);
                distance = getXZDistance((float *)(*(int *)(ball + CANNONBALL_CURRENT_OWNER) + 0x18),
                                         (float *)(candidateNode + 8));
                if (distance < bestDistance) {
                    targetNode = candidateNode;
                    bestDistance = distance;
                }
            }

            curveFn_800da23c((void *)(ball + CANNONBALL_ROUTE), targetNode);
        }

        speed = *(float *)(ball + CANNONBALL_SPEED);
        if ((*(u32 *)(ball + CANNONBALL_FLAGS) & CANNONBALL_SPEED_DECAY_FLAG) != 0) {
            speed += lbl_803E23F4 * timeDelta;
            if (speed < lbl_803E23DC) {
                speed = lbl_803E23DC;
            }
        } else if (speed > lbl_803E2508) {
            speed += lbl_803E241C * timeDelta;
            if (speed < lbl_803E2508) {
                speed = lbl_803E2508;
            }
        } else {
            speed += lbl_803E2420 * timeDelta;
            if (speed > lbl_803E2508) {
                speed = lbl_803E2508;
            }
        }

        *(float *)(ball + CANNONBALL_SPEED) = speed;
        fn_80139834(obj, (void *)(ball + CANNONBALL_ROUTE), *(float *)(ball + CANNONBALL_SPEED));
        trickyMove(obj, (void *)(ball + CANNONBALL_MOVE_STATE));

        if (fn_800DBCFC((float *)(obj + 0x18), (void *)0) == 0) {
            *(u32 *)(ball + CANNONBALL_FLAGS) |= CANNONBALL_HIDE_FLAG;
        } else {
            *(u32 *)(ball + CANNONBALL_FLAGS) &= ~CANNONBALL_HIDE_FLAG;
        }

        *(float *)(ball + CANNONBALL_SFX_TIMER) -= timeDelta;
        if (*(float *)(ball + CANNONBALL_SFX_TIMER) < lbl_803E23DC) {
            nodeIds[5] = randomGetRange(200, 600) ^ 0x80000000;
            nodeIds[4] = 0x43300000;
            *(float *)(ball + CANNONBALL_SFX_TIMER) = (float)(*(double *)&nodeIds[4] - lbl_803E2460);

            sfxState = *(int *)(obj + 0xb8);
            if (((*(u8 *)(sfxState + 0x58) >> 6 & 1) == 0) &&
                ((*(s16 *)(obj + 0xa0) >= 0x30 || *(s16 *)(obj + 0xa0) < 0x29) &&
                 !Sfx_IsPlayingFromObjectChannel(obj, 0x10))) {
                objAudioFn_800393f8(obj, (void *)(sfxState + 0x3a8), 0x29b, 0x1000, -1, 0);
            }
        }
    } else {
        trickyFn_8013b368(obj, ball, lbl_803E2488);
        nodeCount = fn_800DBCFC((float *)(*(int *)(ball + CANNONBALL_CURVE) + 8), (void *)0);

        if (fn_800DBCFC((float *)(obj + 0x18), (void *)0) == nodeCount) {
            curve = *(int *)(ball + CANNONBALL_CURVE);

            (*(void (**)(int, int))(*(int *)gRomCurveInterface + 0x54))(curve, 0);
            fromNode = (*(int (**)(void))(*(int *)gRomCurveInterface + 0x1c))();

            (*(void (**)(int, int))(*(int *)gRomCurveInterface + 0x60))(curve, 0);
            toNode = (*(int (**)(void))(*(int *)gRomCurveInterface + 0x1c))();

            bestDistance = getXZDistance((float *)(*(int *)(ball + CANNONBALL_OWNER_LINK) + 0x18),
                                         (float *)(fromNode + 8));
            distance = getXZDistance((float *)(*(int *)(ball + CANNONBALL_OWNER_LINK) + 0x18),
                                     (float *)(toNode + 8));

            if (bestDistance > distance) {
                (*(void (**)(int, int))(*(int *)gRomCurveInterface + 0x54))(fromNode, 0);
                targetNode = (*(int (**)(void))(*(int *)gRomCurveInterface + 0x1c))();
                *(int *)(ball + CANNONBALL_ROUTE_REVERSING) = 0;
            } else {
                fromNode = toNode;
                (*(void (**)(int, int))(*(int *)gRomCurveInterface + 0x60))(toNode, 0);
                targetNode = (*(int (**)(void))(*(int *)gRomCurveInterface + 0x1c))();
                *(int *)(ball + CANNONBALL_ROUTE_REVERSING) = 1;
            }

            fn_800DA980((void *)(ball + CANNONBALL_ROUTE), curve, fromNode, targetNode);
            if (*(int *)(ball + CANNONBALL_ROUTE_REVERSING) != 0) {
                fn_800DA928((float *)(ball + CANNONBALL_ROUTE), lbl_803E250C);
            } else {
                fn_800DA928((float *)(ball + CANNONBALL_ROUTE), lbl_803E23E0);
            }

            *(float *)(ball + CANNONBALL_SFX_TIMER) = lbl_803E23DC;
            *(u8 *)(ball + CANNONBALL_INIT_DONE) = 1;
        }
    }
}

/* Trivial 4b 0-arg blr leaves. */
void fn_8014187C(void) {}
