/*
 * DIM boss player-vs-baddie reaction dispatcher (fn_801B9ECC, address-taken
 * into the boss anim-fn table at slot 5 from dll_01E0_dimboss).
 */
#include "main/dll/baddie_state.h"
#include "main/gameplay_runtime.h"

extern int* gBaddieControlInterface;
extern int* gPlayerInterface;
extern u8 lbl_803DDB84;
extern u8 lbl_80325960[];
extern u8 gDIMbossAnimController[];
extern void DIM2icicle_updateHitResponse(int obj, int playerObj);
extern f32 lbl_803E4BB8;

typedef void (*Dim2QueryTargetMoveFn)(int obj, void* targetObj, int queryFlags, u16* animId,
                                      s16* outParam, u16* targetDistance);
typedef u8 (*Dim2CheckTargetRangeFn)(int obj, BaddieState* state, f32 rangeScale);
typedef void (*Dim2RequestControlModeFn)(int obj, BaddieState* state, int controlMode);

typedef struct Dim2BaddieControlInterface {
    u8 pad00[0x14];
    Dim2QueryTargetMoveFn queryTargetMove;
    Dim2CheckTargetRangeFn checkTargetRange;
} Dim2BaddieControlInterface;

typedef struct Dim2PlayerInterface {
    u8 pad00[0x14];
    Dim2RequestControlModeFn requestControlMode;
} Dim2PlayerInterface;

static inline Dim2BaddieControlInterface* DIM2_GetBaddieControlInterface(void)
{
    return (Dim2BaddieControlInterface*)*gBaddieControlInterface;
}

static inline Dim2PlayerInterface* DIM2_GetPlayerInterface(void)
{
    return (Dim2PlayerInterface*)*gPlayerInterface;
}

typedef struct DimAnimTable
{
    u8 pad[0x168];     /* 0x000 */
    s16 surprised[6];  /* 0x168: far random "surprised" anim ids */
    s16 group3[8];     /* 0x174: hitPoints==3 round-robin anim ids */
    s16 group2[8];     /* 0x184: hitPoints==2 round-robin anim ids */
    s16 group1[8];     /* 0x194: hitPoints==1 round-robin anim ids */
} DimAnimTable;

#pragma scheduling off
#pragma peephole off
int fn_801B9ECC(int a, int obj)
{
    DimAnimTable* base;
    BaddieState* state;
    s16 targetParam;
    u16 targetDistance;
    u16 targetAnim[2];

    base = (DimAnimTable*)lbl_80325960;
    state = (BaddieState*)obj;
    if ((s8)state->moveDone != 0 || (s8)state->moveJustStartedB != 0)
    {
        DIM2_GetBaddieControlInterface()->queryTargetMove(a, state->targetObj, 0x10, targetAnim,
                                                          &targetParam, &targetDistance);
        state->moveDone = 0;
        if (targetDistance < 0x5a)
        {
            if (targetDistance > 0x1e &&
                ((u16)(targetAnim[0] - 3) <= 1 || targetAnim[0] == 0xb || targetAnim[0] == 0xc))
            {
                DIM2_GetPlayerInterface()->requestControlMode(a, state, 2);
            }
            else
            {
                DIM2_GetPlayerInterface()->requestControlMode(a, state, 9);
            }
        }
        else if (targetAnim[0] == 0 || targetAnim[0] == 0xf)
        {
            state->moveDone = 0;
            if (targetDistance > 0x1a9 &&
                (DIM2_GetBaddieControlInterface()->checkTargetRange(a, state, lbl_803E4BB8) & 1) != 0)
            {
                DIM2_GetPlayerInterface()->requestControlMode(
                    a, state, base->surprised[randomGetRange(0, 5)]);
            }
            else if (targetDistance < 0xfa)
            {
                DIM2_GetPlayerInterface()->requestControlMode(a, state, 3);
            }
            else
            {
                if (lbl_803DDB84 > 6)
                {
                    lbl_803DDB84 = 0;
                }
                switch ((s8)state->hitPoints)
                {
                case 3:
                    DIM2_GetPlayerInterface()->requestControlMode(
                        a, state, base->group3[lbl_803DDB84++]);
                    break;
                case 2:
                    DIM2_GetPlayerInterface()->requestControlMode(
                        a, state, base->group2[lbl_803DDB84++]);
                    break;
                case 1:
                    DIM2_GetPlayerInterface()->requestControlMode(
                        a, state, base->group1[lbl_803DDB84++]);
                    break;
                default:
                    DIM2_GetPlayerInterface()->requestControlMode(a, state, 3);
                    break;
                }
            }
        }
        else
        {
            DIM2_GetPlayerInterface()->requestControlMode(a, state, 2);
        }
    }
    if (state->controlMode == 3 || state->controlMode == 7)
    {
        gDIMbossAnimController[0x611] |= 1;
    }
    else
    {
        gDIMbossAnimController[0x611] &= ~1;
    }
    DIM2icicle_updateHitResponse(a, (int)state);
    return 0;
}
#pragma peephole reset
#pragma scheduling reset
