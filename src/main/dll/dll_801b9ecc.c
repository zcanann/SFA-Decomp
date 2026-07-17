/*
 * DIM boss player-vs-baddie reaction dispatcher (fn_801B9ECC, address-taken
 * into the boss anim-fn table at slot 5 from dll_01E0_dimboss).
 */
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_control_interface.h"
#include "main/player_control_interface.h"
#include "main/dll/dll_801b9ecc.h"
#include "main/dll/DIM/DIM2icicle.h"

extern u8 lbl_803DDB84;
int lbl_80325960[16] = {
    1, 8, 9, 9, 10, 10, 10, 10, 7, 7, 7, 7, 6, 6, 5, 1,
};
extern u8 gDIMbossAnimController[];
extern f32 lbl_803E4BB8;

static inline Dim2BaddieControlInterface* DIM2_GetBaddieControlInterface(void)
{
    return (Dim2BaddieControlInterface*)*gBaddieControlInterface;
}

static inline Dim2PlayerInterface* DIM2_GetPlayerInterface(void)
{
    return (Dim2PlayerInterface*)*gPlayerInterface;
}

#pragma scheduling off
#pragma peephole off
int fn_801B9ECC(int a, int obj)
{
    DimAnimTable* base;
    BaddieState* state;
    s16 targetParam;
    u16 targetDistance;
    u16 targetAnim[2];

    state = (BaddieState*)obj;
    base = (DimAnimTable*)lbl_80325960;
    if ((s8)state->moveDone != 0 || (s8)state->moveJustStartedB != 0)
    {
        DIM2_GetBaddieControlInterface()->queryTargetMove(a, state->targetObj, 0x10, targetAnim, &targetParam,
                                                          &targetDistance);
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
                s16 surprisedAnim = base->surprised[randomGetRange(0, 5)];
                DIM2_GetPlayerInterface()->requestControlMode(a, state, surprisedAnim);
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
                    (*(Dim2PlayerInterface**)gPlayerInterface)
                        ->requestControlMode(a, state, base->group3[lbl_803DDB84++]);
                    break;
                case 2:
                    (*(Dim2PlayerInterface**)gPlayerInterface)
                        ->requestControlMode(a, state, base->group2[lbl_803DDB84++]);
                    break;
                case 1:
                    (*(Dim2PlayerInterface**)gPlayerInterface)
                        ->requestControlMode(a, state, base->group1[lbl_803DDB84++]);
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
