/* DIM2 mixed-DLL TU: 0x801B9ECC–0x801BA224. Contains the hit-reaction dispatcher
 * (fn_801B9ECC) and shared helpers for DIM2 objects (icicle, geyser, rolling rock,
 * conveyor, crusher, snowball, path generator, truth-horn ice). */
#include "main/dll/baddie_state.h"
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/gameplay_runtime.h"
#include "main/game_object.h"

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

static inline int* DIM2snowball_GetActiveModel(void* obj);

extern int* gBaddieControlInterface;
extern int* gPlayerInterface;
extern u8 lbl_803DDB84;
extern u8 lbl_80325960[];
extern u8 gDIMbossAnimController[];
extern int DIM2icicle_updateHitResponse();
extern f32 lbl_803E4BB8;

void FUN_801b9cc4(int param_1)
{
    char* pcVar1;
    int iVar2;

    pcVar1 = ((GameObject*)param_1)->extra;
    if ((pcVar1[2] & 1U) == 0)
    {
        iVar2 = *(int*)&((GameObject*)param_1)->anim.placementData;
        if (('\0' < *pcVar1) && (*pcVar1 = *pcVar1 + -1, *pcVar1 == '\0'))
        {
            pcVar1[2] = pcVar1[2] | 1;
            GameBit_Set((int)*(short*)(iVar2 + 0x1e), 1);
        }
    }
    return;
}


/* dll_1DA_update: rolling-rock physics -- damp velocity, bounce off geometry normal,
 * fall, land on contact object, clamp to floor height. */

/* fn_801B9ECC: DIM boss player-vs-baddie reaction dispatcher -- picks a player anim
 * from distance/anim-state via the interface vtables. */

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

typedef struct
{
    u8 pad[0x168];
    s16 surprised[6]; /* 0x168 */
    s16 group3[8]; /* 0x174 */
    s16 group2[8]; /* 0x184 */
    s16 group1[8]; /* 0x194 */
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


/* dll_1DF_init: similar romlist param init, but reads three u8 fields, packs to s16
 *              fields, and on a u8 flag does a u32->f32 conversion (MWCC emits the
 *              magic-2^52 trick using a 2^52 constant) to scale obj[0x50]->f4 into
 *              obj[8]. Also sets obj[0xB8]->f10 from a constant and OR-merges flags
 *              into obj[0x64]->u32_30 (0x810) and obj[0xB0]'s u16 (0x2000). */

/* dim2lavacontrol_setScale: every-frame tick -- if not already "armed" (bit 0 of
 *   sub.b2 is clear), decrement sub.b0 counter; when it hits 0 set the armed bit
 *   and tell the game-event tracker (via param.s16_1E) that this trigger fired. */

/* dll_1DF_update: per-frame texture-color update + proximity-driven expgfx trigger.
 *   - objFindTexture(obj,0,0); if non-null and obj.s16_46 == 209 set tex.color
 *     (bytes 0xC..0xE) to (u8)(int)lbl_803E4B9C via three independent fctiwz casts,
 *     else do the same dest writes (different scheduling).
 *   - Then if (distance^2 from player to obj position < lbl_803E4BA0) and sub.f24
 *     decremented by timeDelta is < lbl_803E4B9C, call gPartfxInterface->vt[2] with
 *     (obj, 525, 0, 2, -1, 0) and reset sub.f24 to lbl_803E4BA4. */

/* dll_1DB_init: read romlist params, set s16 at obj[0] and a u8 flag on obj->sub_B8
 *              from a GameBit, and OR-set bit 0x2000 in obj->flags_B0. */
