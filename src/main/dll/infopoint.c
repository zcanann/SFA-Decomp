/*
 * TrickyCurve (DLL 0xEC) - axis-aligned box trigger that applies a random
 * velocity kick to the player when they enter the volume. Used for the
 * "Tricky curve" current-like push zone. The box half-extents are stored in
 * TrickyCurveState; the object's world position is the centre. On each update
 * the function counts how many of the three axis intervals contain the player
 * (requires all three = axisCount 3) then fires a random horizontal nudge.
 */
#include "main/dll/infopoint.h"
#include "main/gameplay_runtime.h"



extern void fn_802960E4(int obj, f32 xVelocity, f32 zVelocity);

extern f32 lbl_803E644C;

typedef struct TrickyCurveObject
{
    u8 pad0[0xc];
    f32 x;
    f32 y;
    f32 z;
    u8 pad18[0xa0];
    struct TrickyCurveState* state;
} TrickyCurveObject;

typedef struct TrickyCurveState
{
    s16 halfWidthX;
    s16 halfWidthZ;
    s16 halfHeightY;
} TrickyCurveState;

void TrickyCurve_updateCooldownTrigger(int obj)
{
    TrickyCurveObject* curve;
    TrickyCurveState* state;
    TrickyCurveObject* player;
    int axisCount;
    f32 deltaX;
    f32 deltaZ;
    f32 deltaY;
    f32 bound;
    f32 randomX;
    f32 randomZ;

    curve = (TrickyCurveObject*)obj;
    state = curve->state;
    player = (TrickyCurveObject*)Obj_GetPlayerObject();
    axisCount = 0;
    deltaX = player->x - curve->x;
    deltaY = player->y - curve->y;
    deltaZ = player->z - curve->z;

    if (deltaX <= 0.0f)
    {
        bound = state->halfWidthX;
        if (deltaX > -bound)
        {
            axisCount = 1;
        }
    }
    if (deltaX > 0.0f)
    {
        bound = state->halfWidthX;
        if (deltaX < bound)
        {
            axisCount = axisCount + 1;
        }
    }

    if (deltaZ <= 0.0f)
    {
        bound = state->halfWidthZ;
        if (deltaZ > -bound)
        {
            axisCount = axisCount + 1;
        }
    }
    if (deltaZ > 0.0f)
    {
        bound = state->halfWidthZ;
        if (deltaZ < bound)
        {
            axisCount = axisCount + 1;
        }
    }

    if (deltaY <= 0.0f)
    {
        bound = state->halfHeightY;
        if (deltaY > -bound)
        {
            axisCount = axisCount + 1;
        }
    }
    if (deltaY > 0.0f)
    {
        bound = state->halfHeightY;
        if (deltaY < bound)
        {
            axisCount = axisCount + 1;
        }
    }

    if ((u8)axisCount == 3)
    {
        randomX = lbl_803E644C * randomGetRange(-0x17, 0x17);
        randomZ = lbl_803E644C * randomGetRange(-0x17, 0x17);
        fn_802960E4((int)player, randomX, randomZ);
    }
    return;
}
