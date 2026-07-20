/*
 * skeetlawall (DLL 0x00D4) - an axis-aligned bounding-box wall/trigger
 * object used in the Skeetla arena level.  Each instance stores six
 * per-axis extents (in unsigned world units) and an optional shape flag;
 * SkeetlaWall_setScale unpacks these into a float[6] min/max array for
 * the engine's collision layer.  The render function delegates to
 * objRenderModelAndHitVolumes only when userData1 == 0 (default/inactive shape).
 */
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/dll/dll_00D4_skeetlawall.h"
#include "main/object_render.h"

typedef struct SkeetlaWallState
{
    u8 negXExtent;
    u8 posXExtent;
    u8 posZExtent;
    u8 negZExtent;
    u8 posYExtent;
    u8 negYExtent;
    u8 shapeFlag;
} SkeetlaWallState;

typedef struct SkeetlaWallPlacement
{
    u8 pad00[0x18];
    u8 negXExtent; /* 0x18 */
    u8 posXExtent; /* 0x19 */
    u8 posZExtent; /* 0x1a */
    u8 negZExtent; /* 0x1b */
    u8 posYExtent; /* 0x1c */
    u8 negYExtent; /* 0x1d */
    u8 shapeFlag;  /* 0x1e */
} SkeetlaWallPlacement;

void SkeetlaWall_setScale(GameObject* obj, f32* outVec, u8* outByte)
{
    SkeetlaWallState* state = obj->extra;
    outVec[0] = obj->anim.worldPosX - (f32)(u32)state->negXExtent;
    outVec[1] = obj->anim.worldPosX + (f32)(u32)state->posXExtent;
    outVec[2] = obj->anim.worldPosZ + (f32)(u32)state->posZExtent;
    outVec[3] = obj->anim.worldPosZ - (f32)(u32)state->negZExtent;
    outVec[4] = obj->anim.worldPosY + (f32)(u32)state->posYExtent;
    outVec[5] = obj->anim.worldPosY - (f32)(u32)state->negYExtent;
    outByte[0] = state->shapeFlag;
}

int SkeetlaWall_getExtraSize(void)
{
    return 0x7;
}
int SkeetlaWall_getObjectTypeId(void)
{
    return 0x0;
}

void SkeetlaWall_free(void)
{
}

void SkeetlaWall_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        switch (((GameObject*)obj)->userData1)
        {
        case 0:
            objRenderModelAndHitVolumes((GameObject*)obj, p2, p3, p4, p5, 1.0f);
            break;
        }
    }
}

void SkeetlaWall_hitDetect(void)
{
}

void SkeetlaWall_update(void)
{
}

void SkeetlaWall_init(GameObject* obj, SkeetlaWallPlacement* def)
{
    SkeetlaWallState* state = obj->extra;
    state->negXExtent = def->negXExtent;
    state->posXExtent = def->posXExtent;
    state->posZExtent = def->posZExtent;
    state->negZExtent = def->negZExtent;
    state->posYExtent = def->posYExtent;
    state->negYExtent = def->negYExtent;
    state->shapeFlag = def->shapeFlag;
}

void SkeetlaWall_release(void)
{
}

void SkeetlaWall_initialise(void)
{
}

ObjectDescriptor11WithPadding gSkeetlaWallObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)SkeetlaWall_initialise,
        (ObjectDescriptorCallback)SkeetlaWall_release,
        0,
        (ObjectDescriptorCallback)SkeetlaWall_init,
        (ObjectDescriptorCallback)SkeetlaWall_update,
        (ObjectDescriptorCallback)SkeetlaWall_hitDetect,
        (ObjectDescriptorCallback)SkeetlaWall_render,
        (ObjectDescriptorCallback)SkeetlaWall_free,
        (ObjectDescriptorCallback)SkeetlaWall_getObjectTypeId,
        SkeetlaWall_getExtraSize,
        (ObjectDescriptorCallback)SkeetlaWall_setScale,
    },
    0,
};

/* ground-baddie move/speed tables referenced via extern by texscroll2; owned here by link order */

s16 lbl_803203F8[6] = {0, 0, 1, 1, 2, 0};

f32 lbl_80320404[5] = {0.004f, 0.006f, 0.01f, 0.01f, 0.01f};
