/*
 * skeetlawall (DLL 0x00D4) - an axis-aligned bounding-box wall/trigger
 * object used in the Skeetla arena level.  Each instance stores six
 * per-axis extents (in unsigned world units) and an optional shape flag;
 * skeetlawall_setScale unpacks these into a float[6] min/max array for
 * the engine's collision layer.  The render function delegates to
 * objRenderModelAndHitVolumes only when unkF4 == 0 (default/inactive shape).
 */
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/gameplay_runtime.h"

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

void skeetlawall_setScale(int* obj, f32* outVec, u8* outByte)
{
    SkeetlaWallState* state = ((GameObject*)obj)->extra;
    outVec[0] = ((GameObject*)obj)->anim.worldPosX - (f32)(u32)
    state->negXExtent;
    outVec[1] = ((GameObject*)obj)->anim.worldPosX + (f32)(u32)
    state->posXExtent;
    outVec[2] = ((GameObject*)obj)->anim.worldPosZ + (f32)(u32)
    state->posZExtent;
    outVec[3] = ((GameObject*)obj)->anim.worldPosZ - (f32)(u32)
    state->negZExtent;
    outVec[4] = ((GameObject*)obj)->anim.worldPosY + (f32)(u32)
    state->posYExtent;
    outVec[5] = ((GameObject*)obj)->anim.worldPosY - (f32)(u32)
    state->negYExtent;
    outByte[0] = state->shapeFlag;
}

int skeetlawall_getExtraSize(void) { return 0x7; }
int skeetlawall_getObjectTypeId(void) { return 0x0; }

void skeetlawall_free(void)
{
}

void skeetlawall_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        switch (((GameObject*)obj)->unkF4)
        {
        case 0:
            ((void(*)(int, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, 1.0f);
            break;
        }
    }
}

void skeetlawall_hitDetect(void)
{
}

void skeetlawall_update(void)
{
}

void skeetlawall_init(int obj, u8* def)
{
    SkeetlaWallState* state = ((GameObject*)obj)->extra;
    state->negXExtent = def[0x18];
    state->posXExtent = def[0x19];
    state->posZExtent = def[0x1A];
    state->negZExtent = def[0x1B];
    state->posYExtent = def[0x1C];
    state->negYExtent = def[0x1D];
    state->shapeFlag = def[0x1E];
}

void skeetlawall_release(void)
{
}

void skeetlawall_initialise(void)
{
}

ObjectDescriptor11WithPadding gSkeetlaWallObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)skeetlawall_initialise,
        (ObjectDescriptorCallback)skeetlawall_release,
        0,
        (ObjectDescriptorCallback)skeetlawall_init,
        (ObjectDescriptorCallback)skeetlawall_update,
        (ObjectDescriptorCallback)skeetlawall_hitDetect,
        (ObjectDescriptorCallback)skeetlawall_render,
        (ObjectDescriptorCallback)skeetlawall_free,
        (ObjectDescriptorCallback)skeetlawall_getObjectTypeId,
        skeetlawall_getExtraSize,
        (ObjectDescriptorCallback)skeetlawall_setScale,
    },
    0,
};

/* ground-baddie move/speed tables referenced via extern by texscroll2; owned here by link order */

u8 lbl_803203F8[0xC] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00,
};

u8 lbl_80320404[0x14] = {
    0x3B, 0x83, 0x12, 0x6F, 0x3B, 0xC4, 0x9B, 0xA6, 0x3C, 0x23, 0xD7, 0x0A,
    0x3C, 0x23, 0xD7, 0x0A, 0x3C, 0x23, 0xD7, 0x0A,
};
