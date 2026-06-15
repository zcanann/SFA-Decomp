#include "main/game_object.h"
#include "main/object_descriptor.h"

extern void objRenderFn_8003b8f4(f32);

extern f32 lbl_803E3058;

extern void skeetlawall_setScale(int* obj, f32* outVec, u8* outByte);

void skeetlawall_free(void)
{
}

void skeetlawall_hitDetect(void)
{
}

void skeetlawall_update(void)
{
}

void skeetlawall_release(void)
{
}

void skeetlawall_initialise(void)
{
}

int skeetlawall_getExtraSize(void) { return 0x7; }
int skeetlawall_getObjectTypeId(void) { return 0x0; }

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

void skeetlawall_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        switch (((GameObject*)obj)->unkF4)
        {
        case 0:
            ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E3058);
            break;
        }
    }
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
