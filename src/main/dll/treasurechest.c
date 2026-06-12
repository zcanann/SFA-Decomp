#include "main/dll/landedArwing.h"
#include "main/game_object.h"
#include "main/dll/treasurechest_state.h"
#include "main/objanim.h"
#include "main/objseq.h"
#include "main/objfx.h"
#include "main/object_descriptor.h"

typedef struct DllD3Placement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x2E - 0x14];
    u8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DllD3Placement;


extern u32 randomGetRange(int min, int max);
extern void* Obj_GetPlayerObject(void);
extern int ObjContact_AddCallback(int* obj, int p2, void* cb);
extern int ObjList_FindNearestObjectByDefNo(int* obj, int defNo, f32* radius);
extern int objBboxFn_800640cc(int a, f32* pos, f32 b, int c, int* out, int* obj, int e, int g, int h, int i);
extern void objRenderFn_8003b8f4(f32);
extern void ObjHits_DisableObject(int obj);
extern f32 sqrtf(f32);
extern void* memset(void* dst, int val, u32 size);

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern int* gBaddieControlInterface;
extern int* gPlayerInterface;

extern int lbl_803202E8[];
extern int lbl_80320360[];
extern int lbl_803AC638[];
extern void* gLandedArwingStateHandlers[];
extern void* gLandedArwingDefaultStateHandler;

extern f32 timeDelta;
extern double lbl_803E3040;
extern f32 lbl_803E3030;
extern f32 lbl_803E3034;
extern f32 lbl_803E3038;
extern f32 lbl_803E3048;
extern f32 lbl_803E3058;
extern f32 lbl_803E2FDC;
extern f32 lbl_803E2FF4;

extern void fn_801659B8(void);
extern void LandedArwing_UpdateRetreatChase(void);
extern void LandedArwing_UpdateBounceFade(void);
extern void LandedArwing_TriggerLaunchTarget(void);
extern void LandedArwing_ReturnZero(void);

extern void skeetlawall_setScale(int* obj, f32* outVec, u8* outByte);
extern void fn_80167550(int* obj);

/*
 * --INFO--
 *
 * Function: dll_D3_update
 * EN v1.0 Address: 0x80166F2C
 * EN v1.0 Size: 1228b
 */
void dll_D3_update(int* obj);

/*
 * --INFO--
 *
 * Function: dll_D3_init
 * EN v1.0 Address: 0x801673F8
 * EN v1.0 Size: 344b
 */
void dll_D3_init(int obj, int def, int flag);

void dll_D3_initialise(void);


/* Trivial 4b 0-arg blr leaves. */
void dll_D3_release_nop(void);

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

/* 8b "li r3, N; blr" returners. */
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

void fn_80167550(int* obj);

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
