/*
 * imanimspacecraft (DLL 0x16E) - the animated SpaceCraft cinematic
 * object on the Ice Mountain map.
 *
 * Its animation sequence (imanimspacecraft_SeqFn) toggles a set of
 * "mask" bits that the parent queries through setScale to decide which
 * sub-models are shown, runs a blink cycle on a warning light, and
 * spawns engine-glow particles while the light is lit. init seeds the
 * five spacecraft game bits and the shared particle-spawn position.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/imanimspacecraftstate_struct.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/objtexture.h"
#include "main/frame_timing.h"
#include "main/object_render_legacy.h"
#include "main/gamebits.h"
#include "main/dll/IM/dll_016E_imanimspacecraft.h"
#include "main/object_descriptor.h"

STATIC_ASSERT(sizeof(ImAnimSpacecraftState) == 0x4);

/* state->flags */
#define ANIMSPACECRAFT_PARTFX        0x133
#define ANIMSPACECRAFT_FLAG_BLINK_ON 0x2
#define ANIMSPACECRAFT_FLAG_TOGGLE_8 0x8
#define ANIMSPACECRAFT_FLAG_TOGGLE_4 0x4

/* state->maskBits: bits 4..6 toggled together as one group */
#define ANIMSPACECRAFT_MASK_GROUP 0x70

char lbl_803AC948[0x18];

void imanimspacecraft_modelMtxFn(void)
{
}

/* vtable slot 0x0B: reports whether the spacecraft's ANIMSPACECRAFT_FLAG_TOGGLE_4
   flag bit is set. */
u32 imanimspacecraft_func0B(int* obj)
{
    return ((ImAnimSpacecraftState*)((GameObject*)obj)->extra)->flags & ANIMSPACECRAFT_FLAG_TOGGLE_4;
}

int imanimspacecraft_setScale(int* obj, int bitIdx)
{
    ImAnimSpacecraftState* state = (ImAnimSpacecraftState*)((GameObject*)obj)->extra;
    switch (state->maskBits & (1 << bitIdx))
    {
    default:
        return TRUE;
    case 0:
        return FALSE;
    }
}

int imanimspacecraft_getExtraSize(void);
int imanimspacecraft_getObjectTypeId(void);
void imanimspacecraft_free(GameObject* obj);
void imanimspacecraft_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void imanimspacecraft_hitDetect(void);
void imanimspacecraft_update(GameObject* obj);
void imanimspacecraft_init(GameObject* obj);
void imanimspacecraft_release(void);
void imanimspacecraft_initialise(void);

ObjectDescriptor13 gIMAnimSpaceCraftObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    (ObjectDescriptorCallback)imanimspacecraft_initialise,
    (ObjectDescriptorCallback)imanimspacecraft_release,
    0,
    (ObjectDescriptorCallback)imanimspacecraft_init,
    (ObjectDescriptorCallback)imanimspacecraft_update,
    (ObjectDescriptorCallback)imanimspacecraft_hitDetect,
    (ObjectDescriptorCallback)imanimspacecraft_render,
    (ObjectDescriptorCallback)imanimspacecraft_free,
    (ObjectDescriptorCallback)imanimspacecraft_getObjectTypeId,
    imanimspacecraft_getExtraSize,
    (ObjectDescriptorCallback)imanimspacecraft_setScale,
    (ObjectDescriptorCallback)imanimspacecraft_func0B,
    (ObjectDescriptorCallback)imanimspacecraft_modelMtxFn,
};

int imanimspacecraft_SeqFn(int* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    ImAnimSpacecraftState* state;
    int i;
    ObjTextureRuntimeSlot* tex;

    state = ((GameObject*)obj)->extra;
    tex = objFindTexture((GameObject*)(obj), 1, 0);
    tex->textureId = ((state->flags >> 1 & 1) ^ 1) << 8;
    if (!(state->flags & ANIMSPACECRAFT_FLAG_BLINK_ON))
    {
        if ((state->blinkTimer -= framesThisStep) < 0)
        {
            state->flags |= ANIMSPACECRAFT_FLAG_BLINK_ON;
            state->blinkTimer = 0x78;
        }
    }
    else
    {
        state->flags &= ~ANIMSPACECRAFT_FLAG_BLINK_ON;
    }
    if (state->flags & ANIMSPACECRAFT_FLAG_BLINK_ON)
    {
        *(f32*)(lbl_803AC948 + 0xc) = 143.0f;
        *(f32*)(lbl_803AC948 + 0x10) = 16.0f;
        *(f32*)(lbl_803AC948 + 0x14) = -79.0f;
        (*gPartfxInterface)->spawnObject(obj, ANIMSPACECRAFT_PARTFX, lbl_803AC948, 4, -1, NULL);
        *(f32*)(lbl_803AC948 + 0xc) = -143.0f;
        *(f32*)(lbl_803AC948 + 0x10) = 16.0f;
        *(f32*)(lbl_803AC948 + 0x14) = -79.0f;
        (*gPartfxInterface)->spawnObject(obj, ANIMSPACECRAFT_PARTFX, lbl_803AC948, 4, -1, NULL);
    }
    tex = objFindTexture((GameObject*)(obj), 0, 0);
    tex->textureId = 0x100;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u32 ev = animUpdate->eventIds[i];
        switch (ev)
        {
        case 1:
            state->maskBits = (u8)(state->maskBits ^ (1 << (ev - 1)));
            break;
        case 2:
            state->maskBits = (u8)(state->maskBits ^ (1 << (ev - 1)));
            break;
        case 3:
            state->maskBits = (u8)(state->maskBits ^ (1 << (ev - 1)));
            break;
        case 4:
            state->maskBits = (u8)(state->maskBits ^ (1 << (ev - 1)));
            break;
        case 5:
            state->maskBits = (u8)(state->maskBits ^ ANIMSPACECRAFT_MASK_GROUP);
            break;
        case 6:
            state->flags = (u8)(state->flags ^ ANIMSPACECRAFT_FLAG_TOGGLE_8);
            break;
        case 7:
            state->flags = (u8)(state->flags ^ ANIMSPACECRAFT_FLAG_TOGGLE_4);
            break;
        }
    }
    return 0;
}

int imanimspacecraft_getExtraSize(void)
{
    return 0x4;
}
int imanimspacecraft_getObjectTypeId(void)
{
    return 0x0;
}

void imanimspacecraft_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void imanimspacecraft_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void imanimspacecraft_hitDetect(void)
{
}

void imanimspacecraft_update(GameObject* obj)
{
    if (obj->unkF4 != 0)
        return;
    obj->unkF4 = 1;
}

void imanimspacecraft_init(GameObject* obj)
{
    f32 pos;
    obj->animEventCallback = imanimspacecraft_SeqFn;
    pos = 0.0f;
    *(f32*)(lbl_803AC948 + 0xc) = pos;
    *(f32*)(lbl_803AC948 + 0x10) = pos;
    *(f32*)(lbl_803AC948 + 0x14) = pos;
    mainSetBits(GAMEBIT_IM_Unk0BEB, 1);
    mainSetBits(GAMEBIT_IM_Unk0BEC, 1);
    mainSetBits(GAMEBIT_IM_Unk0BED, 1);
    mainSetBits(GAMEBIT_IM_Unk0BEE, 1);
    mainSetBits(GAMEBIT_IM_Unk0BEF, 1);
}

void imanimspacecraft_release(void)
{
}

void imanimspacecraft_initialise(void)
{
}
