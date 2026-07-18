/*
 * DLL 0x01DF — a small placed scenery/effect object (TU 0x801B9CB4..0x801B9ECC).
 *
 * init seeds rotation from three placement bytes, optionally scales the model's
 * root motion by a placement flag, primes 0.01f into state->unk10 (0x10),
 * and OR-merges model-state flags (0x810) and object flags (0x2000). render draws
 * the model when visible. update recolours the object's first texture each frame
 * and, when the player comes within range, runs a countdown that spawns particle
 * effect 525 and rearms. The other entry points
 * (free/hitDetect/release/initialise/typeId) are stubs.
 *
 * The seqId==209 if/else in update assigns the same value in both arms but is
 * intentional and must not be collapsed to a single assignment.
 */
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objtexture.h"
#include "main/object_api.h"
#include "main/frame_timing.h"
#include "main/object_render_legacy.h"
#include "main/vecmath_distance_api.h"
#include "main/object_descriptor.h"

#define DLL1DF_OBJFLAG_HITDETECT_DISABLED 0x2000
/* particle effect seeded on the proximity-countdown tick while the player is near */
#define DLL1DF_PARTFX 525
typedef struct Dll1DFPlaceData
{
    ObjPlacement base;
    u8 rotZByte; /* 0x18 */
    u8 rotYByte; /* 0x19 */
    u8 rotXByte; /* 0x1A */
    u8 scaleByte; /* 0x1B: nonzero scales root motion */
} Dll1DFPlaceData;

typedef struct Dll1DFState
{
    u8 pad0[0x4];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 pad7[0x10 - 0x7];
    f32 unk10; /* 0x10: primed to 0.01f at init */
    u8 pad14[0x24 - 0x14];
    f32 spawnTimer; /* 0x24: counts down by timeDelta while player is near */
} Dll1DFState;

STATIC_ASSERT(offsetof(Dll1DFPlaceData, rotZByte) == 0x18);
STATIC_ASSERT(offsetof(Dll1DFPlaceData, scaleByte) == 0x1B);
STATIC_ASSERT(offsetof(Dll1DFState, unk10) == 0x10);
STATIC_ASSERT(offsetof(Dll1DFState, spawnTimer) == 0x24);

int dll_1DF_getExtraSize(void) { return 0x28; }
int dll_1DF_getObjectTypeId(void) { return 0x0; }

void dll_1DF_free(void)
{
}

void dll_1DF_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

void dll_1DF_hitDetect(void)
{
}

void dll_1DF_update(GameObject* obj)
{
    Dll1DFState* sub = obj->extra;
    ObjTextureRuntimeSlot* tex;
    GameObject* player;
    f32 dist;
    f32 t;

    tex = objFindTexture((GameObject*)(obj), 0, 0);
    if (tex != NULL)
    {
        if (obj->anim.seqId == 209)
        {
            f32 v = 0.0f;
            tex->colorR = v;
            tex->colorG = v;
            tex->colorB = v;
        }
        else
        {
            f32 v = 0.0f;
            tex->colorR = v;
            tex->colorG = v;
            tex->colorB = v;
        }
    }
    player = Obj_GetPlayerObject();
    dist = vec3f_distanceSquared(&player->anim.worldPosX, &obj->anim.worldPosX);
    if (dist < 90000.0f)
    {
        t = sub->spawnTimer - timeDelta;
        sub->spawnTimer = t;
        if (t < 0.0f)
        {
            (*gPartfxInterface)->spawnObject(obj, DLL1DF_PARTFX, NULL, 2, -1, NULL);
            sub->spawnTimer = 12.0f;
        }
    }
}

void dll_1DF_init(GameObject* obj, Dll1DFPlaceData* p)
{
    u32 scaleParam;
    void* objDef;
    void* modelState;
    obj->anim.rotZ = (s16)((u32)p->rotZByte << 8);
    obj->anim.rotY = (s16)((u32)p->rotYByte << 8);
    obj->anim.rotX = (s16)((u32)p->rotXByte << 8);
    scaleParam = p->scaleByte;
    if (scaleParam != 0)
    {
        objDef = *(void**)&obj->anim.modelInstance;
        obj->anim.rootMotionScale = ((ObjDef*)objDef)->rootMotionScaleBase * ((f32)scaleParam / 255.0f);
    }
    ((Dll1DFState*)obj->extra)->unk10 = 0.01f;
    modelState = *(void**)&obj->anim.modelState;
    if (modelState != NULL)
    {
        ((ObjModelState*)modelState)->flags |= 0x810;
    }
    obj->objectFlags |= DLL1DF_OBJFLAG_HITDETECT_DISABLED;
}

void dll_1DF_release(void)
{
}

void dll_1DF_initialise(void)
{
}

ObjectDescriptor lbl_80325928 = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_1DF_initialise,
    (ObjectDescriptorCallback)dll_1DF_release,
    0,
    (ObjectDescriptorCallback)dll_1DF_init,
    (ObjectDescriptorCallback)dll_1DF_update,
    (ObjectDescriptorCallback)dll_1DF_hitDetect,
    (ObjectDescriptorCallback)dll_1DF_render,
    (ObjectDescriptorCallback)dll_1DF_free,
    (ObjectDescriptorCallback)dll_1DF_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)dll_1DF_getExtraSize,
};

/* .sdata2 constant pool */
const f32 lbl_803E4BB8 = 2e+02f;
const f32 lbl_803E4BBC = 1e+02f;
const f32 lbl_803E4BC0 = 0.9f;
const f32 lbl_803E4BC4 = 2.5f;
const f32 lbl_803E4BC8 = 5.0f;
const f32 lbl_803E4BCC = 2.0f;
const f32 lbl_803E4BD0 = 12.0f;
const f32 lbl_803E4BD4 = 0.002f;
const f32 lbl_803E4BD8 = 0.0f;
const f32 lbl_803E4BDC = 0.0f;
const f32 lbl_803E4BE0 = 176.0f;
const f32 lbl_803E4BE4 = -0.0f;
const f32 lbl_803E4BE8 = 0.01f;
const f32 lbl_803E4BEC = 7.8e+02f;
const f32 lbl_803E4BF0 = 0.008f;
const f32 lbl_803E4BF4 = 1e+01f;
const f32 lbl_803E4BF8 = 4.0f;
const f32 lbl_803E4BFC = 2e+01f;
const f32 lbl_803E4C00 = 0.005f;
const f32 lbl_803E4C04 = 0.006f;
const f32 lbl_803E4C08 = 0.0025f;
const f32 lbl_803E4C0C = 0.95f;
const f32 lbl_803E4C10 = 0.3f;
const f32 lbl_803E4C14 = 0.025f;
const f32 lbl_803E4C18 = 0.55f;
const f32 lbl_803E4C1C = 0.25f;
const f32 lbl_803E4C20 = 0.35f;
const f32 lbl_803E4C24 = 0.021f;
const f32 lbl_803E4C28 = 4e+01f;
const f32 lbl_803E4C2C = 8e+01f;
const f32 lbl_803E4C30 = 155.0f;
const f32 lbl_803E4C34 = -75.0f;
const f32 lbl_803E4C38 = 0.5f;
const f32 lbl_803E4C3C = -15.0f;
const f32 lbl_803E4C40 = -2e+01f;
const f32 lbl_803E4C44 = 1.0f;
const f32 lbl_803E4C48 = -6.0f;
const f32 lbl_803E4C4C = 0.2f;
const f32 lbl_803E4C50 = -0.3f;
const f32 lbl_803E4C54 = -1.0f;
const f32 lbl_803E4C58 = 0.1f;
const f32 lbl_803E4C5C = -0.25f;
const f32 lbl_803E4C60 = -0.2f;
const f32 lbl_803E4C64 = -0.1f;
const f32 lbl_803E4C68 = -1.5f;
const f32 lbl_803E4C6C = 3e+01f;
const f32 lbl_803E4C70 = 0.17f;
const f32 gDim2IcicleLightDuration = 3.6e+03f;
const f32 lbl_803E4C78 = 3e+02f;
const f32 lbl_803E4C7C = 0.0f;
const f32 lbl_803E4C80 = 0.005f;
const f32 lbl_803E4C84 = 1.0f;
const f32 lbl_803E4C88[2] = {0.0f, 0.0f};
const f32 lbl_803E4C90 = 0.0f;
const f32 lbl_803E4C94 = 0.005f;
const f32 lbl_803E4C98 = 0.01f;
const f32 lbl_803E4C9C = 3e+01f;
const f32 lbl_803E4CA0 = 5e+01f;
const f32 lbl_803E4CA4 = 0.028f;
const f32 lbl_803E4CA8 = 16.0f;
const f32 lbl_803E4CAC = 3.0f;
const f32 lbl_803E4CB0 = 9e+01f;
const f32 lbl_803E4CB4 = 0.125f;
const f32 lbl_803E4CB8 = 1.0f;
const f32 lbl_803E4CBC = 1e+02f;
const f32 lbl_803E4CC0 = 8.0f;
const f32 lbl_803E4CC4 = -0.1f;
const f32 lbl_803E4CC8 = 7.8e+02f;
const f32 lbl_803E4CCC = 2e+01f;
