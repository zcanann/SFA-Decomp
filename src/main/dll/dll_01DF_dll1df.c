/*
 * DLL 0x01DF — a small placed scenery/effect object (TU 0x801B9CB4..0x801B9ECC).
 *
 * init seeds rotation from three placement bytes, optionally scales the model's
 * root motion by a placement flag, primes lbl_803E4BAC into state->unk10 (0x10),
 * and OR-merges model-state flags (0x810) and object flags (0x2000). render draws
 * the model when visible. update recolours the object's first texture each frame
 * and, when the player comes within range, runs a countdown that spawns particle
 * effect 525 and rearms. The other entry points
 * (free/hitDetect/release/initialise/typeId) are stubs.
 *
 * The seqId==209 if/else in update assigns the same value in both arms but is
 * intentional and must not be collapsed to a single assignment.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objtexture.h"
#include "main/dll/VF/vf_shared.h"

#define DLL1DF_OBJFLAG_HITDETECT_DISABLED 0x2000
extern f32 lbl_803E4B98;
extern f32 lbl_803E4B9C, lbl_803E4BA0, lbl_803E4BA4, lbl_803E4BA8, lbl_803E4BAC;
extern f32 vec3f_distanceSquared(f32* a, f32* b);

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
    f32 unk10; /* 0x10: primed to lbl_803E4BAC at init */
    u8 pad14[0x24 - 0x14];
    f32 spawnTimer; /* 0x24: counts down by timeDelta while player is near */
} Dll1DFState;

STATIC_ASSERT(offsetof(Dll1DFPlaceData, rotZByte) == 0x18);
STATIC_ASSERT(offsetof(Dll1DFPlaceData, scaleByte) == 0x1B);
STATIC_ASSERT(offsetof(Dll1DFState, unk10) == 0x10);
STATIC_ASSERT(offsetof(Dll1DFState, spawnTimer) == 0x24);

void dll_1DF_free(void)
{
}

void dll_1DF_hitDetect(void)
{
}

void dll_1DF_release(void)
{
}

void dll_1DF_initialise(void)
{
}

int dll_1DF_getExtraSize(void) { return 0x28; }
int dll_1DF_getObjectTypeId(void) { return 0x0; }

void dll_1DF_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E4B98);
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
        obj->anim.rootMotionScale = ((ObjDef*)objDef)->rootMotionScaleBase * ((f32)scaleParam / lbl_803E4BA8);
    }
    ((Dll1DFState*)obj->extra)->unk10 = lbl_803E4BAC;
    modelState = *(void**)&obj->anim.modelState;
    if (modelState != NULL)
    {
        ((ObjModelState*)modelState)->flags |= 0x810;
    }
    obj->objectFlags |= DLL1DF_OBJFLAG_HITDETECT_DISABLED;
}

void dll_1DF_update(GameObject* obj)
{
    Dll1DFState* sub = obj->extra;
    ObjTextureRuntimeSlot* tex;
    GameObject* player;
    f32 dist;
    f32 t;

    tex = objFindTexture(obj, 0, 0);
    if (tex != NULL)
    {
        if (obj->anim.seqId == 209)
        {
            f32 v = lbl_803E4B9C;
            tex->colorR = v;
            tex->colorG = v;
            tex->colorB = v;
        }
        else
        {
            f32 v = lbl_803E4B9C;
            tex->colorR = v;
            tex->colorG = v;
            tex->colorB = v;
        }
    }
    player = Obj_GetPlayerObject();
    dist = vec3f_distanceSquared(&player->anim.worldPosX, &obj->anim.worldPosX);
    if (dist < lbl_803E4BA0)
    {
        t = sub->spawnTimer - timeDelta;
        sub->spawnTimer = t;
        if (t < lbl_803E4B9C)
        {
            (*gPartfxInterface)->spawnObject(obj, 525, NULL, 2, -1, NULL);
            sub->spawnTimer = lbl_803E4BA4;
        }
    }
}
