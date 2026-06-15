/* DLL 0x01DF — dim2snowball / dim2conveyor / dll1d6 group. TU: 0x801B8798–0x801B8860. */
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/game_object.h"

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

static inline int* DIM2snowball_GetActiveModel(void* obj);

extern undefined4 GameBit_Set(int eventId, int value);


extern f32 timeDelta;

extern void objRenderFn_8003b8f4(f32);
extern void* Obj_GetPlayerObject(void);

#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objtexture.h"

typedef struct Dll1DFState
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 pad7[0x24 - 0x7];
    f32 unk24;
} Dll1DFState;

#pragma scheduling on
#pragma peephole on
extern f32 lbl_803E4B98;
extern f32 lbl_803E4BA8;
extern f32 lbl_803E4BAC;
extern f32 vec3f_distanceSquared(f32 * a, f32 * b);
extern f32 lbl_803E4B9C, lbl_803E4BA0, lbl_803E4BA4;

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

void dll_1DA_release(void);

/* dll_1DA_update: rolling-rock physics -- damp velocity, bounce off geometry normal,
 * fall, land on contact object, clamp to floor height. */

/* fn_801B9ECC: DIM boss player-vs-baddie reaction dispatcher -- picks a player anim
 * from distance/anim-state via the interface vtables. */

#pragma scheduling off
#pragma peephole off
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

int dll_1DB_getExtraSize(void);
int dll_1DF_getExtraSize(void) { return 0x28; }
int dll_1DF_getObjectTypeId(void) { return 0x0; }

void dll_1DF_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4B98);
}

void dll_1DA_init(void* obj);

/* dll_1DF_init: similar romlist param init, but reads three u8 fields, packs to s16
 *              fields, and on a u8 flag does a u32->f32 conversion (MWCC emits the
 *              magic-2^52 trick using a 2^52 constant) to scale obj[0x50]->f4 into
 *              obj[8]. Also sets obj[0xB8]->f10 from a constant and OR-merges flags
 *              into obj[0x64]->u32_30 (0x810) and obj[0xB0]'s u16 (0x2000). */

void dll_1DF_init(void* obj, void* p)
{
    u32 flag;
    void* p50;
    void* p64;
    ((GameObject*)obj)->anim.rotZ = (s16)((u32) * (u8*)((char*)p + 0x18) << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((u32) * (u8*)((char*)p + 0x19) << 8);
    ((GameObject*)obj)->anim.rotX = (s16)((u32) * (u8*)((char*)p + 0x1A) << 8);
    flag = *(u8*)((char*)p + 0x1B);
    if (flag != 0)
    {
        p50 = *(void**)&((GameObject*)obj)->anim.modelInstance;
        ((GameObject*)obj)->anim.rootMotionScale = ((ObjDef*)p50)->rootMotionScaleBase * ((f32)flag / lbl_803E4BA8);
    }
    *(f32*)((char*)*(void**)&((GameObject*)obj)->extra + 0x10) = lbl_803E4BAC;
    p64 = *(void**)&((GameObject*)obj)->anim.modelState;
    if (p64 != 0)
    {
        ((ObjModelState*)p64)->flags |= 0x810;
    }
    ((GameObject*)obj)->objectFlags |= 0x2000;
}

/* dim2lavacontrol_setScale: every-frame tick -- if not already "armed" (bit 0 of
 *   sub.b2 is clear), decrement sub.b0 counter; when it hits 0 set the armed bit
 *   and tell the game-event tracker (via param.s16_1E) that this trigger fired. */
void dim2lavacontrol_setScale(void* obj);

/* dll_1DF_update: per-frame texture-color update + proximity-driven expgfx trigger.
 *   - objFindTexture(obj,0,0); if non-null and obj.s16_46 == 209 set tex.color
 *     (bytes 0xC..0xE) to (u8)(int)lbl_803E4B9C via three independent fctiwz casts,
 *     else do the same dest writes (different scheduling).
 *   - Then if (distance^2 from player to obj position < lbl_803E4BA0) and sub.f24
 *     decremented by timeDelta is < lbl_803E4B9C, call gPartfxInterface->vt[2] with
 *     (obj, 525, 0, 2, -1, 0) and reset sub.f24 to lbl_803E4BA4. */

void dll_1DF_update(void* obj)
{
    void* sub = ((GameObject*)obj)->extra;
    ObjTextureRuntimeSlot* tex;
    void* player;
    f32 dist;
    f32 t;

    tex = objFindTexture(obj, 0, 0);
    if (tex != 0)
    {
        if (((GameObject*)obj)->anim.seqId == 209)
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
    dist = vec3f_distanceSquared(&((GameObject*)player)->anim.worldPosX, &((GameObject*)obj)->anim.worldPosX);
    if (dist < lbl_803E4BA0)
    {
        t = ((Dll1DFState*)sub)->unk24 - timeDelta;
        ((Dll1DFState*)sub)->unk24 = t;
        if (t < lbl_803E4B9C)
        {
            (*gPartfxInterface)->spawnObject(obj, 525, NULL, 2, -1, NULL);
            ((Dll1DFState*)sub)->unk24 = lbl_803E4BA4;
        }
    }
}

/* dll_1DB_init: read romlist params, set s16 at obj[0] and a u8 flag on obj->sub_B8
 *              from a GameBit, and OR-set bit 0x2000 in obj->flags_B0. */
void dll_1DB_init(void* obj, void* p);
