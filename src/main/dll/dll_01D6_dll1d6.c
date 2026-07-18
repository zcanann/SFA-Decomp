/* DLL 0x1D6 - DIM2 crusher platform [801B63F4-801B6464) */
#include "main/dll/dimmagicbridge_state.h"
#include "main/object_api.h"
#include "main/dll/dimwooddoor2state_struct.h"
#include "main/dll/fbwgpipe_struct.h"
#include "main/dll/dll1cestate_struct.h"
#include "main/dll/explosionpartfxsource_struct.h"
#include "main/dll/dim2pathgeneratorstate_struct.h"
#include "main/dll/dim2snowballstate_struct.h"
#include "main/dll/truthhornicestate_struct.h"
#include "main/dll/dim2conveyorstate_struct.h"
#include "main/dll/dll1d6state_struct.h"
#include "main/dll/explosion_state.h"
#include "main/objtexture.h"
#include "main/frame_timing.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx.h"
#include "main/asset_load.h"
#include "main/pi_dolphin.h"
#include "main/game_object.h"
#include "main/model.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/mm.h"
#include "main/vecmath.h"
#include "main/object_render_legacy.h"
#include "main/object_descriptor.h"

s16 gDll1D6SlotTabIndex[4] = {0x10A, 0x14F, 0x151, 0x153};
u8 gDll1D6SlotInUse[8] = {0};

typedef struct Dll1D6Placement
{
    u8 pad0[0x18 - 0x0];
    s8 rotXParam; /* 0x18: <<8 -> anim.rotX seed */
    u8 pad19[0x1A - 0x19];
    s16 upTimer;
    s16 downTimer;
    u8 pad1E[0x20 - 0x1E];
} Dll1D6Placement;

/*
 * Per-object extra state for the dimwooddoor2 burnable door
 * (dimwooddoor2_getExtraSize == 0xC).
 */

STATIC_ASSERT(sizeof(DimWoodDoor2State) == 0xC);

/*
 * Per-object extra state for the dll_1CE hatch door
 * (dll_1CE_getExtraSize == 0xC).
 */

STATIC_ASSERT(sizeof(Dll1CEState) == 0xC);

/*
 * Per-object extra state for the dimmagicbridge flame bridge
 * (dimmagicbridge_getExtraSize == 0x68). init/SeqFn here, dll_199/19A
 * variants in dimmagicbridge.c use their own layout.
 */

STATIC_ASSERT(sizeof(DimMagicBridgeState) == 0x68);

STATIC_ASSERT(sizeof(ExplosionPartfxSource) == 0x38);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, rootMotionScale) == 0x08);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, localPosX) == 0x0C);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, worldPosX) == 0x18);
STATIC_ASSERT(offsetof(ExplosionPartfxSource, velocityX) == 0x24);

/*
 * Per-object extra state for the explosion effect
 * (explosion_getExtraSize == 0xA60). The flame pool (50 x 0x30 records)
 * and the debris pool (6 x 0x24 at 0x964) are walked with raw stride
 * pointers in update/render and stay untyped.
 */

STATIC_ASSERT(sizeof(ExplosionState) == 0xA60);
STATIC_ASSERT(offsetof(ExplosionState, driftYSpeed) == 0xA3C);

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* DIM2PathGenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

#define DLL1D6_OBJFLAG_HITDETECT_DISABLED 0x2000

FbWGPipe GXWGFifo : (0xCC008000);

int dll_1D6_getExtraSize(void)
{
    return 0x20;
}

int dll_1D6_getObjectTypeId(void)
{
    return 0x0;
}

void dll_1D6_free(int* obj)
{
    Dll1D6State* state = ((GameObject*)obj)->extra;
    if ((state->flags1D & 4) != 0)
    {
        state->flags1D = (u8)(state->flags1D & ~4);
    }
    mm_free(state->bufA);
    mm_free(state->bufB);
    (gDll1D6SlotInUse)[state->slot] = 0;
}

void dll_1D6_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

void dll_1D6_hitDetect(void)
{
}

static inline ObjModel* DIM2snowball_GetActiveModel(GameObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (ObjModel*)objAnim->banks[objAnim->bankIndex];
}

void dll_1D6_update(int* obj)
{
    Dll1D6State* extra;
    int* def;
    ObjModel* model;
    ObjTextureRuntimeSlot* tex;
    GameObject* player;
    f32 mtx[20];
    s16 ang[6];
    f32 lx, ly, lz;

    def = *(int**)&((GameObject*)obj)->anim.placementData;
    extra = ((GameObject*)obj)->extra;

    if ((extra->flags1D & 1) != 0)
    {
        if ((extra->flags1D & 4) == 0)
        {
            extra->flags1D |= 4;
            extra->bobPhase = (f32)(int)randomGetRange(20, 40);
            extra->bobRate = (f32)(int)randomGetRange(6, 10) / 20.0f;
        }
        extra->downTimer -= framesThisStep;
        extra->dizzyTimer = extra->dizzyTimer - framesThisStep;
        if (extra->dizzyTimer <= 0)
        {
            Sfx_PlayFromObject((u32)obj, SFXTRIG_en_trpopn_c_9f);
        }
        if (extra->downTimer <= 0)
        {
            model = DIM2snowball_GetActiveModel((GameObject*)(obj));
            ObjModel_SetBlendChannelTargets(model, 0, -1, 0, 0.1f, 16);
            extra->upTimer = ((Dll1D6Placement*)def)->upTimer;
            if (extra->upTimer < 15)
            {
                extra->upTimer = 15;
            }
            extra->flags1D &= ~1;
            Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_boar1_c_1f6);
        }
    }
    else
    {
        void* p28;
        model = DIM2snowball_GetActiveModel((GameObject*)(obj));
        p28 = *(void**)((char*)model + 0x28);
        if (p28 != NULL && (extra->flags1D & 4) != 0)
        {
            if (*(f32*)p28 >= 1.0f)
            {
                extra->flags1D &= ~4;
            }
        }
        extra->upTimer -= framesThisStep;
        if (extra->upTimer <= 0)
        {
            ObjModel_SetBlendChannelTargets(model, 0, -1, 0, -0.1f, 16);
            extra->downTimer = ((Dll1D6Placement*)def)->downTimer;
            if (extra->downTimer < 15)
            {
                extra->downTimer = 15;
            }
            extra->flags1D |= 1;
            Sfx_PlayFromObject((u32)obj, SFXTRIG_dn_boar1_c_1f7);
            extra->dizzyTimer = 20;
        }
    }
    tex = objFindTexture((GameObject*)(obj), 0, 0);
    {
        s16 t = -tex->offsetT;
        int v = t + 256;
        if ((s16)v > 2048)
        {
            v = v - 2048;
        }
        tex->offsetT = -v;
    }
    tex = objFindTexture((GameObject*)(obj), 1, 0);
    {
        s16 t = -tex->offsetT;
        int v = t + 160;
        if ((s16)v > 2048)
        {
            v = v - 2048;
        }
        tex->offsetT = -v;
    }
    player = Obj_GetPlayerObject();
    mtx[0] = -((GameObject*)obj)->anim.localPosX;
    mtx[1] = -((GameObject*)obj)->anim.localPosY;
    mtx[2] = -((GameObject*)obj)->anim.localPosZ;
    ang[0] = -((GameObject*)obj)->anim.rotX;
    ang[1] = 0;
    ang[2] = 0;
    mtxRotateByVec3s(&mtx[3], ang);
    Matrix_TransformPoint(&mtx[3], player->anim.localPosX, player->anim.localPosY, player->anim.localPosZ, &lx, &ly,
                          &lz);
    if ((extra->flags1D & 2) != 0)
    {
        ly = ((GameObject*)obj)->anim.localPosY - player->anim.localPosY;
        if (ly < 0.0f)
        {
            ly = -ly;
        }
        if (ly < 50.0f)
        {
            lz = lz * lz;
            if (lz <= extra->hitRangeSqA)
            {
                int* row;
                f32 lim;
                model = DIM2snowball_GetActiveModel((GameObject*)(obj));
                {
                    char* mrow = (char*)model + 4;
                    row = *(int**)(mrow + ((*(u16*)((char*)model + 0x18) >> 1) & 1) * 4);
                }
                lim = ((GameObject*)obj)->anim.rootMotionScale * (f32)(int)*(s16*)((char*)row + extra->hitRow * 16);
                if (lx <= lim)
                {
                    ObjHits_RecordObjectHit((int)player, (int)obj, 11, 4, 0);
                }
            }
        }
    }
    if ((extra->flags1D & 4) != 0)
    {
        extra->bobPhase = extra->bobRate * timeDelta + extra->bobPhase;
        if (extra->bobPhase > 40.0f)
        {
            extra->bobRate = -(f32)(int)randomGetRange(6, 10) / 20.0f;
            extra->bobPhase = 40.0f;
        }
        else if (extra->bobPhase < 20.0f)
        {
            extra->bobRate = (f32)(int)randomGetRange(6, 10) / 20.0f;
            extra->bobPhase = 20.0f;
        }
    }
    if (mainGetBit(496) != 0)
    {
        extra->flags1D |= 2;
    }
    else
    {
        extra->flags1D &= ~2;
    }
}

void dll_1D6_init(int* obj, u8* paramsBytes)
{
    Dll1D6Placement* params = (Dll1D6Placement*)paramsBytes;
    Dll1D6State* extra;
    ObjModel* model;
    int i;

    ((GameObject*)obj)->anim.rotX = (s16)(params->rotXParam << 8);
    extra = ((GameObject*)obj)->extra;
    model = DIM2snowball_GetActiveModel((GameObject*)(obj));
    ObjModel_SetBlendChannelTargets(model, 0, -1, 0, 0.0f, 0);
    ObjModel_SetBlendChannelWeight(model, 0, 1.0f);
    extra->upTimer = params->upTimer;
    if (extra->upTimer < 15)
    {
        extra->upTimer = 15;
    }
    extra->downTimer = params->downTimer;
    if (extra->downTimer < 15)
    {
        extra->downTimer = 15;
    }
    {
        f32 k = 0.0f;
        extra->hitRangeSqA = k * ((GameObject*)obj)->anim.rootMotionScale;
        extra->hitRangeSqA = extra->hitRangeSqA * extra->hitRangeSqA;
        extra->hitRangeSqB = k * ((GameObject*)obj)->anim.rootMotionScale;
        extra->hitRangeSqB = extra->hitRangeSqB * extra->hitRangeSqB;
    }
    extra->flags1D = mainGetBit(496) ? 2 : 0;
    for (i = 0; i < 4; i++)
    {
        if ((gDll1D6SlotInUse)[i] == 0)
        {
            (gDll1D6SlotInUse)[i] = 1;
            extra->slot = i;
            i = 4;
        }
    }
    extra->bufA = mmAlloc(40, 18, 0);
    getTabEntry(extra->bufA, MLDF_FILEID_LACTIONS_BIN, (gDll1D6SlotTabIndex)[extra->slot] * 40, 40);
    extra->bufB = mmAlloc(40, 18, 0);
    getTabEntry(extra->bufB, MLDF_FILEID_LACTIONS_BIN, ((gDll1D6SlotTabIndex)[extra->slot] + 1) * 40, 40);
    ((GameObject*)obj)->objectFlags |= DLL1D6_OBJFLAG_HITDETECT_DISABLED;
}

void dll_1D6_release(void)
{
}

void dll_1D6_initialise(void)
{
}

ObjectDescriptor dll_1D6 = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_1D6_initialise,
    (ObjectDescriptorCallback)dll_1D6_release,
    0,
    (ObjectDescriptorCallback)dll_1D6_init,
    (ObjectDescriptorCallback)dll_1D6_update,
    (ObjectDescriptorCallback)dll_1D6_hitDetect,
    (ObjectDescriptorCallback)dll_1D6_render,
    (ObjectDescriptorCallback)dll_1D6_free,
    (ObjectDescriptorCallback)dll_1D6_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)dll_1D6_getExtraSize,
};

const f32 lbl_803E4AA0 = 1.0f;
const f32 lbl_803E4AA4 = 0.9f;
const f32 lbl_803E4AA8 = -0.1f;
const f32 lbl_803E4AAC = 0.05f;
const f32 lbl_803E4AB0 = 0.98f;
const f32 lbl_803E4AB4 = 0.1f;
const f32 lbl_803E4AB8 = 36.0f;
const f32 lbl_803E4ABC = 0.75f;
const f32 lbl_803E4AC0[2] = {2.1f, 0.0f};
const f32 lbl_803E4AC8 = 2.859375f;
const f32 lbl_803E4AD0 = 0.0f;
const f32 lbl_803E4AD8 = 1.0f;
const f32 lbl_803E4ADC = 0.5f;
const f32 lbl_803E4AE0 = 0.85f;
const f32 lbl_803E4AE4 = 0.9f;
const f32 lbl_803E4AE8 = 0.1f;
const f32 lbl_803E4AEC = -0.1f;
const f32 lbl_803E4AF0 = 0.0f;
const f32 lbl_803E4AF4 = 6.5f;
const f32 lbl_803E4AF8 = 2.0f;
const f32 lbl_803E4AFC = 0.8f;
const f32 lbl_803E4B00 = 0.2f;
const f32 lbl_803E4B04 = 5.0f;
