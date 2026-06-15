#include "main/dll/dimmagicbridge_state.h"
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
#include "main/objseq.h"

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
 * pointers in update/render and stay untyped. REFERENCE-ONLY for now:
 * every consumer keeps raw derefs - retyping the state local (or adding
 * (int) casts) flips saved-reg coloring in init/update/render/fn_801B3DE4
 * (recipe #36/#77); the layout is documented here for a future pass.
 */

STATIC_ASSERT(sizeof(ExplosionState) == 0xA60);
STATIC_ASSERT(offsetof(ExplosionState, driftYSpeed) == 0xA3C);

extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);

/* dimwooddoor2 variant: trigger-init that loads a different float into the
 * extra block's [4]. Body shape matches FUN_801b5b00 but uses lbl_803E49F0. */

/* dimmagicbridge_update: advance texture phase and bridge vertex wave, then
 * either fire the death VFX (fn_80065574(0x11, 0, 0)) when sub->_5f is set or,
 * when GameBit 0x1ef is on and the player's emission controller is lingering,
 * latch GameBit 0x1e8. */

/* dimwooddoor2 variant: trigger-init writing extra block [4]=[8]=lbl_803E49D4
 * and using mask 0x6000 + initial state byte 3 at +0. */

/* dimmagicbridge_scrollTextureChannels: scroll two material channels and keep
 * the bridge wave phases in sub[0x60]/sub[0x62] moving with framesThisStep. */
extern u8 framesThisStep;

/* dimmagicbridge_flameSeqFn: tick the spawn timer, allocate a free flame slot
 * every 16 frames, and ramp each active slot's alpha toward full; then update
 * the animated bridge mesh. */

extern f32 timeDelta;

volatile FbWGPipe GXWGFifo : (0xCC008000);

/* segment pragma-stack balance (re-split): */

#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"

typedef struct Dim2snowballObjectDef
{
    u8 pad0[0x14 - 0x0];
    s32 targetId;
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
} Dim2snowballObjectDef;

STATIC_ASSERT(sizeof(Dim2ConveyorState) == 0x14);

STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

STATIC_ASSERT(sizeof(TruthHornIceState) == 0x8);

STATIC_ASSERT(sizeof(Dim2SnowballState) == 0xb0);

/* dim2pathgenerator_getExtraSize == 0x9a8 (incl. three 200-entry curve
 * tables filled by the RomCurve interface). */

STATIC_ASSERT(sizeof(Dim2PathGeneratorState) == 0x9a8);

extern undefined4 FUN_800067c0();
extern f32 lbl_803E4AA0;
extern int ObjList_FindObjectById(int id);
extern int** ObjList_GetObjects(int* startOut, int* countOut);
extern void objMove(int* obj, f32 dx, f32 dy, f32 dz);
extern int objBboxFn_800640cc(void* a, void* b, f32 c, int d, int e, int* f, int g, int h, int i, int j);
extern int getAngle(f32 a, f32 b);
extern int hitDetectFn_80065e50(int* obj, f32 x, f32 y, f32 z, int*** listOut, int p3, int p4);
extern void Sfx_KeepAliveLoopedObjectSound(int* obj, int sfx);
extern f32 oneOverTimeDelta;
extern f32 lbl_803E4AA4;
extern f32 lbl_803E4AA8;
extern f32 lbl_803E4AAC;
extern f32 lbl_803E4AB0;
extern f32 lbl_803E4AB4;
extern f32 lbl_803E4AB8;
extern f32 lbl_803E4ABC;
extern f32 lbl_803E4AC0;
extern f64 lbl_803E4AC8;
extern f32 lbl_803E4AD0;

static inline int* DIM2snowball_GetActiveModel(void* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    return (int*)objAnim->banks[objAnim->bankIndex];
}

#pragma scheduling on
#pragma peephole on
void FUN_801b7314(int param_1, undefined4 param_2, float* param_3, float* param_4)
{
    uint uVar1;
    int iVar2;
    float* pfVar3;

    pfVar3 = ((GameObject*)param_1)->extra;
    if (pfVar3[4] == 0.0)
    {
        FUN_800067c0((int*)0xdf, 1);
    }
    pfVar3[4] = 2.8026e-44;
    iVar2 = *(int*)(*(int*)&((GameObject*)param_1)->anim.placementData + 0x14);
    if (iVar2 == 0x49b23)
    {
        uVar1 = GameBit_Get(0xc5c);
        if ((uVar1 != 0) && (uVar1 = GameBit_Get(0xc5b), uVar1 == 0))
        {
            *param_3 = *pfVar3;
            *param_4 = pfVar3[1];
        }
        uVar1 = GameBit_Get(0xc5b);
        if ((uVar1 != 0) && (uVar1 = GameBit_Get(0xc5c), uVar1 == 0))
        {
            *param_3 = -*pfVar3;
            *param_4 = -pfVar3[1];
        }
        uVar1 = GameBit_Get(0xc5b);
        if (uVar1 != 0)
        {
            GameBit_Set(0xc5c, 0);
        }
        uVar1 = GameBit_Get(0xc5b);
        if (uVar1 == 0)
        {
            GameBit_Set(0xc5c, 1);
        }
    }
    else if ((iVar2 < 0x49b23) && (iVar2 == 0x1ea9))
    {
        *param_3 = *pfVar3;
        *param_4 = pfVar3[1];
    }
    else
    {
        *param_3 = *pfVar3;
        *param_4 = pfVar3[1];
    }
    return;
}

void dll_1CF_free(void);

#pragma scheduling off
#pragma peephole off
void dim2snowball_free(void)
{
}

void dim2snowball_hitDetect(void)
{
}

void dim2snowball_release(void)
{
}

void dim2snowball_initialise(void)
{
}

void dim2pathgenerator_free(void);

int dim2snowball_getExtraSize(void) { return 0xb0; }
int dim2snowball_getObjectTypeId(void) { return 0x0; }
int dim2pathgenerator_getExtraSize(void);

void dim2snowball_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(f32);
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E4AA0);
}

/* fn_801B6D40 (EN v1.0 0x801B6D40, size 44): subtract v from state[2] byte,
 * return 1 if the signed result dropped to or below 0. */

void dim2snowball_init(int* obj, int* def)
{
    Dim2SnowballState* state = ((GameObject*)obj)->extra;
    state->targetId = ((Dim2snowballObjectDef*)def)->targetId;
    state->flagsAC = (u8)(state->flagsAC | 4);
    ((Dim2snowballObjectDef*)def)->targetId = -1;
    *(s16*)obj = (s16)((s32)((Dim2snowballObjectDef*)def)->unk18 << 8);
    *(s8*)&((GameObject*)obj)->anim.alpha = 0;
    {
        ObjModelState* p = ((GameObject*)obj)->anim.modelState;
        if (p != NULL)
        {
            p->flags |= 0xA10;
        }
    }
    state->targetObj = (int*)ObjList_FindObjectById(state->targetId);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
}

void dll_1CF_init(int* obj, int* def);

void dim2snowball_update(int* obj)
{
    extern void Obj_FreeObject(int* obj);
    extern int Sfx_PlayFromObject(int obj, int sfxId);
    int* extra = ((GameObject*)obj)->extra;
    int** results;
    int count;
    int start;
    f32 evt[6];
    f32 k;

    if ((((Dim2SnowballState*)extra)->flagsAC & 4) != 0)
    {
        int v = ((GameObject*)obj)->anim.alpha + framesThisStep * 2;
        if (v > 255)
        {
            v = 255;
            ((Dim2SnowballState*)extra)->flagsAC &= ~4;
        }
        ((GameObject*)obj)->anim.alpha = v;
    }
    else if ((((Dim2SnowballState*)extra)->flagsAC & 8) != 0)
    {
        int v = ((GameObject*)obj)->anim.alpha - framesThisStep * 2;
        if (v < 0)
        {
            v = 0;
            ((Dim2SnowballState*)extra)->flagsAC &= ~8;
        }
        ((GameObject*)obj)->anim.alpha = v;
    }

    if ((((Dim2SnowballState*)extra)->flagsAC & 1) == 0)
    {
        int* cobj = ((Dim2SnowballState*)extra)->targetObj;
        ((Dim2SnowballState*)extra)->curve.count =
            (*(int (**)(int*, void*, void*, void*, void*))(**(int**)((char*)cobj + 0x68) + 0x20))(
                cobj, (char*)extra + 0x84, (char*)extra + 0x88, (char*)extra + 0x8c, (char*)extra + 0xa8);
        ((Dim2SnowballState*)extra)->curve.dir = 0;
        ((Dim2SnowballState*)extra)->curve.eval = Curve_EvalHermite;
        ((Dim2SnowballState*)extra)->curve.coeffFn = Curve_BuildHermiteCoeffs;
        curvesMove(&((Dim2SnowballState*)extra)->curve);
        ((Dim2SnowballState*)extra)->flagsAC |= 1;
    }

    if ((((Dim2SnowballState*)extra)->flagsAC & 2) != 0)
    {
        if (((GameObject*)obj)->anim.localPosY < ((Dim2SnowballState*)extra)->floorY)
        {
            ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (k = lbl_803E4AA4);
            ((GameObject*)obj)->anim.velocityY = lbl_803E4AA8;
            ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * k;
            if ((((Dim2SnowballState*)extra)->flagsAC & 0x10) == 0)
            {
                int** list;
                int* hit;
                ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (k = lbl_803E4AAC);
                ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * k;
                ((Dim2SnowballState*)extra)->flagsAC |= 0x18;
                list = ObjList_GetObjects(&start, &count);
                for (; start < count; start++)
                {
                    if (*(s16*)((char*)list[start] + 0x46) == 214)
                    {
                        hit = list[start];
                        goto checkHit;
                    }
                }
                hit = NULL;
            checkHit:
                if (hit != NULL)
                {
                    (*(void (**)(int*))(**(int**)&((GameObject*)hit)->anim.dll + 0x20))(hit);
                }
                Sfx_PlayFromObject((int)obj, SFXfoot_run_jingle1);
            }
            evt[3] = ((GameObject*)obj)->anim.localPosX;
            evt[4] = ((GameObject*)obj)->anim.localPosY;
            evt[5] = ((GameObject*)obj)->anim.localPosZ;
            (*gPartfxInterface)->spawnObject(obj, 518, evt, 4, -1, NULL);
            if (((GameObject*)obj)->anim.alpha == 0)
            {
                Obj_FreeObject(obj);
                return;
            }
            objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta,
                    ((GameObject*)obj)->anim.velocityY * timeDelta,
                    ((GameObject*)obj)->anim.velocityZ * timeDelta);
        }
        else
        {
            int bbox;
            ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (k = lbl_803E4AB0);
            ((GameObject*)obj)->anim.velocityY =
                ((GameObject*)obj)->anim.velocityY - lbl_803E4AB4 * timeDelta;
            ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * k;
            objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta,
                    ((GameObject*)obj)->anim.velocityY * timeDelta,
                    ((GameObject*)obj)->anim.velocityZ * timeDelta);
            bbox = objBboxFn_800640cc((char*)obj + 0x80, (char*)obj + 0xc, lbl_803E4AB8, 0, 0,
                                      obj, 8, -1, 0, 0);
            if (bbox != 0)
            {
                ((GameObject*)obj)->anim.velocityX = -((GameObject*)obj)->anim.velocityX;
                ((GameObject*)obj)->anim.velocityZ = -((GameObject*)obj)->anim.velocityZ;
                ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (k = lbl_803E4ABC);
                ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * k;
            }
        }
    }
    else
    {
        int done = Curve_AdvanceAlongPath(&((Dim2SnowballState*)extra)->curve, lbl_803E4AC0);
        ((GameObject*)obj)->anim.localPosX = ((Dim2SnowballState*)extra)->curve.sample[0];
        ((GameObject*)obj)->anim.localPosY = (f32)(lbl_803E4AC8 + ((Dim2SnowballState*)extra)->curve.sample[1]);
        ((GameObject*)obj)->anim.localPosZ = ((Dim2SnowballState*)extra)->curve.sample[2];
        *(s16*)obj = getAngle(((Dim2SnowballState*)extra)->curve.tangent[0], ((Dim2SnowballState*)extra)->curve.tangent[2]);
        ((GameObject*)obj)->anim.rotY = ((GameObject*)obj)->anim.rotY + framesThisStep * 800;
        ((GameObject*)obj)->anim.velocityX =
            oneOverTimeDelta * (((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX);
        ((GameObject*)obj)->anim.velocityY = lbl_803E4AD0;
        ((GameObject*)obj)->anim.velocityZ =
            oneOverTimeDelta * (((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ);
        if (done != 0)
        {
            Obj_FreeObject(obj);
            return;
        }
        if (*(u8*)((char*)*(int**)&((Dim2SnowballState*)extra)->curveData + (((Dim2SnowballState*)extra)->curve.idx >>
            2)) == 32)
        {
            if (GameBit_Get(648) != 0)
            {
                int n;
                ((Dim2SnowballState*)extra)->flagsAC |= 2;
                n = hitDetectFn_80065e50(obj, ((GameObject*)obj)->anim.localPosX,
                                         ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ,
                                         &results, 0, 0);
                ((Dim2SnowballState*)extra)->floorY = ((GameObject*)obj)->anim.localPosY;
                while (n > 0)
                {
                    int* r;
                    n--;
                    r = results[n];
                    if (*(f32*)r < ((GameObject*)obj)->anim.localPosY)
                    {
                        s8 t = *(s8*)((char*)r + 0x14);
                        if (t == 26 || t == 8)
                        {
                            ((Dim2SnowballState*)extra)->floorY = *(f32*)r;
                            n = 0;
                        }
                    }
                }
                ((GameObject*)obj)->anim.velocityX = ((GameObject*)obj)->anim.velocityX * (k = lbl_803E4ABC);
                ((GameObject*)obj)->anim.velocityZ = ((GameObject*)obj)->anim.velocityZ * k;
            }
        }
    }

    if (((GameObject*)obj)->anim.alpha == 255)
    {
        int* m = *(int**)&((GameObject*)obj)->anim.hitReactState;
        if (m != NULL)
        {
            ((ObjHitsPriorityState*)m)->flags |= 1;
            *(u8*)&((ObjHitsPriorityState*)m)->hitVolumePriority = 4;
            *(u8*)&((ObjHitsPriorityState*)m)->hitVolumeId = 2;
            *(int*)&((ObjHitsPriorityState*)m)->objectHitMask = 16;
            *(int*)&((ObjHitsPriorityState*)m)->skeletonHitMask = 16;
        }
    }
    Sfx_KeepAliveLoopedObjectSound(obj, 1171);
}
