/* DLL 0x019B - torch / fire-effect objects [801CBA98-801CBD88) */
#include "main/dll/dll_019B_dll19b.h"
#include "main/dll/dll_019C_dll19c.h"
#include "main/dll/dll_019D_dll19d.h"
#include "main/dll/dll_019E_dim_tricky.h"
#include "main/dll/dll_019F_nwtreebrid.h"
#include "main/dll/dll_01A0_nwgeyser.h"
#include "main/frame_timing.h"
#include "main/vecmath_distance_api.h"
#include "main/object_render_legacy.h"
#include "main/debug.h"
#define RENDER_ENVFX_DIRECT_INT_CALL
#include "main/render_envfx_api.h"
#undef RENDER_ENVFX_DIRECT_INT_CALL
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "main/obj_group.h"
#include "main/obj_message.h"
#include "main/object_api.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/modgfx_interface.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "main/gamebits.h"
#include "main/gamebit_ids.h"

#define ObjMsg_PopLegacy(obj, msg, param, flags) \
    ((int (*)())ObjMsg_Pop)((obj), (msg), (param), (flags))
#define ObjGroup_FindNearestObjectLegacy(group, from, distance) \
    ((int (*)())ObjGroup_FindNearestObject)((group), (from), (distance))

#define DLL19B_TARGET_OBJGROUP 0xe

/* env effects driven by anim events; ENVFX_B is the default when no override id set */
#define DLL19B_ENVFX_A 0xc3
#define DLL19B_ENVFX_B 0x14

extern void* return0_8005669C(int);
extern int lbl_803DB610;
void* lbl_803DDBE0;
extern f32 lbl_803E5188;
extern f32 lbl_803E518C;
extern f32 lbl_803E5190;
extern f32 lbl_803E5194;
extern f32 lbl_803E5198;
extern f32 lbl_803E519C;
extern f32 lbl_803E51A0;

/* Romlist placement for the 0x19B torch object. The standard ObjPlacement
 * header occupies 0x00..0x18; this class stores a packed activation-distance
 * value at 0x1A (the high byte >> 8 seeds Dll19BState.activationDist). */
typedef struct Dll19BPlacement
{
    u8 pad0[0x1A - 0x00];
    s16 activationDistPacked; /* 0x1A */
} Dll19BPlacement;

STATIC_ASSERT(offsetof(Dll19BPlacement, activationDistPacked) == 0x1A);

int dll_19B_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern int* gTitleMenuControlInterface;

    int state;
    int i;

    state = *(int*)&((GameObject*)obj)->extra;
    animUpdate->hitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;

    if (((Dll19BState*)state)->brightnessBVel != 0)
    {
        ((Dll19BState*)state)->brightnessB += ((Dll19BState*)state)->brightnessBVel;
        if (((Dll19BState*)state)->brightnessB <= 1 && ((Dll19BState*)state)->brightnessBVel <= 0)
        {
            ((Dll19BState*)state)->brightnessB = 1;
            ((Dll19BState*)state)->brightnessBVel = 0;
        }
        else if (((Dll19BState*)state)->brightnessB >= 0x46 && ((Dll19BState*)state)->brightnessBVel >= 0)
        {
            ((Dll19BState*)state)->brightnessB = 0x46;
            ((Dll19BState*)state)->brightnessBVel = 0;
        }
        ((void (**)(int, u8))*gTitleMenuControlInterface)[0x38 / 4](3, (u8)((Dll19BState*)state)->brightnessB);
    }

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 cmd = animUpdate->eventIds[i];
        if (cmd != 0)
        {
            switch (cmd)
            {
            case 1:
                getEnvfxAct(obj, obj, DLL19B_ENVFX_A, 0);
                break;
            case 2:
                if (lbl_803DB610 == -1)
                {
                    getEnvfxAct(obj, obj, DLL19B_ENVFX_B, 0);
                }
                else
                {
                    getEnvfxAct(obj, obj, lbl_803DB610 & 0xffff, 0);
                }
                break;
            case 3:
                ((Dll19BState*)state)->pendingEvent = 1;
                break;
            case 4:
                ((Dll19BState*)state)->phase = 4;
                ((Dll19BState*)state)->pendingEvent = 2;
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
                mainSetBits(0x1d2, 0);
                mainSetBits(0x126, 1);
                ((Dll19BState*)state)->brightnessBVel = -3;
                break;
            case 5:
                ((Dll19BState*)state)->phase = 6;
                ((Dll19BState*)state)->pendingEvent = 3;
                ((Dll19BState*)state)->brightnessBVel = -3;
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
                break;
            case 6:
                mainSetBits(0x1d2, 1);
                break;
            case 7:
                mainSetBits(0x1d2, 0);
                ((Dll19BState*)state)->brightnessBVel = -3;
                break;
            case 9:
                mainSetBits(0x128, 1);
                if (lbl_803DDBE0 == NULL)
                {
                    lbl_803DDBE0 = return0_8005669C(1);
                }
                break;
            case 8:
                mainSetBits(0x127, 1);
                break;
            case 0xb:
                ((Dll19BState*)state)->brightnessB = 100;
                ((void (**)(int, int, int, u8, int))*gTitleMenuControlInterface)[0x18 / 4](
                    3, 0x2d, 0x50, (u8)((Dll19BState*)state)->brightnessB, 0);
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}

int dll_19B_getExtraSize(void)
{
    return 0x18;
}
int dll_19B_getObjectTypeId(void)
{
    return 0x0;
}

void dll_19B_free(int* obj)
{
    (*gModgfxInterface)->detachSource(obj);
}

void dll_19B_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E5188);
}

void dll_19B_hitDetect(void)
{
}

char sShrineTimeFormat[] = "time %d\n";

void dll_19B_update(int obj)
{
    extern void* gTitleMenuControlInterface;

    Dll19BState* st;
    int player;
    int near;
    Dll19BState* st2;
    int v;
    f32 dy;
    f32 dist;
    int unk16;
    int msg;
    int unk8;

    st = ((GameObject*)obj)->extra;
    player = (int)Obj_GetPlayerObject();
    dist = lbl_803E518C;
    st2 = ((GameObject*)obj)->extra;
    unk16 = 0;
    while (ObjMsg_PopLegacy(obj, &msg, &unk8, &unk16) != 0)
    {
        switch (msg)
        {
        case 0x30005:
            st2->brightnessAVel = -3;
            break;
        case 0x30006:
            st2->brightnessAVel = 0x10;
            break;
        }
    }
    mainSetBits(0x127, 1);
    if ((v = st->brightnessAVel) != 0)
    {
        st->brightnessA += (s16)v;
        if (st->brightnessA <= 12)
        {
            st->brightnessA = 12;
            st->brightnessAVel = 0;
        }
        else if (st->brightnessA >= 70)
        {
            st->brightnessA = 70;
            st->brightnessAVel = 0;
        }
        (*(void (**)(int, int))(*(int*)gTitleMenuControlInterface + 0x38))(2, st->brightnessA & 0xff);
    }
    if ((v = st->brightnessBVel) != 0)
    {
        st->brightnessB += (s16)v;
        if (st->brightnessB <= 1 && st->brightnessBVel <= 0)
        {
            st->brightnessB = 1;
            st->brightnessBVel = 0;
        }
        else if (st->brightnessB >= 70 && st->brightnessBVel >= 0)
        {
            st->brightnessB = 70;
            st->brightnessBVel = 0;
        }
        (*(void (**)(int, int))(*(int*)gTitleMenuControlInterface + 0x38))(3, st->brightnessB & 0xff);
    }
    if (st->timer > 0)
    {
        st->timer -= framesThisStep;
        if (st->timer <= 0)
        {
            st->timer = 0;
            if (st->displayedFlag == 0)
            {
                (*(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(3, 0x2c, 0x50,
                                                                                                  st->brightnessB, 0);
                st->displayedFlag = 1;
            }
        }
    }
    else
    {
        near = ObjGroup_FindNearestObjectLegacy(DLL19B_TARGET_OBJGROUP, player, &dist);
        if ((u32)near != 0 && dist < lbl_803E5190 && dist > lbl_803E5194)
        {
            dy = ((GameObject*)near)->anim.localPosZ - ((GameObject*)player)->anim.localPosZ;
            if (dy <= lbl_803E5198)
            {
                if (dy < lbl_803E5198)
                {
                    dy = dy * lbl_803E519C;
                }
                if (st->brightnessB != 30)
                {
                    st->brightnessB = 30;
                }
                v = (int)((f32)st->brightnessB * ((dy - lbl_803E5194) / lbl_803E51A0));
                if ((s16)v < 1)
                {
                    v = 1;
                }
                (*(void (**)(int, int))(*(int*)gTitleMenuControlInterface + 0x38))(3, v & 0xff);
                v = (int)((f32)st->brightnessA * ((lbl_803E51A0 - (dy - lbl_803E5194)) / *(f32*)&lbl_803E51A0));
                if ((s16)v < 1)
                {
                    v = 1;
                }
                (*(void (**)(int, int))(*(int*)gTitleMenuControlInterface + 0x38))(2, v & 0xff);
            }
        }
        switch (st->phase)
        {
        case DLL19B_PHASE_IDLE:
            if (Vec_distance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) < st->activationDist)
            {
                st->phase = DLL19B_PHASE_WAIT_EVENT;
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 0);
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                {
                    void* handle = Resource_Acquire(0x83, 1);
                    (*(s16(**)(int, int, int, int, int, int))(*(int*)handle + 4))(obj, 1, 0, 1, -1, 0);
                    Resource_Release(handle);
                }
                {
                    void* handle = Resource_Acquire(0x84, 1);
                    (*(s16(**)(int, int, int, int, int, int))(*(int*)handle + 4))(obj, 0, 0, 1, -1, 0);
                    Resource_Release(handle);
                }
                mainSetBits(0x126, 0);
                (*gModgfxInterface)->releaseHandle(&st->gfxHandle);
            }
            break;
        case DLL19B_PHASE_WAIT_EVENT:
            if (st->pendingEvent == 1)
            {
                st->phase = DLL19B_PHASE_COUNTDOWN;
                st->timer = 160;
            }
            break;
        case DLL19B_PHASE_COUNTDOWN:
            if (st->unlockCount == 0 && mainGetBit(GAMEBIT_WM_KrazTest1TorchesActive) == 0)
            {
                mainSetBits(GAMEBIT_WM_KrazTest1TorchesActive, 1);
            }
            if ((u32)mainGetBit(0x1d8) != 0)
            {
                st->unlockCount += 1;
                mainSetBits(0x1d8, 0);
            }
            st->countdown -= (s16)timeDelta;
            logPrintf(sShrineTimeFormat, st->countdown);
            if (st->countdown <= 0)
            {
                mainSetBits(0x1d4, 1);
                (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
                st->timer = 10;
                st->phase = DLL19B_PHASE_RESET;
                (*(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(
                    3, 0x35, 0x50, st->brightnessB & 0xff, 0);
                st->brightnessBVel = 1;
                mainSetBits(GAMEBIT_WM_KrazTest1TorchesActive, 0);
            }
            else if (st->unlockCount == 1)
            {
                st->phase = DLL19B_PHASE_RESOLVE;
                st->timer = 200;
                st->brightnessBVel = -3;
            }
            break;
        case DLL19B_PHASE_RESOLVE:
            if ((u32)mainGetBit(0x1d1) != 0)
            {
                st->brightnessB = 1;
                (*(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(
                    3, 0x2c, 0x50, st->brightnessB & 0xff, 0);
                st->brightnessBVel = 1;
                mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
                st->phase = DLL19B_PHASE_DONE;
            }
            else
            {
                playerCancelSpell((GameObject*)player, -1);
                mainSetBits(0x126, 0);
                (*(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(
                    3, 0x2a, 0x50, st->brightnessB & 0xff, 0);
                st->brightnessBVel = 1;
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                st->phase = DLL19B_PHASE_COMPLETE;
            }
            break;
        case DLL19B_PHASE_COMPLETE:
            if ((u32)mainGetBit(0xfd) == 0)
            {
                mainSetBits(0xfd, 1);
            }
            mainSetBits(0x1d2, 0);
            mainSetBits(0x127, 0);
            st->phase = DLL19B_PHASE_DONE;
            (*(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(
                3, 0x2c, 0x50, st->brightnessB & 0xff, 0);
            break;
        case DLL19B_PHASE_RESET:
            st->phase = DLL19B_PHASE_IDLE;
            st->pendingEvent = 0;
            st->timer = 400;
            mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
            mainSetBits(0x126, 1);
            mainSetBits(0x127, 1);
            {
                void* handle = Resource_Acquire(0x6a, 1);
                st->gfxHandle =
                    (*(s16(**)(int, int, int, int, int, int))(*(int*)handle + 4))(obj, 2, 0, 0x402, -1, 0);
                Resource_Release(handle);
            }
            mainSetBits(0x1d8, 0);
            st->unlockCount = 0;
            st->countdown = 4000;
            mainSetBits(0x1d4, 0);
            break;
        }
    }
}

void dll_19B_init(GameObject* obj, u8* params)
{
    extern void* gTitleMenuControlInterface;

    register Dll19BState* sub;
    void* res;

    sub = obj->extra;
    obj->anim.rotX = 0;
    sub->activationDist = 0xa;
    if (((Dll19BPlacement*)params)->activationDistPacked > 0)
    {
        sub->activationDist = (s16)(((Dll19BPlacement*)params)->activationDistPacked >> 8);
    }
    sub->phase = 0;
    sub->pendingEvent = 0;
    sub->timer = 0;
    sub->unlockCount = 0;
    obj->animEventCallback = dll_19B_SeqFn;
    ObjMsg_AllocQueue(obj, 4);
    mainSetBits(GAMEBIT_WM_EnteredKrazoaTest1_0129, 1);
    mainSetBits(0x1d2, 0);
    mainSetBits(0x126, 1);
    mainSetBits(0x127, 1);
    mainSetBits(GAMEBIT_STAFF_ABILITY_FIRE_BLASTER, 1);
    mainSetBits(GAMEBIT_STAFF_ABILITY_SHARPCLAW_DISGUISE, 1);
    mainSetBits(GAMEBIT_ITEM_DeletedSpell1D7, 1);
    mainSetBits(0x1d8, 0);
    sub->brightnessA = 0xc;
    sub->brightnessB = 0x1e;
    sub->timer = 0xc8;
    ((void (*)(int, int, int, int, int))((void**)*(void**)gTitleMenuControlInterface)[6])(2, 0x2b, 0x50, 1, 0);
    sub->brightnessAVel = 0;
    sub->brightnessBVel = 0;
    sub->displayedFlag = 0;
    sub->unk10 = 0xc8;
    sub->countdown = 0xfa0;
    res = Resource_Acquire(0x6a, 1);
    sub->gfxHandle =
        ((s16 (*)(GameObject*, int, int, int, int, int))((void**)*(int*)res)[1])(obj, 1, 0, 0x402, -1, 0);
    Resource_Release(res);
    obj->anim.worldPosX = obj->anim.localPosX;
    obj->anim.worldPosY = obj->anim.localPosY;
    obj->anim.worldPosZ = obj->anim.localPosZ;
}

void dll_19B_release(void)
{
}

void dll_19B_initialise(void)
{
}

void* dll_19C[14] = {(void*)0x00000000,       (void*)0x00000000,   (void*)0x00000000, (void*)0x00090000,
                     dll_19C_initialise,      dll_19C_release,     (void*)0x00000000, dll_19C_init,
                     dll_19C_update,          dll_19C_hitDetect,   dll_19C_render,    dll_19C_free,
                     dll_19C_getObjectTypeId, dll_19C_getExtraSize};
void* dll_19D[14] = {(void*)0x00000000,       (void*)0x00000000,   (void*)0x00000000, (void*)0x00090000,
                     dll_19D_initialise,      dll_19D_release,     (void*)0x00000000, dll_19D_init,
                     dll_19D_update,          dll_19D_hitDetect,   dll_19D_render,    dll_19D_free,
                     dll_19D_getObjectTypeId, dll_19D_getExtraSize};
void* dll_19E[14] = {(void*)0x00000000,       (void*)0x00000000,   (void*)0x00000000, (void*)0x00090000,
                     dll_19E_initialise,      dll_19E_release,     (void*)0x00000000, dll_19E_init,
                     dll_19E_update,          dll_19E_hitDetect,   dll_19E_render,    dll_19E_free,
                     dll_19E_getObjectTypeId, dll_19E_getExtraSize};
void* gTreeBirdObjDescriptor[14] = {(void*)0x00000000, (void*)0x00000000,    (void*)0x00000000, (void*)0x00090000,
                                    (void*)0x00000000, (void*)0x00000000,    (void*)0x00000000, treebird_init,
                                    treebird_update,   (void*)0x00000000,    treebird_render,   (void*)0x00000000,
                                    (void*)0x00000000, treebird_getExtraSize};
void* gNW_geyserObjDescriptor[14] = {(void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000,
                                     (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, nw_geyser_init,
                                     nw_geyser_update,  (void*)0x00000000, (void*)0x00000000, nw_geyser_free,
                                     (void*)0x00000000, (void*)0x00000000};
