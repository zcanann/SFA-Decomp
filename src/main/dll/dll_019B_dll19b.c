/* DLL 0x019B - torch / fire-effect objects [801CBA98-801CBD88) */
#include "main/dll/torch1CD.h"
#include "main/dll/dll19cstate_struct.h"
#include "main/game_object.h"
#include "main/dll/torch1cd_state.h"
#include "main/dll_000A_expgfx.h"
#include "main/objseq.h"
#include "main/resource.h"
#include "main/gamebits.h"
extern int getEnvfxAct(int a, int b, u16 idx, int d);
extern void* return0_8005669C(int);
extern int lbl_803DB610;
extern void* lbl_803DDBE0;
extern f32 lbl_803E5188;
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern ModgfxInterface** gModgfxInterface;
extern void ObjMsg_AllocQueue(void* obj, int capacity);
extern int Obj_GetPlayerObject(void);
extern int ObjGroup_FindNearestObject(int group, u32 obj, float* maxDistance);
extern int ObjMsg_Pop(int obj, int* msg, int* a, int* b);
extern f32 Vec_distance(f32* a, f32* b);
extern void fn_80296B78(int obj, int a);
extern void fn_80137948(char* fmt, ...);
char sShrineTimeFormat[] = "time %d\n";
extern f32 lbl_803E518C;
extern f32 lbl_803E5190;
extern f32 lbl_803E5194;
extern f32 lbl_803E5198;
extern f32 lbl_803E519C;
extern f32 lbl_803E51A0;
extern f32 timeDelta;
extern u8 framesThisStep;

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

    if (((Torch1CDState*)state)->flameFrameVel != 0)
    {
        ((Torch1CDState*)state)->flameFrame += ((Torch1CDState*)state)->flameFrameVel;
        if (((Torch1CDState*)state)->flameFrame <= 1 && ((Torch1CDState*)state)->flameFrameVel <= 0)
        {
            ((Torch1CDState*)state)->flameFrame = 1;
            ((Torch1CDState*)state)->flameFrameVel = 0;
        }
        else if (((Torch1CDState*)state)->flameFrame >= 0x46 && ((Torch1CDState*)state)->flameFrameVel >= 0)
        {
            ((Torch1CDState*)state)->flameFrame = 0x46;
            ((Torch1CDState*)state)->flameFrameVel = 0;
        }
        ((void (**)(int, u8))*gTitleMenuControlInterface)[0x38 / 4](3, (u8)((Torch1CDState*)state)->flameFrame);
    }

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        u8 cmd = animUpdate->eventIds[i];
        if (cmd != 0)
        {
            switch (cmd)
            {
            case 1:
                getEnvfxAct(obj, obj, 0xc3, 0);
                break;
            case 2:
                if (lbl_803DB610 == -1)
                {
                    getEnvfxAct(obj, obj, 0x14, 0);
                }
                else
                {
                    getEnvfxAct(obj, obj, lbl_803DB610 & 0xffff, 0);
                }
                break;
            case 3:
                ((Torch1CDState*)state)->unk14 = 1;
                break;
            case 4:
                ((Torch1CDState*)state)->unk13 = 4;
                ((Torch1CDState*)state)->unk14 = 2;
                GameBit_Set(0x129, 1);
                GameBit_Set(0x1d2, 0);
                GameBit_Set(0x126, 1);
                ((Torch1CDState*)state)->flameFrameVel = -3;
                break;
            case 5:
                ((Torch1CDState*)state)->unk13 = 6;
                ((Torch1CDState*)state)->unk14 = 3;
                ((Torch1CDState*)state)->flameFrameVel = -3;
                GameBit_Set(0x129, 1);
                break;
            case 6:
                GameBit_Set(0x1d2, 1);
                break;
            case 7:
                GameBit_Set(0x1d2, 0);
                ((Torch1CDState*)state)->flameFrameVel = -3;
                break;
            case 8:
                GameBit_Set(0x128, 1);
                if (lbl_803DDBE0 == NULL)
                {
                    lbl_803DDBE0 = return0_8005669C(1);
                }
                break;
            case 9:
                GameBit_Set(0x127, 1);
                break;
            case 0xb:
                ((Torch1CDState*)state)->flameFrame = 100;
                ((void (**)(int, int, int, u8, int))*gTitleMenuControlInterface)[0x18 / 4]
                    (3, 0x2d, 0x50, (u8)((Torch1CDState*)state)->flameFrame, 0);
                break;
            }
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}

void dll_19B_hitDetect(void)
{
}

int dll_19B_getExtraSize(void) { return 0x18; }
int dll_19B_getObjectTypeId(void) { return 0x0; }

void dll_19B_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, lbl_803E5188);
}

void dll_19B_free(int* obj)
{
    (*gModgfxInterface)->detachSource(obj);
}

enum Dll19BPhase
{
    DLL19B_PHASE_IDLE = 0,       /* wait for player proximity, then arm shrine */
    DLL19B_PHASE_WAIT_EVENT = 1, /* wait for pendingEvent, then start countdown */
    DLL19B_PHASE_COUNTDOWN = 2,  /* shrine timer ticking; success or timeout */
    DLL19B_PHASE_RESOLVE = 3,    /* branch on unlock bit: success vs fail path */
    DLL19B_PHASE_COMPLETE = 4,   /* set completion bits, finish */
    DLL19B_PHASE_DONE = 5,       /* terminal, no per-tick handling */
    DLL19B_PHASE_RESET = 6       /* tear down and return to idle */
};

typedef struct Dll19BState
{
    s16 activationDist; /* 0x00: st[0], proximity trigger distance */
    s16 timer;          /* 0x02: st[1], frame countdown */
    s16 brightnessA;    /* 0x04: st[2] */
    s16 brightnessAVel; /* 0x06: st[3] */
    s16 brightnessB;    /* 0x08: st[4] */
    s16 brightnessBVel; /* 0x0a: st[5] */
    s16 gfxHandle;      /* 0x0c: st[6], modgfx source handle */
    s16 countdown;      /* 0x0e: st[7], shrine timer */
    s16 unk10;          /* 0x10: init=0xc8 */
    u8 unlockCount;     /* 0x12 */
    u8 phase;           /* 0x13 */
    u8 pendingEvent;    /* 0x14 */
    u8 pad15[0x16 - 0x15];
    u8 displayedFlag;   /* 0x16 */
    u8 pad17[0x18 - 0x17];
} Dll19BState;

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
    player = Obj_GetPlayerObject();
    dist = lbl_803E518C;
    st2 = ((GameObject*)obj)->extra;
    unk16 = 0;
    while (ObjMsg_Pop(obj, &msg, &unk8, &unk16) != 0)
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
    GameBit_Set(0x127, 1);
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
                (*(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(
                    3, 0x2c, 0x50, st->brightnessB, 0);
                st->displayedFlag = 1;
            }
        }
    }
    else
    {
        near = ObjGroup_FindNearestObject(0xe, player, &dist);
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
                GameBit_Set(0x129, 0);
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
                {
                    void* handle = Resource_Acquire(0x83, 1);
                    (*(s16 (**)(int, int, int, int, int, int))(*(int*)handle + 4))(obj, 1, 0, 1, -1, 0);
                    Resource_Release(handle);
                }
                {
                    void* handle = Resource_Acquire(0x84, 1);
                    (*(s16 (**)(int, int, int, int, int, int))(*(int*)handle + 4))(obj, 0, 0, 1, -1, 0);
                    Resource_Release(handle);
                }
                GameBit_Set(0x126, 0);
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
            if (st->unlockCount == 0 && GameBit_Get(0x1d3) == 0)
            {
                GameBit_Set(0x1d3, 1);
            }
            if ((u32)GameBit_Get(0x1d8) != 0)
            {
                st->unlockCount += 1;
                GameBit_Set(0x1d8, 0);
            }
            st->countdown -= (s16)timeDelta;
            fn_80137948(sShrineTimeFormat, st->countdown);
            if (st->countdown <= 0)
            {
                GameBit_Set(0x1d4, 1);
                (*gObjectTriggerInterface)->runSequence(2, (void*)obj, -1);
                st->timer = 10;
                st->phase = DLL19B_PHASE_RESET;
                (*(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(
                    3, 0x35, 0x50, st->brightnessB & 0xff, 0);
                st->brightnessBVel = 1;
                GameBit_Set(0x1d3, 0);
            }
            else if (st->unlockCount == 1)
            {
                st->phase = DLL19B_PHASE_RESOLVE;
                st->timer = 200;
                st->brightnessBVel = -3;
            }
            break;
        case DLL19B_PHASE_RESOLVE:
            if ((u32)GameBit_Get(0x1d1) != 0)
            {
                st->brightnessB = 1;
                (*(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(
                    3, 0x2c, 0x50, st->brightnessB & 0xff, 0);
                st->brightnessBVel = 1;
                GameBit_Set(0x129, 1);
                st->phase = DLL19B_PHASE_DONE;
            }
            else
            {
                fn_80296B78(player, -1);
                GameBit_Set(0x126, 0);
                (*(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(
                    3, 0x2a, 0x50, st->brightnessB & 0xff, 0);
                st->brightnessBVel = 1;
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
                st->phase = DLL19B_PHASE_COMPLETE;
            }
            break;
        case DLL19B_PHASE_COMPLETE:
            if ((u32)GameBit_Get(0xfd) == 0)
            {
                GameBit_Set(0xfd, 1);
            }
            GameBit_Set(0x1d2, 0);
            GameBit_Set(0x127, 0);
            st->phase = DLL19B_PHASE_DONE;
            (*(void (**)(int, int, int, int, int))(*(int*)gTitleMenuControlInterface + 0x18))(
                3, 0x2c, 0x50, st->brightnessB & 0xff, 0);
            break;
        case DLL19B_PHASE_RESET:
            st->phase = DLL19B_PHASE_IDLE;
            st->pendingEvent = 0;
            st->timer = 400;
            GameBit_Set(0x129, 1);
            GameBit_Set(0x126, 1);
            GameBit_Set(0x127, 1);
            {
                void* handle = Resource_Acquire(0x6a, 1);
                st->gfxHandle = (*(s16 (**)(int, int, int, int, int, int))(*(int*)handle + 4))(obj, 2, 0, 0x402, -1, 0);
                Resource_Release(handle);
            }
            GameBit_Set(0x1d8, 0);
            st->unlockCount = 0;
            st->countdown = 4000;
            GameBit_Set(0x1d4, 0);
            break;
        }
    }
}

void dll_19B_release(void)
{
}

void dll_19B_initialise(void)
{
}


void dll_19B_init(u8* obj, u8* params)
{
    extern void* gTitleMenuControlInterface;

    register Dll19BState* sub;
    void* res;

    sub = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = 0;
    sub->activationDist = 0xa;
    if (((Dll19BPlacement*)params)->activationDistPacked > 0)
    {
        sub->activationDist = (s16)(((Dll19BPlacement*)params)->activationDistPacked >> 8);
    }
    sub->phase = 0;
    sub->pendingEvent = 0;
    sub->timer = 0;
    sub->unlockCount = 0;
    ((GameObject*)obj)->animEventCallback = dll_19B_SeqFn;
    ObjMsg_AllocQueue(obj, 4);
    GameBit_Set(0x129, 1);
    GameBit_Set(0x1d2, 0);
    GameBit_Set(0x126, 1);
    GameBit_Set(0x127, 1);
    GameBit_Set(0x2d, 1);
    GameBit_Set(0x40, 1);
    GameBit_Set(0x1d7, 1);
    GameBit_Set(0x1d8, 0);
    sub->brightnessA = 0xc;
    sub->brightnessB = 0x1e;
    sub->timer = 0xc8;
    ((void(*)(int, int, int, int, int))((void**)*(void**)gTitleMenuControlInterface)[6])(2, 0x2b, 0x50, 1, 0);
    sub->brightnessAVel = 0;
    sub->brightnessBVel = 0;
    sub->displayedFlag = 0;
    sub->unk10 = 0xc8;
    sub->countdown = 0xfa0;
    res = Resource_Acquire(0x6a, 1);
    sub->gfxHandle = ((s16(*)(u8*, int, int, int, int, int))((void**)*(int*)res)[1])(obj, 1, 0, 0x402, -1, 0);
    Resource_Release(res);
    ((GameObject*)obj)->anim.worldPosX = ((GameObject*)obj)->anim.localPosX;
    ((GameObject*)obj)->anim.worldPosY = ((GameObject*)obj)->anim.localPosY;
    ((GameObject*)obj)->anim.worldPosZ = ((GameObject*)obj)->anim.localPosZ;
}

/*
 * Function: dll_19C_init
 * EN v1.0 Address: 0x801CC950
 * EN v1.0 Size: 64b
 */
void dll_19C_init(int obj, u8* initData);

/*
 * Function: dll_19D_free
 * EN v1.0 Address: 0x801CC9A8
 * EN v1.0 Size: 132b
 */

/*
 * Function: dll_19D_init
 * EN v1.0 Address: 0x801CCECC
 * EN v1.0 Size: 208b
 */

/*
 * Function: dll_19D_hitDetect
 * EN v1.0 Address: 0x801CCA30
 * EN v1.0 Size: 276b
 */

/*
 * Function: dll_19D_update
 * EN v1.0 Address: 0x801CCB44
 * EN v1.0 Size: 904b
 */

/*__DATA_EXTERNS__*/
extern void nw_geyser_free();
extern void nw_geyser_update();
extern void nw_geyser_init();
extern void treebird_getExtraSize();
extern void treebird_render();
extern void treebird_update();
extern void treebird_init();
extern void dll_19E_getExtraSize();
extern void dll_19E_getObjectTypeId();
extern void dll_19E_free();
extern void dll_19E_render();
extern void dll_19E_hitDetect();
extern void dll_19E_update();
extern void dll_19E_init();
extern void dll_19E_release();
extern void dll_19E_initialise();
extern void dll_19D_getExtraSize();
extern void dll_19D_getObjectTypeId();
extern void dll_19D_free();
extern void dll_19D_render();
extern void dll_19D_hitDetect();
extern void dll_19D_update();
extern void dll_19D_init();
extern void dll_19D_release();
extern void dll_19D_initialise();
extern void dll_19C_getExtraSize();
extern void dll_19C_getObjectTypeId();
extern void dll_19C_free();
extern void dll_19C_render();
extern void dll_19C_hitDetect();
extern void dll_19C_update();
extern void dll_19C_release();
extern void dll_19C_initialise();
/* .data table (attributed from auto object; pointer tables regenerate ADDR32 relocs) */
void* jumptable_8032668C[7] = { (void*)((u8*)dll_19B_update + 0x380), (void*)((u8*)dll_19B_update + 0x490), (void*)((u8*)dll_19B_update + 0x4B0), (void*)((u8*)dll_19B_update + 0x5E4), (void*)((u8*)dll_19B_update + 0x6C0), (void*)((u8*)dll_19B_update + 0x7D0), (void*)((u8*)dll_19B_update + 0x72C) };
void* dll_19C[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, dll_19C_initialise, dll_19C_release, (void*)0x00000000, dll_19C_init, dll_19C_update, dll_19C_hitDetect, dll_19C_render, dll_19C_free, dll_19C_getObjectTypeId, dll_19C_getExtraSize };
void* dll_19D[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, dll_19D_initialise, dll_19D_release, (void*)0x00000000, dll_19D_init, dll_19D_update, dll_19D_hitDetect, dll_19D_render, dll_19D_free, dll_19D_getObjectTypeId, dll_19D_getExtraSize };
void* dll_19E[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, dll_19E_initialise, dll_19E_release, (void*)0x00000000, dll_19E_init, dll_19E_update, dll_19E_hitDetect, dll_19E_render, dll_19E_free, dll_19E_getObjectTypeId, dll_19E_getExtraSize };
void* gTreeBirdObjDescriptor[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, treebird_init, treebird_update, (void*)0x00000000, treebird_render, (void*)0x00000000, (void*)0x00000000, treebird_getExtraSize };
void* gNW_geyserObjDescriptor[14] = { (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, (void*)0x00090000, (void*)0x00000000, (void*)0x00000000, (void*)0x00000000, nw_geyser_init, nw_geyser_update, (void*)0x00000000, (void*)0x00000000, nw_geyser_free, (void*)0x00000000, (void*)0x00000000 };
