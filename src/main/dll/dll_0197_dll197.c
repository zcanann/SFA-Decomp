#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/dll/cup1C3.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "main/resource.h"



extern uint GameBit_Get(int eventId);
extern u32 randomGetRange(int min, int max);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern int Sfx_IsPlayingFromObjectChannel(int obj, int channel);
extern f32 Vec_distance(void* a, void* b);
extern void objUpdateOpacity(int obj);

extern ModgfxInterface** gModgfxInterface;
extern EffectInterface** gPartfxInterface;
extern u8 framesThisStep;
extern int lbl_802C23C8[];
extern s8 lbl_803DDBD0;
extern f32 lbl_803E5138;
extern f32 lbl_803E513C;

typedef struct Cup197State
{
    s32 gameBit;
    s16 sparkTimer;
    s16 activeTimer;
    s16 hitCooldown;
    u8 visibleToCamera;
    u8 mode;
    u8 active;
    u8 sparkArmed;
    u8 previousActive;
    u8 stage;
} Cup197State;

/*
 * --INFO--
 *
 * Function: DBSH_Symbol_SeqFn
 * EN v1.0 Address: 0x801C9660
 * EN v1.0 Size: 2276b
 * EN v1.1 Address: 0x801C9C14
 * EN v1.1 Size: 1500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

typedef struct DbshSymbolFlags
{
    u8 finished : 1;
    u8 active : 1;
} DbshSymbolFlags;

/*
 * Per-object extra state for the DBSH spin-symbol minigame
 * (dbsh_symbol_getExtraSize == 0x24).
 */
typedef struct DbshSymbolState
{
    void* partnerObj; /* nearest objType-0x20F symbol, spun in mirror */
    f32 spinSpeed;
    f32 sfxTimerB; /* object creak sfx 0x4A3 */
    f32 sfxTimerA; /* player grunt sfx 0x13A */
    int spinProgress; /* 0..0x7EF4 = fully turned */
    int prevSpinProgress;
    int triggerHandle;
    u8 pad1C[2];
    s16 phase; /* update: 0 hide, 1 scuff, 2 arm trigger, 3 resolve */
    DbshSymbolFlags flags;
    u8 pad21[3];
} DbshSymbolState;

STATIC_ASSERT(sizeof(DbshSymbolState) == 0x24);
STATIC_ASSERT(offsetof(DbshSymbolState, phase) == 0x1E);
STATIC_ASSERT(offsetof(DbshSymbolState, flags) == 0x20);



/*
 * --INFO--
 *
 * Function: dbsh_symbol_update
 * EN v1.0 Address: 0x801C9F84
 * EN v1.0 Size: 348b
 * EN v1.1 Address: 0x801CA234
 * EN v1.1 Size: 484b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dbsh_symbol_getExtraSize
 * EN v1.0 Address: 0x801C9C34
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: dbsh_symbol_free
 * EN v1.0 Address: 0x801C9C3C
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: dbsh_symbol_render
 * EN v1.0 Address: 0x801CA0E0
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801CA418
 * EN v1.1 Size: 84b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



/* Trivial 4b 0-arg blr leaves. */
void dll_197_hitDetect(void)
{
}

void dll_197_update(int obj)
{
    extern int Obj_GetPlayerObject(void);
    extern undefined4 GameBit_Set(int eventId, int value);
    Cup197State* state = ((GameObject*)obj)->extra;
    int resourceParams[4];
    u8 callbackData[0x14];
    int player;
    f32 distance;
    void* resource;
    int effect;
    int stageEffectBase;
    int* resourceDefaults;

    resourceDefaults = lbl_802C23C8;
    resourceParams[0] = resourceDefaults[0];
    resourceParams[1] = resourceDefaults[1];
    resourceParams[2] = resourceDefaults[2];
    resourceParams[3] = resourceDefaults[3];

    player = Obj_GetPlayerObject();
    distance = Vec_distance((void*)(player + 0x18), (void*)&((GameObject*)obj)->anim.worldPosX);
    if (Sfx_IsPlayingFromObjectChannel(obj, 0x40) != 0)
    {
        if (distance >= lbl_803E5138 && state->active != 0)
        {
            Sfx_StopObjectChannel(obj, 0x40);
        }
    }
    else if (distance < lbl_803E5138 && state->active != 0)
    {
        Sfx_PlayFromObject(obj, 0x72);
    }

    objUpdateOpacity(obj);

    if (state->hitCooldown > 0)
    {
        state->hitCooldown -= framesThisStep;
    }

    switch (state->mode)
    {
    case 1:
        break;
    default:
        return;
    }

    *(f32*)(callbackData + 0x10) = lbl_803E513C;
    state->previousActive = state->active;
    if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0 ||
        (state->hitCooldown != 0 && state->hitCooldown <= 0x14))
    {
        state->active = 1 - state->active;
        if (state->active != 0)
        {
            state->activeTimer = 1000;
        }
        if (state->hitCooldown != 0)
        {
            state->hitCooldown = 0;
            lbl_803DDBD0 = 3;
            state->activeTimer = 300;
            if (state->stage == 2)
            {
                GameBit_Set(0x472, 1);
            }
        }
    }

    if (state->active != 0 && state->activeTimer != 0)
    {
        state->activeTimer -= framesThisStep;
        if (state->activeTimer <= 0)
        {
            state->activeTimer = 0;
            state->active = 0;
        }
    }

    if (state->active != 0 && state->sparkTimer <= 0 && state->sparkArmed != 0)
    {
        state->sparkArmed = 0;
        Sfx_PlayFromObject(obj, 0x80);
    }

    if (state->active == state->previousActive)
    {
        return;
    }

    if (state->active != 0)
    {
        resource = Resource_Acquire(0x69, 1);
        stageEffectBase = state->stage * 2;
        resourceParams[1] = stageEffectBase + 0x19d;
        resourceParams[2] = stageEffectBase + 0x19e;
        (*(void (*)(int, int, void*, int, int, void*))(*(int*)(*(int*)resource + 4)))(
            obj, 1, callbackData, 0x10004, -1, resourceParams);
        Resource_Release(resource);

        for (effect = 0; effect < 200; effect++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x1a3, NULL, 0,
                                             -1, NULL);
        }

        if (state->gameBit != -1 && GameBit_Get(state->gameBit) == 0)
        {
            GameBit_Set(state->gameBit, 1);
        }
        if (lbl_803DDBD0 == 0 && state->stage == 0 && GameBit_Get(state->gameBit) != 0)
        {
            lbl_803DDBD0 = 1;
        }
        if (lbl_803DDBD0 == 1 && state->stage == 1 && GameBit_Get(state->gameBit) != 0)
        {
            lbl_803DDBD0 = 2;
        }
        if (lbl_803DDBD0 == 2 && state->stage == 2 && GameBit_Get(state->gameBit) != 0)
        {
            GameBit_Set(0x472, 1);
            lbl_803DDBD0 = 3;
        }
        state->sparkArmed = 1;
        state->sparkTimer = 1;
    }
    else
    {
        Sfx_StopObjectChannel(obj, 0x7f);
        (*gModgfxInterface)->detachSource((void*)obj);
        (*gExpgfxInterface)->freeSource(obj);
        if (state->gameBit != -1 && GameBit_Get(state->gameBit) != 0)
        {
            GameBit_Set(state->gameBit, 0);
        }
        if (lbl_803DDBD0 == 1 && state->stage == 0)
        {
            lbl_803DDBD0 = 0;
        }
        if (lbl_803DDBD0 == 2 && state->stage == 1)
        {
            lbl_803DDBD0 = 0;
        }
        if (lbl_803DDBD0 == 3 && state->stage == 2 && GameBit_Get(0x474) == 0)
        {
            GameBit_Set(0x472, 0);
            lbl_803DDBD0 = 0;
        }
    }
}

/* 8b "li r3, N; blr" returners. */
int dll_197_getExtraSize(void) { return 0x10; }
int dll_197_getObjectTypeId(void) { return 0x1; }

/* Render-side line-of-sight particle callback for the cup object. */
extern f32 lbl_803E5120;
extern f32 lbl_803E5124;
extern f32 lbl_803E5128;
extern f32 lbl_803E512C;
extern f32 lbl_803E5130;
extern f32 lbl_803E5134;
extern void* Camera_GetCurrentViewSlot(void);
extern f32 sqrtf(f32 x);
extern void voxmaps_worldToGrid(void* world, void* grid);
extern int voxmaps_traceLine(void* from, void* to, void* out, int p4, int p5);

void dll_197_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    struct
    {
        u8 pad[0xc];
        f32 pos[3];
    } particleParams;
    f32 dir[3];
    f32 objTrace[3];
    f32 cameraTrace[3];
    s16 startGrid[4];
    s16 endGrid[4];
    u8 traceOut[8];
    Cup197State* state = ((GameObject*)obj)->extra;
    u8* camera;
    f32 dist;
    f32 scale;
    void* dirAlias = (void*)dir;

    if (visible == 0)
    {
        state->sparkTimer = 0;
        state->visibleToCamera = 0;
        return;
    }

    if (state->active == 0)
    {
        return;
    }

    state->visibleToCamera = 1;
    camera = Camera_GetCurrentViewSlot();
    dir[0] = *(f32*)(camera + 0xc) - ((GameObject*)obj)->anim.localPosX;
    dir[1] = *(f32*)(camera + 0x10) - ((GameObject*)obj)->anim.localPosY;
    dir[2] = *(f32*)(camera + 0x14) - ((GameObject*)obj)->anim.localPosZ;

    dist = sqrtf(dir[2] * dir[2] + (dir[0] * dir[0] + dir[1] * dir[1]));
    if (dist > lbl_803E5120)
    {
        scale = lbl_803E5124 / dist;
        dir[0] = dir[0] * scale;
        dir[1] = dir[1] * scale;
        dir[2] = dir[2] * scale;

        objTrace[0] = lbl_803E5128 * dir[0];
        objTrace[1] = lbl_803E5128 * dir[1];
        objTrace[2] = lbl_803E5128 * dir[2];
        objTrace[0] = objTrace[0] + ((GameObject*)obj)->anim.localPosX;
        objTrace[1] = objTrace[1] + ((GameObject*)obj)->anim.localPosY;
        objTrace[2] = objTrace[2] + ((GameObject*)obj)->anim.localPosZ;
        cameraTrace[0] = lbl_803E512C * dir[0];
        cameraTrace[1] = lbl_803E512C * dir[1];
        cameraTrace[2] = lbl_803E512C * dir[2];
        cameraTrace[0] = cameraTrace[0] + *(f32*)(camera + 0xc);
        cameraTrace[1] = cameraTrace[1] + *(f32*)(camera + 0x10);
        cameraTrace[2] = cameraTrace[2] + *(f32*)(camera + 0x14);

        voxmaps_worldToGrid((void*)objTrace, startGrid);
        voxmaps_worldToGrid((void*)cameraTrace, endGrid);
        if (voxmaps_traceLine(startGrid, endGrid, traceOut, 0, 0) == 0)
        {
            state->visibleToCamera = 0;
            (*gExpgfxInterface)->freeSource(obj);
        }
    }

    if (state->sparkTimer > 0)
    {
        state->sparkTimer -= framesThisStep;
        return;
    }

    if (state->visibleToCamera != 0)
    {
        particleParams.pos[0] = lbl_803E5130;
        particleParams.pos[1] = lbl_803E5134;
        particleParams.pos[2] = lbl_803E5130;
        (*gPartfxInterface)->spawnObject((void*)obj, 0x1f7, &particleParams,
                                         0x12, -1, NULL);
    }

    state->sparkTimer = randomGetRange(-10, 10) + 0x3c;
}

void dll_197_free(int obj)
{
    (*gModgfxInterface)->detachSource((void*)obj);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

extern f32 lbl_803E5118;


/* === moved from main/dll/explosion.c [801CA5B4-801CA718) (TU re-split, docs/boundary_audit.md) === */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/resource.h"

typedef struct Dll197State
{
    u8 pad0[0x2 - 0x0];
    s16 unk2;
    s16 unk4;
    u8 pad6[0x8 - 0x6];
    s16 unk8;
    s16 unkA;
    u8 unkC;
    u8 unkD;
    u8 unkE;
    u8 unkF;
    u8 unk10;
    u8 pad11[0x18 - 0x11];
} Dll197State;


extern int ObjHits_GetPriorityHit();


/*
 * --INFO--
 *
 * Function: dll_197_init
 * EN v1.0 Address: 0x801CA5B4
 * EN v1.0 Size: 1148b
 * EN v1.1 Address: 0x801CA6BC
 * EN v1.1 Size: 1196b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 lbl_803E5140;
extern f32 lbl_803E5144;

void dll_197_init(int obj, int data)
{
    u8* st;
    void* res;
    struct
    {
        u8 buf[16];
        f32 f;
    } stk;

    st = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)(((s8) * (u8*)(data + 0x18) & 0x3fu) << 10);
    if (*(s16*)(data + 0x1a) > 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32) * (s16*)(data + 0x1a) / lbl_803E5140;
    }
    else
    {
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E5144;
    }
    *(u8*)(st + 0xb) = *(u8*)(data + 0x19);
    ((Dll197State*)st)->unkC = 0;
    ((Dll197State*)st)->unkF = 0;
    *(int*)st = *(s16*)(data + 0x1e);
    stk.f = lbl_803E513C;
    switch (*(u8*)(st + 0xb))
    {
    case 0:
        ((Dll197State*)st)->unkC = 1;
        res = Resource_Acquire(0x69, 1);
        if (*(s16*)(data + 0x1c) == 0)
        {
            (*(void (**)(int, int, void*, int, int, int))(*(int*)res + 4))(obj, 0, stk.buf, 0x10004, -1, 0);
        }
        break;
    case 1:
        ((Dll197State*)st)->unkF = *(s16*)(data + 0x1c);
        ((Dll197State*)st)->unkD = 0;
        ((Dll197State*)st)->unk8 = ((Dll197State*)st)->unkF * 0x28 + 0x398;
        ((Dll197State*)st)->unkE = 0;
        break;
    }
    ((Dll197State*)st)->unk4 = 0;
}


/*
 * --INFO--
 *
 * Function: FUN_801caa30
 * EN v1.0 Address: 0x801CAA30
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x801CAB68
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801cacd4
 * EN v1.0 Address: 0x801CACD4
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801CAE40
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cacd4(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible);


/*
 * --INFO--
 *
 * Function: FUN_801caeac
 * EN v1.0 Address: 0x801CAEAC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801CAEF8
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801caeb0
 * EN v1.0 Address: 0x801CAEB0
 * EN v1.0 Size: 1240b
 * EN v1.1 Address: 0x801CAF74
 * EN v1.1 Size: 788b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off
void dll_197_release(void)
{
}

void dll_197_initialise(void)
{
}

void nwsh_levcon_hitDetect(void);




/* 8b "li r3, N; blr" returners. */

/* render-with-objRenderFn_8003b8f4 pattern. */












