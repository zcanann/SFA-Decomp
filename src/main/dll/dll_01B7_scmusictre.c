/* === moved from main/dll/CR/CRsnowbike.c [801DBFA0-801DC310) (TU re-split, docs/boundary_audit.md) === */
#include "main/obj_placement.h"
#include "main/game_object.h"


typedef struct ScMusictreePlacement
{
    u8 pad0[0x20 - 0x0];
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 pad23[0x28 - 0x23];
} ScMusictreePlacement;




typedef struct ScMusictreeSpawnAmbientEffectPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    u8 pad8[0x20 - 0x8];
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 pad23[0x28 - 0x23];
} ScMusictreeSpawnAmbientEffectPlacement;


/* sc_levelcontrol_getExtraSize == 0x24 (CloudRunner race level control). */
typedef struct ScLevelControlState
{
    f32 fogNear; /* 0x00: enableHeavyFog base */
    f32 fog04; /* 0x04 */
    f32 fog08; /* 0x08 */
    f32 fog0C; /* 0x0c */
    f32 timer10; /* 0x10 */
    f32 fadeTimer; /* 0x14 */
    u8 pad18[4];
    u8 musicStep; /* 0x1c: index into the lbl_803DC060 cue table */
    u8 mode; /* 0x1d: anim-event mode latch */
    u8 areaCell; /* 0x1e: 0xff until the player enters map 0xe */
    u8 flags1F; /* 0x1f */
    u8 musicTrack; /* 0x20 */
    s8 unk21; /* 0x21 */
    u8 flags22; /* 0x22: SnowFlags22 overlay (bit 7) */
    u8 pad23;
} ScLevelControlState;





/*
 * --INFO--
 *
 * Function: sh_emptytumblew_init
 * EN v1.0 Address: 0x801DAFDC
 * EN v1.0 Size: 1440b
 * EN v1.1 Address: 0x801DB048
 * EN v1.1 Size: 1080b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



/*
 * --INFO--
 *
 * Function: FUN_801db580
 * EN v1.0 Address: 0x801DB580
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801DB594
 * EN v1.1 Size: 56b
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
 * Function: sc_levelcontrol_processAnimEvents
 * EN v1.0 Address: 0x801DB670
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x801DB688
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: sc_levelcontrol_setAnimEventState
 * EN v1.0 Address: 0x801DB7B4
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x801DB7E8
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_801db8c4
 * EN v1.0 Address: 0x801DB8C4
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x801DB904
 * EN v1.1 Size: 96b
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
 * Function: FUN_801db924
 * EN v1.0 Address: 0x801DB924
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801DB964
 * EN v1.1 Size: 52b
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



void sc_musictree_free(void)
{
}

void sc_musictree_hitDetect(void)
{
}

/* 8b "li r3, N; blr" returners. */
int sc_musictree_getExtraSize(void) { return 0x50; }
int sc_musictree_getObjectTypeId(void) { return 0x0; }

/* Pattern wrappers. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);


extern void fn_8003B608(int a, int b, int c);
extern int ObjPath_GetPointWorldPosition(int obj, int idx, f32* x, f32* y, f32* z, int p6);
extern f32 lbl_803E558C;

typedef struct SCMusicTreeState
{
    int ambientEffect[3];
    f32 pathPoint[3][3];
    f32 proximityBurstTimer;
    f32 animSpeed;
    f32 scale;
    f32 proximityCooldown;
    f32 hitCooldown;
    int hitCooldownState;
    u16 hearRadius;
    s16 previousDistance;
    u8 flags;
    u8 pad4D[0x50 - 0x4D];
} SCMusicTreeState;

void sc_musictree_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int* def = *(int**)&((GameObject*)obj)->anim.placementData;
    SCMusicTreeState* state = ((GameObject*)obj)->extra;
    int i;
    if (visible == 0) return;
    fn_8003B608((int)((ScMusictreePlacement*)def)->unk20, (int)((ScMusictreePlacement*)def)->unk21,
                (int)((ScMusictreePlacement*)def)->unk22);
    ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E558C);
    if ((state->flags & 0x80) != 0)
    {
        for (i = 0; i < 3; i++)
        {
            ObjPath_GetPointWorldPosition(obj, i,
                                          &state->pathPoint[0][0],
                                          &state->pathPoint[0][1],
                                          &state->pathPoint[0][2],
                                          0);
            state = (SCMusicTreeState*)&((ScLevelControlState*)state)->fog0C;
        }
    }
    ((GameObject*)obj)->unkF8 = 1;
}



extern void GameBit_Set(int bit, int val);
extern void Sfx_PlayFromObject(int a, int b);



extern void enableHeavyFog(f32 a, f32 b, f32 c, f32 d, f32 e, int f);

typedef struct
{
    u8 bit7 : 1;
    u8 lo : 7;
} SnowFlags22;


extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int setup, int a, int b, int c, int d);

#pragma dont_inline on
void sc_musictree_spawnAmbientEffect(int obj, int p2, int p3, s8 idx)
{
    extern int randomGetRange(int lo, int hi); /* #57 */
    int def = *(int*)&((GameObject*)obj)->anim.placementData;
    SCMusicTreeState* state = (SCMusicTreeState*)p2;
    int setup;

    if (Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(0x28, 0x210);
        *(u8*)(setup + 4) = ((ScMusictreeSpawnAmbientEffectPlacement*)def)->unk4;
        *(u8*)(setup + 6) = ((ScMusictreeSpawnAmbientEffectPlacement*)def)->unk6;
        *(u8*)(setup + 5) = ((ScMusictreeSpawnAmbientEffectPlacement*)def)->unk5;
        *(u8*)(setup + 7) = ((ScMusictreeSpawnAmbientEffectPlacement*)def)->unk7 - 10;
        ((ObjPlacement*)setup)->posX = state->pathPoint[idx][0];
        ((ObjPlacement*)setup)->posY = state->pathPoint[idx][1];
        ((ObjPlacement*)setup)->posZ = state->pathPoint[idx][2];
        *(u16*)(setup + 0x1c) = randomGetRange(0x708, 0x1770);
        *(u16*)(setup + 0x1e) = 1;
        *(u8*)(setup + 0x20) = 10;
        *(u8*)(setup + 0x21) = 40;
        *(u8*)(setup + 0x22) = 50;
        *(u8*)(setup + 0x23) = 10;
        *(u8*)(setup + 0x24) = 50;
        *(s8*)(setup + 0x25) = -50;
        *(s16*)(setup + 0x26) = -1;
        *(int*)(setup + 0x18) = 0;
        state->ambientEffect[idx] = Obj_SetupObject(setup, 5, -1, -1, *(int*)&((GameObject*)obj)->anim.parent);
    }
}
#pragma dont_inline reset

extern f32 lbl_803E5588;

#pragma dont_inline on
void sc_musictree_handleHitObject(int p1, int p2, int effectType)
{
    extern int GameBit_Get(int bit); /* #57 */
    int id = *(int*)(*(int*)(p1 + 0x4c) + 0x14);
    SCMusicTreeState* state = (SCMusicTreeState*)p2;
    (void)effectType;

    switch (id)
    {
    case 0x30d9c:
        Sfx_PlayFromObject(p1, 299);
        Sfx_PlayFromObject(p1, 298);
        GameBit_Set(0x7d, 1);
        break;
    case 0x30d9d:
        Sfx_PlayFromObject(p1, 300);
        Sfx_PlayFromObject(p1, 298);
        GameBit_Set(0x7e, 1);
        break;
    case 0x30d9b:
        Sfx_PlayFromObject(p1, 0x12d);
        Sfx_PlayFromObject(p1, 298);
        GameBit_Set(0x7f, 1);
        break;
    case 0x448c2:
        if ((u32)GameBit_Get(0xc44) != 0)
            GameBit_Set(0xc41, 1);
        break;
    case 0x45178:
        if ((u32)GameBit_Get(0xc44) != 0)
            GameBit_Set(0xc43, 1);
        break;
    case 0x4517c:
        if ((u32)GameBit_Get(0xc44) != 0)
            GameBit_Set(0xc45, 1);
        break;
    }
    state->animSpeed = lbl_803E5588;
}
#pragma dont_inline reset

extern u16 lbl_803DC060[4];

/* EN v1.0 0x801DB3A8  size: 2732b  SnowBike Race level controller per-frame
 * driver: replays the env-fx set on map (re)entry, latches the race
 * GameBits, runs the two race countdown timers, eases the heavy fog level,
 * tracks the totem combo code (bits 0x7d..0x7f), and keeps the area music
 * in sync with the Thorntail animation state. */

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/dll/DR/cloudrunner_state.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objfx.h"
#include "main/objseq.h"

typedef struct ScCloudrunneraPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    u8 pad1A[0x20 - 0x1A];
} ScCloudrunneraPlacement;


typedef struct ScMusictreeState
{
    u8 pad0[0x30 - 0x0];
    f32 unk30;
    f32 moveStepScale;
    u8 pad38[0x48 - 0x38];
    u16 unk48;
    u16 unk4A;
    u8 unk4C;
    u8 pad4D[0x50 - 0x4D];
} ScMusictreeState;


extern void GameBit_Set(int id, int value);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void ObjHitbox_SetCapsuleBounds(int obj, int radius, int a, int b);
extern int ObjHits_GetPriorityHitWithPosition(int obj, int* type, int* a, int* b, f32* x, f32* y, f32* z);
extern int ObjHits_PollPriorityHitEffectWithCooldown(int obj, int a, int b, int c, int d, int e, int* state);
extern void ObjHits_RecordObjectHit(int target, int src, int a, int b, int c);
extern int* ObjList_GetObjects(int* startIndex, int* objectCount);
extern int Obj_SetupObject(int s, int a, int b, int c, int d);
extern int ObjLink_AttachChild(int parent, int child, int a);
extern int ObjLink_DetachChild(int parent, int child);
extern void cmbsrc_setExternalActive(int obj, int active);
extern void Obj_FreeObject(int obj);
extern void* Obj_GetPlayerObject(void);
extern void objSetSlot(int obj, int slot);
extern void Obj_SetModelColorFadeRecursive(int obj, int r, int g, int b, int a, int frames);
extern void objfx_spawnRandomBurst(int obj, int mode, int p3, void* vec, f32 f, int flag);
extern void vecRotateZXY(int obj, void* vec);
extern f32 sqrtf(f32 x);
extern f32 fn_8001461C(void);


extern ObjectTriggerInterface** gObjectTriggerInterface;
extern int* gTitleMenuControlInterface;

extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

extern u8 lbl_803DB411;
extern int lbl_803DC068;
extern int lbl_803DDC08;
extern f32 lbl_803E5590;
extern f32 lbl_803E5594;
extern f32 lbl_803E5598;
extern f32 lbl_803E559C;
extern f32 lbl_803E55A0;
extern f32 lbl_803E55A4;
extern f32 lbl_803E55A8;
extern f32 lbl_803E55AC;
extern f32 lbl_803E55B0;
extern f32 lbl_803E55B4;
extern f32 lbl_803E55B8;
extern f32 lbl_803E55BC;
extern f32 lbl_803E55C0;
extern f32 lbl_803E55D0;
extern f32 lbl_803E55D4;
extern f32 lbl_803E55D8;
extern f32 lbl_803E55DC;
extern f32 lbl_803E55E0;


typedef struct SCMusicTreeSetup
{
    ObjPlacement base;
    u8 rotXByte;
    u8 rotZByte;
    u8 yawByte;
    u8 hearRadiusHalf;
    f32 scale;
    u8 pad20[0x23 - 0x20];
    u8 flags;
} SCMusicTreeSetup;

STATIC_ASSERT(sizeof(SCMusicTreeSetup) == 0x24);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, rotZByte) == 0x19);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, yawByte) == 0x1A);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, hearRadiusHalf) == 0x1B);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, scale) == 0x1C);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, flags) == 0x23);

void sc_musictree_update(int obj)
{
    extern void sc_musictree_spawnAmbientEffect(int obj, int inner, u8 frames, int idx); /* #57 */
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 stk[7];
    f32 vec[3];
    f32 vec2[3];
    int rcType;
    int hr1, hr2, hr3;
    int i;
    int* p;
    int* q;

    ObjAnim_AdvanceCurrentMove(((ScMusictreeState*)inner)->moveStepScale, timeDelta, obj,
                               (ObjAnimEventList*)&stk);
    if (((ScMusictreeState*)inner)->unk4C == 0)
    {
        return;
    }
    if (((CloudRunnerState*)inner)->baddie.velY > lbl_803E5590)
    {
        ((CloudRunnerState*)inner)->baddie.velY = ((CloudRunnerState*)inner)->baddie.velY - timeDelta;
    }
    if (((ScMusictreeState*)inner)->moveStepScale > lbl_803E5594)
    {
        ((ScMusictreeState*)inner)->moveStepScale = ((ScMusictreeState*)inner)->moveStepScale - lbl_803E5598;
    }
    if ((((ScMusictreeState*)inner)->unk4C & 0x80) && ((GameObject*)obj)->unkF8 != 0)
    {
        p = (int*)inner;
        q = (int*)inner;
        for (i = 0; i < 3; i++)
        {
            if (*(void**)p == NULL)
            {
                sc_musictree_spawnAmbientEffect(obj, inner, framesThisStep, (s8)i);
            }
            else
            {
                int r = (*(int (**)(int))(*(int*)(*(int*)(*p + 0x68)) + 0x28))(*p);
                if (r > 3)
                {
                    *p = 0;
                }
                else
                {
                    (*(void (**)(int, int))(*(int*)(*(int*)(*p + 0x68)) + 0x24))(*p, (int)q + 0xc);
                }
            }
            p = (int*)((char*)p + 4);
            q = (int*)((char*)q + 0xc);
        }
    }
    if ((((ScMusictreeState*)inner)->unk4C & 0x20) == 0)
    {
        goto end;
    }
    if (((ScMusictreeState*)inner)->unk4C & 0xc0)
    {
        rcType = ObjHits_GetPriorityHitWithPosition(obj, &hr1, &hr2, &hr3, &vec[0], &vec[1], &vec[2]);
    }
    else
    {
        rcType = ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129, (int*)(inner + 0x44));
    }
    if (((CloudRunnerState*)inner)->baddie.velZ >= lbl_803E5590)
    {
        ((CloudRunnerState*)inner)->baddie.velZ = ((CloudRunnerState*)inner)->baddie.velZ - timeDelta;
    }
    if (rcType == 0) goto end;
    if (rcType == 0x11) goto end;
    if (!(((CloudRunnerState*)inner)->baddie.velZ <= lbl_803E5590)) goto end;
    if (((ScMusictreeState*)inner)->unk4C & 0xc0)
    {
        vec[0] = vec[0] + playerMapOffsetX;
        vec[2] = vec[2] + playerMapOffsetZ;
        objLightFn_8009a1dc((void*)obj, lbl_803E559C, vec2, 1, 0);
        Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
        sc_musictree_handleHitObject(obj, inner, ((ScMusictreeState*)inner)->unk4C & 0xf);
    }
    else
    {
        Sfx_PlayFromObject(obj, 0x129);
        Sfx_PlayFromObject(obj, 0x12a);
    }
    {
        f32 zero = lbl_803E5590;
        vec[0] = zero;
        vec[1] = lbl_803E55A0 * ((CloudRunnerState*)inner)->baddie.velX;
        vec[2] = zero;
        objfx_spawnRandomBurst(obj, ((ScMusictreeState*)inner)->unk4C & 0xf, 0x14, vec2,
                               lbl_803E55A4 * ((CloudRunnerState*)inner)->baddie.velX, 0);
    }
    ((ScMusictreeState*)inner)->moveStepScale = lbl_803E5588;
    ((CloudRunnerState*)inner)->baddie.velZ = lbl_803E55A8;
    if (((ScMusictreeState*)inner)->unk4C & 0x80)
    {
        int* pp;
        int idx;
        for (idx = 0, pp = (int*)inner; idx < 3; idx++)
        {
            int rc = *pp;
            if ((u32)rc != 0)
            {
                int rr = (*(int (**)(int))(*(int*)(*(int*)(rc + 0x68)) + 0x28))(rc);
                if (rr > 1)
                {
                    ObjHits_RecordObjectHit(*pp, obj, 0xe, 1, 0);
                }
            }
            pp = (int*)((char*)pp + 4);
        }
    }
end:
    {
        void* player = Obj_GetPlayerObject();
        f32 dx = ((GameObject*)obj)->anim.localPosX - ((GameObject*)player)->anim.localPosX;
        f32 dz = ((GameObject*)obj)->anim.localPosZ - ((GameObject*)player)->anim.localPosZ;
        f32 d = sqrtf(dx * dx + dz * dz);
        if ((u16)(s32)d < ((ScMusictreeState*)inner)->unk48
        )
        {
            if ((((ScMusictreeState*)inner)->unk4C & 0x10) && ((ScMusictreeState*)inner)->unk4A >= (u16)(s32)d && ((
                CloudRunnerState*)inner)->baddie.velY <= lbl_803E5590
            )
            {
                vec[0] = lbl_803E5590;
                vec[1] = lbl_803E55AC * (lbl_803E55A0 * ((CloudRunnerState*)inner)->baddie.velX);
                vec[2] = lbl_803E5590;
                objfx_spawnRandomBurst(obj, ((ScMusictreeState*)inner)->unk4C & 0xf, 0xa, vec2,
                                       lbl_803E55A4 * ((CloudRunnerState*)inner)->baddie.velX, 1);
                ((CloudRunnerState*)inner)->baddie.velY = lbl_803E55B0;
            }
            ((ScMusictreeState*)inner)->unk30 = ((ScMusictreeState*)inner)->unk30 - timeDelta;
            if (((ScMusictreeState*)inner)->unk30 <= lbl_803E5590)
            {
                vec[0] = lbl_803E5590;
                vec[1] = lbl_803E55A0 * ((CloudRunnerState*)inner)->baddie.velX;
                vec[2] = lbl_803E5590;
                vecRotateZXY(obj, vec);
                objfx_spawnRandomBurst(obj, ((ScMusictreeState*)inner)->unk4C & 0xf, 1, vec2,
                                       lbl_803E55A4 * ((CloudRunnerState*)inner)->baddie.velX, 0);
                ((ScMusictreeState*)inner)->unk30 = ((ScMusictreeState*)inner)->unk30 + lbl_803E55B4;
            }
        }
        ((ScMusictreeState*)inner)->unk4A = (s32)d;
    }
}

void sc_musictree_init(int obj, SCMusicTreeSetup* setup)
{
    extern u32 randomGetRange(int min, int max); /* #57 */
    SCMusicTreeState* state = ((GameObject*)obj)->extra;
    f32 stk[7];
    f32 ratio;
    f32 zero;

    state->animSpeed = lbl_803E5594;
    zero = lbl_803E5590;
    state->proximityBurstTimer = zero;
    state->hearRadius = (u16)((u32)setup->hearRadiusHalf << 1);
    state->flags = setup->flags;
    state->proximityCooldown = zero;
    state->scale = setup->scale;
    ((GameObject*)obj)->anim.rotZ = (s16)((setup->rotXByte - 0x7f) << 7);
    ((GameObject*)obj)->anim.rotY = (s16)((setup->rotZByte - 0x7f) << 7);
    ((GameObject*)obj)->anim.rotX = (s16)((u32)setup->yawByte << 8);
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E55B8 * setup->scale;
    ((GameObject*)obj)->unkF8 = 0;
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x2000);
    ratio = (f32)(s32)
    randomGetRange(1, 99) / lbl_803E55BC;
    ObjAnim_SetCurrentMove(obj, 0, ratio, 0);
    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E558C, *(f32*)&lbl_803E558C,
                                                                (ObjAnimEventList*)&stk);
    ObjHitbox_SetCapsuleBounds(obj, (s32)(lbl_803E55C0 * state->scale), -5, 0xff);
    if (state->flags & 0x80)
    {
        state->flags = state->flags | 0x20;
    }
}

void sc_musictree_release(void)
{
}

void sc_musictree_initialise(void)
{
}

typedef struct SCTotemPoleState
{
    u16 gameBit;
    u8 currentState;
    u8 previousState;
    f32 animSpeed;
} SCTotemPoleState;

#define SC_TOTEMPOLE_OBJECT_TYPE 0x282
#define SC_TOTEMPOLE_GAMEBIT_FRONT 0x81
#define SC_TOTEMPOLE_GAMEBIT_LEFT 0x82
#define SC_TOTEMPOLE_GAMEBIT_RIGHT 0x83
#define SC_TOTEMPOLE_GAMEBIT_REAR 0x84
#define SC_TOTEMPOLE_SETUP_REAR 0x44916
#define SC_TOTEMPOLE_SETUP_RIGHT 0x44909
#define SC_TOTEMPOLE_SETUP_FRONT 0x4490C
#define SC_TOTEMPOLE_SETUP_LEFT 0x4490F

int sc_totempole_sortCompletionGameBits(u16* bits, u16 param2);

int sc_totempole_getExtraSize(void);
int sc_totempole_getObjectTypeId(void);

void sc_totempole_free(void);

void sc_totempole_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void sc_totempole_hitDetect(void);

void sc_totempole_update(int obj);

void sc_totempole_init(int obj, int p2);

void sc_totempole_release(void);

void sc_totempole_initialise(void);

int sc_cloudrunnera_getExtraSize(void);
int sc_cloudrunnera_getObjectTypeId(void);

void sc_cloudrunnera_free(int* obj);

void sc_cloudrunnera_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void sc_cloudrunnera_hitDetect(void);

void sc_cloudrunnera_update(int obj);

void sc_cloudrunnera_init(int obj, int p2);

void sc_cloudrunnera_release(void);

void sc_cloudrunnera_initialise(void);

int fn_801DD170(void);
