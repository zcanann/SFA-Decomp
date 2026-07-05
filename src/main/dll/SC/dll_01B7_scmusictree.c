/* DLL 0x01B7 — SC music-tree objects [801DBFA0-801DC310) */
#include "main/obj_placement.h"
#include "main/dll/scmusictreesetup_struct.h"
#include "main/dll/sclevelcontrolstate_types.h"
#include "main/game_object.h"
#include "main/dll/DR/cloudrunner_state.h"
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/audio/sfx_trigger_ids.h"

#define SCMUSICTREE_OBJFLAG_HITDETECT_DISABLED 0x2000

/* placement mapIds: striking the three totem trees sets the combo bits
   sclevelcontrol watches; the three "gate" trees gate their bits on
   GAMEBIT_MUSICTREE_GATE. */
#define SC_MUSICTREE_MAP_TOTEM_1 0x30d9c
#define SC_MUSICTREE_MAP_TOTEM_2 0x30d9d
#define SC_MUSICTREE_MAP_TOTEM_3 0x30d9b
#define SC_MUSICTREE_MAP_GATE_1 0x448c2
#define SC_MUSICTREE_MAP_GATE_2 0x45178
#define SC_MUSICTREE_MAP_GATE_3 0x4517c

#define GAMEBIT_TOTEM_COMBO_1 0x7d
#define GAMEBIT_TOTEM_COMBO_2 0x7e
#define GAMEBIT_TOTEM_COMBO_3 0x7f
#define GAMEBIT_MUSICTREE_GATE 0xc44

typedef struct ScMusictreePlacement
{
    u8 pad0[0x20 - 0x0];
    u8 colorR; /* 0x20: render tint red   (passed to fn_8003B608) */
    u8 colorG; /* 0x21: render tint green */
    u8 colorB; /* 0x22: render tint blue */
    u8 pad23[0x28 - 0x23];
} ScMusictreePlacement;

typedef struct ScMusictreeSpawnAmbientEffectPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 colorR; /* 0x4: ambient particle tint red   -> setup head.color[0] */
    u8 colorG; /* 0x5: ambient particle tint green -> setup head.color[1] */
    u8 colorB; /* 0x6: ambient particle tint blue  -> setup head.color[2] */
    u8 colorA; /* 0x7: ambient particle tint alpha -> setup head.color[3] */
    u8 pad8[0x20 - 0x8];
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 pad23[0x28 - 0x23];
} ScMusictreeSpawnAmbientEffectPlacement;

/* Obj_AllocObjectSetup(0x28,...) buffer composed in sc_musictree_spawnAmbient.
 * Head is the common ObjPlacement; tail (0x18..0x27) is file-local. */
typedef struct ScMusictreeSetup
{
    ObjPlacement head; /* 0x00..0x17 */
    int unk18;         /* 0x18 */
    u16 unk1C;         /* 0x1C */
    u16 unk1E;         /* 0x1E */
    u8 unk20;          /* 0x20 */
    u8 unk21;          /* 0x21 */
    u8 unk22;          /* 0x22 */
    u8 unk23;          /* 0x23 */
    u8 unk24;          /* 0x24 */
    s8 unk25;          /* 0x25 */
    s16 unk26;         /* 0x26 */
} ScMusictreeSetup;

STATIC_ASSERT(offsetof(ScMusictreeSetup, unk18) == 0x18);
STATIC_ASSERT(offsetof(ScMusictreeSetup, unk1C) == 0x1C);
STATIC_ASSERT(offsetof(ScMusictreeSetup, unk26) == 0x26);

extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void fn_8003B608(int a, int b, int c);
extern void ObjPath_GetPointWorldPosition(int obj, int pointIndex, float* outX, float* outY, float* outZ, int useInputPosition);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int size, int objectId);
extern int randomGetRange(int lo, int hi);
extern int Obj_SetupObject(int setup, int a, int b, int c, int d);
extern void ObjHitbox_SetCapsuleBounds(int obj, int radius, int a, int b);
extern void* Obj_GetPlayerObject(void);
extern void Obj_SetModelColorFadeRecursive(int obj, int r, int g, int b, int a, int frames);
extern void objfx_spawnRandomBurst(int obj, int mode, int p3, void* vec, f32 f, int flag);
extern void vecRotateZXY(int obj, void* vec);
extern f32 sqrtf(f32 x);
extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E5588;
extern f32 lbl_803E558C;
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
STATIC_ASSERT(sizeof(SCMusicTreeSetup) == 0x24);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, rotZByte) == 0x19);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, yawByte) == 0x1A);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, hearRadiusHalf) == 0x1B);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, scale) == 0x1C);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, flags) == 0x23);

void sc_musictree_free(void)
{
}

void sc_musictree_hitDetect(void)
{
}

int sc_musictree_getExtraSize(void) { return 0x50; }
int sc_musictree_getObjectTypeId(void) { return 0x0; }

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

/* music-tree flags (setup 0x23 copied to runtime 0x4C); low nibble 0xf is a
   burst count/palette passed to the fx helpers, not individual flag bits */
#define SCMUSICTREE_FLAG_APPROACH_BURST 0x10 /* emit a burst when player crosses hearRadius */
#define SCMUSICTREE_FLAG_HIT_ACTIVE 0x20     /* run hit detection this frame */
#define SCMUSICTREE_FLAG_PRIORITY_HIT 0x40   /* use priority-hit poll + color fade path */
#define SCMUSICTREE_FLAG_SATELLITES 0x80     /* manage the 3 ambient satellite objects */

void sc_musictree_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    int* def = *(int**)&((GameObject*)obj)->anim.placementData;
    SCMusicTreeState* state = ((GameObject*)obj)->extra;
    int i;
    if (visible == 0) return;
    fn_8003B608((int)((ScMusictreePlacement*)def)->colorR, (int)((ScMusictreePlacement*)def)->colorG,
                (int)((ScMusictreePlacement*)def)->colorB);
    ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E558C);
    if ((state->flags & SCMUSICTREE_FLAG_SATELLITES) != 0)
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

#pragma dont_inline on
void sc_musictree_spawnAmbientEffect(int obj, int p2, int p3, s8 idx)
{
    int def = *(int*)&((GameObject*)obj)->anim.placementData;
    SCMusicTreeState* state = (SCMusicTreeState*)p2;
    int setup;

    if (Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(0x28, 0x210);
        ((ScMusictreeSetup*)setup)->head.color[0] = ((ScMusictreeSpawnAmbientEffectPlacement*)def)->colorR;
        ((ScMusictreeSetup*)setup)->head.color[2] = ((ScMusictreeSpawnAmbientEffectPlacement*)def)->colorB;
        ((ScMusictreeSetup*)setup)->head.color[1] = ((ScMusictreeSpawnAmbientEffectPlacement*)def)->colorG;
        ((ScMusictreeSetup*)setup)->head.color[3] = ((ScMusictreeSpawnAmbientEffectPlacement*)def)->colorA - 10;
        ((ObjPlacement*)setup)->posX = state->pathPoint[idx][0];
        ((ObjPlacement*)setup)->posY = state->pathPoint[idx][1];
        ((ObjPlacement*)setup)->posZ = state->pathPoint[idx][2];
        ((ScMusictreeSetup*)setup)->unk1C = randomGetRange(0x708, 0x1770);
        ((ScMusictreeSetup*)setup)->unk1E = 1;
        ((ScMusictreeSetup*)setup)->unk20 = 10;
        ((ScMusictreeSetup*)setup)->unk21 = 40;
        ((ScMusictreeSetup*)setup)->unk22 = 50;
        ((ScMusictreeSetup*)setup)->unk23 = 10;
        ((ScMusictreeSetup*)setup)->unk24 = 50;
        ((ScMusictreeSetup*)setup)->unk25 = -50;
        ((ScMusictreeSetup*)setup)->unk26 = -1;
        ((ScMusictreeSetup*)setup)->unk18 = 0;
        state->ambientEffect[idx] = Obj_SetupObject(setup, 5, -1, -1, *(int*)&((GameObject*)obj)->anim.parent);
    }
}
#pragma dont_inline reset

#pragma dont_inline on
void sc_musictree_handleHitObject(int p1, int p2, int effectType)
{
    int id = ((ObjPlacement*)((GameObject*)p1)->anim.placementData)->mapId;
    SCMusicTreeState* state = (SCMusicTreeState*)p2;
    (void)effectType;

    switch (id)
    {
    case SC_MUSICTREE_MAP_TOTEM_1:
        Sfx_PlayFromObject(p1, SFXTRIG_sdrstp_c);
        Sfx_PlayFromObject(p1, SFXTRIG_gland2_c);
        GameBit_Set(GAMEBIT_TOTEM_COMBO_1, 1);
        break;
    case SC_MUSICTREE_MAP_TOTEM_2:
        Sfx_PlayFromObject(p1, SFXTRIG_en_sdrstp_c);
        Sfx_PlayFromObject(p1, SFXTRIG_gland2_c);
        GameBit_Set(GAMEBIT_TOTEM_COMBO_2, 1);
        break;
    case SC_MUSICTREE_MAP_TOTEM_3:
        Sfx_PlayFromObject(p1, SFXTRIG_en_sdrstp_c_12d);
        Sfx_PlayFromObject(p1, SFXTRIG_gland2_c);
        GameBit_Set(GAMEBIT_TOTEM_COMBO_3, 1);
        break;
    case SC_MUSICTREE_MAP_GATE_1:
        if ((u32)GameBit_Get(GAMEBIT_MUSICTREE_GATE) != 0)
            GameBit_Set(0xc41, 1);
        break;
    case SC_MUSICTREE_MAP_GATE_2:
        if ((u32)GameBit_Get(GAMEBIT_MUSICTREE_GATE) != 0)
            GameBit_Set(0xc43, 1);
        break;
    case SC_MUSICTREE_MAP_GATE_3:
        if ((u32)GameBit_Get(GAMEBIT_MUSICTREE_GATE) != 0)
            GameBit_Set(0xc45, 1);
        break;
    }
    state->animSpeed = lbl_803E5588;
}
#pragma dont_inline reset

/* Alternate field view of the music-tree object's extra block used by
   sc_musictree_update (the CloudRunnerState/SCMusicTreeState families
   overlap this same 0x50-byte block). */
typedef struct ScMusictreeState
{
    u8 pad0[0x30 - 0x0];
    f32 proximityBurstTimer; /* 0x30 (aliases SCMusicTreeState.proximityBurstTimer) */
    f32 moveStepScale;       /* 0x34 (aliases SCMusicTreeState.animSpeed) */
    u8 pad38[0x48 - 0x38];
    u16 hearRadius;          /* 0x48 */
    u16 previousDistance;    /* 0x4A */
    u8 flags;                /* 0x4C */
    u8 pad4D[0x50 - 0x4D];
} ScMusictreeState;

void sc_musictree_update(int obj)
{
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
    if (((ScMusictreeState*)inner)->flags == 0)
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
    if ((((ScMusictreeState*)inner)->flags & SCMUSICTREE_FLAG_SATELLITES) && ((GameObject*)obj)->unkF8 != 0)
    {
        for (i = 0, p = (int*)inner, q = (int*)inner; i < 3; i++)
        {
            if (*(void**)p == NULL)
            {
                sc_musictree_spawnAmbientEffect(obj, inner, framesThisStep, i);
            }
            else
            {
                int r = (*(int (**)(int))(*(int*)(*(int*)&((GameObject*)*p)->anim.dll) + 0x28))(*p);
                if (r > 3)
                {
                    *p = 0;
                }
                else
                {
                    (*(void (**)(int, int))(*(int*)(*(int*)&((GameObject*)*p)->anim.dll) + 0x24))(*p, (int)q + 0xc);
                }
            }
            p = (int*)((char*)p + 4);
            q = (int*)((char*)q + 0xc);
        }
    }
    if ((((ScMusictreeState*)inner)->flags & SCMUSICTREE_FLAG_HIT_ACTIVE) == 0)
    {
        goto end;
    }
    if (((ScMusictreeState*)inner)->flags & (SCMUSICTREE_FLAG_PRIORITY_HIT | SCMUSICTREE_FLAG_SATELLITES))
    {
        rcType = ObjHits_GetPriorityHitWithPosition(obj, &hr1, &hr2, (u32*)&hr3, &vec[0],
                                                    &vec[1], &vec[2]);
    }
    else
    {
        rcType = ObjHits_PollPriorityHitEffectWithCooldown(obj, 8, 0xff, 0xff, 0x78, 0x129,
                                                           (f32*)(inner + 0x44));
    }
    if (((CloudRunnerState*)inner)->baddie.velZ >= lbl_803E5590)
    {
        ((CloudRunnerState*)inner)->baddie.velZ = ((CloudRunnerState*)inner)->baddie.velZ - timeDelta;
    }
    if (rcType == 0) goto end;
    if (rcType == 0x11) goto end;
    if (!(((CloudRunnerState*)inner)->baddie.velZ <= lbl_803E5590)) goto end;
    if (((ScMusictreeState*)inner)->flags & (SCMUSICTREE_FLAG_PRIORITY_HIT | SCMUSICTREE_FLAG_SATELLITES))
    {
        vec[0] = vec[0] + playerMapOffsetX;
        vec[2] = vec[2] + playerMapOffsetZ;
        objLightFn_8009a1dc((void*)obj, lbl_803E559C, vec2, 1, 0);
        Obj_SetModelColorFadeRecursive(obj, 0xf, 0xc8, 0, 0, 1);
        sc_musictree_handleHitObject(obj, inner, ((ScMusictreeState*)inner)->flags & 0xf);
    }
    else
    {
        Sfx_PlayFromObject(obj, SFXTRIG_swdtest222);
        Sfx_PlayFromObject(obj, SFXTRIG_gland2_c);
    }
    {
        f32 zero = lbl_803E5590;
        vec[0] = zero;
        vec[1] = lbl_803E55A0 * ((CloudRunnerState*)inner)->baddie.velX;
        vec[2] = zero;
        objfx_spawnRandomBurst(obj, ((ScMusictreeState*)inner)->flags & 0xf, 0x14, vec2,
                               lbl_803E55A4 * ((CloudRunnerState*)inner)->baddie.velX, 0);
    }
    ((ScMusictreeState*)inner)->moveStepScale = lbl_803E5588;
    ((CloudRunnerState*)inner)->baddie.velZ = lbl_803E55A8;
    if (((ScMusictreeState*)inner)->flags & SCMUSICTREE_FLAG_SATELLITES)
    {
        int* pp;
        int idx;
        for (idx = 0, pp = (int*)inner; idx < 3; idx++)
        {
            int rc = *pp;
            if ((u32)rc != 0)
            {
                int rr = (*(int (**)(int))(*(int*)(*(int*)&((GameObject*)rc)->anim.dll) + 0x28))(rc);
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
        u16 di = d;
        if (di < ((ScMusictreeState*)inner)->hearRadius
        )
        {
            if ((((ScMusictreeState*)inner)->flags & SCMUSICTREE_FLAG_APPROACH_BURST)
                && ((ScMusictreeState*)inner)->previousDistance >= ((ScMusictreeState*)inner)->hearRadius && ((
                CloudRunnerState*)inner)->baddie.velY <= lbl_803E5590
            )
            {
                vec[0] = lbl_803E5590;
                vec[1] = lbl_803E55AC * (lbl_803E55A0 * ((CloudRunnerState*)inner)->baddie.velX);
                vec[2] = lbl_803E5590;
                objfx_spawnRandomBurst(obj, ((ScMusictreeState*)inner)->flags & 0xf, 0xa, vec2,
                                       lbl_803E55A4 * ((CloudRunnerState*)inner)->baddie.velX, 1);
                ((CloudRunnerState*)inner)->baddie.velY = lbl_803E55B0;
            }
            ((ScMusictreeState*)inner)->proximityBurstTimer = ((ScMusictreeState*)inner)->proximityBurstTimer - timeDelta;
            if (((ScMusictreeState*)inner)->proximityBurstTimer <= lbl_803E5590)
            {
                f32* rv;
                *(rv = &vec[0]) = lbl_803E5590;
                vec[1] = lbl_803E55A0 * ((CloudRunnerState*)inner)->baddie.velX;
                vec[2] = lbl_803E5590;
                vecRotateZXY(obj, rv);
                objfx_spawnRandomBurst(obj, ((ScMusictreeState*)inner)->flags & 0xf, 1, vec2,
                                       lbl_803E55A4 * ((CloudRunnerState*)inner)->baddie.velX, 0);
                ((ScMusictreeState*)inner)->proximityBurstTimer = ((ScMusictreeState*)inner)->proximityBurstTimer + lbl_803E55B4;
            }
        }
        ((ScMusictreeState*)inner)->previousDistance = di;
    }
}

void sc_musictree_init(int obj, SCMusicTreeSetup* setup)
{
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
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | SCMUSICTREE_OBJFLAG_HITDETECT_DISABLED);
    ratio = (f32)(s32)
    randomGetRange(1, 99) / lbl_803E55BC;
    ObjAnim_SetCurrentMove(obj, 0, ratio, 0);
    ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(obj, lbl_803E558C, *(f32*)&lbl_803E558C,
                                                                (ObjAnimEventList*)&stk);
    ObjHitbox_SetCapsuleBounds(obj, (s32)(lbl_803E55C0 * state->scale), -5, 0xff);
    if (state->flags & SCMUSICTREE_FLAG_SATELLITES)
    {
        state->flags = state->flags | SCMUSICTREE_FLAG_HIT_ACTIVE;
    }
}

void sc_musictree_release(void)
{
}

void sc_musictree_initialise(void)
{
}
