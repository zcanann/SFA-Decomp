/*
 * DLL 0x150 - GCRobotLight (retail object name "GCRobotLigh[t]"), the
 * electric scanning-beam of CloudRunner Fortress. It is spawned as the
 * child of a GCRobotPatrol robot (the patrolling enemy run by
 * dll_00C9_enemy.c, placed in CloudRunner Fortress / fortress.romlist):
 * gcrobotlightbea_update aims a point light along a traced vector (the
 * beam) and gcrobotlightbea_hitDetect flags "player caught in the beam"
 * (hitFlags 0x80) unless playerIsDisguised - the sharp-claw disguise
 * fools it; the parent robot reads this child's hit result to react.
 * "GC" = GameCube: Rare's prefix for content reworked/added when the N64
 * "Dinosaur Planet" became the GameCube Star Fox Adventures (the GCRobot
 * family + GCbaddieShip, the GCrubble/GCpillar destructibles, and the
 * reworked GCRF_* CloudRunner Fortress sequences all carry it).
 *
 * This file is part of the sandwormBoss 10-DLL container (0x14A
 * CFPowerBase .. 0x157 SpiritDoorSpirit) covering [8019D578-801A0B14).
 * DLLs 0x148/0x149 are defined in DR/dll_0148_cfguardian.c and
 * DR/dll_0149_cfwindlift.c; their prototypes appear here.
 */
#include "main/dll/cfguardian_state.h"
#include "main/dll/bit80_struct.h"
#include "main/dll/cfprisonunclestate_struct.h"
#include "main/dll/gcrobotlightbeastate_struct.h"
#include "main/dll/cfprisonguardstate_struct.h"
#include "main/dll/cfpowerbasestate_struct.h"
#include "main/dll/cfmaincrystalstate_types.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/DR/sandwormBoss.h"
#include "main/dll/modgfx.h"
#include "main/sky_state.h"
extern u32 ObjHits_SetHitVolumeSlot();
extern u32 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern u32 ObjLink_DetachChild();
extern void* Obj_GetPlayerObject(void);
extern void objBboxFn_800640cc(f32* p0, f32* p1, int p5, int* out, int* self, int p8, int p9, int slot, f32 f, u8 arg8);
extern void modelLightStruct_freeSlot(int* p);
extern f32 lbl_80322C38[];
extern f32 lbl_803DBE58;
extern f32 lbl_803DBE5C;
extern void* modelLightStruct_createPointLight(int unused, u8 red, u8 green, u8 blue, u8 setFlag);
extern void modelLightStruct_setDistanceAttenuation(u8* obj, f32 a, f32 b);
extern void modelLightStruct_setPosition(void* light, f32 x, f32 y, f32 z);
extern void Obj_TransformLocalVectorByWorldMatrix(void* obj, f32* src, f32* dst);
extern void voxmaps_traceScaledVectorEnd(f32* dst, void* posA, f32* dir, f32 factor);
extern f32 PSVECDistance(void* a, void* b);
extern void PSVECScale(void* in, void* out, f32 scale);
extern void modelLightStruct_setDiffuseColor(void* p, int r, int g, int b, int a);

/* Per-object extra state for the baby CloudRunner
 * (babycloudrunner_getExtraSize == 0x248). */
typedef struct BabyCloudRunnerState
{
    f32 unk00;
    u8 pad04[0x38]; /* 0x18: position used for the sandworm handoff */
    u8 lookBlock[0x30]; /* 0x3c: fn_8003ADC4 head-track block */
    u8 audioBlock[0x3c]; /* 0x6c: objAudioFn block */
    f32 animSpeed;
    f32 scale; /* 0xac: copied to the linked object's scale */
    int unkB0;
    int unkB4;
    int unkB8;
    int unkBC;
    int turnLatch; /* 0xc0: sandworm_turnTowardTargetAnim turn/idle move latch */
    int behaviourState; /* 0xc4: def[0x1c]; SeqFn 0..0xb dispatch */
    u8 padC8[4];
    int unkCC;
    s16 roostYaw; /* 0xd0: heading captured at init */
    u8 padD2[0x42];
    void* linkedObj; /* 0x114 */
    u8 pad118[0xc];
    u8 curveWalker[0x108]; /* 0x124: rom-curve follow block */
    u8 flags22C; /* 1 = alive/active */
    u8 pad22D[3];
    int runnerState; /* 0x230: 0 curve-seek, 1 follow, 2 chased, 3 freed */
    int runnerIndex; /* 0x234: gamebit base index, -1 keyed off */
    f32 countdownTimer; /* 0x238 */
    f32 curveSpeed; /* 0x23c */
    void* mutterSfxTable; /* 0x240 */
    u8 spitFlags; /* 0x244: BabyCloudrunnerFlags / WormSpitByte overlay */
    u8 pad245[3];
} BabyCloudRunnerState;

STATIC_ASSERT(sizeof(BabyCloudRunnerState) == 0x248);


/* Per-object extra state for the CloudRunner guardian
 * (cfguardian_getExtraSize == 0xa9c). */
STATIC_ASSERT(sizeof(CfGuardianState) == 0xa9c);

/* Per-object extra state for the CloudRunner main crystal
 * (cfmaincrystal_getExtraSize == 0x160). */

STATIC_ASSERT(sizeof(CfMainCrystalState) == 0x160);

/* Per-object extra state for the CloudRunner power base
 * (cfpowerbase_getExtraSize == 0x6). */

STATIC_ASSERT(sizeof(CfPowerBaseState) == 0x6);

/* Per-object extra state for the CloudRunner prison guard
 * (cfprisonguard_getExtraSize == 0x3c). */

STATIC_ASSERT(sizeof(CfPrisonGuardState) == 0x3c);

/* Per-object extra state for the CloudRunner prison uncle
 * (cfprisonuncle_getExtraSize == 0xa8). */

STATIC_ASSERT(sizeof(CfPrisonUncleState) == 0xa8);

/* Per-object extra state for the robot light beacon
 * (gcrobotlightbea_getExtraSize == 0xc). */

STATIC_ASSERT(sizeof(GcRobotLightBeaState) == 0xc);

#pragma scheduling off
#pragma peephole off

u32 fn_801A0174(int* obj) { return (((GcRobotLightBeaState*)(int*)((GameObject*)obj)->extra)->hitFlags >> 7) & 1; }

int gcrobotlightbea_getExtraSize(void) { return 0xc; }
int gcrobotlightbea_getObjectTypeId(void) { return 0x0; }

void gcrobotlightbea_free(int* obj)
{
    GcRobotLightBeaState* state = ((GameObject*)obj)->extra;
    if (state->light != NULL)
    {
        modelLightStruct_freeSlot((int*)state);
    }
    if (((GameObject*)obj)->ownerObj != NULL)
    {
        ObjLink_DetachChild(((GameObject*)obj)->ownerObj, obj);
    }
}

void gcrobotlightbea_render(void)
{
}

/* EN v1.0 0x801A01E8  size: 296b  gcrobotlightbea_hitDetect: clear the hit
 * flag, then re-set it only if the priority hit is the (undisguised) player
 * and lands inside the beacon's bounding box. */
void gcrobotlightbea_hitDetect(int obj)
{
    float out[22];
    f32 vec[3];
    void* hit;
    GcRobotLightBeaState* sub = ((GameObject*)obj)->extra;
    ((Bit80*)&sub->hitFlags)->top = 0;
    if (((GameObject*)obj)->ownerObj == NULL) return;
    if (ObjHits_GetPriorityHit(obj, &hit, 0, 0) == 0)
    {
        hit = (void*)(*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->lastHitObject;
        if (hit == NULL) return;
    }
    if (hit != Obj_GetPlayerObject()) return;
    if (playerIsDisguised(hit) != 0) return;
    vec[0] = ((ObjHitsPriorityState*)hit)->primaryRadiusSquared;
    vec[1] = 10.0f + ((ObjHitsPriorityState*)hit)->localPosX;
    vec[2] = ((ObjHitsPriorityState*)hit)->localPosY;
    if (voxmaps_traceWorldLine((void*)((char*)obj + 0xc), vec) == 0) return;
    if (((GameObject*)obj)->unkF4 != 0 ||
        ((int (*)(int, f32*, f32, int, f32*, int, int, int, int, int))objBboxFn_800640cc)(obj + 0xc, vec, 1.0f, 0, out, obj, 4, -1, 0, 0) == 0)
    {
        ((Bit80*)&sub->hitFlags)->top = 1;
    }
}

void gcrobotlightbea_update(int* obj)
{
    GcRobotLightBeaState* sub;
    f32 vec[3];
    f32 vec2[3];
    u8 r_byte, g_byte, b_byte;

    sub = ((GameObject*)obj)->extra;
    if (sub->light == NULL)
    {
        sub->light = modelLightStruct_createPointLight((int)obj, 0xfa, 0xfa, 0xfa, 1);
        if (sub->light != NULL)
        {
            modelLightStruct_setDistanceAttenuation(sub->light, lbl_803DBE58, 12.0f + lbl_803DBE58);
        }
    }
    ObjHits_SetHitVolumeSlot(obj, 0x17, 0, 0);
    vec[0] = lbl_80322C38[0];
    vec[1] = lbl_80322C38[1];
    vec[2] = lbl_80322C38[2];
    Obj_TransformLocalVectorByWorldMatrix(obj, lbl_80322C38, vec);
    voxmaps_traceScaledVectorEnd(vec2, obj + 3, vec, lbl_803DBE5C);
    PSVECScale(lbl_80322C38, vec2, PSVECDistance((char*)obj + 0xc, vec2));
    getAmbientColor(0, &r_byte, &g_byte, &b_byte);
    if (sub->light != NULL)
    {
        modelLightStruct_setDiffuseColor(sub->light,
                                         (s32)(0.7f * (f32)(u32)r_byte),
                                         (s32)(0.7f * (f32)(u32)g_byte),
                                         (s32)(0.7f * (f32)(u32)b_byte),
                                         0xff);
        modelLightStruct_setPosition(sub->light, vec2[0], vec2[1], vec2[2]);
    }
}

void gcrobotlightbea_init(int* obj)
{
    GcRobotLightBeaState* state = ((GameObject*)obj)->extra;
    state->light = 0;
    state->unk4 = 0;
    ObjHits_EnableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0x80;
}

void gcrobotlightbea_release(void)
{
}

void gcrobotlightbea_initialise(void)
{
}
