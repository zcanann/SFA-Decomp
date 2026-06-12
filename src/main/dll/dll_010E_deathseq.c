/* === moved from main/dll/CF/CFtoggleswitch.c [8018BC48-8018BC50) (TU re-split, docs/boundary_audit.md) === */
#include "main/objseq.h"

typedef struct TrickyguardspotPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    s16 unk1E;
} TrickyguardspotPlacement;


typedef struct MagiccavetopPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s8 unk20;
    s8 unk21;
    u8 pad22[0x28 - 0x22];
} MagiccavetopPlacement;


typedef struct MagiccavetopObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s8 unk20;
    s8 unk21;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} MagiccavetopObjectDef;


typedef struct MagiccavetopState
{
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    u8 pad2[0x4 - 0x2];
    f32 unk4;
    u8 pad8[0xC - 0x8];
} MagiccavetopState;


extern uint GameBit_Get(int eventId);
extern undefined4 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern int ObjGroup_FindNearestObject();
extern int ObjTrigger_IsSet();

extern ObjectTriggerInterface** gObjectTriggerInterface;
extern f64 DOUBLE_803e4908;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803e48b8;
extern f32 FLOAT_803e48c0;
extern f32 FLOAT_803e48c4;
extern f32 FLOAT_803e48c8;
extern f32 FLOAT_803e48cc;
extern f32 FLOAT_803e48d0;
extern f32 FLOAT_803e48d4;
extern f32 FLOAT_803e48d8;
extern f32 FLOAT_803e48dc;
extern f32 FLOAT_803e48e0;
extern f32 FLOAT_803e48e4;
extern f32 FLOAT_803e48e8;
extern f32 FLOAT_803e48ec;
extern f32 FLOAT_803e48f0;
extern f32 FLOAT_803e48f4;
extern f32 FLOAT_803e48f8;
extern f32 FLOAT_803e48fc;
extern f32 FLOAT_803e4900;
extern f32 FLOAT_803e4904;


/*
 * --INFO--
 *
 * Function: FUN_8018af28
 * EN v1.0 Address: 0x8018AF28
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8018AF64
 * EN v1.1 Size: 84b
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
 * Function: FUN_8018b220
 * EN v1.0 Address: 0x8018B220
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018B230
 * EN v1.1 Size: 228b
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
 * Function: FUN_8018b224
 * EN v1.0 Address: 0x8018B224
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8018B314
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

extern int* getTrickyObject(void);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern void objRenderFn_80041018(int obj);
extern u8 framesThisStep;

#define TRICKY_GUARD_SPOT_VTABLE(tricky) \
    (*(TrickyGuardSpotInterfaceVTable **)((tricky)->dll))


/* 8b "li r3, N; blr" returners. */
int deathgas_getExtraSize(void);

/* ObjGroup_RemoveObject(x, N) wrappers. */

extern void objSetHintTextIdx(int obj, int idx);


void infotext_init(int obj, s8* def);

void cctestinfot_init(int obj, s8* def);

extern int playerIsDisguised(void);
extern void Obj_SetActiveModelIndex(int* obj, int idx);
extern u8 fn_801334E0(void);
extern void showHelpText(s16 id);
extern f32 timeDelta;
extern f32 lbl_803E3C88;
extern f32 lbl_803E3C8C;

void cctestinfot_update(int* obj);

extern int* ObjModel_GetRenderOpTextureRefs(int model, int idx);
extern f32 lbl_803E3C4C;

void magiccavetop_init(int* obj, s8* def);

extern void stopRumble2(void);
extern void* fn_802966CC(void* player);
extern void staffSetGlow(void* a, int b, int c);
extern int mapGetDirIdx(int mapId);
extern void mapUnload(int idx, int flags);

void magiccavetop_free(int* obj);

extern void envFxActFn_800887f8(int a);
extern void getEnvfxAct(int* obj, int* target, int id, int p);
extern void Music_Trigger(int a, int b);
extern void setAButtonIcon(int idx);
extern void warpToMap(int mapId, int b);


extern f32 lbl_803E3C80;
extern f32 lbl_803E3C84;

void infotext_update(int obj);

extern int loadMapAndParent(int mapId);
extern void unlockLevel(int a, int b, int c);
extern void lockLevel(int idx, int b);
extern void stopRumble(void);
extern void doRumble(f32 v);
extern void Sfx_PlayFromObject(int* obj, int sfxId);
extern void objfx_spawnArcedBurst(int* obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 sx, f32 sy, f32 sz,
                                  void* args, int a);
extern f32 lbl_803E3C30;
extern f32 lbl_803E3C34;
extern f32 lbl_803E3C38;
extern f32 lbl_803E3C3C;
extern f32 lbl_803E3C40;
extern f32 lbl_803E3C44;
extern f32 lbl_803E3C48;
extern f32 lbl_803E3C50;
extern f32 lbl_803E3C54;
extern f32 lbl_803E3C58;
extern f32 lbl_803E3C5C;
extern f32 lbl_803E3C60;
extern f32 lbl_803E3C64;
extern f32 lbl_803E3C68;
extern f32 lbl_803E3C6C;

typedef struct MagicCaveTopFxArgs
{
    u8 pad[12];
    f32 x;
    f32 y;
    f32 z;
} MagicCaveTopFxArgs;

void magiccavetop_update(int* obj);

#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/objanim_internal.h"
#include "main/dll/CF/CFforcecontrol.h"
#include "main/screen_transition.h"


extern u32 randomGetRange(int min, int max);
extern undefined4 ObjHits_RecordObjectHit();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern void GXSetAlphaCompare(int comp0, int ref0, int op, int comp1, int ref1);
extern void GXSetBlendMode(int type, int srcFactor, int dstFactor, int op);
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();

extern f64 DOUBLE_803e4910;
extern f64 DOUBLE_803e4950;
extern f64 DOUBLE_803e4998;
extern f32 FLOAT_803e4918;
extern f32 FLOAT_803e491c;
extern f32 FLOAT_803e4920;
extern f32 FLOAT_803e4924;
extern f32 FLOAT_803e4928;
extern f32 FLOAT_803e492c;
extern f32 FLOAT_803e4930;
extern f32 FLOAT_803e4934;
extern f32 FLOAT_803e4938;
extern f32 FLOAT_803e493c;
extern f32 FLOAT_803e4940;
extern f32 FLOAT_803e4944;
extern f32 FLOAT_803e4948;
extern f32 FLOAT_803e494c;
extern f32 FLOAT_803e4960;
extern f32 FLOAT_803e4964;
extern f32 FLOAT_803e4968;
extern f32 FLOAT_803e496c;
extern f32 FLOAT_803e4970;
extern f32 FLOAT_803e4974;
extern f32 FLOAT_803e4978;
extern f32 FLOAT_803e497c;
extern f32 FLOAT_803e4980;
extern f32 FLOAT_803e4984;
extern f32 FLOAT_803e4988;
extern f32 FLOAT_803e498c;
extern f32 FLOAT_803e4990;
extern f32 FLOAT_803e49a0;
extern f32 FLOAT_803e49a4;
extern f32 FLOAT_803e49a8;

/*
 * --INFO--
 *
 * Function: deathgas_free
 * EN v1.0 Address: 0x8018BC50
 * EN v1.0 Size: 192b
 * EN v1.1 Address: 0x8018BC64
 * EN v1.1 Size: 208b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern s16* Camera_GetCurrentViewSlot(void);
extern ScreenTransitionInterface** gScreenTransitionInterface;
extern void setScreenTransitionPause(int v);
extern void addButtonObject(int* obj);
extern f32 lbl_803E3D1C;
extern f32 lbl_803E3D58;
extern f32 lbl_803E3D2C;

void deathseq_init(int* obj)
{
    f32* state = ((GameObject*)obj)->extra;
    s16* cam = Camera_GetCurrentViewSlot();
    f32 f;

    setScreenTransitionPause(1);
    (*gScreenTransitionInterface)->start(1, 1);
    ObjAnim_SetCurrentMove((int)obj, 0x8e, lbl_803E3D1C, 0);
    state[0] = lbl_803E3D58;
    state[1] = ((GameObject*)cam)->anim.localPosX;
    state[2] = ((GameObject*)cam)->anim.localPosY;
    state[3] = ((GameObject*)cam)->anim.localPosZ;
    *(int*)(state + 6) = cam[0];
    *(int*)(state + 7) = cam[1];
    f = lbl_803E3D2C;
    state[4] = f;
    state[5] = f;
    addButtonObject(obj);
    ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x400);
}


/* Trivial 4b 0-arg blr leaves. */
void deathseq_render(void)
{
}

void deathseq_hitDetect(void)
{
}

void deathseq_release(void)
{
}

void deathseq_initialise(void)
{
}

void dll_127_free_nop(void);

void dll_127_hitDetect_nop(void);

/* 8b "li r3, N; blr" returners. */
int fuelcell_getExtraSize(void);
int deathseq_getExtraSize(void) { return 0x24; }
int deathseq_getObjectTypeId(void) { return 0x0; }
int dll_127_getExtraSize_ret_0(void);
int dll_127_getObjectTypeId(void);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3D60;
extern void objRenderFn_8003b8f4(f32);

void dll_127_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

/* Drift-recovery: add new fns with v1.0 names. */
extern void setPendingMapLoad(int v);
extern void removeButtonObject(int* obj);
extern void ObjModel_SetPostRenderCallback(void* model, void* cb);
extern f32 lbl_803E3CC0;
extern void mm_free_(void* ptr);

typedef struct
{
    f32 timer; // 0x0
    f32 hitTimer; // 0x4
    f32 radius; // 0x8
    u8 fogOn : 1; // 0xc bit 7
    u8 draining : 1; // bit 6
    u8 noFog : 1; // bit 5
} DeathGasState;

typedef struct
{
    u8 pad[0x18];
    u8 drainRate; // 0x18
    u8 fillRate; // 0x19
    s16 activeBit; // 0x1a
} DeathGasSetup;

typedef struct
{
    u16 msg; // 0x0
    u8 pad[0x5a];
    u8 lit : 1; // 0x5c bit 7
    u8 grabbed : 1; // bit 6
    u8 unkBit5 : 1; // bit 5
    u8 resetPos : 1; // bit 4
} FuelcellState;

typedef struct
{
    u8 pad[8];
    f32 homeX; // 0x8
    f32 homeY; // 0xc
    f32 homeZ; // 0x10
    u8 pad2[0xa];
    s16 offBit; // 0x1e
    s16 onBit; // 0x20
} FuelcellSetup;


void deathseq_free(int* obj)
{
    setScreenTransitionPause(0);
    setPendingMapLoad(0);
    removeButtonObject(obj);
}

void deathgas_init(int* obj);

int fuelcell_func0B(int* obj);

void fuelcell_modelMtxFn(u8* model);

void fuelcell_free(int* obj);

void fuelcell_init(int* obj);

extern void disableHeavyFog(void);

void deathgas_free(int* obj);

extern f32 Vec_distance(void* a, void* b);
extern void enableHeavyFog(f32 top, f32 bottom, f32 r, f32 g, f32 b, int p6);
extern f32 lbl_803E3C90;
extern f32 lbl_803E3C94;
extern f32 lbl_803E3C98;
extern f32 lbl_803E3C9C;
extern f32 lbl_803E3CA0;
extern f32 lbl_803E3CA4;
extern f32 lbl_803E3CA8;
extern f32 lbl_803E3CAC;
extern f32 lbl_803E3CB0;
extern f32 lbl_803E3CB4;

void deathgas_update(int* obj);

extern void gameBitIncrement(int eventId);
extern void Sfx_AddLoopedObjectSound(int* obj, int soundId);
extern void Sfx_RemoveLoopedObjectSound(int* obj, int soundId);
extern void Sfx_PlayFromObject(int* obj, int soundId);
extern f32 getXZDistance(void* a, void* b);
extern f32 lbl_803E3D08;
extern f32 lbl_803E3D0C;
extern f32 lbl_803E3D10;

void fuelcell_update(int* obj);

extern void objfx_spawnDirectionalBurst(int* obj, int idx, f32 scale, int b, int c, int d, f32 speed, int e, int f);
extern int ObjModel_GetRenderOp(int model, int idx);
extern void lightningRender(void* particle);
extern int getHudHiddenFrameCount(void);
extern int lightningCreate(float* start, float* end, f32 radiusX, f32 radiusY, int param_5, int param_6, int param_7);
extern f32 lbl_803E3CC8;
extern f32 lbl_803E3CCC;
extern f32 lbl_803E3CD0;
extern f32 lbl_803E3CD4;
extern f32 lbl_803E3CD8;
extern f32 lbl_803E3CDC;
extern f32 lbl_803E3CE0;
extern f32 lbl_803E3CE4;
extern f32 lbl_803E3CE8;
extern f32 lbl_803E3CEC;
extern f32 lbl_803E3CF0;
extern f32 lbl_803E3CF4;
extern f32 lbl_803E3CF8;

typedef struct
{
    u8 pad0[0xc];
    f32 pos[3]; // 0xc
    f32 pos2[3]; // 0x18
} GameObjPos;

#pragma opt_loop_invariants off
void fuelcell_render(int* obj, int p2, int p3, int p4, int p5);
#pragma opt_loop_invariants reset

typedef struct
{
    f32 timer; // 0x0
    f32 camX; // 0x4
    f32 camY; // 0x8
    f32 camZ; // 0xc
    f32 dist; // 0x10
    f32 distTarget; // 0x14
    int camRotY; // 0x18
    int camRotX; // 0x1c
    u8 menuShown : 1; // 0x20 bit 7
    u8 camActive : 1; // bit 6
    u8 transitionStarted : 1; // bit 5
} DeathSeqState;

extern int fn_80296C5C(void);
extern void fn_80296C6C(int* player, int v);
extern void AudioStream_StopCurrent(void);
extern void AudioStream_StartPrepared(void);
extern void AudioStream_Play(int streamId, void* cb);
extern int* objFindTexture(int* obj, int idx, int p3);
extern void cutsceneFadeInOut(int v);
extern void Obj_FreeObject(int* obj);
extern void showDeathMenu(void);
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern f32 interpolate(f32 cur, f32 target, f32 t);
extern void Camera_SetFovY(f32 fov);
extern void Rcp_SetViewFinderHudEnabled(int v);
extern f32 lbl_803E3D18;
extern f32 lbl_803E3D20;
extern f32 lbl_803E3D24;
extern f32 lbl_803E3D28;
extern f32 lbl_803E3D30;
extern f32 lbl_803E3D34;
extern f32 lbl_803E3D38;
extern f32 lbl_803E3D3C;
extern f32 lbl_803E3D40;
extern f32 lbl_803E3D44;
extern f32 lbl_803E3D48;

void deathseq_update(int* obj)
{
    extern int* Obj_GetPlayerObject(void);
    s16* cam = Camera_GetCurrentViewSlot();
    DeathSeqState* state = ((GameObject*)obj)->extra;
    int ready;
    int* player = Obj_GetPlayerObject();
    int* tex;

    ready = 0;
    if (fn_80296C5C() != 0)
    {
        state->distTarget = lbl_803E3D18;
        if (((GameObject*)obj)->anim.currentMove != 0x92)
        {
            AudioStream_StopCurrent();
            AudioStream_Play(0x51e1, (void*)AudioStream_StartPrepared);
            ObjAnim_SetCurrentMove((int)obj, 0x92, lbl_803E3D1C, 0);
        }
        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E3D20, timeDelta, NULL);
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E3D24)
        {
            tex = objFindTexture(obj, 5, 0);
            *tex = 0;
            tex = objFindTexture(obj, 4, 0);
            *tex = 0;
        }
        if (((GameObject*)obj)->anim.currentMoveProgress >= lbl_803E3D28)
        {
            if (!state->transitionStarted)
            {
                setScreenTransitionPause(0);
                (*gScreenTransitionInterface)->step(10, 1);
                state->transitionStarted = 1;
            }
            if ((*gScreenTransitionInterface)->isFinished() != 0)
            {
                if (player != NULL)
                {
                    fn_80296C6C(player, 0);
                }
                cutsceneFadeInOut(0);
                setPendingMapLoad(0);
                Obj_FreeObject(obj);
            }
        }
        else
        {
            ready = 1;
        }
    }
    else
    {
        state->distTarget = lbl_803E3D2C;
        if ((*gScreenTransitionInterface)->isFinished() != 0)
        {
            ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E3D20, timeDelta, NULL);
            ready = 1;
        }
        if (((GameObject*)obj)->anim.currentMoveProgress > lbl_803E3D24)
        {
            tex = objFindTexture(obj, 5, 0);
            *tex = 0x200;
            tex = objFindTexture(obj, 4, 0);
            *tex = 0x200;
        }
        state->timer -= timeDelta;
        if (state->timer <= *(f32*)&lbl_803E3D1C)
        {
            state->timer = lbl_803E3D1C;
            if (!state->menuShown)
            {
                showDeathMenu();
                state->menuShown = 1;
            }
        }
    }

    if (ready != 0)
    {
        f32 cos30 = mathSinf(lbl_803E3D30);
        f32 sin30 = mathCosf(lbl_803E3D30);
        f32 sin34 = mathCosf(lbl_803E3D34);
        f32 cos34 = mathSinf(lbl_803E3D34);
        f32 xTerm;
        f32 negSin;
        f32 fz;
        f32 zTerm;
        f32 dz = state->dist * cos34;
        sin34 = state->dist * sin34;
        sin30 = sin34 * sin30;
        sin34 = sin34 * cos30;
        cam[0] = 0x2000;
        cam[1] = 0x1000;
        xTerm = lbl_803E3D38 * -mathSinf((lbl_803E3D3C * (f32) * (s16*)obj) / lbl_803E3D40);
        negSin = -mathCosf((lbl_803E3D3C * (f32) * (s16*)obj) / lbl_803E3D40);
        zTerm = (fz = lbl_803E3D38) * negSin;
        ((GameObject*)cam)->anim.localPosX = sin30 + (((GameObject*)obj)->anim.worldPosX + xTerm);
        ((GameObject*)cam)->anim.localPosY = (fz + ((GameObject*)obj)->anim.worldPosY) + dz;
        ((GameObject*)cam)->anim.localPosZ = sin34 + (((GameObject*)obj)->anim.worldPosZ + zTerm);
        Camera_SetFovY(lbl_803E3D44);
        state->camActive = 1;
        state->dist += interpolate(state->distTarget - state->dist, lbl_803E3D48, timeDelta);
        Rcp_SetViewFinderHudEnabled(0);
    }
    else
    {
        cam[0] = state->camRotY;
        cam[1] = state->camRotX;
        ((GameObject*)cam)->anim.localPosX = state->camX;
        ((GameObject*)cam)->anim.localPosY = state->camY;
        ((GameObject*)cam)->anim.localPosZ = state->camZ;
        state->camActive = 0;
    }

    if (state->camActive)
    {
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags & ~0x4000;
    }
    else
    {
        ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags | 0x4000;
    }
}
