/*
 * DLL 0xE2 - the player staff weapon DLL plus the spell/weapon objects it
 * ships alongside (object type 0x9 = gStaffObjDescriptor).
 *
 * The staff drives a procedural swipe trail (staff_setupSwipe builds vertex
 * strips from the weapon's per-frame da-table via B-spline interpolation;
 * staffDrawSwipe / staff_update render and age them through GXWGFifo) and the
 * ground-quake spell (staffStartQuakeSpell / staffDrawQuakeSpellRing create and
 * draw a scaled torus and shake the camera; staffUpdateAttackEffects spawns
 * per-frame particle bursts keyed by the player's current move and charge
 * level). staff_hitDetectGeometry plays per-surface impact sfx/water splashes
 * from the contact hit-volume index, and the grow/shrink lock-on animation is
 * in staffDoGrowShrinkAnim.
 *
 */
#include "dlls/objects/226.h"
#include "main/model.h"
#include "dolphin/mtx.h"
#include "main/texture.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_trig_api.h"
#include "main/shader_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "game/objects/object_setup.h"
#include "game/objects/object.h"
#include "string.h"
#include "sys/objects/lifecycle.h"
#include "main/dll/player_api.h"
#include "main/objfx.h"
#include "sys/objects.h"
#include "main/mm.h"
#include "main/audio/sfx_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/waterfx_interface.h"
#include "main/resource.h"
#include "main/objHitReact.h"
#include "main/objhits.h"
#include "main/gamebits.h"
#include "main/camera.h"
#include "main/curve.h"
#include "dolphin/gx/GXDraw.h"
#include "dolphin/gx/GXEnum.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/frame_timing.h"
#include "main/rcp_dolphin_api.h"
#include "track/intersect_texture_api.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/hud_visibility_api.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_geom_api.h"
#include "track/intersect_render_setup_api.h"
#include "main/dll/partfx_interface.h"

extern Texture* gStaffSwipeTextures[2];
extern StaffCollisionInterface** gStaffSwipeResource;

#define STAFF_CONTACT_HIT_VOLUME_COUNT 36

/* Hit-volume-indexed staff impact SFX ids; zero entries are filled at initialisation. */
static s16 sStaffContactSfxIds[STAFF_CONTACT_HIT_VOLUME_COUNT] = {
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C2, 0x006F, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};

/* Hit-volume-indexed entries in gStaffSwipeColorTable. */
static u8 sStaffContactColorIndices[STAFF_CONTACT_HIT_VOLUME_COUNT] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
};

s16 sStaffSwipeTextureIdTable[4] = {0xC7F, 0x3EC, 0, 0};
#define STAFF_QUAKE_HIT_VOLUME_SLOT 17

/* object group the staff joins while active */
#define STAFF_OBJGROUP 7
/* quake-spell effect object (cached into StaffQuakeSpellState.object by superQuake) */
#define STAFF_CHILD_OBJ_QUAKE 0x63c
/* partfx spawned at player position when the quake spell activates (ground burst) */
#define STAFF_PARTFX_QUAKE 0x565
/* swipe/attack spread burst: spawned in 4x clusters per attack type (spark spread) */
#define STAFF_PARTFX_SWIPE_BURST 0x7b2
/* swipe/attack lingering trail: single follow-up spawn after the burst cluster */
#define STAFF_PARTFX_SWIPE_TRAIL 0x7b3

#define CLAMP_EXPR(value, low, high) ((value) < (low) ? (low) : ((value) > (high) ? (high) : (value)))
#define STAFF_SWIPE_SLOT_COUNT       3
#define STAFF_SWIPE_VERTEX_CAPACITY  3000
#define STAFF_SWIPE_VERTEX_LIMIT     (STAFF_SWIPE_VERTEX_CAPACITY - 2)
#define STAFF_SWIPE_FLAG_START       1
#define STAFF_SWIPE_FLAG_ACTIVE      2

extern StaffQuakeSpellState gStaffQuakeSpellState;

#define GXWGFifo (*(volatile PPCWGPipe*)0xCC008000)

static inline void swipePos3f32(const f32 x, const f32 y, const f32 z) {
    GXWGFifo.f32 = x;
    GXWGFifo.f32 = y;
    GXWGFifo.f32 = z;
}
static inline void swipeColor4u8(const u8 r, const u8 g, const u8 b, const u8 a) {
    GXWGFifo.u8 = r;
    GXWGFifo.u8 = g;
    GXWGFifo.u8 = b;
    GXWGFifo.u8 = a;
}
static inline void swipeTexCoord2f32(const f32 s, const f32 t) {
    GXWGFifo.f32 = s;
    GXWGFifo.f32 = t;
}

static inline f32 staffGetSwipeAlpha(f32 age) {
    f32 fade = 255.0f * (age / 8.0f);
    return 255.0f - CLAMP_EXPR(fade, 0.0f, 255.0f);
}

void staffUpdateAttackEffects(GameObject* obj, GameObject* player) {
    StaffEffectParams fxB;
    StaffEffectParams fxA;
    int moveId;
    f32 chargeLevel;
    f32 chargeRatio;
    f32* effectOffsets;
    StaffState* staffState = obj->extra;
    if (obj == NULL || player == NULL) {
        return;
    }
    {
        if (staffState->glowEnable != 0) {
            f32 burstScale;
            if (playerIsStaffActionPending(player) != 0) {
                chargeLevel = 1.0f;
                burstScale = 1.0f;
            } else {
                chargeLevel = 0.25f;
                burstScale = 0.4f;
            }
            if (staffState->glowAttackType == 7) {
                objfx_spawnArcedBurst(obj, staffState->glowAttackType, 0.5f, staffState->glowEnable, 1,
                                      (int)(30.0f * burstScale), 0.5f, 0.5f, 45.0f * chargeLevel, NULL, 0);
            } else {
                objfx_spawnArcedBurst(obj, staffState->glowAttackType, 1.0f, staffState->glowEnable, 1,
                                      (int)(30.0f * burstScale), 1.0f, 1.0f, 45.0f * chargeLevel, NULL, 0);
            }
        }
        playerGetMoveAndChargeLevel(player, &moveId, &chargeLevel);
        fxB.id = 0;
        fxB.a = 0;
        fxB.b = 0;
        fxB.scale = 1.0f;
        switch (moveId) {
        case 135:
            fxB.count = 21 - (int)(15.0f * ((chargeRatio = chargeLevel) / 30.0f));
            fxB.posX = 40.0f * (chargeRatio / 10.0f - 0.5f);
            fxB.id = 0xc94;
            (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_BURST, &fxB, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_BURST, &fxB, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_BURST, &fxB, 2, -1, NULL);
            (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_BURST, &fxB, 2, -1, NULL);
            fxB.count = 9;
            fxB.scale = 0.9f * (chargeLevel / 10.0f) + 0.1f;
            fxB.posY = 0.0f;
            fxB.id = 0xc0e;
            (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_TRAIL, &fxB, 2, -1, NULL);
            break;
        case 67:
            if (chargeLevel > 0.0f) {
                fxB.count = (int)(15.0f * (chargeLevel / 30.0f)) + 6;
                fxB.posX = 40.0f * (chargeLevel / 10.0f - 0.5f);
                fxB.id = 0xc94;
                (*gPartfxInterface)->spawnObject(obj, 0x7b4, &fxB, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, 0x7b4, &fxB, 2, -1, NULL);
                fxB.count = 9;
                fxB.scale = 0.9f * (chargeLevel / 10.0f) + 0.1f;
                fxB.posY = 0.0f;
                fxB.id = 0xc0e;
                (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_TRAIL, &fxB, 2, -1, NULL);
            }
            break;
        case 136:
            fxB.scale = 1.0f;
            fxB.count = 35;
            fxB.posY = 0.0f;
            fxB.posX = 20.0f;
            fxB.id = 0xc0e;
            (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_TRAIL, &fxB, 2, -1, NULL);
            fxB.count = 18;
            fxB.posY = 0.005f;
            (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_TRAIL, &fxB, 2, -1, NULL);
            break;
        case 127:
            fxB.scale = 0.75f;
            fxB.count = 10;
            fxB.posY = 0.005f;
            fxB.posX = 20.0f;
            fxB.id = 0xc0e;
            (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_TRAIL, &fxB, 2, -1, NULL);
            break;
        case 133:
            if (chargeLevel > 0.0f) {
                if (mainGetBit(GAMEBIT_STAFF_ABILITY_SUPER_QUAKE) != 0) {
                    fxB.count = 21 - (int)(15.0f * (chargeRatio = chargeLevel / 20.0f));
                    fxB.posX = 50.0f * (0.4f - chargeRatio);
                    fxB.id = 0xc75;
                } else {
                    fxB.count = 21 - (int)(15.0f * (chargeRatio = chargeLevel / 10.0f));
                    fxB.posX = 50.0f * (0.4f - chargeRatio);
                    fxB.id = 0xc94;
                }
                (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_BURST, &fxB, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_BURST, &fxB, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_BURST, &fxB, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_BURST, &fxB, 2, -1, NULL);
                fxB.count = 9;
                if (mainGetBit(GAMEBIT_STAFF_ABILITY_SUPER_QUAKE) != 0) {
                    fxB.scale = 0.9f * (chargeLevel / 20.0f) + 0.1f;
                    fxB.id = 0xc75;
                } else {
                    fxB.scale = 0.9f * (chargeLevel / 10.0f) + 0.1f;
                    fxB.id = 0xc0e;
                }
                fxB.posY = 0.0f;
                (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_TRAIL, &fxB, 2, -1, NULL);
            }
            break;
        case 1135:
            if (chargeLevel > 0.0f) {
                fxB.count = 21 - (int)(15.0f * (chargeLevel / 60.0f));
                fxB.posX = 50.0f * (0.4f - chargeLevel / 60.0f);
                fxB.id = 0xc94;
                (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_BURST, &fxB, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_BURST, &fxB, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_BURST, &fxB, 2, -1, NULL);
                (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_BURST, &fxB, 2, -1, NULL);
                fxB.count = 9;
                fxB.scale = 0.9f * (chargeLevel / 60.0f) + 0.1f;
                fxB.posY = 0.0f;
                fxB.id = 0xc0e;
                (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_TRAIL, &fxB, 2, -1, NULL);
            }
            break;
        case 1128:
            if (chargeLevel > 0.0f) {
                fxA.count = 21 - (int)(15.0f * (chargeLevel / 60.0f));
                fxA.id = 0xc95;
                playerGetFxOffsets((GameObject*)obj->ownerObj, &effectOffsets);
                fxB.posX = effectOffsets[3];
                fxB.posY = effectOffsets[4];
                fxB.posZ = effectOffsets[5];
                (*gPartfxInterface)->spawnObject(obj->ownerObj, 0x7b9, &fxB, 0x200001, -1, &fxA);
                (*gPartfxInterface)->spawnObject(obj->ownerObj, 0x7b9, &fxB, 0x200001, -1, &fxA);
                (*gPartfxInterface)->spawnObject(obj->ownerObj, 0x7b9, &fxB, 0x200001, -1, &fxA);
                (*gPartfxInterface)->spawnObject(obj->ownerObj, 0x7b9, &fxB, 0x200001, -1, &fxA);
                fxA.count = 9;
                fxA.id = 0xc95;
                fxA.scale = 0.8f * (chargeLevel / 60.0f) + 0.1f;
                fxB.posX = effectOffsets[3];
                fxB.posY = effectOffsets[4];
                fxB.posZ = effectOffsets[5];
                (*gPartfxInterface)->spawnObject(obj->ownerObj, 0x7ba, &fxB, 0x200001, -1, &fxA);
            }
            break;
        case 134: {
            f32 progress;
            u16 effectParamId;
            if (mainGetBit(GAMEBIT_STAFF_ABILITY_SUPER_QUAKE) != 0) {
                effectParamId = 0xc75;
            } else {
                effectParamId = 0xc0e;
            }
            fxB.id = effectParamId;
            progress = player->anim.currentMoveProgress;
            if (progress < 0.05f) {
                fxB.posX = -25.0f;
                fxB.count = 9;
                fxB.scale = 1.0f;
                fxB.posY = 0.0f;
                (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_TRAIL, &fxB, 2, -1, NULL);
            } else if (progress < 0.2f) {
                fxB.posX = 50.0f * (6.667f * (progress - 0.05f) - 0.5f);
                fxB.count = 9;
                fxB.scale = 1.0f;
                fxB.posY = 0.0f;
                (*gPartfxInterface)->spawnObject(obj, STAFF_PARTFX_SWIPE_TRAIL, &fxB, 2, -1, NULL);
            }
            break;
        }
        }
    }
}
void staffSetGlow(GameObject* obj, u8 attackType, u8 enable) {
    StaffState* state = obj->extra;
    state->glowAttackType = attackType;
    state->glowEnable = enable;
}

static void staffUpdateQuakeSpell(void) {
    StaffQuakeSpellState* q = &gStaffQuakeSpellState;

    if (q->active != 0) {
        q->scale += 5.5f;
        ObjHitbox_SetSphereRadius(&q->object->anim, q->scale);
        ObjHits_SetHitVolumeSlot(&q->object->anim, STAFF_QUAKE_HIT_VOLUME_SLOT, 5, 0);
        gStaffQuakeSpellState.fade += -4.0f;
        gStaffQuakeSpellState.radius *= 0.97f;
        gStaffQuakeSpellState.heightScale *= 1.01f;
        q->object->anim.alpha = gStaffQuakeSpellState.fade;
        q->object->anim.rootMotionScale += 0.07f;
        if (gStaffQuakeSpellState.fade < 1.0f) {
            q->active = 0;
            Obj_FreeObject(q->object);
            q->object = NULL;
        }
    }
}

void staffStartQuakeSpell(f32* pos) {
    GameObject* player;
    u8 canSetupObject;

    if (gStaffQuakeSpellState.active != 0) {
        Obj_FreeObject(gStaffQuakeSpellState.object);
        gStaffQuakeSpellState.object = NULL;
    }
    gStaffQuakeSpellState.posX = pos[0];
    gStaffQuakeSpellState.posY = 10.0f + pos[1];
    gStaffQuakeSpellState.posZ = pos[2];
    gStaffQuakeSpellState.fade = 255.0f;
    gStaffQuakeSpellState.scale = 1.0f;
    gStaffQuakeSpellState.radius = 0.4f;
    gStaffQuakeSpellState.heightScale = 1.0f;
    CameraShake_StartDampened(5.0f, 10.0f, 4.0f);
    player = Obj_GetPlayerObject();
    if (player != NULL && (canSetupObject = Obj_CanSetupObject()) > 0) {
        PartFxSpawnParams v;
        ObjPlacement* setup;
        gStaffQuakeSpellState.active = 1;
        v.posX = gStaffQuakeSpellState.posX;
        v.posY = gStaffQuakeSpellState.posY;
        v.posZ = gStaffQuakeSpellState.posZ;
        v.scale = 1.0f;
        v.rotX = 0;
        v.rotZ = 0;
        v.rotY = 0;
        (*gPartfxInterface)->spawnObject(player, STAFF_PARTFX_QUAKE, &v, 0x200000, -1, NULL);
        setup = Obj_AllocObjectSetup(36, STAFF_CHILD_OBJ_QUAKE);
        setup->color[0] = 1;
        setup->color[2] = 0xff;
        setup->color[1] = 2;
        setup->color[3] = 0xff;
        setup->posX = gStaffQuakeSpellState.posX;
        setup->posY = gStaffQuakeSpellState.posY;
        setup->posZ = gStaffQuakeSpellState.posZ;
        gStaffQuakeSpellState.object =
            (GameObject*)objSetupObject((ObjPlacement*)setup, 5, player->anim.mapEventSlot, -1, player->anim.parent);
        if (mainGetBit(GAMEBIT_STAFF_ABILITY_SUPER_QUAKE) != 0) {
            gStaffQuakeSpellState.object->anim.bankIndex = 1;
        }
        ObjHitbox_SetSphereRadius(&gStaffQuakeSpellState.object->anim, 1);
        ObjHits_SetHitVolumeSlot(&gStaffQuakeSpellState.object->anim, STAFF_QUAKE_HIT_VOLUME_SLOT, 5, 0);
        gStaffQuakeSpellState.object->anim.rootMotionScale = 0.05f;
        gStaffQuakeSpellState.object->anim.alpha = 0xff;
    }
}

const f32 gStaffHalfPi[1] = {1.5707964f};
const f32 gStaffPi[1] = {3.1415927f};
const f32 gStaffAngleUnitScale[1] = {32768.0f};

void staffDrawQuakeSpellRing(void) {
    Mtx mResult;
    Mtx mScale;
    Mtx mRot;
    Mtx mTrans;
    Mtx mView;

    if (gStaffQuakeSpellState.active != 0) {
        f32 scale;
        f32 z;
        setupQuakeSpellRingGxState(gStaffQuakeSpellState.fade);
        memcpy(mView, Camera_GetViewMatrix(), 0x30);
        PSMTXRotRad(mRot, 'x', gStaffHalfPi[0]);
        scale = gStaffQuakeSpellState.scale;
        PSMTXScale(mScale, scale, scale * gStaffQuakeSpellState.heightScale, scale);
        PSMTXConcat(mScale, mRot, mScale);
        PSMTXTrans(mTrans, gStaffQuakeSpellState.posX - playerMapOffsetX, gStaffQuakeSpellState.posY,
                   gStaffQuakeSpellState.posZ - playerMapOffsetZ);
        PSMTXConcat(mView, mTrans, mView);
        PSMTXConcat(mView, mScale, mResult);
        GXLoadPosMtxImm(mResult, GX_PNMTX0);
        PSMTXConcat(mView, mRot, mResult);
        z = 0.0f;
        mResult[0][3] = z;
        mResult[1][3] = z;
        mResult[2][3] = z;
        GXLoadTexMtxImm(mResult, GX_TEXMTX0, GX_MTX3x4);
        GXDrawTorus(gStaffQuakeSpellState.radius, 10, 20);
    }
}

void staffDrawSwipe(GameObject* obj, StaffState* swipe) {
    StaffSwipeSlot* swp;
    int i;

    selectTexture(gStaffSwipeTextures[swipe->swipeTextureIndex], 0);
    gxTevResetStages();
    gxTevTextureTimesRasStage();
    gxTevCommitStages();
    gxSetZMode_(1, GX_LEQUAL, 0);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXLoadPosMtxImm((MtxPtr)Camera_GetViewMatrix(), GX_PNMTX0);
    GXSetCurrentMtx(GX_PNMTX0);

    i = 0;
    for (; i < STAFF_SWIPE_SLOT_COUNT; i++) {
        swp = &swipe->slots[i];
        if ((swp->flags & STAFF_SWIPE_FLAG_ACTIVE) && swp->vertexCount >= 4) {
            SwipeVertex* vp;
            int j;
            f32 v1, v0, u;
            j = swp->startIndex;
            vp = &swp->vertexData[j];
            for (; j < swp->endIndex - 2; j += 2) {
                u = 0.5f;
                v0 = 0.0f;
                v1 = 1.0f;
                GXBegin(GX_QUADS, GX_VTXFMT2, 4);
                swipePos3f32(vp[0].x - playerMapOffsetX, vp[0].y, vp[0].z - playerMapOffsetZ);
                swipeColor4u8(255, 255, 255, (u8)vp[0].alpha);
                swipeTexCoord2f32(u, v0);
                swipePos3f32(vp[1].x - playerMapOffsetX, vp[1].y, vp[1].z - playerMapOffsetZ);
                swipeColor4u8(255, 255, 255, (u8)vp[1].alpha);
                swipeTexCoord2f32(u, v1);
                swipePos3f32(vp[3].x - playerMapOffsetX, vp[3].y, vp[3].z - playerMapOffsetZ);
                swipeColor4u8(255, 255, 255, (u8)vp[3].alpha);
                swipeTexCoord2f32(u, v1);
                swipePos3f32(vp[2].x - playerMapOffsetX, vp[2].y, vp[2].z - playerMapOffsetZ);
                swipeColor4u8(255, 255, 255, (u8)vp[2].alpha);
                swipeTexCoord2f32(u, v0);
                vp += 2;
            }
        }
    }
}
void staff_setupSwipe(int unusedStaff, StaffState* state, int unusedContext, int playerArg) {
    StaffWeaponSample* samples;
    int sampleCount;
    int subdivisions;
    int sampleIndex;
    int refreshControlPoints;
    SwipeVertex* vertices;
    int sampleIndices[4];
    f32 endpointAX[4];
    f32 endpointAY[4];
    f32 endpointAZ[4];
    f32 endpointBX[4];
    f32 endpointBY[4];
    f32 endpointBZ[4];
    f32 sinAngle, cosAngle, samplePosition, endPosition, lastFrame, step, startPosition, angle, splineT, movementT,
        swipeEnd, frame;
    int yaw;

    {
        ObjAnimState* animation;
        StaffSwipeSlot* slot;
        GameObject* player;

        player = (GameObject*)playerArg;
        if (state->activeSlot == NULL || state->hudSuppressed != 0) {
            return;
        }
        yaw = player->anim.rotX;
        if (player->anim.parentAnim != NULL) {
            yaw += player->anim.parentAnim->rotX;
        }
        angle = (gStaffPi[0] * (f32)(int)-yaw) / gStaffAngleUnitScale[0];
        sinAngle = mathSinf(angle);
        cosAngle = mathCosf(angle);
        animation = Obj_GetActiveModel(player)->currentState;
        if (player->anim.weaponDaTable != NULL && player->anim.weaponDaTable->byteCount > 0) {
            f32 previousFrame;
            slot = state->activeSlot;
            sampleCount = (int)(2.0f * animation->frameLength);
            swipeEnd = slot->lengthScale * animation->frameLength;
            if (slot->flags & STAFF_SWIPE_FLAG_START) {
                state->anchorX = player->anim.worldPosX;
                state->anchorY = player->anim.worldPosY;
                state->anchorZ = player->anim.worldPosZ;
                state->progress = 0.0f;
                slot->flags &= ~STAFF_SWIPE_FLAG_START;
            }
            previousFrame = state->progress;
            frame = animation->framePhase;
            lastFrame = frame;
            if (previousFrame > swipeEnd) {
                state->progress = frame;
                return;
            }
            if (frame > swipeEnd) {
                lastFrame = swipeEnd;
            }
            samples = (StaffWeaponSample*)player->anim.weaponDaTable->entries;
            if (previousFrame >= 0.0f) {
                previousFrame *= 40.0f;
                startPosition = fastFloorf(previousFrame) / 40.0f;
                startPosition *= 2.0f;
                lastFrame *= 40.0f;
                endPosition = fastFloorf(lastFrame) / 40.0f;
                endPosition *= 2.0f;
                sampleIndex = startPosition;
                splineT = startPosition - sampleIndex;
                subdivisions = (int)((endPosition - startPosition) / 0.1f);
                if (subdivisions == 0) {
                    if (animation->framePhase > swipeEnd) {
                        state->progress = animation->framePhase;
                    }
                    return;
                }
                movementT = 0.0f;
                step = 1.0f / subdivisions;
                refreshControlPoints = 1;
                while (subdivisions != 0) {
                    if (slot->endIndex == STAFF_SWIPE_VERTEX_LIMIT) {
                        subdivisions = 0;
                    } else {
                        splineT += 0.1f;
                        if (splineT >= 1.0f) {
                            splineT -= 1.0f;
                            sampleIndex += 1;
                            refreshControlPoints = 1;
                        }
                        movementT += step;
                        if (refreshControlPoints) {
                            int n;
                            sampleIndices[0] = sampleIndex - 1;
                            sampleIndices[1] = sampleIndex;
                            sampleIndices[2] = sampleIndex + 1;
                            sampleIndices[3] = sampleIndex + 2;
                            if (sampleIndex - 1 < 0) {
                                sampleIndices[0] = 0;
                            }
                            if (sampleIndices[1] >= sampleCount) {
                                sampleIndices[1] = sampleCount;
                            }
                            if (sampleIndices[2] >= sampleCount) {
                                sampleIndices[2] = sampleCount;
                            }
                            if (sampleIndices[3] >= sampleCount) {
                                sampleIndices[3] = sampleCount;
                            }
                            for (n = 0; n < 4; n++) {
                                f32 t1, t2;
                                endpointAX[n] = (f32)samples[sampleIndices[n]].endpointA[0] / 255.0f;
                                endpointAY[n] = (f32)samples[sampleIndices[n]].endpointA[1] / 255.0f;
                                endpointAZ[n] = (f32)samples[sampleIndices[n]].endpointA[2] / 255.0f;
                                endpointBX[n] = (f32)samples[sampleIndices[n]].endpointB[0] / 255.0f;
                                endpointBY[n] = (f32)samples[sampleIndices[n]].endpointB[1] / 255.0f;
                                endpointBZ[n] = (f32)samples[sampleIndices[n]].endpointB[2] / 255.0f;
                                t1 = cosAngle * endpointAX[n] - sinAngle * endpointAZ[n];
                                t2 = sinAngle * endpointAX[n] + cosAngle * endpointAZ[n];
                                endpointAX[n] = t1;
                                endpointAZ[n] = t2;
                                t2 = sinAngle * endpointBX[n] + cosAngle * endpointBZ[n];
                                t1 = cosAngle * endpointBX[n] - sinAngle * endpointBZ[n];
                                endpointBX[n] = t1;
                                endpointBZ[n] = t2;
                            }
                            refreshControlPoints = 0;
                        }
                        vertices = &slot->vertexData[slot->endIndex];
                        vertices[0].x = Curve_EvalBSpline(endpointBX, splineT, NULL);
                        vertices[0].y = Curve_EvalBSpline(endpointBY, splineT, NULL);
                        vertices[0].z = Curve_EvalBSpline(endpointBZ, splineT, NULL);
                        vertices[0].x += state->anchorX + movementT * (player->anim.worldPosX - state->anchorX);
                        vertices[0].y += state->anchorY + movementT * (player->anim.worldPosY - state->anchorY);
                        vertices[0].z += state->anchorZ + movementT * (player->anim.worldPosZ - state->anchorZ);
                        samplePosition = sampleIndex + splineT;
                        vertices[0].life = samplePosition;
                        vertices[0].alpha = staffGetSwipeAlpha(endPosition - vertices[0].life);
                        vertices[1].x = Curve_EvalBSpline(endpointAX, splineT, NULL);
                        vertices[1].y = Curve_EvalBSpline(endpointAY, splineT, NULL);
                        vertices[1].z = Curve_EvalBSpline(endpointAZ, splineT, NULL);
                        vertices[1].x += state->anchorX + movementT * (player->anim.worldPosX - state->anchorX);
                        vertices[1].y += state->anchorY + movementT * (player->anim.worldPosY - state->anchorY);
                        vertices[1].z += state->anchorZ + movementT * (player->anim.worldPosZ - state->anchorZ);
                        vertices[1].life = samplePosition;
                        vertices[1].alpha = staffGetSwipeAlpha(endPosition - vertices[1].life);
                        slot->vertexCount += 2;
                        slot->endIndex += 2;
                        subdivisions -= 1;
                    }
                }
            }
        }
        state->anchorX = player->anim.worldPosX;
        state->anchorY = player->anim.worldPosY;
        state->anchorZ = player->anim.worldPosZ;
        state->progress = animation->framePhase;
    }
}

void staffDoGrowShrinkAnim(GameObject* obj, u8 grow, u8 flag2, int unused) {
    StaffState* state = obj->extra;
    if (grow != 0) {
        if (state->moveSpeed < 0.0f) {
            Sfx_PlayFromObject(obj, SFXTRIG_wp_stpos4_b);
        }
        if (flag2 == 0) {
            state->moveSpeed = 0.15f;
        } else {
            state->moveSpeed = 1.0f;
        }
    } else {
        if (state->moveSpeed > 0.0f) {
            Sfx_PlayFromObject(obj, SFXTRIG_wp_stapo1_b);
        }
        if (flag2 == 0) {
            state->moveSpeed = -0.15f;
        } else {
            state->moveSpeed = -1.0f;
        }
    }
}

void staff_getHitGeometryPoints(GameObject* obj, f32* outA, f32* outB) {
    StaffState* state = obj->extra;
    outA[0] = state->geometryPointAX[0];
    outA[1] = state->geometryPointAY[0];
    outA[2] = state->geometryPointAZ[0];
    outB[0] = state->geometryPointBX[0];
    outB[1] = state->geometryPointBY[0];
    outB[2] = state->geometryPointBZ[0];
}
ObjectDescriptor23 gStaffObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_23_SLOTS,
    (ObjectDescriptorCallback)staff_initialise,
    (ObjectDescriptorCallback)staff_release,
    0,
    (ObjectDescriptorCallback)staff_init,
    (ObjectDescriptorCallback)staff_update,
    (ObjectDescriptorCallback)staff_hitDetect,
    (ObjectDescriptorCallback)staff_render,
    (ObjectDescriptorCallback)staff_free,
    (ObjectDescriptorCallback)staff_getObjectTypeId,
    staff_getExtraSize,
    (ObjectDescriptorCallback)staff_func0A,
    (ObjectDescriptorCallback)staff_func0B,
    (ObjectDescriptorCallback)staff_updateSwipe,
    (ObjectDescriptorCallback)staff_hitDetectGeometry,
    (ObjectDescriptorCallback)staff_func0E,
    (ObjectDescriptorCallback)staff_func0F,
    (ObjectDescriptorCallback)staff_func10,
    (ObjectDescriptorCallback)staff_setHitReactValue,
    (ObjectDescriptorCallback)staff_addHitReactValue,
    (ObjectDescriptorCallback)staff_getHitReactValue,
    (ObjectDescriptorCallback)staff_getHitGeometryPoints,
    (ObjectDescriptorCallback)staff_startSwipe,
    (ObjectDescriptorCallback)staff_getSwipeTextureIndex,
};

s32 staff_getSwipeTextureIndex(GameObject* obj) {
    return ((StaffState*)obj->extra)->swipeTextureIndex;
}

s16 staff_getHitReactValue(GameObject* obj) {
    return ((StaffState*)obj->extra)->hitReactValue;
}

void staff_addHitReactValue(GameObject* obj, s32 delta) {
    s16* p = &((StaffState*)obj->extra)->hitReactValue;
    s32 clamped;
    *p = (s16)(*p + delta);
    clamped = *p;
    if (clamped < 0) {
        clamped = 0;
    } else if (clamped > 0xff) {
        clamped = 0xff;
    }
    *p = clamped;
}

void objSetAnimField48to0(GameObject* obj) {
    StaffState* state = obj->extra;
    state->activeSlot = NULL;
}

void staff_startSwipe(GameObject* obj, s16 idx, f32 start, f32 lengthScale) {
    StaffSwipeSlot* slot;
    int n;
    StaffState* state = obj->extra;
    StaffSwipeSlot* slots = state->slots;
    for (n = 0; n < STAFF_SWIPE_SLOT_COUNT; n++) {
        slot = &slots[n];
        if ((slot->flags & STAFF_SWIPE_FLAG_ACTIVE) == 0) {
            break;
        }
    }
    slot->flags = (u8)(slot->flags | STAFF_SWIPE_FLAG_START | STAFF_SWIPE_FLAG_ACTIVE);
    slot->start = start;
    slot->lengthScale = lengthScale;
    slot->startIndex = 0;
    slot->endIndex = 0;
    slot->vertexCount = 0;
    slot->idx = idx;
    state->activeSlot = slot;
}

void staff_setHitReactValue(GameObject* obj, s32 value) {
    s16* p = &((StaffState*)obj->extra)->hitReactValue;
    if (value > 0xff) {
        value = 0xff;
    }
    *p = value;
}

void staff_func10(GameObject* obj, s32 value) {
    ((StaffState*)obj->extra)->fieldB2 = value;
}

void staff_func0F(void) {
}

void staff_func0E(void) {
}

const SwipeColorTable gStaffSwipeColorTable = {{
    {0x08, 0xFF, 0xBE, 0x78},
    {0x08, 0xFF, 0xFF, 0x78},
    {0x08, 0xB4, 0xF0, 0xFF},
    {0x08, 0xAA, 0xFF, 0xAA},
}};

void staff_hitDetectGeometry(GameObject* obj) {
    ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    StaffState* swipe = obj->extra;
    SwipeColorTable tbl = gStaffSwipeColorTable;

    staffDrawSwipe(obj, swipe);
    if (hitState->contactFlags != 0 && getHudHiddenFrameCount() == 0) {
        int contactHitVolume = hitState->contactHitVolume;
        int idx;
        if (contactHitVolume < 0) {
            idx = 0;
        } else if (contactHitVolume > 35) {
            idx = 35;
        } else {
            idx = contactHitVolume;
        }
        if (idx == 14) {
            Sfx_PlayAtPositionFromObject(obj, hitState->contactPosX, hitState->contactPosY, hitState->contactPosZ,
                                         SFXTRIG_foot_water_walk_1);
            (*gWaterfxInterface)
                ->spawnSplashBurst(obj, hitState->contactPosX, hitState->contactPosY, hitState->contactPosZ, 0.0f);
            (*gWaterfxInterface)
                ->spawnRipple(hitState->contactPosX, hitState->contactPosY, hitState->contactPosZ, 0, 0.0f, 2);
        } else {
            PartFxSpawnParams v;
            v.scale = 1.0f;
            v.rotZ = 0;
            v.rotY = 0;
            v.rotX = 0;
            v.posX = hitState->contactPosX;
            v.posY = hitState->contactPosY;
            v.posZ = hitState->contactPosZ;
            (*gStaffSwipeResource)
                ->spawn(OBJHITREACT_HIT_EFFECT_PARENT_NONE, OBJHITREACT_HIT_EFFECT_MODE, &v,
                        OBJHITREACT_HIT_EFFECT_SPAWN_FLAGS, OBJHITREACT_HIT_EFFECT_NO_SOURCE,
                        &tbl.colors[sStaffContactColorIndices[idx]]);
            Sfx_PlayAtPositionFromObject(obj, hitState->contactPosX, hitState->contactPosY, hitState->contactPosZ,
                                         (u16)sStaffContactSfxIds[idx]);
        }
    }
}

void staff_updateSwipe(GameObject* obj, GameObject* player, int context) {
    StaffState* inner = obj->extra;
    staff_setupSwipe((int)obj, inner, context, (int)player);
    if (getHudHiddenFrameCount() != 0) {
        inner->hudSuppressed = 1;
    } else {
        inner->hudSuppressed = 0;
    }
}

void staff_func0B(void) {
}

Texture* gStaffSwipeTextures[2];
s16* gStaffSwipeTextureIds;
StaffCollisionInterface** gStaffSwipeResource;

void staff_func0A(void) {
}

StaffQuakeSpellState gStaffQuakeSpellState;

void staffUpdateWhileTimeStopped(GameObject* obj) {
    staffUpdateAttackEffects(obj, (GameObject*)obj->ownerObj);
}

int staff_getExtraSize(void) {
    return sizeof(StaffState);
}

static inline void staff_initialiseBody(s16* p, int i) {
    for (; i < 35; i++) {
        if (*p == 0) {
            *p = 0xc3;
        }
        p++;
    }
    gStaffSwipeTextureIds = sStaffSwipeTextureIdTable;
    if (gStaffSwipeTextures[0] == NULL) {
        for (i = 0; i < 2; i++) {
            gStaffSwipeTextures[i] = textureLoad(gStaffSwipeTextureIds[i], 0);
        }
    }
    if (gStaffSwipeResource == NULL) {
        gStaffSwipeResource = Resource_Acquire(90, 1);
    }
}
int staff_getObjectTypeId(void) {
    return 0x9;
}

void staff_free(GameObject* obj) {
    StaffState* state = obj->extra;
    int i;
    i = 0;
    for (; i < STAFF_SWIPE_SLOT_COUNT; i++) {
        mm_free(state->slots[i].vertexData);
    }
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void staff_render(void) {
}

void staff_hitDetect(void) {
}

static inline s16 staffClampSwipeAlpha(s16 alpha) {
    return CLAMP_EXPR(alpha, 0, 255);
}

void staff_update(GameObject* obj) {
    StaffState* state = obj->extra;
    StaffSwipeSlot* slot;
    int n;
    ObjModel* model = Obj_GetActiveModel(obj);
    model->bufferFlags &= ~0x8;
    ObjAnim_AdvanceCurrentMove(obj, state->moveSpeed, timeDelta, NULL);

    for (n = 0; n < STAFF_SWIPE_SLOT_COUNT; n++) {
        slot = &state->slots[n];
        if (slot->flags & STAFF_SWIPE_FLAG_ACTIVE) {
            SwipeVertex* vertices;
            int vertexIndex;

            vertexIndex = slot->startIndex;
            vertices = &slot->vertexData[vertexIndex];
            for (; vertexIndex < slot->endIndex; vertexIndex += 2) {
                if (slot == state->activeSlot) {
                    vertices[0].alpha = staffGetSwipeAlpha(2.0f * state->progress - vertices[0].life);
                    vertices[1].alpha = vertices[0].alpha;
                } else {
                    vertices[0].alpha = -(16.0f * timeDelta - (f32)(int)vertices[0].alpha);
                    vertices[1].alpha = vertices[0].alpha;
                }
                vertices[0].alpha = staffClampSwipeAlpha(vertices[0].alpha);
                vertices[1].alpha = staffClampSwipeAlpha(vertices[1].alpha);
                if (vertices[0].alpha <= 0 && vertices[1].alpha <= 0) {
                    slot->vertexCount += -2;
                    slot->startIndex += 2;
                }
                vertices += 2;
            }
            if (slot != state->activeSlot && slot->vertexCount == 0) {
                slot->flags &= ~STAFF_SWIPE_FLAG_ACTIVE;
            }
        }
    }

    staffUpdateAttackEffects(obj, (GameObject*)obj->ownerObj);
    objGetAnimState80A((GameObject*)obj->ownerObj);
    state->swipeTextureIndex = 0;
    staffUpdateQuakeSpell();
}

void staff_init(GameObject* obj) {
    StaffState* state = obj->extra;
    ObjHitsPriorityState* hitState;
    StaffSwipeSlot* slot;
    int i;
    state->unkAA = 1;
    state->unkB0 = 2;
    state->moveSpeed = -1.0f;
    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    if (hitState != NULL) {
        hitState->trackContactMask = 0x109;
    }
    i = 0;
    for (; i < STAFF_SWIPE_SLOT_COUNT; i++) {
        slot = &state->slots[i];
        slot->vertexData = mmAlloc(sizeof(SwipeVertex) * STAFF_SWIPE_VERTEX_CAPACITY, 0x1a, 0);
        slot->idx = -1;
    }
    gStaffQuakeSpellState.active = 0;
    gStaffQuakeSpellState.object = 0;
}

void staff_release(void) {
    int i;
    if (gStaffSwipeTextures[0] != NULL) {
        for (i = 0; i < 2; i++) {
            textureFree(gStaffSwipeTextures[i]);
            gStaffSwipeTextures[i] = NULL;
        }
    }
    if (gStaffSwipeResource != NULL) {
        Resource_Release(gStaffSwipeResource);
        gStaffSwipeResource = NULL;
    }
}

void staff_initialise(void) {
    int i;

    i = 0;
    staff_initialiseBody(sStaffContactSfxIds, i);
}
