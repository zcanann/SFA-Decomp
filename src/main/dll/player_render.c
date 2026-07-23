#define BADDIE_MOVE_STATUS_SIGNED

#include "main/dll/modgfx_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/obj_placement.h"
#include "main/model_engine.h"
#include "main/model_engine_ui_api.h"
#include "main/object.h"
#include "main/dll/dll_80136a40.h"
#include "main/debug.h"
#include "main/render_envfx_api.h"
#include "main/game_object.h"
#include "main/model.h"
#include "main/maketex_api.h"
#include "main/objprint_api.h"
#include "main/objprint_character_api.h"
#include "main/objprint_render_api.h"
#include "main/dll/objfx_api.h"
#include "main/dll/player_api.h"
#include "main/dll/player_spirit_api.h"
#include "main/dll/player_state_api.h"
#include "main/dll/player_motion_api.h"
#include "main/dll/dll_00E5_shield_api.h"
#include "main/dll/dll_000D_playershadow.h"
#include "main/dll/dll_01B5_lightfoot.h"
#include "main/dll/DB/DBprotection.h"
#include "main/dll/SB/dll_01E8_sbgalleon.h"
#include "main/dll/dll_00E2_staff_api.h"
#include "main/dll/CF/staffactivated_helpers.h"
#include "main/dll/viewfinder.h"
#include "main/sky_api.h"
#include "main/object_render.h"
#include "main/dll/dll_0015_curves.h"
#include "track/intersect_api.h"
#include "main/track_dolphin_api.h"
#include "main/track_bbox_api.h"
#include "main/vecmath_distance_api.h"

#include "main/object_api.h"
#include "main/curve_eval.h"
#include "main/objhits.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/stream_api.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_object_query_api.h"
#include "main/audio/sfx_play_legacy_api.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_stop_object_api.h"
#include "main/audio/music_api.h"
#include "main/gameloop_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/lightmap_api.h"
#include "main/newshadows_audio_api.h"
#include "main/objfx.h"
#include "main/screen_transition.h"
#include "main/object_transform.h"
#include "ghidra_import.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/objseq_api.h"
#include "main/shader_api.h"
#include "main/pi_dolphin_api.h"
#include "main/dll/player_state.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/boneparticleeffect_interface.h"
#include "main/camera_interface.h"
#include "main/camera.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/waterfx_interface.h"

#include "main/game_ui_interface.h"
#include "main/mapEventTypes.h"
#include "main/mm.h"
#include "main/objanim.h"
#include "main/objanim_update.h"
#include "main/objtexture.h"
#include "main/objseq.h"
#include "main/dll/player_motion.h"
#include "main/dll/player_objects.h"
#include "main/dll/player_status.h"
#include "main/dll/player_target.h"
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/vecmath.h"
#include "main/dll/path_control_interface.h"
#include "main/frame_timing.h"
#include "main/byte_flags.h"
#include "main/pad.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTransform.h"
#include "string.h"
#include "main/dll/dll_002F_carryable.h"
#include "main/dll/dll_0104_smallbasket.h"
#define FEAR_TEST_METER_POSITION_INT
#include "main/dll/dll_0000_gameui.h"
#undef FEAR_TEST_METER_POSITION_INT
#include "main/dll/dll_00C9_enemy.h"
#include "main/obj_group.h"
#include "main/obj_link.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/obj_query.h"
#include "main/player_eye_anim.h"
#include "main/dll/dll_029B_arwingandrossstuff.h"
#include "main/dll/player.h"
#include "main/dll/tricky_api.h"
#include "main/gamebits.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/player_control_interface.h"
#include "main/sky.h"

#undef BADDIE_MOVE_STATUS_SIGNED

static inline ObjHitsPriorityState* Player_GetObjHitsState(GameObject* obj)
{
    return (ObjHitsPriorityState*)obj->anim.hitReactState;
}

typedef struct
{
    u8 pad[0x88];
    u8 flags;
    u8 pad2[0x1f];
    u8 valsA[3];
    u8 valsB[5];
} HitDesc;

extern int lbl_803E7E68;
extern int lbl_803E7E6C;
extern f32 lbl_803E8110;
extern f32 lbl_803E8160;

void fn_802A9D0C(int p1, int p2, int p3, int p4, int p5, int p6, int p7, int p8);
void fn_802AAF80(GameObject* obj, int inner, int a, int b, int c);
void playerDrawTeleportAnim(GameObject* obj);

void fn_802B4ED8(GameObject* obj, int p2, int mode)
{
    PlayerState* inner = obj->extra;
    f32 sx, sy, sz;
    u32 v;
    u32 m;

    if ((s8)p2 != -1)
    {
        if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x4001) != 0)
        {
            return;
        }
    }
    v = (inner->flags3F3 >> 3) & 1;
    if (v != 0)
    {
        return;
    }
    if ((u32)obj->anim.alpha < 2)
    {
        return;
    }
    if (*(void**)((char*)inner + 0x7f0) != NULL)
    {
        if ((obj->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 ||
            arrayIndexOf((int*)&lbl_803DC6C4, 2, inner->baddie.controlMode) != -1)
        {
            int p = (int)inner->focusObject;
            (*(void (*)(int, f32))(*(int*)((char*)*(int*)*(int*)((char*)p + 0x68) + 0x50)))(
                p, obj->anim.modelInstance->rootMotionScaleBase);
        }
    }
    if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x8000000) != 0)
    {
        sx = obj->anim.localPosX;
        sy = obj->anim.localPosY;
        sz = obj->anim.localPosZ;
        obj->anim.localPosX = obj->anim.modelState->overrideWorldPosX;
        obj->anim.localPosY = obj->anim.modelState->overrideWorldPosY;
        obj->anim.localPosZ = obj->anim.modelState->overrideWorldPosZ;
        obj->anim.modelState->overrideWorldPosX = sx;
        obj->anim.modelState->overrideWorldPosY = sy;
        obj->anim.modelState->overrideWorldPosZ = sz;
    }
    obj->anim.localPosY = obj->anim.localPosY + inner->sinkOffsetY;
    m = (u32)(mode & 0xff);
    if (m == 1)
    {
        objRenderFuzz((int*)obj);
    }
    else if (m == 2)
    {
        objRenderFn_800413d4((int*)obj);
    }
    else if (m == 4)
    {
        fuzzRenderFn_800412dc((int*)obj);
    }
    objSetMtxFn_800412d4(0);
    obj->anim.localPosY = obj->anim.localPosY - inner->sinkOffsetY;
    if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x8000000) != 0)
    {
        obj->anim.modelState->overrideWorldPosX = obj->anim.localPosX;
        obj->anim.modelState->overrideWorldPosY = obj->anim.localPosY;
        obj->anim.modelState->overrideWorldPosZ = obj->anim.localPosZ;
        obj->anim.localPosX = sx;
        obj->anim.localPosY = sy;
        obj->anim.localPosZ = sz;
    }
}

void playerRender(int obj, int a, int b, int c, int d, int flag)
{
    int in2;
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 sx;
    f32 sy;
    f32 sz;
    f32 qz;
    f32 qy;
    f32 qx;
    f32 pz;
    f32 py;
    f32 px;
    int tbl[2];
    struct
    {
        u16 mode;
        u8 pad[6];
        f32 scale;
        f32 x;
        f32 y;
        f32 z;
    } pfx;
    f32 vel[3];

    if ((s8)flag == -1 || (*(u32*)&((PlayerState*)inner)->flags360 & 0x4001) == 0)
    {
        if (*(void**)((char*)inner + 0x7f0) != NULL &&
            ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 ||
             arrayIndexOf((int*)&lbl_803DC6C4, 2, ((PlayerState*)inner)->baddie.controlMode) != -1))
        {
            fn_802A9D0C(obj, inner, (int)((PlayerState*)inner)->focusObject, a, b, c, d, 1);
        }
        if (((PlayerState*)inner)->teleportAnimActive == 1)
        {
            playerDrawTeleportAnim((GameObject*)(obj));
        }
        (*gPlayerShadowInterface)->renderObject((GameObject*)obj);
        if (*(void**)((char*)inner + 0x7f0) != NULL &&
            ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 ||
             arrayIndexOf((int*)&lbl_803DC6C4, 2, ((PlayerState*)inner)->baddie.controlMode) != -1))
        {
            {
                char* held = (char*)((PlayerState*)inner)->focusObject;
                ObjDef* mi = ((GameObject*)obj)->anim.modelInstance;
                (*(void (*)(char*, f32)) * (int*)(*(int*)(*(int*)(held + 0x68)) + 0x50))(held, mi->rootMotionScaleBase);
            }
        }
        if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x8000000) != 0)
        {
            sx = ((GameObject*)obj)->anim.localPosX;
            sy = ((GameObject*)obj)->anim.localPosY;
            sz = ((GameObject*)obj)->anim.localPosZ;
            ((GameObject*)obj)->anim.localPosX = ((GameObject*)obj)->anim.modelState->overrideWorldPosX;
            ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.modelState->overrideWorldPosY;
            ((GameObject*)obj)->anim.localPosZ = ((GameObject*)obj)->anim.modelState->overrideWorldPosZ;
        }
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY + ((PlayerState*)inner)->sinkOffsetY;
        objRenderModelAndHitVolumes((GameObject*)obj, a, b, c, d, lbl_803E7EE0);
        ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - ((PlayerState*)inner)->sinkOffsetY;
        if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x8000000) != 0)
        {
            ((GameObject*)obj)->anim.localPosX = sx;
            ((GameObject*)obj)->anim.localPosY = sy;
            ((GameObject*)obj)->anim.localPosZ = sz;
        }
        if ((s8)flag != 0)
        {
            fn_802AAF80((GameObject*)obj, inner, a, b, c);
        }
        ObjPath_GetPointWorldPositionArray((GameObject*)obj, 6, 2, (f32*)(inner + 0x3c4));
        ObjPath_GetPointWorldPosition((GameObject*)obj, 0xb, (f32*)((char*)inner + 0x768), (f32*)((char*)inner + 0x76c),
                                      (f32*)((char*)inner + 0x770), 0);
        if (playerHasKrazoaSpirit(1, 0) != 0)
        {
            if ((void*)gPlayerHeldObject == NULL)
            {
                int i;
                ModelFileHeader* m = Obj_GetActiveModel((GameObject*)obj)->file;
                for (i = 0; i < m->renderOpCount; i++)
                {
                    ModelRenderOp* op = ObjModel_GetRenderOp(m, i);
                    if (op->mode == 2)
                    {
                        Shader_getLayer(op, 1);
                        gPlayerHeldObject = (int)op;
                        op->flags |= 0x100000LL;
                        break;
                    }
                }
            }
        }
        else if ((void*)gPlayerHeldObject != NULL)
        {
            *(u32*)((char*)gPlayerHeldObject + 0x3c) &= ~0x100000LL;
            {
                int zero = 0;
                gPlayerHeldObject = zero;
            }
        }
        {
            in2 = *(int*)&((GameObject*)obj)->extra;
            if (((PlayerState*)in2)->heldObj != NULL && *(int*)((char*)(int)((PlayerState*)in2)->heldObj + 0xf8) == 1)
            {
                ObjPath_GetPointWorldPosition((GameObject*)obj, 8, &px, &py, &pz, 0);
                ObjPath_GetPointWorldPosition((GameObject*)obj, 9, &qx, &qy, &qz, 0);
                px = lbl_803E7E98 * (px + qx);
                py = lbl_803E7E98 * (py + qy);
                pz = lbl_803E7E98 * (pz + qz);
                if (*(s16*)((char*)(int)((PlayerState*)in2)->heldObj + 0x46) == 0x112)
                {
                    py = py + lbl_803E7ED4;
                }
                *(f32*)((char*)(int)((PlayerState*)in2)->heldObj + 0xc) = *(f32*)((char*)(int)((PlayerState*)in2)->heldObj + 0x18) =
                    px;
                *(f32*)((char*)(int)((PlayerState*)in2)->heldObj + 0x10) =
                    *(f32*)((char*)(int)((PlayerState*)in2)->heldObj + 0x1c) = py;
                *(f32*)((char*)(int)((PlayerState*)in2)->heldObj + 0x14) =
                    *(f32*)((char*)(int)((PlayerState*)in2)->heldObj + 0x20) = pz;
                if (*(s16**)&((GameObject*)obj)->anim.parent != NULL)
                {
                    *(s16*)(int)((PlayerState*)in2)->heldObj =
                        **(s16**)&((GameObject*)obj)->anim.parent + ((GameObject*)obj)->anim.rotX;
                }
                else
                {
                    *(s16*)(int)((PlayerState*)in2)->heldObj = ((PlayerState*)in2)->targetYaw;
                }
                (*(void (*)(int, int, int, int, int, int)) *
                 (int*)(*(int*)(*(int*)((char*)(int)((PlayerState*)in2)->heldObj + 0x68)) + 0x10))(
                    (int)((PlayerState*)in2)->heldObj, 0, 0, 0, 0, -1);
            }
        }
        if (((PlayerState*)inner)->knockbackTimer > lbl_803E7EA4 || (((PlayerState*)inner)->pendingFxFlags & 2) != 0)
        {
            {
                int t1;
                int t0;
                t0 = lbl_803E7E68;
                t1 = lbl_803E7E6C;
                tbl[0] = t0;
                tbl[1] = t1;
            }
            objParticleFn_80099d84((GameObject*)obj, lbl_803E7E9C,
                                   tbl[((((PlayerState*)inner)->knockKindBits >> 5) & 7) - 1] & 0xff,
                                   lbl_803E7EE0, NULL);
        }
        if ((((PlayerState*)inner)->pendingFxFlags & 1) != 0)
        {
            objParticleFn_80099d84((GameObject*)obj, lbl_803E7E9C, 8, lbl_803E7EE0, NULL);
        }
        if (((PlayerState*)inner)->waterDepth > lbl_803E7EA4)
        {
            if ((((PlayerState*)inner)->pendingFxFlags & 4) != 0)
            {
                *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_WATER_SPLASH_PENDING;
                ((PlayerState*)inner)->pendingFxFlags = ((PlayerState*)inner)->pendingFxFlags & ~0x4;
            }
        }
        else
        {
            if (gPlayerSurfacePfxModeTable[((PlayerState*)inner)->surfaceType] == 6 ||
                gPlayerSurfacePfxModeTable[((PlayerState*)inner)->surfaceType] == 3)
            {
                if ((((PlayerState*)inner)->pendingFxFlags & 8) != 0)
                {
                    u8 n;
                    vel[0] = lbl_803E7F6C * ((GameObject*)obj)->anim.velocityX;
                    vel[1] = lbl_803E7F6C * ((GameObject*)obj)->anim.velocityY;
                    vel[2] = lbl_803E7F6C * ((GameObject*)obj)->anim.velocityZ;
                    pfx.x = *(f32*)&lbl_803E8018 * ((GameObject*)obj)->anim.velocityX + ((PlayerState*)inner)->fxOffsetX;
                    pfx.y = lbl_803E8018 * ((GameObject*)obj)->anim.velocityY + ((PlayerState*)inner)->fxOffsetY;
                    pfx.z = lbl_803E8018 * ((GameObject*)obj)->anim.velocityZ + ((PlayerState*)inner)->fxOffsetZ;
                    pfx.scale = lbl_803E7F18;
                    pfx.mode = gPlayerSurfacePfxModeTable[((PlayerState*)inner)->surfaceType];
                    for (n = 5; n != 0; n--)
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x7e6, &pfx, 0x200001, -1, vel);
                    }
                    pfx.x = lbl_803E8018 * ((GameObject*)obj)->anim.velocityX + ((PlayerState*)inner)->fxOffset2X;
                    pfx.y = lbl_803E8018 * ((GameObject*)obj)->anim.velocityY + ((PlayerState*)inner)->fxOffset2Y;
                    pfx.z = lbl_803E8018 * ((GameObject*)obj)->anim.velocityZ + ((PlayerState*)inner)->fxOffset2Z;
                    pfx.scale = lbl_803E7F18;
                    pfx.mode = gPlayerSurfacePfxModeTable[((PlayerState*)inner)->surfaceType];
                    for (n = 5; n != 0; n--)
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x7e6, &pfx, 0x200001, -1, vel);
                    }
                    ((PlayerState*)inner)->pendingFxFlags = ((PlayerState*)inner)->pendingFxFlags & ~0x8;
                }
                if ((((PlayerState*)inner)->pendingFxFlags & 4) != 0)
                {
                    u8 n2;
                    vel[0] = lbl_803E7F44 * ((GameObject*)obj)->anim.velocityX;
                    vel[1] = lbl_803E7F44 * ((GameObject*)obj)->anim.velocityY;
                    vel[2] = lbl_803E7F44 * ((GameObject*)obj)->anim.velocityZ;
                    pfx.x = ((GameObject*)obj)->anim.worldPosX;
                    pfx.y = lbl_803E7F10 + ((GameObject*)obj)->anim.worldPosY;
                    pfx.z = ((GameObject*)obj)->anim.worldPosZ;
                    pfx.scale = lbl_803E7EE0;
                    pfx.mode = gPlayerSurfacePfxModeTable[((PlayerState*)inner)->surfaceType];
                    for (n2 = 0; n2 < 10; n2++)
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x7e6, &pfx, 0x200001, -1, vel);
                    }
                    ((PlayerState*)inner)->pendingFxFlags = ((PlayerState*)inner)->pendingFxFlags & ~0x4;
                }
            }
        }
    }
}

void playerDoHitDetection(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 dt = timeDelta;
    f32 spd;
    int sub;
    int desc;
    HitDesc* hd;
    u32 fl;
    f32 x;
    f32 y;
    f32 z;

    *(u32*)&((PlayerState*)inner)->flags360 &= ~PLAYER_FLAG_WORLDPOS_OVERRIDE;
    if (((ByteFlags*)((char*)inner + 0x3f2))->b20 != 0 &&
        (((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0)
    {
        u8 zero = 0;
        ((PlayerState*)inner)->baddie.physicsActive = zero;
    }
    (*gPathControlInterface)->update((void*)obj, (void*)(inner + 4), timeDelta);
    (*gPathControlInterface)->apply((void*)obj, (void*)(inner + 4));
    (*gPathControlInterface)->advance((void*)obj, (void*)(inner + 4), timeDelta);
    ObjModelChain_AdvancePhase((ObjModelChain*)gPlayerModelChain);
    if (!(((PlayerState*)inner)->cutsceneTimer >= lbl_803E7EF0))
    {
        (*gPlayerInterface)->updateVelocityState((void*)obj, (void*)inner, gPlayerStateHandlers);
        if (*(s8*)&((PlayerState*)inner)->baddie.stateTag == 1)
        {
            if (gPlayerPathObject != 0 && ((ByteFlags*)((char*)inner + 0x3f4))->b40 != 0 &&
                (*(void**)((sub = *(int*)((char*)gPlayerPathObject + 0x54)) + 0x50) != NULL ||
                 (*(s8*)(sub + 0xad) != 0 && *(s8*)(sub + 0xac) != 0xe)))
            {
                {
                    u8 one = 1;
                    Player_GetObjHitsState((GameObject*)(obj))->suppressOutgoingHits = one;
                }
                ((PlayerState*)inner)->boulderChargeLevel = lbl_803E7EA4;
                *(u8*)&((PlayerState*)inner)->hitWindowIndex = *(u8*)&((PlayerState*)inner)->activeHitWindow;
                {
                    hd = (HitDesc*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                    if ((hd->flags & 1) != 0)
                    {
                        ((PlayerState*)inner)->cutsceneTimer = lbl_803E80A8;
                    }
                    hd = (HitDesc*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                    if ((hd->flags & 2) != 0)
                    {
                        ((PlayerState*)inner)->hitInterval = hd->valsA[((PlayerState*)inner)->activeHitWindow];
                        hd = (HitDesc*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                        hd = (HitDesc*)((u8*)hd + ((PlayerState*)inner)->activeHitWindow);
                        ((PlayerState*)inner)->hitCountMax = hd->valsB[0];
                        ((PlayerState*)inner)->hitTimer = (f32)(u32)((PlayerState*)inner)->hitInterval;
                        ((PlayerState*)inner)->hitCount += 1;
                        ((PlayerState*)inner)->lastHitObject = *(int*)(sub + 0x50);
                    }
                }
                {
                    hd = *(HitDesc**)(sub + 0x50);
                    if (hd != NULL)
                    {
                        if ((((GameObject*)hd)->anim.modelInstance->effectFlags & 4) != 0)
                        {
                            doRumble(lbl_803E7ED8);
                        }
                        if ((((GameObject*)hd)->anim.modelInstance->effectFlags & 8) != 0)
                        {
                            lbl_803DE459 = 1;
                        }
                    }
                    else if (*(s8*)(sub + 0xad) != 0)
                    {
                        doRumble(lbl_803E7ED8);
                        lbl_803DE459 = 1;
                    }
                }
                {
                    u8 c = ((PlayerState*)inner)->moveSlotIndex;
                    if (c == 0xf)
                    {
                        ((PlayerState*)inner)->attackVariantMode = 1;
                    }
                    else if (c == 0x1b)
                    {
                        ((PlayerState*)inner)->attackVariantMode = 2;
                    }
                    else if (c == 0x11)
                    {
                        ((PlayerState*)inner)->attackVariantMode = 0;
                    }
                    else
                    {
                        ((PlayerState*)inner)->attackVariantMode = 1;
                    }
                }
            }
            if (Player_GetObjHitsState((GameObject*)(obj))->lastHitObject != 0)
            {
                Player_GetObjHitsState((GameObject*)(obj))->suppressOutgoingHits = 1;
                ((PlayerState*)inner)->boulderChargeLevel = lbl_803E7EA4;
                *(u8*)&((PlayerState*)inner)->hitWindowIndex = *(u8*)&((PlayerState*)inner)->activeHitWindow;
                {
                    hd = (HitDesc*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                    if ((hd->flags & 1) != 0)
                    {
                        ((PlayerState*)inner)->cutsceneTimer = lbl_803E80A8;
                    }
                    hd = (HitDesc*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                    if ((hd->flags & 2) != 0)
                    {
                        ((PlayerState*)inner)->hitInterval = hd->valsA[((PlayerState*)inner)->activeHitWindow];
                        hd = (HitDesc*)((PlayerState*)inner)->moveSlots + (u32)((PlayerState*)inner)->moveSlotIndex;
                        hd = (HitDesc*)((u8*)hd + ((PlayerState*)inner)->activeHitWindow);
                        ((PlayerState*)inner)->hitCountMax = hd->valsB[0];
                        ((PlayerState*)inner)->hitTimer = (f32)(u32)((PlayerState*)inner)->hitInterval;
                        ((PlayerState*)inner)->hitCount += 1;
                        ((PlayerState*)inner)->lastHitObject =
                            Player_GetObjHitsState((GameObject*)(obj))->lastHitObject;
                    }
                }
            }
        }
        if ((*(u32*)&((PlayerState*)inner)->flags360 & 2) != 0)
        {
            void* h = *(void**)((char*)inner + 0xdc);
            if (h != NULL &&
                ((fl = ((ObjAnimComponent*)h)->modelInstance->flags) & OBJMODEL_FLAG_SKIP_RESET_UPDATE) != 0 &&
                (fl & 0x8000) == 0)
            {
                objHitDetectFn_80062e84((GameObject*)obj, (GameObject*)h, 1);
            }
            else if (((GameObject*)obj)->anim.parent != NULL && h == NULL)
            {
                objHitDetectFn_80062e84((GameObject*)obj, NULL, 1);
            }
        }
        *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_HITDETECT;
        if (((PlayerState*)inner)->focusObject != NULL &&
            ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) != 0 ||
             arrayIndexOf((int*)&lbl_803DC6C4, 2, ((PlayerState*)inner)->baddie.controlMode) != -1))
        {
            (*(void (*)(int, f32*, f32*, f32*))(*(int*)(*(int*)(*(int*)((int)((PlayerState*)inner)->focusObject + 0x68)) +
                                                        0x34)))((int)((PlayerState*)inner)->focusObject, &x, &y, &z);
            (*gCameraInterface)->overridePos(x, y, z);
            fn_802A9D0C(obj, inner, (int)((PlayerState*)inner)->focusObject, 0, 0, 0, 0, 0);
        }
        if (*(s8*)&((PlayerState*)inner)->baddie.physicsActive == 1 && (*(int*)((char*)inner + 4) & 0x100000) == 0)
        {
            if ((*(u32*)&((PlayerState*)inner)->flags360 & 0x2000) == 0 && (*(s8*)((char*)inner + 0x264) & 0x33) != 0)
            {
                ((GameObject*)obj)->anim.velocityY =
                    (((GameObject*)obj)->anim.worldPosY - ((GameObject*)obj)->anim.previousWorldPosY) / dt;
                if (((GameObject*)obj)->anim.velocityY < *(f32*)&lbl_803E811C)
                {
                    ((GameObject*)obj)->anim.velocityY = lbl_803E811C;
                }
                if (((GameObject*)obj)->anim.velocityY > *(f32*)&lbl_803E7EA4)
                {
                    ((GameObject*)obj)->anim.velocityY = lbl_803E7EA4;
                }
            }
            if ((*(int*)inner & 0x800000) != 0 && lbl_803E7EA4 == ((PlayerState*)inner)->pushVelX &&
                lbl_803E7EA4 == ((PlayerState*)inner)->pushVelZ)
            {
                spd = sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
                            ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ);
                if (((GameObject*)obj)->anim.parent != NULL)
                {
                    ((GameObject*)obj)->anim.velocityX =
                        (((GameObject*)obj)->anim.localPosX - ((GameObject*)obj)->anim.previousLocalPosX) / dt;
                    ((GameObject*)obj)->anim.velocityZ =
                        (((GameObject*)obj)->anim.localPosZ - ((GameObject*)obj)->anim.previousLocalPosZ) / dt;
                }
                else
                {
                    ((GameObject*)obj)->anim.velocityX =
                        (((GameObject*)obj)->anim.worldPosX - ((GameObject*)obj)->anim.previousWorldPosX) / dt;
                    ((GameObject*)obj)->anim.velocityZ =
                        (((GameObject*)obj)->anim.worldPosZ - ((GameObject*)obj)->anim.previousWorldPosZ) / dt;
                }
                if (((*(s8*)((char*)inner + 0x264) & 2) != 0 && (*(s8*)((char*)inner + 0x264) & 0x20) == 0) ||
                    *(u8*)((char*)inner + 0x262) != 0 || (Player_GetObjHitsState((GameObject*)(obj))->flags & 8) != 0)
                {
                    if (((PlayerState*)inner)->rumbleCooldown <= lbl_803E7EA4 &&
                        ((PlayerState*)inner)->baddie.animSpeedA > lbl_803E8160)
                    {
                        doRumble(lbl_803E7F10);
                        ((PlayerState*)inner)->rumbleCooldown = lbl_803E7F30;
                        Sfx_PlayFromObject(obj, SFXTRIG_foot_run_jingle4);
                    }
                    dt = mathSinf((gPlayerPi * (f32)((PlayerState*)inner)->yaw) / lbl_803E7F98);
                    {
                        f32 s = mathCosf((gPlayerPi * (f32)((PlayerState*)inner)->yaw) / lbl_803E7F98);
                        ((PlayerState*)inner)->baddie.animSpeedA =
                            -((GameObject*)obj)->anim.velocityZ * s - ((GameObject*)obj)->anim.velocityX * dt;
                    }
                    ((PlayerState*)inner)->baddie.animSpeedA = ((PlayerState*)inner)->baddie.animSpeedA * lbl_803E7FC4;
                    {
                        f32 c = ((PlayerState*)inner)->baddie.animSpeedA;
                        f32 lo = lbl_803E8110 * ((PlayerState*)inner)->baddie.inputMagnitude;
                        ((PlayerState*)inner)->baddie.animSpeedA =
                            (c < lo) ? lo
                                     : ((c > ((PlayerState*)inner)->maxSpeed) ? ((PlayerState*)inner)->maxSpeed : c);
                    }
                    {
                        f32 c = ((PlayerState*)inner)->baddie.animSpeedA;
                        ((PlayerState*)inner)->baddie.animSpeedA =
                            (c < lbl_803E7EA4) ? lbl_803E7EA4 : ((c > spd) ? spd : c);
                    }
                    if (((ByteFlags*)((char*)inner + 0x3f0))->b40 == 0)
                    {
                        ((PlayerState*)inner)->baddie.animSpeedC = ((PlayerState*)inner)->baddie.animSpeedA;
                    }
                }
                *(u32*)inner &= ~0x800000;
            }
        }
        if ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_PARENT_SLACK) == 0)
        {
            *(s16*)obj = ((PlayerState*)inner)->targetYaw;
        }
        {
            GameObject* g = getSbGalleon();
            if (g != NULL && DBprotection_getCameraState(g) == 2)
            {
                ((GameObject*)obj)->anim.modelState->overrideWorldPosX =
                    ((GameObject*)obj)->anim.localPosX - *(f32*)((char*)g + 0xc);
                ((GameObject*)obj)->anim.modelState->overrideWorldPosY =
                    ((GameObject*)obj)->anim.localPosY - *(f32*)((char*)g + 0x10);
                ((GameObject*)obj)->anim.modelState->overrideWorldPosZ =
                    ((GameObject*)obj)->anim.localPosZ - *(f32*)((char*)g + 0x14);
                vecRotateZXY((void*)g, &((GameObject*)obj)->anim.modelState->overrideWorldPosX);
                ((GameObject*)obj)->anim.modelState->overrideWorldPosX =
                    ((GameObject*)obj)->anim.modelState->overrideWorldPosX + *(f32*)((char*)g + 0xc);
                ((GameObject*)obj)->anim.modelState->overrideWorldPosY =
                    ((GameObject*)obj)->anim.modelState->overrideWorldPosY + *(f32*)((char*)g + 0x10);
                ((GameObject*)obj)->anim.modelState->overrideWorldPosZ =
                    ((GameObject*)obj)->anim.modelState->overrideWorldPosZ + *(f32*)((char*)g + 0x14);
                ((GameObject*)obj)->anim.modelState->flags |= 0x2020;
                ((GameObject*)obj)->anim.rotZ = *(s16*)((char*)g + 4);
                *(u32*)&((PlayerState*)inner)->flags360 |= PLAYER_FLAG_WORLDPOS_OVERRIDE;
            }
        }
        *(u32*)&((PlayerState*)inner)->flags360 &= ~0x400000LL;
    }
}

