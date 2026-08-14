/*
 * CFCrate multi-prop handler (DLL slot 298 / 0x12A).
 *
 * This DLL drives dozens of simple placement types across the game: cogs,
 * warding stones, moving water, spinning rings, lock symbols, the galleon,
 * ice floes, and other stationary props. Initialization and update behavior
 * are selected by the object's retail romDefNo.
 */
#include "dlls/objects/298_CFCrate.h"

#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera.h"
#include "main/dll/partfx_interface.h"
#include "main/dll_000A_expgfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/object_render.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "sys/objects.h"
#include "main/audio/sfx_play_api.h"
#include "main/objhits.h"
#include "main/render_lactions_api.h"
#include "sys/objects/lifecycle.h"
#include "main/vecmath.h"

/*
 * romDefNo values resolved through the active EN OBJINDEX.bin and OBJECTS.bin.
 * The three numeric-only entries have no live OBJINDEX record.
 */
typedef enum CFCrateObjectId {
    CFCRATE_OBJ_BOSS_DARKOR_F = 0x085, /* BossDarkorF */
    CFCRATE_OBJ_CC_QUEEN = 0x086,      /* CCqueen */
    CFCRATE_OBJ_SB_GALLEON = 0x08E,    /* SB_Galleon */
    CFCRATE_OBJ_CF_LEVEL_CONT = 0x0AB, /* CFLevelCont */
    CFCRATE_OBJ_CF_CLOUD_CALL = 0x0AE, /* CFCloudCall */
    CFCRATE_OBJ_CF_POWER_CRYS = 0x0D7, /* CFPowerCrys */
    CFCRATE_OBJ_DIM2_ICE_FLOE = 0x10D, /* DIM2IceFloe */
    CFCRATE_OBJ_SB_LAMP = 0x125,       /* SB_Lamp */
    CFCRATE_OBJ_DFSH_COL = 0x1D0,      /* DFSHcol */
    CFCRATE_OBJ_LINK_BLUE_MU = 0x1D1,  /* LINK_BlueMu */
    CFCRATE_OBJ_ECSH_COL = 0x1D7,      /* ECSHcol */
    CFCRATE_OBJ_CC_EYE_VINES = 0x1E6,  /* CCeyeVines */
    CFCRATE_OBJ_CC_PRESSURE = 0x201,   /* CC_Pressure */
    CFCRATE_OBJ_WORLD_ASTERO = 0x216,  /* WORLDAstero */
    CFCRATE_OBJ_ANIM_WHITE_SP = 0x23B, /* AnimWhiteSp */
    CFCRATE_OBJ_WM_LARGE_ROC = 0x2B7,  /* WM_largeroc */
    CFCRATE_OBJ_WM_FALLEN_CO = 0x2BB,  /* WM_fallenco */
    CFCRATE_OBJ_EC_SHRINE_D = 0x409,   /* EC_Shrine_d */
    CFCRATE_OBJ_DFP_DISH = 0x492,      /* DFP_dish */
    CFCRATE_OBJ_DFP_BLOCK_WA = 0x4BF,  /* DFP_blockwa */
    CFCRATE_OBJ_VFP_LOCKSYM = 0x622,   /* VFP_locksym */
    CFCRATE_OBJ_65C = 0x65C,
    CFCRATE_OBJ_65D = 0x65D,
    CFCRATE_OBJ_66C = 0x66C,
    CFCRATE_OBJ_MMP_ORGANIC = 0x6B4,   /* MMP_Organic */
    CFCRATE_OBJ_VFP_LIFTGRA = 0x6BE,   /* VFP_liftgra */
    CFCRATE_OBJ_VFP_SPELLST = 0x6BF,   /* VFP_Spellst */
    CFCRATE_OBJ_DFP_WATER = 0x6FC,     /* DFP_Water */
    CFCRATE_OBJ_DFP_INNER_RI = 0x6FD,  /* DFP_InnerRi */
    CFCRATE_OBJ_DFP_OUTER_RI = 0x6FE,  /* DFP_OuterRi */
    CFCRATE_OBJ_VFP_NEWBALL = 0x708,   /* VFP_newball */
    CFCRATE_OBJ_DFP_WATER_HI = 0x71B,  /* DFP_WaterHi */
    CFCRATE_OBJ_DFP_PLACE_PL = 0x726,  /* DFP_PlacePl */
    CFCRATE_OBJ_VFP_WARDING = 0x729,   /* VFP_Warding */
    CFCRATE_OBJ_WM_KRAZOAST_A = 0x78B, /* WM_krazoast */
    CFCRATE_OBJ_WM_KRAZOAST_B = 0x78C, /* WM_krazoast */
    CFCRATE_OBJ_LINKF_COG = 0x7DE,     /* LinkF_cog */
    CFCRATE_OBJ_DFPSP_SG = 0x828,      /* DFPSpSG */
} CFCrateObjectId;

#define CFCRATE_HIT_VOLUME_SLOT         0x13
#define CFCRATE_LARGE_ROCK_PARTFX_ID    0x44
#define CFCRATE_LOCK_ACTIVE_TEXTURE_ID  0x100
#define CFCRATE_ROTATION_BYTE_SHIFT     8
#define CFCRATE_MAX_ROTATION            0x7FFF
#define CFCRATE_BLOCK_WALL_RISE_HEIGHT  30.0f
#define CFCRATE_WATER_RISE_HEIGHT       40.0f
#define CFCRATE_LAMP_PROXIMITY_DISTANCE 75.0f
#define CFCRATE_LAMP_NEAR_ACTION_ID     0x5C
#define CFCRATE_LAMP_FAR_ACTION_ID      0x5D
#define CFCRATE_SCALE_PARAM_MIN         0x3E8
#define CFCRATE_SCALE_PARAM_DIVISOR     1000.0f
#define CFCRATE_LAMP_RANDOM_MIN         0x3E8
#define CFCRATE_LAMP_RANDOM_MAX         0x1388

u16 gCFCrateDefaultSfxTable[4] = {SFXwp_robolaser16, 0, 0, 0};

int CFCrate_getExtraSize(void) {
    return sizeof(CFCrateState);
}

int CFCrate_getObjectTypeId(void) {
    return 0x1;
}

void CFCrate_free(GameObject* obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void CFCrate_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible) {
    int objectId;
    CFCrateState* state;

    state = obj->extra;
    if ((s32)visible == 0 || (objectId = obj->anim.romDefNo) == CFCRATE_OBJ_SCALESSWORD) {
        return;
    }
    if (visible == 0 || objectId == CFCRATE_OBJ_VFP_SPELLST) {
        if (mainGetBit(state->gameBitB) == 0) {
            return;
        }
    }
    objRenderModelAndHitVolumes(obj, renderArg2, renderArg3, renderArg4, renderArg5, 1.0f);
}

int CFCrate_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate) {
    CFCrateState* state;
    int i;

    state = obj->extra;
    switch (obj->anim.romDefNo) {
    case CFCRATE_OBJ_BOSS_DARKOR_F:
    case CFCRATE_OBJ_CC_QUEEN:
        break;
    case CFCRATE_OBJ_SB_GALLEON:
        break;
    case CFCRATE_OBJ_CF_LEVEL_CONT:
        break;
    case CFCRATE_OBJ_CF_CLOUD_CALL:
        break;
    case CFCRATE_OBJ_DIM2_ICE_FLOE:
        break;
    case CFCRATE_OBJ_EC_SHRINE_D:
        break;
    case CFCRATE_OBJ_WM_LARGE_ROC:
        if (mainGetBit(state->gameBitB) != 0) {
            animUpdate->sequenceControlFlags |= OBJSEQ_CONTROL_SET_LATCH_A;
        }
        for (i = 0; i < animUpdate->eventCount; i++) {
            if (animUpdate->eventIds[i] == 1) {
                (*gPartfxInterface)->spawnObject((void*)obj, CFCRATE_LARGE_ROCK_PARTFX_ID, NULL, 2, -1, NULL);
            }
            animUpdate->eventIds[i] = 0;
        }
        break;
    }
    return 0;
}

void CFCrate_hitDetect(void) {
}

void CFCrate_update(GameObject* obj) {
    CFCrateState* state;
    CFCratePlacement* placement;
    Camera* camera;
    int rotDelta;
    s16 objectId;

    Obj_GetPlayerObject();
    state = obj->extra;
    camera = Camera_GetCurrent();
    placement = (CFCratePlacement*)obj->anim.placementData;
    objectId = obj->anim.romDefNo;

    switch (objectId) {
    case CFCRATE_OBJ_LINKF_COG:
        if (mainGetBit(state->gameBitA) != 0) {
            obj->anim.rotZ = (s16) - (timeDelta * state->oscVelB - (f32)obj->anim.rotZ);
        } else {
            obj->anim.rotZ = (s16)(timeDelta * state->oscVelB + (f32)obj->anim.rotZ);
        }
        break;
    case CFCRATE_OBJ_VFP_WARDING:
        if (mainGetBit(state->gameBitA) == 0) {
            obj->anim.rotY = obj->anim.rotY + framesThisStep * 100;
        }
        break;
    case CFCRATE_OBJ_DFP_WATER_HI:
        state->lingerTimer -= framesThisStep;
        ObjHits_SetHitVolumeSlot(&obj->anim, CFCRATE_HIT_VOLUME_SLOT, 1, 0);
        if (state->lingerTimer <= 0) {
            Obj_FreeObject(obj);
        } else {
            obj->anim.localPosY = (f32) - (2.0 * timeDelta - obj->anim.localPosY);
        }
        break;
    case CFCRATE_OBJ_DFP_WATER:
        if ((mainGetBit(state->gameBitA) != 0) &&
            (obj->anim.localPosY <= CFCRATE_WATER_RISE_HEIGHT + placement->base.posY)) {
            obj->anim.localPosY = 0.5f * timeDelta + obj->anim.localPosY;
            if (obj->anim.localPosY >= CFCRATE_WATER_RISE_HEIGHT + placement->base.posY) {
                mainSetBits(state->gameBitA, 0);
            }
        }
        break;
    case CFCRATE_OBJ_DFP_INNER_RI:
        if (mainGetBit(state->gameBitA) != 0) {
            obj->anim.rotX = obj->anim.rotX + (s32)(4000.0f * timeDelta);
            obj->anim.rotZ = obj->anim.rotZ + (s32)(1000.0f * timeDelta);
        } else {
            obj->anim.rotX = obj->anim.rotX + (s32)(4000.0f * timeDelta);
            obj->anim.rotZ = obj->anim.rotZ + (s32)(1000.0f * timeDelta);
        }
        break;
    case CFCRATE_OBJ_DFP_OUTER_RI:
        if (mainGetBit(state->gameBitA) != 0) {
            obj->anim.rotY = obj->anim.rotY + (s32)(4000.0f * timeDelta);
            obj->anim.rotZ = obj->anim.rotZ + (s32)(1000.0f * timeDelta);
        } else {
            obj->anim.rotY = obj->anim.rotY + (s32)(4000.0f * timeDelta);
            obj->anim.rotZ = obj->anim.rotZ + (s32)(1000.0f * timeDelta);
        }
        break;
    case CFCRATE_OBJ_VFP_LOCKSYM: {
        ObjTextureRuntimeSlot* texture = objFindTexture(obj, 0, 0);
        if ((texture != NULL) && (mainGetBit(state->gameBitA) != 0) && (texture->textureId == 0)) {
            Sfx_PlayFromObject(obj, SFXTRIG_en_littletink22_3c4);
            texture->textureId = CFCRATE_LOCK_ACTIVE_TEXTURE_ID;
        }
        break;
    }
    case CFCRATE_OBJ_65C:
        break;
    case CFCRATE_OBJ_65D:
        ObjAnim_AdvanceCurrentMove(obj, 0.002f, timeDelta, NULL);
        break;
    case CFCRATE_OBJ_MMP_ORGANIC:
        ObjAnim_AdvanceCurrentMove(obj, 0.002f, timeDelta, NULL);
        break;
    case CFCRATE_OBJ_VFP_NEWBALL:
        if (ObjHits_GetPriorityHit(obj, NULL, NULL, NULL) != 0) {
            mainSetBits(state->gameBitA, 1);
        }
        if (mainGetBit(state->gameBitA) == 0) {
            obj->anim.rotX = obj->anim.rotX + placement->initialRotX * framesThisStep;
        }
        break;
    case CFCRATE_OBJ_EC_SHRINE_D:
        (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        break;
    case CFCRATE_OBJ_VFP_LIFTGRA:
        if ((mainGetBit(state->gameBitB) != 0) && (state->gameBitBLatch == 0)) {
            state->gameBitBLatch = 1;
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
        }
        break;
    case CFCRATE_OBJ_DFP_BLOCK_WA:
        if ((obj->anim.localPosY < CFCRATE_BLOCK_WALL_RISE_HEIGHT + placement->base.posY) &&
            (mainGetBit(state->gameBitA) != 0)) {
            obj->anim.localPosY = obj->anim.localPosY + timeDelta;
        }
        break;
    case CFCRATE_OBJ_DFPSP_SG:
        if ((mainGetBit(state->gameBitB) != 0) && (state->gameBitBLatch == 0)) {
            if (obj->anim.rotZ + (rotDelta = (s32)(100.0f * timeDelta)) > CFCRATE_MAX_ROTATION) {
                state->gameBitBLatch = 1;
                obj->anim.rotZ = CFCRATE_MAX_ROTATION;
            } else {
                obj->anim.rotZ = (s16)(obj->anim.rotZ + rotDelta);
            }
        }
        break;
    case CFCRATE_OBJ_SB_GALLEON:
        state->oscPosA = 3.0f * state->oscVelA + state->oscPosA;
        if ((state->oscPosA > 180.0f) || (state->oscPosA < -180.0f)) {
            state->oscVelA = -state->oscVelA;
        }
        if ((state->oscPosB > 90.0f) || (state->oscPosB < -90.0f)) {
            state->oscVelB = -state->oscVelB;
        }
        state->oscPosB = 3.0f * state->oscVelB + state->oscPosB;
        break;
    case CFCRATE_OBJ_DIM2_ICE_FLOE:
        state->sfxTimer -= framesThisStep;
        if (state->sfxTimer < 0) {
            u32 tableOffset;
            u8* sfxTable;

            tableOffset = randomGetRange(0, state->sfxCount - 1) << 1;
            sfxTable = (u8*)state->sfxTable;
            Sfx_PlayFromObject(obj, *(u16*)(sfxTable + tableOffset));
            state->sfxTimer = state->sfxPeriod;
            tableOffset = randomGetRange(0, state->sfxPeriod);
            state->sfxTimer = state->sfxTimer + tableOffset;
        }
        break;
    case CFCRATE_OBJ_SB_LAMP: {
        f32 deltaX;
        f32 deltaY;
        f32 deltaZ;
        f32 distance;
        GameObject* player;

        obj->anim.rotZ = (s16)(1.5 * (double)-(s32)camera->roll);
        player = Obj_GetPlayerObject();
        deltaX = player->anim.worldPosX - obj->anim.worldPosX;
        deltaZ = player->anim.worldPosZ - obj->anim.worldPosZ;
        deltaY = player->anim.worldPosY - obj->anim.worldPosY;
        distance = sqrtf(deltaY * deltaY + (deltaX * deltaX + deltaZ * deltaZ));
        if (distance < CFCRATE_LAMP_PROXIMITY_DISTANCE && state->proximityLatch == 1) {
            state->proximityLatch = 0;
            getLActions(obj, obj, CFCRATE_LAMP_NEAR_ACTION_ID, 0, 0, 0);
        } else if ((distance > CFCRATE_LAMP_PROXIMITY_DISTANCE) && (state->proximityLatch == 0)) {
            state->proximityLatch = 1;
            getLActions(obj, obj, CFCRATE_LAMP_FAR_ACTION_ID, 0, 0, 0);
        }
        break;
    }
    }
}

void CFCrate_init(GameObject* obj, CFCratePlacement* placement) {
    ObjAnimComponent* objAnim;
    CFCrateState* state;
    s16 objectId;
    f32 unitScale;

    objAnim = &obj->anim;
    objectId = placement->base.objectId;
    state = obj->extra;
    unitScale = 1.0f;
    state->unusedValue = unitScale;

    switch (objectId) {
    case CFCRATE_OBJ_WM_FALLEN_CO:
        obj->anim.rotX = (s16)(placement->initialRotX << CFCRATE_ROTATION_BYTE_SHIFT);
        obj->anim.rotY = placement->param1A;
        obj->anim.rotZ = placement->param1C;
        obj->anim.rootMotionScale = unitScale;
        break;
    case CFCRATE_OBJ_DFSH_COL:
    case CFCRATE_OBJ_LINK_BLUE_MU:
    case CFCRATE_OBJ_ECSH_COL:
    case CFCRATE_OBJ_CC_EYE_VINES:
    case CFCRATE_OBJ_CC_PRESSURE:
    case CFCRATE_OBJ_ANIM_WHITE_SP:
    case CFCRATE_OBJ_DFP_DISH:
    case CFCRATE_OBJ_WM_KRAZOAST_A:
    case CFCRATE_OBJ_WM_KRAZOAST_B:
        obj->anim.rotX = (s16)(placement->initialRotX << CFCRATE_ROTATION_BYTE_SHIFT);
        break;
    case CFCRATE_OBJ_DFP_PLACE_PL:
        obj->animEventCallback = CFCrate_sequenceCallback;
        obj->anim.rotX = (s16)(placement->initialRotX << CFCRATE_ROTATION_BYTE_SHIFT);
        break;
    case CFCRATE_OBJ_DFP_WATER_HI:
        state->lingerTimer = placement->param1A;
        break;
    case CFCRATE_OBJ_VFP_LIFTGRA:
        obj->anim.rotX = (s16)(placement->initialRotX << CFCRATE_ROTATION_BYTE_SHIFT);
        state->gameBitBLatch = 0;
        state->gameBitB = placement->gameBitB;
        break;
    case CFCRATE_OBJ_DFPSP_SG:
        obj->anim.rotX = (s16)(placement->initialRotX << CFCRATE_ROTATION_BYTE_SHIFT);
        state->gameBitBLatch = 0;
        state->gameBitB = placement->gameBitB;
        if ((mainGetBit(state->gameBitB) != 0) && (state->gameBitBLatch == 0)) {
            obj->anim.rotZ = CFCRATE_MAX_ROTATION;
            state->gameBitBLatch = 1;
        }
        break;
    case CFCRATE_OBJ_VFP_SPELLST:
        obj->anim.rotX = (s16)(placement->initialRotX << CFCRATE_ROTATION_BYTE_SHIFT);
        obj->anim.rotY = placement->param1A;
        state->gameBitB = placement->gameBitB;
        break;
    case CFCRATE_OBJ_VFP_NEWBALL:
        objAnim->bankIndex = (s8)placement->param1A;
        state->gameBitA = placement->gameBitB;
        if (objAnim->bankIndex >= 3) {
            objAnim->bankIndex = 0;
        }
        Obj_SetActiveModelIndex(obj, objAnim->bankIndex);
        break;
    case CFCRATE_OBJ_DFP_WATER:
        state->gameBitA = placement->gameBitB;
        break;
    case CFCRATE_OBJ_VFP_LOCKSYM:
        obj->anim.rotX = (s16)(placement->initialRotX << CFCRATE_ROTATION_BYTE_SHIFT);
        state->gameBitA = placement->gameBitB;
        break;
    case CFCRATE_OBJ_MMP_ORGANIC:
        obj->anim.rotX = (s16)(placement->initialRotX << CFCRATE_ROTATION_BYTE_SHIFT);
        obj->anim.rotY = placement->param1A;
        ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
        break;
    case CFCRATE_OBJ_66C:
        obj->anim.rotX = (s16)(placement->initialRotX << CFCRATE_ROTATION_BYTE_SHIFT);
        state->gameBitA = placement->gameBitB;
        break;
    case CFCRATE_OBJ_WORLD_ASTERO:
        obj->anim.rotX = (s16)(placement->initialRotX << CFCRATE_ROTATION_BYTE_SHIFT);
        obj->anim.rotY = placement->param1A;
        break;
    case CFCRATE_OBJ_DFP_BLOCK_WA:
        obj->anim.rotX = (s16)(placement->initialRotX << CFCRATE_ROTATION_BYTE_SHIFT);
        *(u8*)&objAnim->bankIndex = placement->bankIndex;
        state->gameBitA = placement->gameBitB;
        if (mainGetBit(state->gameBitA) != 0) {
            obj->anim.localPosY = CFCRATE_BLOCK_WALL_RISE_HEIGHT + placement->base.posY;
        }
        break;
    case CFCRATE_OBJ_SB_GALLEON:
        obj->anim.rotX = 0;
        obj->anim.rotY = 0;
        if (placement->param1C >= CFCRATE_SCALE_PARAM_MIN) {
            obj->anim.rootMotionScale = unitScale / ((f32)(s32)placement->param1C / CFCRATE_SCALE_PARAM_DIVISOR);
        } else {
            obj->anim.rootMotionScale = 0.2f;
        }
        state->gameBitBLatch = 0;
        state->homeX = placement->base.posX;
        state->homeY = placement->base.posY;
        state->homeZ = placement->base.posZ;
        state->oscPosA = state->oscPosB = 0.0f;
        state->unk28 = 1000.0f;
        state->unk20 = 400.0f;
        state->oscVelA = state->oscVelB = 0.5f;
        obj->anim.rotZ = 0;
        obj->animEventCallback = CFCrate_sequenceCallback;
        break;
    case CFCRATE_OBJ_LINKF_COG:
        obj->anim.rotX = (s16)(placement->initialRotX << CFCRATE_ROTATION_BYTE_SHIFT);
        obj->anim.rotY = 0;
        if (placement->param1C >= CFCRATE_SCALE_PARAM_MIN) {
            obj->anim.rootMotionScale = unitScale / ((f32)(s32)placement->param1C / CFCRATE_SCALE_PARAM_DIVISOR);
        } else {
            obj->anim.rootMotionScale = unitScale;
        }
        state->oscVelB = (f32)(s32)placement->param1A;
        state->gameBitA = placement->gameBitB;
        if (mainGetBit(state->gameBitA) != 0) {
            state->oscVelB *= -1.0f;
        }
        break;
    case CFCRATE_OBJ_CF_POWER_CRYS:
        obj->anim.rotX = (s16)(placement->initialRotX << CFCRATE_ROTATION_BYTE_SHIFT);
        obj->anim.rootMotionScale = unitScale;
        state->gameBitBLatch = 0;
        state->homeX = placement->base.posX;
        state->homeY = placement->base.posY;
        state->homeZ = placement->base.posZ;
        state->oscVelA = state->oscVelB = state->unk20 = state->unk28 = state->oscPosA = state->oscPosB = 0.0f;
        obj->animEventCallback = CFCrate_sequenceCallback;
        break;
    case CFCRATE_OBJ_SB_LAMP:
        obj->anim.rotX = 0;
        obj->anim.rotY = 0;
        obj->anim.rotZ = 0;
        obj->anim.rootMotionScale = unitScale;
        obj->userData1 = 0;
        obj->userData2 = 0;
        state->oscVelB = 600.0f;
        state->oscVelA = 0.5f;
        state->lampValue = 0;
        state->lampRandom = randomGetRange(CFCRATE_LAMP_RANDOM_MIN, CFCRATE_LAMP_RANDOM_MAX);
        state->proximityLatch = 1;
        obj->animEventCallback = CFCrate_sequenceCallback;
        break;
    case CFCRATE_OBJ_DIM2_ICE_FLOE:
        obj->anim.hitReactState = NULL;
        if (placement->param1A == 0) {
            state->sfxTable = gCFCrateDefaultSfxTable;
            state->sfxCount = 1;
        }
        state->sfxPeriod = (u16)placement->param1C;
        state->sfxTimer = state->sfxPeriod;
        break;
    }
}

void CFCrate_release(void) {
}

void CFCrate_initialise(void) {
}

ObjectDescriptor gCFCrateObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)CFCrate_initialise,
    (ObjectDescriptorCallback)CFCrate_release,
    0,
    (ObjectDescriptorCallback)CFCrate_init,
    (ObjectDescriptorCallback)CFCrate_update,
    (ObjectDescriptorCallback)CFCrate_hitDetect,
    (ObjectDescriptorCallback)CFCrate_render,
    (ObjectDescriptorCallback)CFCrate_free,
    (ObjectDescriptorCallback)CFCrate_getObjectTypeId,
    CFCrate_getExtraSize,
};
