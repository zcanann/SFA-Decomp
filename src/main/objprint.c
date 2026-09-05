#define OBJHITS_SETTERS_S16
#define OBJHITS_STATE_INDEX_S8
#include "main/frame_timing.h"
#include "main/shader_api.h"
#include "main/debug.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "main/model.h"
#include "main/obj_contact.h"
#include "main/obj_list.h"
#include "main/objhits.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "main/track_dolphin_api.h"
#include "dolphin/os.h"
#include "main/asset_load.h"
#include "main/audio/sfx.h"
#include "main/mm.h"
#include "main/objanim_internal.h"
#include "main/objfx.h"
#include "main/objHitReact_types.h"
#include "main/dll/dll_005A_staffcollision.h"
#include "main/dll/dll_00E2_staff_api.h"
#include "main/resource.h"
#include "dolphin/mtx.h"
#include "main/dll/objpathtransform_struct.h"
#include "main/game_ui_interface.h"
#include "main/lightmap_api.h"
#include "main/dll/player_api.h"
#include "sys/objects/lifecycle.h"
#include "sys/objects.h"
#include "main/objtype.h"
#include "main/obj_hit_region.h"
#include "main/obj_link.h"
#include "main/objlib_api.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/obj_query.h"
#include "main/obj_trigger.h"
#include "main/player_eye_anim.h"
#include "main/pad_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/rcp_dolphin_render_api.h"
#include "main/texture.h"
#include "main/objprint_dolphin_api.h"
#include "main/curve_eval.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "main/objprint_sound_api.h"
#include "main/newshadows.h"
#include "main/objtexture.h"
#include "main/object_render.h"
#include "main/dll/modgfx.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXPixel.h"
#include "main/acosf.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "track/intersect_api.h"
#include "main/objprint_internal.h"
#include "main/audio/sfx_channel_query_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/objprint_render_api.h"

#define OBJLIB_BLINK_LEFT_JOINT_TAG  5
#define OBJLIB_BLINK_RIGHT_JOINT_TAG 4

/* Eye-blink state machine (PlayerBlinkState.mode). amount = eyelid closure 0..255. */
typedef enum ObjLibBlinkMode {
    OBJLIB_BLINK_MODE_OPEN = 0,       /* eyes open; randomly start a blink or a wink */
    OBJLIB_BLINK_MODE_CLOSING = 1,    /* eyelids ramping shut (amount -> 255) */
    OBJLIB_BLINK_MODE_CLOSED = 2,     /* fully shut; randomly start opening */
    OBJLIB_BLINK_MODE_OPENING = 3,    /* eyelids ramping open (amount -> 0) */
    OBJLIB_BLINK_MODE_WINK_RIGHT = 4, /* hold shut, right eye scaled apart */
    OBJLIB_BLINK_MODE_WINK_LEFT = 5,  /* hold shut, left eye scaled apart */
} ObjLibBlinkMode;

typedef struct PlayerBlinkState {
    u8 pad[0x2b];
    u8 mode;   /* 0x2b */
    u8 timer;  /* 0x2c */
    u8 amount; /* 0x2d */
} PlayerBlinkState;

static inline ObjJointPose18* playerEyeAnim_FindJoint(ObjAnimComponent* objAnim, int tag) {
    int jointCount;
    u8* jointData;
    int poseOffset;
    int jointDataOffset;
    ObjModelInstance* model;
    ObjJointPose18* joint;

    joint = NULL;
    model = objAnim->modelInstance;
    if (model != 0) {
        jointDataOffset = 0;
        poseOffset = 0;
        for (jointCount = model->jointCount; jointCount > 0; jointCount--) {
            jointData = (u8*)model->jointData;
            if (((int)*(u8*)(jointData + objAnim->bankIndex + jointDataOffset + 1) != 0xff) &&
                ((int)jointData[jointDataOffset] == tag)) {
                joint = (ObjJointPose18*)(objAnim->jointPoseData + poseOffset);
            }
            jointDataOffset += model->modelCount + 1;
            poseOffset += 0x12;
        }
    }
    return joint;
}

void playerUpdateBlinkAnimation(void* obj, void* blinkState, u16 flags) {

    PlayerBlinkState* bs = (PlayerBlinkState*)blinkState;
    f32 leftScale;
    s16 rotation;
    ObjAnimComponent* objAnim;
    f32 phase;
    u8 step;
    f32 rightScale;
    f32 wave;

    objAnim = (ObjAnimComponent*)obj;
    step = 3.0f * timeDelta;
    rightScale = (leftScale = 1.0f);
    switch (bs->mode) {
    case OBJLIB_BLINK_MODE_OPEN:
        bs->timer = (u8)((f32)bs->timer + timeDelta);
        bs->amount = 0;
        if ((flags & 1) != 0) {
            if (randomGetRange(0, 100) == 1) {
                switch (bs->mode) {
                case OBJLIB_BLINK_MODE_OPEN:
                    bs->mode = OBJLIB_BLINK_MODE_CLOSING;
                    bs->timer = 0;
                    bs->amount = 0;
                    break;
                case OBJLIB_BLINK_MODE_OPENING:
                    bs->mode = OBJLIB_BLINK_MODE_CLOSING;
                    break;
                }
            } else if (randomGetRange(0, 75) == 1) {
                if (randomGetRange(0, 1) == 0) {
                    bs->mode = OBJLIB_BLINK_MODE_WINK_RIGHT;
                } else {
                    bs->mode = OBJLIB_BLINK_MODE_WINK_LEFT;
                }
            }
        }
        break;
    case OBJLIB_BLINK_MODE_CLOSING:
        bs->timer = (u8)((f32)bs->timer + timeDelta);
        if ((s16)bs->amount + (s16)step > 255) {
            step = (u8)(255 - bs->amount);
            bs->mode = OBJLIB_BLINK_MODE_CLOSED;
        }
        bs->amount += step;
        break;
    case OBJLIB_BLINK_MODE_CLOSED:
        bs->timer = (u8)((f32)bs->timer + timeDelta);
        if (randomGetRange(0, 100) == 1) {
            switch (bs->mode) {
            case OBJLIB_BLINK_MODE_CLOSING:
            case OBJLIB_BLINK_MODE_CLOSED:
                bs->mode = OBJLIB_BLINK_MODE_OPENING;
                break;
            case OBJLIB_BLINK_MODE_WINK_RIGHT:
            case OBJLIB_BLINK_MODE_WINK_LEFT:
                bs->mode = OBJLIB_BLINK_MODE_OPEN;
                break;
            }
        }
        break;
    case OBJLIB_BLINK_MODE_OPENING:
        bs->timer = (u8)((f32)bs->timer + timeDelta);
        if ((s16)bs->amount - (s16)step < 0) {
            step = bs->amount;
            bs->mode = OBJLIB_BLINK_MODE_OPEN;
        }
        bs->amount -= step;
        break;
    case OBJLIB_BLINK_MODE_WINK_RIGHT:
        bs->timer = (u8)(16.0f * timeDelta + bs->timer);
        bs->amount = 0xff;
        rightScale = 0.0f;
        if (randomGetRange(0, 25) == 1) {
            switch (bs->mode) {
            case OBJLIB_BLINK_MODE_CLOSING:
            case OBJLIB_BLINK_MODE_CLOSED:
                bs->mode = OBJLIB_BLINK_MODE_OPENING;
                break;
            case OBJLIB_BLINK_MODE_WINK_RIGHT:
            case OBJLIB_BLINK_MODE_WINK_LEFT:
                bs->mode = OBJLIB_BLINK_MODE_OPEN;
                break;
            }
        }
        break;
    case OBJLIB_BLINK_MODE_WINK_LEFT:
        bs->timer = (u8)(16.0f * timeDelta + bs->timer);
        bs->amount = 0xff;
        leftScale = 0.0f;
        if (randomGetRange(0, 25) == 1) {
            switch (bs->mode) {
            case OBJLIB_BLINK_MODE_CLOSING:
            case OBJLIB_BLINK_MODE_CLOSED:
                bs->mode = OBJLIB_BLINK_MODE_OPENING;
                break;
            case OBJLIB_BLINK_MODE_WINK_RIGHT:
            case OBJLIB_BLINK_MODE_WINK_LEFT:
                bs->mode = OBJLIB_BLINK_MODE_OPEN;
                break;
            }
        }
        break;
    }

    phase = 0.09856f * bs->timer;
    wave = 0.25f * mathCosfHighPrecision(phase);
    wave = wave * bs->amount / 255.0f;
    rotation = (32768.0f * (leftScale * wave)) / 3.142f;
    playerEyeAnim_FindJoint(objAnim, OBJLIB_BLINK_LEFT_JOINT_TAG)->v[1] = rotation;

    rotation = (32768.0f * (rightScale * wave)) / 3.142f;
    playerEyeAnim_FindJoint(objAnim, OBJLIB_BLINK_RIGHT_JOINT_TAG)->v[1] = -rotation;
}

void objSetLookAtFlip(int mode, u8 enabled) {
    if ((int)(u8)mode != 0) {
        return;
    }
    gObjLookAtControlFlags.flip = enabled;
}
int gObjLookAtTurnRateDivisor = 100;
f32 gObjMouthBlendFrames = 20.0f;

void objSoundUpdateMouth(GameObject* obj, ObjSoundState* state) {
    s16* found;
    int timer;

    timer = (s32)state->timer;
    found = objFindJointVecByKey(obj, 1);

    if (state->active != 0) {
        state->active = 0;
    } else if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) != 0) {
        if (timer != -1) {
            timer -= framesThisStep;
            if (timer < 0) {
                Sfx_StopObjectChannel(obj, 0x10);
                state->blendWeight = 0.0f;
                state->mouthAngle = 0;
            }
            state->timer = timer;
        }
    } else {
        state->timer = -1.0f;
        state->mouthAngle = 0;
        if (state->blendWeight > 0.0f) {
            ObjModel* pi;
            state->blendWeight = 0.0f;
            pi = (ObjModel*)OBJPRINT_ACTIVE_BANK(obj);
            if (pi->file->morphTargetCount != 0) {
                ObjModel_SetBlendChannelTargets(pi, 2, pi->blendChannels[2].morphTargetB, -1,
                                                1.0f / gObjMouthBlendFrames, 0);
            }
        }
    }

    if (found != NULL) {
        found[0] = (s16)((found[0] + state->mouthAngle) >> 1);
    }
}

void objKfAnimUpdate(GameObject* obj, ObjKfAnimState* state) {
    int frame;
    ObjModel* model;
    int kfval;
    int* kf;

    f32 t;

    if (state->frame < 0) {
        return;
    }
    t = state->timer - timeDelta;
    state->timer = t;
    if (t < 0.0f) {
        frame = state->frame;
        if (frame >= state->frameCount) {
            state->frame = -1;
            model = (ObjModel*)OBJPRINT_ACTIVE_BANK(obj);
            if (model->file->morphTargetCount != 0) {
                ObjModel_SetBlendChannelTargets(model, 2, model->blendChannels[2].morphTargetB, -1,
                                                1.0f / gObjMouthBlendFrames, 0);
            }
        } else {
            if (frame == 1) {
                Sfx_PlayFromObjectChannel(obj, 0x10, state->sfxId);
            }
            kf = state->keyframes;
            frame = state->frame;
            state->frame = frame + 1;
            kfval = kf[frame];
            model = (ObjModel*)OBJPRINT_ACTIVE_BANK(obj);
            if (model->file->morphTargetCount != 0) {
                ObjModel_SetBlendChannelTargets(model, 2, model->blendChannels[2].morphTargetB, kfval - 1,
                                                1.0f / gObjMouthBlendFrames, 0);
            }
            state->timer = state->timer + state->timerStep;
        }
    }
}

void objKfAnimStop(ObjKfAnimState* state) {
    state->frame = -1;
}

void objSoundStart(GameObject* obj, void* state, u16 sfxId) {
    if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
        Sfx_PlayFromObjectChannel(obj, 0x10, sfxId);
        ((ObjSoundState*)state)->timer = -1.0f;
        ((ObjSoundState*)state)->mouthAngle = -0x500;
        ((ObjSoundState*)state)->active = 1;
        ((ObjSoundState*)state)->blendWeight = 1.0f;
    }
}

void objSoundStartFromDef(GameObject* obj, ObjSoundState* state, ObjSoundDef* soundDef, u8 force) {
    u16 sfx;
    s16 mouthOpenAngle;
    u32 count;
    ObjModel* model;
    int did;

    mouthOpenAngle = soundDef->mouthOpenAngle;
    sfx = (u16)soundDef->sfxId;
    if (force != 0 || Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0) {
        Sfx_PlayFromObjectChannel(obj, 0x10, sfx);
        state->timer = -1.0f;
        state->mouthAngle = (s16)(-mouthOpenAngle);
        state->active = 1;
        state->blendWeight = 1.0f;
    }
    count = soundDef->blendCount;
    if (count != 0) {
        model = (ObjModel*)OBJPRINT_ACTIVE_BANK(obj);
        if (model->file->morphTargetCount != 0) {
            ObjModel_SetBlendChannelTargets(model, 2, model->blendChannels[2].morphTargetB, count - 1,
                                            1.0f / gObjMouthBlendFrames, 0);
            did = 1;
        } else {
            did = 0;
        }
        if (did != 0) {
            soundDef->mouthOpenAngle = 0;
        }
    }
}

void objSoundStartTimed(GameObject* obj, ObjSoundState* state, u16 sfx, int mouthOpenAngle, int duration, u8 force) {
    if (force == 0 && Sfx_IsPlayingFromObjectChannel(obj, 0x10) != 0) {
        return;
    }
    Sfx_PlayFromObjectChannel(obj, 0x10, sfx);
    state->timer = duration;
    state->mouthAngle = (s16)(-mouthOpenAngle);
    state->active = 1;
    state->blendWeight = 1.0f;
}

int gObjLookAtJointKeys[10] = {0, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13};

int* objGetLookAtJointKeys(void) {
    return gObjLookAtJointKeys;
}

ObjTextureRuntimeSlot* objFindTexture(GameObject* obj, int target, int unusedMaterialIndex) {
    ObjTextureRuntimeSlot* result = NULL;
    ObjDef* modelDef = (obj)->anim.modelInstance;
    if (modelDef != NULL) {
        int count;
        ObjTextureSlotDef* entries = modelDef->textureSlotDefs;
        if (entries == NULL) {
            return NULL;
        }
        {
            int i;
            count = modelDef->textureSlotCount;
            for (i = 0; i < count; i++) {
                if (target == entries[i].tag) {
                    result = &(obj)->anim.textureSlots[i];
                }
            }
        }
    }
    return result;
}

void objGetJointWorldPosition(GameObject* obj, int key, f32* outPosition) {
    ObjDef* table;
    int i;
    int k;
    int n;
    int joint;
    ObjModelJointMatrix* model;

    table = (void*)(obj)->anim.modelInstance;
    i = 0;
    n = (s32)(u32)table->jointCount;
    for (k = 0; k < n; k++) {
        if (key == (int)(*(u8**)&table->jointData)[i]) {
            joint = (*(u8**)&table->jointData + i + OBJPRINT_ACTIVE_BANK_INDEX(obj))[1];
            break;
        }
        i = i + table->modelCount + 1;
    }
    model = (ObjModelJointMatrix*)Obj_GetActiveModel(obj);
    model = ObjModel_GetJointMatrix((u8*)model, joint);
    outPosition[0] = model->translationX;
    outPosition[1] = model->translationY;
    outPosition[2] = model->translationZ;
    outPosition[0] += playerMapOffsetX;
    outPosition[2] += playerMapOffsetZ;
}

s16* objFindJointPoseVector(GameObject* obj, int key) {
    int vecOffset;
    u8* jointData;
    int entryIdx;
    ObjDef* modelDef;
    s16* result;
    int count;
    int i;

    result = NULL;
    modelDef = OBJPRINT_MODEL_INSTANCE(obj);
    if (modelDef != NULL) {
        entryIdx = 0;
        vecOffset = 0;
        count = OBJPRINT_JOINT_COUNT(modelDef);
        for (i = 0; i < count; i++) {
            jointData = (u8*)modelDef->jointData;
            if ((int)*(u8*)(jointData + OBJPRINT_ACTIVE_BANK_INDEX(obj) + entryIdx + 1) != 0xff &&
                (s32) * (u8*)(jointData + entryIdx) == key) {
                result = (s16*)((char*)(obj)->anim.jointPoseData + vecOffset);
            }
            entryIdx += OBJPRINT_MODEL_COUNT(modelDef) + 1;
            vecOffset += 0x12;
        }
    }
    return result;
}

void characterDoEyeMovements(GameObject* obj, CharacterEyeAnimState* state, f32 unused) {
    ObjTextureRuntimeSlot* foundA;
    ObjTextureRuntimeSlot* foundB;
    s16 t;
    int flag;
    s8 timer;

    foundA = characterFindEyeJoint(obj, 1);
    foundB = characterFindEyeJoint(obj, 0);
    if (foundA == NULL || foundB == NULL) {
        return;
    }

    flag = 0;
    t = state->movementStep;
    if (t == 0) {
        flag = 1;
    }
    if (t > 0) {
        if (foundA->offsetS >= state->movementTarget) {
            flag = 1;
        }
    }
    if (t < 0) {
        if (foundA->offsetS <= state->movementTarget) {
            flag = 1;
        }
    }
    if (flag != 0) {
        state->movementTarget = randomGetRange(-0x3e8, 0x3e8);
        state->movementStep = (state->movementTarget < foundA->offsetS) ? -0x96 : 0x96;
        state->movementTimer = randomGetRange(0x1e, 0x64);
    }
    timer = state->movementTimer;
    if (timer > 0) {
        state->movementTimer = timer - framesThisStep;
    } else {
        foundA->offsetS = (s16)(foundA->offsetS + state->movementStep * framesThisStep);
        foundA->offsetT = 0;
        foundB->offsetS = foundA->offsetS;
        foundB->offsetT = 0;
    }
}

static int characterTrackJointPitch(s16* curve, s16* state, f32 a, f32 b) {
    f32 buf[4];
    f32 ratio;
    s16 lo;
    s16 hi;

    buf[0] = a;
    buf[1] = a;
    buf[2] = b;
    buf[3] = -b;

    lo = curve[10];
    hi = curve[11];
    if (lo != hi) {
        ratio = ((f32)(s32)*state - (f32)(s32)hi) / ((f32)(s32)lo - (f32)(s32)hi);
    } else {
        return 1;
    }

    if (ratio > 1.0f) {
        ratio = 1.0f;
    } else if (ratio < 0.0f) {
        ratio = 0.0f;
    }

    {
        f32 rate = Curve_EvalHermite(buf, ratio, 0);
        if (curve[10] < curve[11]) {
            rate = -rate;
        }
        *state = rate * timeDelta + (f32)(s32)*state;
    }

    if (1.0f == ratio || *state >= 8191 || *state <= -8191) {
        *state = curve[10];
        return 1;
    }
    return 0;
}
static int characterTrackJointYaw(s16* curve, s16* state) {
    f32 buf[4];
    f32 ratio;
    s16 lo;
    s16 hi;

    buf[0] = 10.0f;
    buf[1] = 10.0f;
    buf[2] = 500.0f;
    buf[3] = -500.0f;

    lo = curve[10];
    hi = curve[11];
    if (lo != hi) {
        ratio = ((f32)(s32)state[1] - (f32)(s32)hi) / ((f32)(s32)lo - (f32)(s32)hi);
    } else {
        return 1;
    }

    if (ratio > 1.0f) {
        ratio = 1.0f;
    } else if (ratio < 0.0f) {
        ratio = 0.0f;
    }

    {
        f32 rate = Curve_EvalHermite(buf, ratio, 0);
        if (curve[10] < curve[11]) {
            rate = -rate;
        }
        state[1] = rate * timeDelta + (f32)(s32)state[1];
    }

    if (1.0f == ratio || state[1] >= 8191 || state[1] <= -8191) {
        state[1] = curve[10];
        return 1;
    }
    return 0;
}

static void characterHeadLookAlert(GameObject* obj, CharacterEyeAnimState* curve, s16* state, f32 val) {
    int masked;
    int flag;

    masked = (curve->headTrackMode >> 8) & 0xff;
    if (val > 0.1f) {
        flag = 1;
    } else {
        flag = 0;
    }
    if (masked != flag) {
        curve->headTrackMode = (s16)(flag << 8 | 4);
        curve->headYawStart = state[1];
        curve->headYaw = 0;
        curve->headTrackTimer = 0;
    }

    switch ((u8)curve->headTrackMode) {
    case 0:
        curve->headTrackMode = (s16)(flag << 8);
        curve->headTrackTimer = randomGetRange(0x32, 0xc8);
        break;
    case 1:
        curve->headTrackTimer -= framesThisStep;
        if (curve->headTrackTimer < 0) {
            if (randomGetRange(0, 100) > 90) {
                curve->headTrackMode = (s16)(flag << 8 | 5);
                if (curve->lookAtActive != 0) {
                    if (randomGetRange(0, 100) > 0) {
                        curve->headYaw = 0x1fff;
                        if (randomGetRange(0, 1) == 0) {
                            curve->headYaw = -curve->headYaw;
                        }
                    }
                } else {
                    curve->headYaw = 0x1fff;
                    if (randomGetRange(0, 1) == 0) {
                        curve->headYaw = -curve->headYaw;
                    }
                }
            }
        }
        break;
    case 2:
        break;
    case 5:
        if (curve->headTrackTimer > 0) {
            curve->headTrackTimer -= framesThisStep;
        } else if (characterTrackJointYaw((s16*)curve, state)) {
            curve->headTrackMode = (s16)(flag << 8 | 6);
            curve->headYaw = -curve->headYaw;
            curve->headTrackTimer = randomGetRange(0x14, 0x64);
        }
        break;
    case 6:
        if (curve->headTrackTimer > 0) {
            curve->headTrackTimer -= framesThisStep;
        } else if (characterTrackJointYaw((s16*)curve, state)) {
            curve->headTrackMode = (s16)(flag << 8 | 4);
            curve->headYaw = 0;
            curve->headTrackTimer = randomGetRange(0x14, 0x64);
        }
        break;
    case 4:
        if (curve->headTrackTimer > 0) {
            curve->headTrackTimer -= framesThisStep;
        } else if (characterTrackJointYaw((s16*)curve, state)) {
            curve->headTrackMode = (s16)(flag << 8);
            state[1] = 0;
        }
        break;
    }
}

static void characterHeadLookIdle(GameObject* obj, CharacterEyeAnimState* curve, s16* state, f32 val) {
    int masked;
    int flag;

    masked = (curve->headTrackMode >> 8) & 0xff;
    if (val > 0.1f) {
        flag = 1;
    } else {
        flag = 0;
    }
    if (masked != flag) {
        curve->headTrackMode = (s16)(flag << 8);
    }

    switch ((u8)curve->headTrackMode) {
    case 0:
        if (curve->lookAtActive != 0) {
            curve->headTrackMode = (s16)(flag << 8 | 3);
            curve->headYawStart = state[1];
            curve->headTrackBlend = 1.0f;
        } else {
            curve->headTrackMode = (s16)(flag << 8 | 1);
            curve->headTrackTimer = randomGetRange(100, 400);
            curve->headYaw = state[1];
        }
        break;
    case 1:
        curve->headTrackTimer -= framesThisStep;
        if (curve->headTrackTimer < 0) {
            int old = curve->headYaw;
            curve->headYaw = randomGetRange(0, 0x1fff);
            if (old > 0) {
                if (old - curve->headYaw < 0xe38) {
                    curve->headYaw += 0xe38;
                }
                if (curve->headYaw > 0x1fff) {
                    curve->headYaw = 0x1fff;
                }
                curve->headYaw = -curve->headYaw;
            } else {
                if (curve->headYaw - old < 0xe38) {
                    curve->headYaw += 0xe38;
                }
                if (curve->headYaw > 0x1fff) {
                    curve->headYaw = 0x1fff;
                }
            }
            curve->headTrackMode = (s16)(flag << 8 | 2);
            curve->headTrackTimer = 0;
            curve->headYawStart = state[1];
        }
        break;
    case 2:
        if (curve->lookAtActive != 0 || characterTrackJointYaw((s16*)curve, state) != 0) {
            curve->headTrackMode = (s16)(flag << 8);
        }
        break;
    case 3:
        if (curve->lookAtActive == 0) {
            curve->headTrackMode = (s16)(flag << 8);
        } else {
            int angle;
            int n;
            angle = getAngle(obj->anim.localPosX - curve->lookAtPosX,
                             obj->anim.localPosZ - curve->lookAtPosZ);
            curve->headYaw = (s16)(angle - (u16)obj->anim.rotX);
            if (curve->headYaw > 0x8000) {
                curve->headYaw = (s16)(curve->headYaw - 0xffff);
            }
            if (curve->headYaw < -0x8000) {
                curve->headYaw = (s16)(curve->headYaw + 0xffff);
            }
            n = curve->headYaw;
            if (n > 0x1fff || n < -0x1fff) {
                curve->headTrackMode = (s16)(flag << 8);
            } else {
                f32 t = curve->headTrackBlend;
                f32 lo = 0.0f;
                if (t > lo) {
                    f32 nv;
                    state[1] = t * (f32)(curve->headYawStart - n) + n;
                    nv = -(0.01f * timeDelta - curve->headTrackBlend);
                    curve->headTrackBlend = nv;
                    if (nv < lo) {
                        curve->headTrackBlend = lo;
                    }
                } else {
                    state[1] = n;
                }
            }
        }
        break;
    }

    if (state[1] < -0x1fff) {
        state[1] = -0x1fff;
    } else if (state[1] > 0x1fff) {
        state[1] = 0x1fff;
    }
}

void characterHeadLookRelax(GameObject* obj, void* state) {
    s16* found;

    found = objFindJointVecByKey(obj, 0);
    if (found == NULL) {
        return;
    }
    if (found[0] != 0) {
        found[0] = (s16)((s32)found[0] * 3 / 4);
    }
    if (found[1] != 0) {
        found[1] = (s16)((s32)found[1] * 3 / 4);
    }
    ((CharacterEyeAnimState*)state)->headTrackMode = 0;
}

void characterUpdateHeadLook(GameObject* obj, CharacterEyeAnimState* state, f32 scale) {
    s16* found;
    int flag;

    found = objFindJointVecByKey(obj, 0);
    if (found != NULL) {
        if (found[0] != 0) {
            found[0] = (s16)(found[0] * 3 / 4);
        }
        if (scale < 0.0f) {
            scale = -scale;
        }
        if (scale <= 0.1f) {
            characterHeadLookIdle(obj, state, found, scale);
        } else {
            characterHeadLookAlert(obj, state, found, scale);
        }
        state->headTrackMode = (s16)(u16)(u8)state->headTrackMode;
        if (scale > 0.1f) {
            flag = 1;
        } else {
            flag = 0;
        }
        state->headTrackMode = (s16)(state->headTrackMode | (flag << 8));
    }
}
s16 objJointTracksAimAtTarget(GameObject* obj, GameObject* target, f32* pos, u8* p4, s16* spd, f32 yOff, int unused, int basePitch);
s16 objJointTracksAimAtTarget(GameObject* obj, GameObject* target, f32* pos, u8* p4, s16* spd, f32 yOff, int unused,
                              int basePitch) {
    s16 src[2];
    s16 dst[2];
    GameObject* go = obj;
    s16* found[1];
    s16* sp2;
    f32 dx, dy, dz, dist;
    int i;
    s16 ret;

    sp2 = spd + 0xf;
    dx = pos[0] - target->anim.localPosX;
    dz = pos[2] - target->anim.localPosZ;
    dy = (pos[1] + yOff) - target->anim.localPosY;
    dist = sqrtf(dx * dx + dz * dz);

    src[0] = (s16)getAngle(dx, dz) - (u16)go->anim.rotX;
    if (src[0] > 0x8000) {
        src[0] = (s16)(src[0] - 0xffff);
    }
    if (src[0] < -0x8000) {
        src[0] = (s16)(src[0] + 0xffff);
    }
    src[1] = basePitch - (u16)-getAngle(dist, dy);
    if (src[1] > 0x8000) {
        src[1] = (s16)(src[1] - 0xffff);
    }
    if (src[1] < -0x8000) {
        src[1] = (s16)(src[1] + 0xffff);
    }

    ret = src[0];
    if (gObjLookAtControlFlags.flip) {
        src[0] -= 0x8000;
        src[1] = -src[1];
        gObjLookAtControlFlags.flip = 0;
    }

    i = 0;
    while (i < 10) {
        int key;
        void* m[1];

        key = gObjLookAtJointKeys[i];
        found[0] = NULL;
        m[0] = (void*)go->anim.modelInstance;
        if (m[0] != NULL) {
            int iv[2];
            int n;
            int j;
            iv[0] = 0;
            iv[1] = 0;
            n = ((ObjDef*)m[0])->jointCount;
            for (j = 0; j < n; j++) {
                u8* entries = (u8*)((ObjDef*)m[0])->jointData;
                if ((int)*(u8*)(entries + OBJPRINT_ACTIVE_BANK_INDEX(go) + iv[0] + 1) != 0xff &&
                    key == (int)*(u8*)(entries + iv[0])) {
                    found[0] = (s16*)(go->anim.jointPoseData + iv[1]);
                }
                iv[0] += ((ObjDef*)m[0])->modelCount + 1;
                iv[1] += 0x12;
            }
        }
        if (found[0] == NULL) {
            int t = ret;
            t = (t >= 0) ? t : -t;
            return (s16)(t < 0x100);
        }

        {
            int n2;
            for (n2 = 0; n2 < 2; n2++) {
                s16 v;
                s16 lim;
                if (n2 % 2 != 0) {
                    lim = (s16)(182.04f * (f32)sp2[i]);
                } else {
                    lim = (s16)(182.04f * (f32)spd[i]);
                }
                v = src[n2];
                dst[n2] = v;
                if (v > lim) {
                    dst[n2] = lim;
                    src[n2] -= lim;
                } else if (v < -lim) {
                    dst[n2] = -(s16)lim;
                    src[n2] += lim;
                } else {
                    src[n2] = 0;
                }
            }
        }

        if (p4 != NULL) {
            ((ObjJointTrackPair*)p4)->yaw.angle = dst[0];
            characterTrackJointYaw((s16*)p4, found[0]);
            ((ObjJointTrackPair*)p4)->pitch.angle = dst[1];
            characterTrackJointPitch((s16*)&((ObjJointTrackPair*)p4)->pitch, found[0], 10.0f, 500.0f);
            p4 += 0x60;
        } else {
            s16* fv = found[0];
            s16 d1 = (s16)((s16)((fv[1] + dst[0]) >> 1) - fv[1]);
            s16 lim;
            s16 d2;
            int t2;
            int lim3;

            lim = (d1 < framesThisStep * ((s16)(s32)(182.04f * (f32)-spd[i]) / gObjLookAtTurnRateDivisor))
                      ? framesThisStep * ((s16)(s32)(182.04f * (f32)-spd[i]) / gObjLookAtTurnRateDivisor)
                      : ((d1 > framesThisStep * ((s16)(s32)(182.04f * (f32)spd[i]) / gObjLookAtTurnRateDivisor))
                             ? framesThisStep * ((s16)(s32)(182.04f * (f32)spd[i]) / gObjLookAtTurnRateDivisor)
                             : d1);
            d2 = (s16)((s16)((fv[0] + dst[1]) >> 1) - fv[0]);
            t2 = (s16)(s32)(182.04f * (f32)sp2[i]);
            lim3 = (d2 < framesThisStep * (-t2 / (gObjLookAtTurnRateDivisor << 1)))
                       ? framesThisStep * (-t2 / (gObjLookAtTurnRateDivisor << 1))
                       : ((d2 > framesThisStep * (t2 / (gObjLookAtTurnRateDivisor << 1)))
                              ? framesThisStep * (t2 / (gObjLookAtTurnRateDivisor << 1))
                              : d2);
            fv[0] += (s16)lim3;
            fv[1] += lim;
        }

        if (i == 0) {
            ret -= found[0][1];
        }
        i++;
    }
    return src[0];
}

int characterTrackJointList(GameObject* objArg, int* keyList, int countArg, u8* p4Arg) {
    int* keys;
    int i;
    int total;
    u8* p4;
    int count;
    GameObject* obj;
    s16* found;

    obj = objArg;
    count = countArg;
    p4 = p4Arg;
    total = 0;
    i = 0;
    keys = keyList;
    while (i < count) {
        found = objFindJointVecByKey(obj, *keys);
        total += characterTrackJointYaw((s16*)p4, found);
        total += characterTrackJointPitch((s16*)&((ObjJointTrackPair*)p4)->pitch, found, 10.0f, 500.0f);
        keys++;
        i++;
        p4 += 0x60;
    }
    return (count * 2 - total) == 0;
}

void objJointTracksSetAngles(u8* channelData, int count, s16 yaw, s16 pitch) {
    ObjJointTrackPair* tracks = (ObjJointTrackPair*)channelData;

    while (count > 0) {
        tracks->yaw.angle = yaw;
        tracks->pitch.angle = pitch;
        tracks++;
        count--;
    }
}

void characterDoEyeMovements(GameObject* obj, CharacterEyeAnimState* state, f32 unused);

void objModelClearJointVectors(GameObject* obj) {
    s16* found;
    int slot;

    for (slot = 0; slot < 0x16; slot++) {
        found = objFindJointVecByKey(obj, slot);
        if (found != NULL) {
            found[0] = 0;
            found[1] = 0;
            found[2] = 0;
        }
    }
}

void characterClampJointVecs(GameObject* obj, int* keys, int count, int lo, int hi) {
    s16* found;
    int idx;
    int v;

    for (idx = 0; idx < count; idx++) {
        found = objFindJointVecByKey(obj, *keys);
        if (found != NULL) {
            v = found[0];
            if (v < lo) {
                v = lo;
            } else if (v > hi) {
                v = hi;
            }
            found[0] = v;
            v = found[1];
            if (v < lo) {
                v = lo;
            } else if (v > hi) {
                v = hi;
            }
            found[1] = v;
            v = found[2];
            if (v < lo) {
                v = lo;
            } else if (v > hi) {
                v = hi;
            }
            found[2] = v;
        }
        keys++;
    }
}

void characterDecayJointVecs(GameObject* obj, int* keys, int count) {
    s16* found;
    int idx;

    for (idx = 0; idx < count; idx++) {
        found = objFindJointVecByKey(obj, *keys);
        if (found != NULL) {
            found[1] = (s16)(found[1] * 3 >> 2);
            found[0] = (s16)(found[0] * 3 >> 2);
            found[2] = (s16)(found[2] * 3 >> 2);
        }
        keys++;
    }
}

void objJointTracksCaptureCurrentAngles(GameObject* obj, int* keys, int count, u8* out) {
    s16* found;
    int idx;

    for (idx = 0; idx < count;) {
        found = objFindJointVecByKey(obj, *keys);
        if (found != NULL) {
            ((ObjJointTrackPair*)out)->yaw.angleStart = found[1];
            ((ObjJointTrackPair*)out)->pitch.angleStart = found[0];
        }
        keys++;
        idx++;
        out += 0x60;
    }
}

void characterAimHeadAtTarget(GameObject* obj, void* tgt, void* state, int limit, u8 inv, int mode) {
    s16 ang[2];
    s16* found[1];
    void* m[1];

    found[0] = NULL;
    m[0] = (void*)(obj)->anim.modelInstance;
    if (m[0] != NULL) {
        int iv[2];
        int n;
        int j;
        iv[0] = 0;
        iv[1] = 0;
        n = ((ObjDef*)m[0])->jointCount;
        for (j = 0; j < n; j++) {
            u8* entries = (u8*)((ObjDef*)m[0])->jointData;
            if ((int)*(u8*)(entries + OBJPRINT_ACTIVE_BANK_INDEX(obj) + iv[0] + 1) != 0xff &&
                (int)*(u8*)(entries + iv[0]) == 0) {
                found[0] = (s16*)((char*)(obj)->anim.jointPoseData + iv[1]);
            }
            iv[0] += ((ObjDef*)m[0])->modelCount + 1;
            iv[1] += 0x12;
        }
    }
    if (found[0] != NULL) {
        if (tgt == NULL) {
            found[0][1] = found[0][1] >> 1;
            found[0][0] = found[0][0] >> 1;
        } else {
            f32 dx = (obj)->anim.localPosX - ((GameObject*)tgt)->anim.localPosX;
            f32 dz = (obj)->anim.localPosZ - ((GameObject*)tgt)->anim.localPosZ;
            f32 dy = (obj)->anim.localPosY - ((GameObject*)tgt)->anim.localPosY;
            f32 dist = sqrtf(dx * dx + dz * dz);
            ObjJointTrackChannel* channel;
            s16* ap;
            int minB;
            int negA;
            int i;
            f32 prodB;

            ang[0] = (s16)getAngle(dx, dz) - (u16)(obj)->anim.rotX;
            if (ang[0] > 0x8000) {
                ang[0] = (s16)(ang[0] - 0xffff);
            }
            if (ang[0] < -0x8000) {
                ang[0] = (s16)(ang[0] + 0xffff);
            }
            if (inv != 0) {
                ang[0] = (s16)(ang[0] + 0x8000);
            }
            ang[1] = (s16)((s16)getAngle(dist, dy) - 0x3fff);

            limit = (s16)(182.04f * limit);
            channel = state;
            ap = ang;
            prodB = 182.04f * mode;
            minB = -(s16)(s32)prodB;
            negA = -limit;
            for (i = 0; i < 2; i++) {
                int v;
                int w;
                f64 pd = prodB;
                *ap -= channel->angle;
                v = *ap;
                if (v < minB) {
                    w = minB;
                } else {
                    if (v > (s16)(s32)pd) {
                        v = (s32)pd;
                    }
                    w = (s16)v;
                }
                *ap = (s16)w;
                channel->angle += *ap;
                if (channel->angle > limit) {
                    channel->angle = limit;
                }
                if (channel->angle < negA) {
                    channel->angle = negA;
                }
                channel++;
                ap++;
            }
            found[0][1] = ((ObjJointTrackPair*)state)->yaw.angle;
            found[0][0] = ((ObjJointTrackPair*)state)->pitch.angle;
        }
    }
}

s16 gObjColorFilterRed;
s16 gObjColorFilterGreen;
s16 gObjColorFilterBlue;
f32* gObjModelMatrixOverride;
u8 gObjGlowColorRed;
u8 gObjGlowColorGreen;
u8 gObjGlowColorBlue;
u8 gObjGlowColorAlpha;
u8 gObjGlowColorEnabled;
u8 gObjColorFilterEnabled;

void characterSetHeadYawToTarget(GameObject* obj, GameObject* target, CharacterEyeAnimState* state, int maxAngle) {
    s16* found;

    found = objFindJointVecByKey(obj, 0);
    if (found != NULL) {
        state->headYaw = (s16)((s16)getAngle((obj)->anim.localPosX - target->anim.localPosX,
                                             (obj)->anim.localPosZ - target->anim.localPosZ) -
                               (obj)->anim.rotX);
        maxAngle = (s16)(182.04f * maxAngle);
        if (state->headYaw > maxAngle) {
            state->headYaw = maxAngle;
        }
        if (state->headYaw < -maxAngle) {
            state->headYaw = -maxAngle;
        }
        found[1] = state->headYaw;
    }
}

void characterCloseEyes(GameObject* obj, void* state) {
    ObjTextureRuntimeSlot* foundA;
    ObjTextureRuntimeSlot* foundB;
    int val;

    foundA = characterFindEyeJoint(obj, 5);
    foundB = characterFindEyeJoint(obj, 4);
    if (foundA == NULL || foundB == NULL) {
        return;
    }
    val = foundB->textureId;
    val += framesThisStep * 0x30;
    if (val >= 0x200) {
        val = 0x200;
    }
    foundA->textureId = val;
    foundB->textureId = val;
    ((CharacterEyeAnimState*)state)->blinkState = 1;
}

void characterDoEyeMovements(GameObject* obj, CharacterEyeAnimState* state, f32 unused);

void characterDoEyeAnims(GameObject* obj, void* stateData) {
    CharacterEyeAnimState* state = stateData;
    ObjTextureRuntimeSlot* a;
    ObjTextureRuntimeSlot* b;

    a = characterFindEyeJoint(obj, 5);
    b = characterFindEyeJoint(obj, 4);

    if (a == NULL || b == NULL) {
        return;
    }
    {
        int st;
        int v;

        v = b->textureId;
        st = state->blinkState;

        switch (st & 0xf) {
        case 0: {
            s8 blinkTimer = state->blinkTimer;
            if (blinkTimer > 0) {
                state->blinkTimer = blinkTimer - framesThisStep;
            } else if (randomGetRange(0, 1000) > 0x3de) {
                state->blinkState = 1;
                state->blinkTimer = 0;
            }
        } break;
        case 1:
            if ((st & 0x80) != 0) {
                v = v - framesThisStep * 0x60;
                if (v < 0) {
                    v = 0;
                    state->blinkState = 0;
                    state->blinkTimer = 0;
                }
            } else {
                v = v + framesThisStep * 0x60;
                if (v > 0x200) {
                    if (v - 0x200 < 0) {
                        v = 0;
                        state->blinkState = 0;
                    } else {
                        v = 0x2ff;
                        state->blinkState = -127;
                    }
                    state->blinkTimer = 0x28;
                }
            }
            a->textureId = v;
            b->textureId = v;
            break;
        }
        characterDoEyeMovements(obj, state, 0.0f);
    }
}

void characterHeadLookCalm(GameObject* obj, s16* state, f32 value) {
    s16* found;

    found = objFindJointVecByKey(obj, 0);
    if (found != NULL) {
        if (found[0] != 0) {
            found[0] = (s16)(found[0] * 3 / 4);
        }
        characterHeadLookIdle(obj, (CharacterEyeAnimState*)state, found, 0.0f);
        ((CharacterEyeAnimState*)state)->headTrackMode = (s16)(u16)(u8)((CharacterEyeAnimState*)state)->headTrackMode;
    }
}

void objSetGlowColor(int red, int green, int blue, u8 alpha) {
    gObjGlowColorRed = red;
    gObjGlowColorGreen = green;
    gObjGlowColorBlue = blue;
    gObjGlowColorEnabled = 1;
    gObjGlowColorAlpha = alpha;
}

void objSetColorFilter(s16 red, s16 green, s16 blue) {
    gObjColorFilterRed = red;
    gObjColorFilterGreen = green;
    gObjColorFilterBlue = blue;
    gObjColorFilterEnabled = 1;
}

#define OBJPRINT_ATTACH_POINTS(staff) ((char*)OBJPRINT_MODEL_INSTANCE(staff)->attachPoints)

void staffUpdateSegmentTransforms(int staffArg, GameObject* objArg, int modelArg, int a, int b, int c) {
    f32 va[3];
    Vec vb;
    int k;
    char* q;
    Vec* vp;
    Vec* vp0;
    int i;
    char* base;
    ObjModel* model;
    int obj;
    GameObject* staff;

    staff = (GameObject*)staffArg;
    obj = (int)objArg;
    model = (ObjModel*)modelArg;

    if (OBJPRINT_MODEL_INSTANCE(staff)->attachPointCount >= 2 && staff->anim.classId == 0x2d) {
        int off;
        base = (char*)staff->extra;
        i = 0;
        k = 1;
        off = 0x18;
        q = base;
        vp0 = (Vec*)va;
        vp = vp0;

        while (i < *(s16*)(base + 0xb0)) {
            if (k < OBJPRINT_MODEL_INSTANCE(staff)->attachPointCount) {
                MtxPtr jm;
                int joint;
                joint = ((ObjAttachPoint*)(OBJPRINT_ATTACH_POINTS(staff) + off))[1].joints[OBJPRINT_ACTIVE_BANK_INDEX(staff)];
                jm = (MtxPtr)ObjModel_GetJointMatrix((u8*)model, joint);
                vp->x = ((ObjAttachPoint*)(OBJPRINT_ATTACH_POINTS(staff) + off))[1].pos[0];
                va[1] = ((ObjAttachPoint*)(OBJPRINT_ATTACH_POINTS(staff) + off))[1].pos[1];
                va[2] = ((ObjAttachPoint*)(OBJPRINT_ATTACH_POINTS(staff) + off))[1].pos[2];
                PSMTXMultVec(jm, vp, vp);
                vp->x = vp->x + playerMapOffsetX;
                va[2] = va[2] + playerMapOffsetZ;
                *(f32*)(q + 0x6c) = vp->x;
                *(f32*)(q + 0x74) = va[1];
                *(f32*)(q + 0x7c) = va[2];
            }
            if (k < OBJPRINT_MODEL_INSTANCE(staff)->attachPointCount) {
                ObjAttachPoint* row = (ObjAttachPoint*)(OBJPRINT_ATTACH_POINTS(staff) + off);
                int idx2 = row->joints[OBJPRINT_ACTIVE_BANK_INDEX(staff)];
                MtxPtr mtx2 =
                    (MtxPtr)(idx2 * 0x40 + *(int*)((u8*)model + ((model->bufferFlags & 1) * 4) + 0xc));
                vb.x = row->pos[0];
                vb.y = ((ObjAttachPoint*)(OBJPRINT_ATTACH_POINTS(staff) + off))->pos[1];
                vb.z = ((ObjAttachPoint*)(OBJPRINT_ATTACH_POINTS(staff) + off))->pos[2];
                PSMTXMultVec(mtx2, &vb, &vb);
                vb.x = vb.x + playerMapOffsetX;
                vb.z = vb.z + playerMapOffsetZ;
                *(f32*)(q + 0x54) = vb.x;
                *(f32*)(q + 0x5c) = vb.y;
                *(f32*)(q + 0x64) = vb.z;
            }
            k += 2;
            off += 0x30;
            q += 4;
            i++;
            vp = vp0;
        }

        if (*(s16*)(base + 0xb0) != 0) {
            char* r = base + *(s16*)(base + 0xb2) * 4;
            va[0] = *(f32*)(r + 0x6c);
            va[1] = *(f32*)(r + 0x74);
            va[2] = *(f32*)(r + 0x7c);
            STAFF_INTERFACE(staff)->updateSwipe(staff, (GameObject*)obj, &vb);
            va[0] = va[0] - vb.x;
            va[1] = va[1] - vb.y;
            va[2] = va[2] - vb.z;
            staff->anim.rotX = getAngle(va[0], va[2]);
            {
                f32 dx = va[0] * va[0];
                f32 dz = va[2] * va[2];
                staff->anim.rotY = (s16)(-getAngle(va[1], sqrtf(dx + dz)) + 0x4000);
            }
            staff->anim.rotZ = 0;
        }
    }
}

void objRenderShadowIfVisible(GameObject* obj, int wpad0, int wpad1, int wpad2, int wpad3, int wpad4) {
    void** arr = (void*)(obj)->anim.banks;
    s8 idx = (obj)->anim.bankIndex;
    if (arr[idx] != NULL) {
        objRenderShadow(obj);
    }
}

void objRenderModelAndHitVolumes(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale) {
    int** table = OBJPRINT_BANK_TABLE((int*)obj);
    (void)scale;
    if (table[OBJPRINT_ACTIVE_BANK_INDEX(obj)] != NULL) {
        objRenderModel(obj);
        if (obj->anim.hitVolumeTransforms != NULL) {
            objUpdateHitVolumeTransforms(obj);
        }
    }
}

void objSetModelMatrixOverride(f32* matrix) {
    gObjModelMatrixOverride = matrix;
}

void objRender(int a, int b, int c, int d, GameObject* obj, int flag) {
    void* sub;
    int walk;
    int i;
    void (*vfn)(GameObject*, int, int, int, int, int);

    if ((obj->objectFlags & OBJECT_OBJFLAG_FREED) != 0 || obj->ownerObj != NULL) {
        return;
    }
    if ((obj->anim.flags & OBJANIM_FLAG_HIDDEN) != 0) {
        return;
    }
    sub = (void*)obj->anim.parent;
    if (sub != NULL && (((GameObject*)sub)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0) {
        return;
    }

    doNothing_beforeRenderObject(4);
    obj->objectFlags |= OBJECT_OBJFLAG_RENDERED;
    sub = (void*)obj->anim.dll;
    if (sub != NULL) {
        if ((obj->objectFlags & OBJECT_OBJFLAG_HIDDEN) == 0) {
            vfn = (void (*)(GameObject*, int, int, int, int, int))((ObjectInterface*)*(ObjectInterfaceHandle)sub)->render;
            if (vfn != NULL) {
                vfn(obj, a, b, c, d, flag);
            }
        } else if ((s8)flag != 0 && OBJPRINT_ACTIVE_BANK(obj) != NULL) {
            objRenderModel(obj);
            if (obj->anim.hitVolumeTransforms != NULL) {
                objUpdateHitVolumeTransforms(obj);
            }
        }
    } else if ((s8)flag != 0) {
        switch (obj->anim.romDefNo) {
        case 0:
        case 0x1f:
            playerRender((int)obj, a, b, c, d, flag);
            break;
        default:
            if (OBJPRINT_ACTIVE_BANK(obj) != NULL) {
                objRenderModel(obj);
                if (obj->anim.hitVolumeTransforms != NULL) {
                    objUpdateHitVolumeTransforms(obj);
                }
            }
            break;
        }
    }
    doNothing_afterRenderObject();
    for (i = 0, walk = (int)obj; i < (s32)(u32)obj->childCount; i++) {
        int staff = (int)((GameObject*)walk)->childObjs[0];
        if (((GameObject*)staff)->anim.classId == 0x2d) {
            staffUpdateSegmentTransforms(staff, obj, (int)OBJPRINT_ACTIVE_BANK(staff), a, b, c);
        }
        walk += 4;
    }
}

int objGetAlphaCompareThreshold(void) {
    return gObjAlphaCompareThreshold;
}

void objSetAlphaCompareThreshold(u8 alpha) {
    gObjAlphaCompareThreshold = alpha;
}
