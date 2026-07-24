#include "main/game_object.h"
#include "main/texture.h"
#include "main/model_light.h"
#include "main/rcp_dolphin_api.h"
#include "main/frame_timing.h"
#include "main/objprint_render_api.h"
#include "main/objprint_dolphin_api.h"
#include "main/objprintgxcolor.h"
#include "main/model.h"
#include "main/object_api.h"
#include "main/objlib_api.h"
#include "main/shader_api.h"
#include "main/pi_dolphin_api.h"
#include "main/curve_eval.h"
#include "main/audio/sfx.h"
#include "main/objprint_anim_api.h"
#include "main/objprint_character_api.h"
#include "main/objprint_sound_api.h"
#include "main/newshadows.h"
#include "main/objtexture.h"
#include "main/object_render.h"
#include "main/dll/modgfx.h"
#include "main/mm.h"
#include "dolphin/mtx.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXPixel.h"
#include "main/atan2f.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "track/intersect_api.h"
#include "track/intersect_fog_api.h"
#include "main/newshadows_shadow_api.h"
#include "main/dll/player_api.h"
#include "main/objprint_internal.h"


int lbl_803DB460 = 100;
f32 lbl_803DB464 = 20.0f;


extern f32 lbl_803DE9D8;
extern f32 lbl_803DE9DC;
extern f32 lbl_803DE9E0;
extern int lbl_803DCC48;
extern f32 lbl_803DEA04;
extern f32 lbl_803DE9E4;
extern int lbl_803DCC44;
extern u8 lbl_803DCC3E;
extern u32 lbl_803DB468;
extern f32 lbl_803DEA28;
extern f32 lbl_803DEA2C;
extern f32 lbl_803DEA30;
extern f32 lbl_803DEA04;
extern f32 lbl_803DEA1C;



extern f32 lbl_803DE9A4;
extern f32 lbl_803DE9C8;
extern f32 lbl_803DE99C;

void objAnimFn_80038f38(GameObject* obj, char* state)
{
    s16* found;
    int timer;

    timer = (s32)((ObjSoundState*)state)->timer;
    found = objFindJointVecByKey(obj, 1);

    if (*(s8*)state != 0)
    {
        *(s8*)state = 0;
    }
    else if (Sfx_IsPlayingFromObjectChannel((u32)obj, 0x10) != 0)
    {
        if (timer != -1)
        {
            timer -= framesThisStep;
            if (timer < 0)
            {
                Sfx_StopObjectChannel((u32)obj, 0x10);
                ((ObjSoundState*)state)->blendWeight = lbl_803DE9A4;
                ((ObjSoundState*)state)->pitch = 0;
            }
            ((ObjSoundState*)state)->timer = timer;
        }
    }
    else
    {
        ((ObjSoundState*)state)->timer = lbl_803DE9C8;
        ((ObjSoundState*)state)->pitch = 0;
        if (((ObjSoundState*)state)->blendWeight > lbl_803DE9A4)
        {
            ObjModel* pi;
            ((ObjSoundState*)state)->blendWeight = *(f32*)&lbl_803DE9A4;
            pi = (ObjModel*)OBJPRINT_ACTIVE_BANK(obj);
            if (pi->file->morphTargetCount != 0)
            {
                ObjModel_SetBlendChannelTargets(pi, 2, pi->blendChannels[2].morphTargetB, -1,
                                                lbl_803DE99C / lbl_803DB464, 0);
            }
        }
    }

    if (found != NULL)
    {
        found[0] = (s16)((found[0] + ((ObjSoundState*)state)->pitch) >> 1);
    }
}

void objKfAnimUpdate(GameObject* obj, ObjKfAnimState* state)
{
    int frame;
    ObjModel* model;
    int kfval;
    int* kf;

    f32 t;

    if (state->frame < 0)
        return;
    t = state->timer - timeDelta;
    state->timer = t;
    if (t < lbl_803DE9A4)
    {
        frame = state->frame;
        if (frame >= state->frameCount)
        {
            state->frame = -1;
            model = (ObjModel*)OBJPRINT_ACTIVE_BANK(obj);
            if (model->file->morphTargetCount != 0)
            {
                ObjModel_SetBlendChannelTargets(model, 2,
                                                model->blendChannels[2].morphTargetB, -1,
                                                lbl_803DE99C / lbl_803DB464, 0);
            }
        }
        else
        {
            if (frame == 1)
            {
                Sfx_PlayFromObjectChannel((u32)obj, 0x10, state->sfxId);
            }
            kf = state->keyframes;
            frame = state->frame;
            state->frame = frame + 1;
            kfval = kf[frame];
            model = (ObjModel*)OBJPRINT_ACTIVE_BANK(obj);
            if (model->file->morphTargetCount != 0)
            {
                ObjModel_SetBlendChannelTargets(model, 2,
                                                model->blendChannels[2].morphTargetB, kfval - 1,
                                                lbl_803DE99C / lbl_803DB464, 0);
            }
            state->timer = state->timer + state->timerStep;
        }
    }
}

void objKfAnimStop(ObjKfAnimState* state)
{
    state->frame = -1;
}

void objAudioFn_80039270(u32 obj, void* p, u16 sfxId)
{
    if (Sfx_IsPlayingFromObjectChannel(obj, 0x10) == 0)
    {
        Sfx_PlayFromObjectChannel(obj, 0x10, sfxId);
        ((ObjSoundState*)p)->timer = lbl_803DE9C8;
        ((ObjSoundState*)p)->pitch = -0x500;
        ((ObjSoundState*)p)->active = 1;
        ((ObjSoundState*)p)->blendWeight = lbl_803DE99C;
    }
}


void objSoundFn_800392f0(GameObject* obj, ObjSoundState* state, ObjSoundDef* soundDef, u8 force)
{
    u16 sfx;
    s16 pitch;
    u32 count;
    ObjModel* model;
    int did;

    pitch = soundDef->pitch;
    sfx = (u16)soundDef->sfxId;
    if (force != 0 || Sfx_IsPlayingFromObjectChannel((u32)obj, 0x10) == 0)
    {
        Sfx_PlayFromObjectChannel((u32)obj, 0x10, sfx);
        state->timer = lbl_803DE9C8;
        state->pitch = (s16)(-pitch);
        state->active = 1;
        state->blendWeight = lbl_803DE99C;
    }
    count = soundDef->blendCount;
    if (count != 0)
    {
        model = (ObjModel*)OBJPRINT_ACTIVE_BANK(obj);
        if (model->file->morphTargetCount != 0)
        {
            ObjModel_SetBlendChannelTargets(model, 2,
                                            model->blendChannels[2].morphTargetB, count - 1,
                                            lbl_803DE99C / lbl_803DB464, 0);
            did = 1;
        }
        else
        {
            did = 0;
        }
        if (did != 0)
        {
            soundDef->pitch = 0;
        }
    }
}


void objAudioFn_800393f8(GameObject* obj, ObjSoundState* state, u16 sfx, int pitch, int volume, u8 force)
{
    if (force == 0 && Sfx_IsPlayingFromObjectChannel((u32)obj, 0x10) != 0)
    {
        return;
    }
    Sfx_PlayFromObjectChannel((u32)obj, 0x10, sfx);
    state->timer = volume;
    state->pitch = (s16)(-pitch);
    state->active = 1;
    state->blendWeight = lbl_803DE99C;
}

int lbl_802CAE88[10] = {0, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13};

int* seqFn_800394a0(void)
{
    return lbl_802CAE88;
}

ObjTextureRuntimeSlot* objFindTexture(GameObject* obj, int target, int unusedMaterialIndex)
{
    ObjTextureRuntimeSlot* result = NULL;
    ObjDef* modelDef = (obj)->anim.modelInstance;
    if (modelDef != NULL)
    {
        int count;
        ObjTextureSlotDef* entries = modelDef->textureSlotDefs;
        if (entries == NULL)
            return NULL;
        {
            int i;
            count = modelDef->textureSlotCount;
            for (i = 0; i < count; i++)
            {
                if (target == entries[i].tag)
                {
                    result = &(obj)->anim.textureSlots[i];
                }
            }
        }
    }
    return result;
}


void objPosFn_80039510(GameObject* obj, int key, f32* outPosition)
{
    int* table;
    int i;
    int k;
    int n;
    int joint;
    int model;

    table = (void*)(obj)->anim.modelInstance;
    i = 0;
    n = (s32)(u32)((ObjDef*)table)->jointCount;
    for (k = 0; k < n; k++)
    {
        if (key == (int)(*(u8**)&((ObjDef*)table)->jointData)[i])
        {
            joint = (*(u8**)&((ObjDef*)table)->jointData + i + OBJPRINT_ACTIVE_BANK_INDEX(obj))[1];
            break;
        }
        i = i + ((ObjDef*)table)->modelCount + 1;
    }
    model = (int)Obj_GetActiveModel(obj);
    model = (int)ObjModel_GetJointMatrix((u8*)model, joint);
    outPosition[0] = ((ObjModelJointMatrix*)model)->translationX;
    outPosition[1] = ((ObjModelJointMatrix*)model)->translationY;
    outPosition[2] = ((ObjModelJointMatrix*)model)->translationZ;
    outPosition[0] += playerMapOffsetX;
    outPosition[2] += playerMapOffsetZ;
}

s16* objModelGetVecFn_800395d8(GameObject* obj, int target)
{
    int vecOffset;
    int entries;
    int entryIdx;
    void* m;
    s16* result;
    int count;
    int i;

    result = NULL;
    m = OBJPRINT_MODEL_INSTANCE(obj);
    if (m != NULL)
    {
        entryIdx = 0;
        vecOffset = 0;
        count = OBJPRINT_JOINT_COUNT(m);
        for (i = 0; i < count; i++)
        {
            entries = *(int*)&((ObjDef*)m)->jointData;
            if ((int)*(u8*)(entries + OBJPRINT_ACTIVE_BANK_INDEX(obj) + entryIdx + 1) != 0xff &&
                (s32) * (u8*)(entries + entryIdx) == target)
            {
                result = (s16*)((char*)(obj)->anim.jointPoseData + vecOffset);
            }
            entryIdx += OBJPRINT_MODEL_COUNT(m) + 1;
            vecOffset += 0x12;
        }
    }
    return result;
}


void characterDoEyeMovements(GameObject* obj, CharacterEyeAnimState* state, f32 unused)
{
    ObjTextureRuntimeSlot* foundA;
    ObjTextureRuntimeSlot* foundB;
    s16 t;
    int flag;
    s8 timer;

    foundA = characterFindEyeJoint(obj, 1);
    foundB = characterFindEyeJoint(obj, 0);
    if (foundA == NULL || foundB == NULL)
    {
        return;
    }

    flag = 0;
    t = state->movementStep;
    if (t == 0)
    {
        flag = 1;
    }
    if (t > 0)
    {
        if (foundA->offsetS >= state->movementTarget)
        {
            flag = 1;
        }
    }
    if (t < 0)
    {
        if (foundA->offsetS <= state->movementTarget)
        {
            flag = 1;
        }
    }
    if (flag != 0)
    {
        state->movementTarget = randomGetRange(-0x3e8, 0x3e8);
        state->movementStep = (state->movementTarget < foundA->offsetS) ? -0x96 : 0x96;
        state->movementTimer = randomGetRange(0x1e, 0x64);
    }
    timer = state->movementTimer;
    if (timer > 0)
    {
        state->movementTimer = timer - framesThisStep;
    }
    else
    {
        foundA->offsetS = (s16)(foundA->offsetS + state->movementStep * framesThisStep);
        foundA->offsetT = 0;
        foundB->offsetS = foundA->offsetS;
        foundB->offsetT = 0;
    }
}

int fn_80039834(s16* curve, s16* state, f32 a, f32 b)
{
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
    if (lo != hi)
    {
        ratio = ((f32)(s32)*state - (f32)(s32)hi) / ((f32)(s32)lo - (f32)(s32)hi);
    }
    else
    {
        return 1;
    }

    if (ratio > lbl_803DE99C)
    {
        ratio = lbl_803DE99C;
    }
    else if (ratio < lbl_803DE9A4)
    {
        ratio = lbl_803DE9A4;
    }

    {
        f32 rate = Curve_EvalHermite(buf, ratio, 0);
        if (curve[10] < curve[11])
        {
            rate = -rate;
        }
        *state = rate * timeDelta + (f32)(s32)*state;
    }

    if (lbl_803DE99C == ratio || *state >= 8191 || *state <= -8191)
    {
        *state = curve[10];
        return 1;
    }
    return 0;
}
int fn_800399C0(s16* curve, s16* state)
{
    f32 buf[4];
    f32 ratio;
    s16 lo;
    s16 hi;

    buf[0] = lbl_803DE9D8;
    buf[1] = lbl_803DE9D8;
    buf[2] = lbl_803DE9DC;
    buf[3] = lbl_803DE9E0;

    lo = curve[10];
    hi = curve[11];
    if (lo != hi)
    {
        ratio = ((f32)(s32)state[1] - (f32)(s32)hi) / ((f32)(s32)lo - (f32)(s32)hi);
    }
    else
    {
        return 1;
    }

    if (ratio > lbl_803DE99C)
    {
        ratio = lbl_803DE99C;
    }
    else if (ratio < lbl_803DE9A4)
    {
        ratio = lbl_803DE9A4;
    }

    {
        f32 rate = Curve_EvalHermite(buf, ratio, 0);
        if (curve[10] < curve[11])
        {
            rate = -rate;
        }
        state[1] = rate * timeDelta + (f32)(s32)state[1];
    }

    if (lbl_803DE99C == ratio || state[1] >= 8191 || state[1] <= -8191)
    {
        state[1] = curve[10];
        return 1;
    }
    return 0;
}

int fn_80039834(s16* curve, s16* state, f32 a, f32 b);
int fn_800399C0(s16* curve, s16* state);

void fn_80039B54(int obj, s16* curve, s16* state, f32 val)
{
    int masked;
    int flag;

    masked = (curve[13] >> 8) & 0xff;
    if (val > lbl_803DE9E4)
    {
        flag = 1;
    }
    else
    {
        flag = 0;
    }
    if (masked != flag)
    {
        curve[13] = (s16)(flag << 8 | 4);
        curve[11] = state[1];
        curve[10] = 0;
        curve[14] = 0;
    }

    switch ((u8)curve[13])
    {
    case 0:
        curve[13] = (s16)(flag << 8);
        curve[14] = randomGetRange(0x32, 0xc8);
        break;
    case 1:
        curve[14] -= framesThisStep;
        if (curve[14] < 0)
        {
            if ((int)randomGetRange(0, 100) > 90)
            {
                curve[13] = (s16)(flag << 8 | 5);
                if (*(s8*)curve != 0)
                {
                    if ((int)randomGetRange(0, 100) > 0)
                    {
                        curve[10] = 0x1fff;
                        if ((int)randomGetRange(0, 1) == 0)
                        {
                            curve[10] = -curve[10];
                        }
                    }
                }
                else
                {
                    curve[10] = 0x1fff;
                    if ((int)randomGetRange(0, 1) == 0)
                    {
                        curve[10] = -curve[10];
                    }
                }
            }
        }
        break;
    case 2:
        break;
    case 5:
        if (curve[14] > 0)
        {
            curve[14] -= framesThisStep;
        }
        else if (fn_800399C0(curve, state))
        {
            curve[13] = (s16)(flag << 8 | 6);
            curve[10] = -curve[10];
            curve[14] = randomGetRange(0x14, 0x64);
        }
        break;
    case 6:
        if (curve[14] > 0)
        {
            curve[14] -= framesThisStep;
        }
        else if (fn_800399C0(curve, state))
        {
            curve[13] = (s16)(flag << 8 | 4);
            curve[10] = 0;
            curve[14] = randomGetRange(0x14, 0x64);
        }
        break;
    case 4:
        if (curve[14] > 0)
        {
            curve[14] -= framesThisStep;
        }
        else if (fn_800399C0(curve, state))
        {
            curve[13] = (s16)(flag << 8);
            state[1] = 0;
        }
        break;
    }
}



extern f32 lbl_803DE9E8;

void fn_80039DF8(GameObject* obj, s16* curve, s16* state, f32 val)
{
    int masked;
    int flag;

    masked = (curve[13] >> 8) & 0xff;
    if (val > lbl_803DE9E4)
    {
        flag = 1;
    }
    else
    {
        flag = 0;
    }
    if (masked != flag)
    {
        curve[13] = (s16)(flag << 8);
    }

    switch ((u8)curve[13])
    {
    case 0:
        if (*(s8*)curve != 0)
        {
            curve[13] = (s16)(flag << 8 | 3);
            curve[11] = state[1];
            *(f32*)((char*)curve + 0x10) = lbl_803DE99C;
        }
        else
        {
            curve[13] = (s16)(flag << 8 | 1);
            curve[14] = randomGetRange(100, 400);
            curve[10] = state[1];
        }
        break;
    case 1:
        curve[14] -= framesThisStep;
        if (curve[14] < 0)
        {
            int old = curve[10];
            curve[10] = randomGetRange(0, 0x1fff);
            if (old > 0)
            {
                if (old - curve[10] < 0xe38)
                {
                    curve[10] += 0xe38;
                }
                if (curve[10] > 0x1fff)
                {
                    curve[10] = 0x1fff;
                }
                curve[10] = -curve[10];
            }
            else
            {
                if (curve[10] - old < 0xe38)
                {
                    curve[10] += 0xe38;
                }
                if (curve[10] > 0x1fff)
                {
                    curve[10] = 0x1fff;
                }
            }
            curve[13] = (s16)(flag << 8 | 2);
            curve[14] = 0;
            curve[11] = state[1];
        }
        break;
    case 2:
        if (*(s8*)curve != 0 || fn_800399C0(curve, state) != 0)
        {
            curve[13] = (s16)(flag << 8);
        }
        break;
    case 3:
        if (*(s8*)curve == 0)
        {
            curve[13] = (s16)(flag << 8);
        }
        else
        {
            int angle;
            int n;
            angle = getAngle(obj->anim.localPosX - *(f32*)((char*)curve + 4),
                             obj->anim.localPosZ - *(f32*)((char*)curve + 0xc));
            curve[10] = (s16)(angle - (u16)obj->anim.rotX);
            if (curve[10] > 0x8000)
            {
                curve[10] = (s16)(curve[10] - 0xffff);
            }
            if (curve[10] < -0x8000)
            {
                curve[10] = (s16)(curve[10] + 0xffff);
            }
            n = curve[10];
            if (n > 0x1fff || n < -0x1fff)
            {
                curve[13] = (s16)(flag << 8);
            }
            else
            {
                f32 t = *(f32*)((char*)curve + 0x10);
                f32 lo = lbl_803DE9A4;
                if (t > lo)
                {
                    f32 nv;
                    state[1] = t * (f32)(curve[11] - n) + n;
                    nv = -(lbl_803DE9E8 * timeDelta - *(f32*)((char*)curve + 0x10));
                    *(f32*)((char*)curve + 0x10) = nv;
                    if (nv < lo)
                    {
                        *(f32*)((char*)curve + 0x10) = lo;
                    }
                }
                else
                {
                    state[1] = n;
                }
            }
        }
        break;
    }

    if (state[1] < -0x1fff)
    {
        state[1] = -0x1fff;
    }
    else if (state[1] > 0x1fff)
    {
        state[1] = 0x1fff;
    }
}

void fn_8003A168(GameObject* obj, void* state)
{
    s16* found;

    found = objFindJointVecByKey(obj, 0);
    if (found == NULL)
        return;
    if (found[0] != 0)
    {
        found[0] = (s16)((s32)found[0] * 3 / 4);
    }
    if (found[1] != 0)
    {
        found[1] = (s16)((s32)found[1] * 3 / 4);
    }
    ((CharacterEyeAnimState*)state)->headTrackMode = 0;
}


void fn_8003A230(GameObject* obj, CharacterEyeAnimState* state, f32 val)
{
    s16* found;
    int flag;

    found = objFindJointVecByKey(obj, 0);
    if (found != NULL)
    {
        if (found[0] != 0)
        {
            found[0] = (s16)(found[0] * 3 / 4);
        }
        if (val < lbl_803DE9A4)
        {
            val = -val;
        }
        if (val <= lbl_803DE9E4)
        {
            fn_80039DF8(obj, (s16*)state, found, val);
        }
        else
        {
            fn_80039B54((int)obj, (s16*)state, found, val);
        }
        state->headTrackMode = (s16)(u16)(u8)state->headTrackMode;
        if (val > lbl_803DE9E4)
        {
            flag = 1;
        }
        else
        {
            flag = 0;
        }
        state->headTrackMode = (s16)(state->headTrackMode | (flag << 8));
    }
}
s16 objMathFn_8003a380(GameObject* obj, GameObject* target, f32* pos, u8* p4, s16* spd, f32 yOff, int unused,
                      int basePitch)
{
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
    if (src[0] > 0x8000)
    {
        src[0] = (s16)(src[0] - 0xffff);
    }
    if (src[0] < -0x8000)
    {
        src[0] = (s16)(src[0] + 0xffff);
    }
    src[1] = basePitch - (u16)-getAngle(dist, dy);
    if (src[1] > 0x8000)
    {
        src[1] = (s16)(src[1] - 0xffff);
    }
    if (src[1] < -0x8000)
    {
        src[1] = (s16)(src[1] + 0xffff);
    }

    ret = src[0];
    if (gObjLookAtControlFlags.flip)
    {
        src[0] -= 0x8000;
        src[1] = -src[1];
        gObjLookAtControlFlags.flip = 0;
    }

    i = 0;
    while (i < 10)
    {
        int key;
        void* m[1];

        key = lbl_802CAE88[i];
        found[0] = NULL;
        m[0] = (void*)go->anim.modelInstance;
        if (m[0] != NULL)
        {
            int iv[2];
            int n;
            int j;
            iv[0] = (int)found[0];
            iv[1] = (int)found[0];
            n = ((ObjDef*)m[0])->jointCount;
            for (j = 0; j < n; j++)
            {
                int entries = *(int*)&((ObjDef*)m[0])->jointData;
                if ((int)*(u8*)(entries + OBJPRINT_ACTIVE_BANK_INDEX(go) + iv[0] + 1) != 0xff &&
                    key == (int)*(u8*)(entries + iv[0]))
                {
                    found[0] = (s16*)((int)go->anim.jointPoseData + iv[1]);
                }
                iv[0] += ((ObjDef*)m[0])->modelCount + 1;
                iv[1] += 0x12;
            }
        }
        if (found[0] == NULL)
        {
            int t = (s16)ret;
            t = (t >= 0) ? t : -t;
            return (s16)(t < 0x100);
        }

        {
            int n2;
            for (n2 = 0; n2 < 2; n2++)
            {
                s16 v;
                s16 lim;
                if (n2 % 2 != 0)
                {
                    lim = (s16)(*(f32*)&gObjPrintDegToAngle * (f32)sp2[i]);
                }
                else
                {
                    lim = (s16)(*(f32*)&gObjPrintDegToAngle * (f32)spd[i]);
                }
                v = src[n2];
                dst[n2] = v;
                if (v > lim)
                {
                    dst[n2] = lim;
                    src[n2] -= lim;
                }
                else if (v < -lim)
                {
                    dst[n2] = -(s16)lim;
                    src[n2] += lim;
                }
                else
                {
                    src[n2] = 0;
                }
            }
        }

        if (p4 != NULL)
        {
            ((ObjJointTrackPair*)p4)->yaw.angle = dst[0];
            fn_800399C0((s16*)p4, found[0]);
            ((ObjJointTrackPair*)p4)->pitch.angle = dst[1];
            fn_80039834((s16*)(p4 + 0x30), found[0], lbl_803DE9D8, lbl_803DE9DC);
            p4 += 0x60;
        }
        else
        {
            s16* fv = found[0];
            int d1 = (s16)((s16)((fv[1] + dst[0]) >> 1) - fv[1]);
            s16 lim;
            int d2;
            int t2;
            int lim3;

            lim = (d1 < framesThisStep * ((s16)(s32)(gObjPrintDegToAngle * (f32)-spd[i]) / lbl_803DB460))
                      ? framesThisStep * ((s16)(s32)(gObjPrintDegToAngle * (f32)-spd[i]) / lbl_803DB460)
                      : ((d1 > framesThisStep * ((s16)(s32)(gObjPrintDegToAngle * (f32)spd[i]) / lbl_803DB460))
                             ? framesThisStep * ((s16)(s32)(gObjPrintDegToAngle * (f32)spd[i]) / lbl_803DB460)
                             : d1);
            d2 = (s16)((s16)((fv[0] + dst[1]) >> 1) - fv[0]);
            t2 = (s16)(s32)(*(f32*)&gObjPrintDegToAngle * (f32)sp2[i]);
            lim3 =
                (d2 < framesThisStep * (-t2 / (lbl_803DB460 << 1)))
                    ? framesThisStep * (-t2 / (lbl_803DB460 << 1))
                    : ((d2 > framesThisStep * (t2 / (lbl_803DB460 << 1))) ? framesThisStep * (t2 / (lbl_803DB460 << 1))
                                                                          : d2);
            fv[0] += (s16)lim3;
            fv[1] += lim;
        }

        if (i == 0)
        {
            ret -= found[0][1];
        }
        i++;
    }
    return src[0];
}

int fn_8003A8B4(GameObject* objArg, int* keyList, int countArg, u8* p4Arg)
{
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
    while (i < count)
    {
        found = objFindJointVecByKey(obj, *keys);
        total += fn_800399C0((s16*)p4, found);
        total += fn_80039834((s16*)(p4 + 0x30), found, lbl_803DE9D8, lbl_803DE9DC);
        keys++;
        i++;
        p4 += 0x60;
    }
    return (count * 2 - total) == 0;
}

void objJointTracksSetAngles(u8* channelData, int count, s16 yaw, s16 pitch)
{
    ObjJointTrackPair* tracks = (ObjJointTrackPair*)channelData;

    while (count > 0)
    {
        tracks->yaw.angle = yaw;
        tracks->pitch.angle = pitch;
        tracks++;
        count--;
    }
}


void characterDoEyeMovements(GameObject* obj, CharacterEyeAnimState* state, f32 unused);

void objModelClearVecFn_8003aa40(GameObject* obj)
{
    s16* found;
    int slot;

    for (slot = 0; slot < 0x16; slot++)
    {
        found = objFindJointVecByKey(obj, slot);
        if (found != NULL)
        {
            found[0] = 0;
            found[1] = 0;
            found[2] = 0;
        }
    }
}

void fn_8003AAE0(GameObject* obj, int* keys, int count, int lo, int hi)
{
    s16* found;
    int idx;
    int v;

    for (idx = 0; idx < count; idx++)
    {
        found = objFindJointVecByKey(obj, *keys);
        if (found != NULL)
        {
            v = found[0];
            if (v < lo)
                v = lo;
            else if (v > hi)
                v = hi;
            found[0] = v;
            v = found[1];
            if (v < lo)
                v = lo;
            else if (v > hi)
                v = hi;
            found[1] = v;
            v = found[2];
            if (v < lo)
                v = lo;
            else if (v > hi)
                v = hi;
            found[2] = v;
        }
        keys++;
    }
}

void fn_8003AC14(GameObject* obj, int* keys, int count)
{
    s16* found;
    int idx;

    for (idx = 0; idx < count; idx++)
    {
        found = objFindJointVecByKey(obj, *keys);
        if (found != NULL)
        {
            found[1] = (s16)(found[1] * 3 >> 2);
            found[0] = (s16)(found[0] * 3 >> 2);
            found[2] = (s16)(found[2] * 3 >> 2);
        }
        keys++;
    }
}

void objFn_8003acfc(GameObject* obj, int* keys, int count, u8* out)
{
    s16* found;
    int idx;

    for (idx = 0; idx < count;)
    {
        found = objFindJointVecByKey(obj, *keys);
        if (found != NULL)
        {
            ((ObjJointTrackPair*)out)->yaw.angleStart = found[1];
            ((ObjJointTrackPair*)out)->pitch.angleStart = found[0];
        }
        keys++;
        idx++;
        out += 0x60;
    }
}
