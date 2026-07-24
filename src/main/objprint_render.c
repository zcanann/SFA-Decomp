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
extern f32 lbl_803DE9E8;

s16 lbl_803DCC18;
s16 lbl_803DCC16;
s16 lbl_803DCC14;
f32* gObjModelMatrixOverride;
u8 lbl_803DCC0D;
u8 lbl_803DCC0C;
u8 lbl_803DCC0B;
u8 lbl_803DCC0A;
u8 lbl_803DCC09;
u8 lbl_803DCC08;

void fn_8003B0D0(GameObject* obj, GameObject* target, CharacterEyeAnimState* state, int maxAngle)
{
    s16* found;

    found = objFindJointVecByKey(obj, 0);
    if (found != NULL)
    {
        state->headYaw =
            (s16)((s16)getAngle((obj)->anim.localPosX - target->anim.localPosX,
                                (obj)->anim.localPosZ - target->anim.localPosZ) -
                  (obj)->anim.rotX);
        maxAngle = (s16)(gObjPrintDegToAngle * maxAngle);
        if (state->headYaw > maxAngle)
        {
            state->headYaw = maxAngle;
        }
        if (state->headYaw < -maxAngle)
        {
            state->headYaw = -maxAngle;
        }
        found[1] = state->headYaw;
    }
}

void fn_8003B228(GameObject* obj, void* state)
{
    ObjTextureRuntimeSlot* foundA;
    ObjTextureRuntimeSlot* foundB;
    int val;

    foundA = characterFindEyeJoint(obj, 5);
    foundB = characterFindEyeJoint(obj, 4);
    if (foundA == NULL || foundB == NULL)
    {
        return;
    }
    val = foundB->textureId;
    val += framesThisStep * 0x30;
    if (val >= 0x200)
    {
        val = 0x200;
    }
    foundA->textureId = val;
    foundB->textureId = val;
    ((CharacterEyeAnimState*)state)->blinkState = 1;
}

void characterDoEyeMovements(GameObject* obj, CharacterEyeAnimState* state, f32 unused);

void characterDoEyeAnims(GameObject* obj, void* stateData)
{
    CharacterEyeAnimState* state = stateData;
    ObjTextureRuntimeSlot* a;
    ObjTextureRuntimeSlot* b;

    a = characterFindEyeJoint(obj, 5);
    b = characterFindEyeJoint(obj, 4);

    if (a == NULL || b == NULL)
    {
        return;
    }
    {
        int st;
        int v;

        v = b->textureId;
        st = state->blinkState;

        switch (st & 0xf)
        {
        case 0:
        {
            s8 blinkTimer = state->blinkTimer;
            if (blinkTimer > 0)
            {
                state->blinkTimer = blinkTimer - framesThisStep;
            }
            else if ((int)randomGetRange(0, 1000) > 0x3de)
            {
                state->blinkState = 1;
                state->blinkTimer = 0;
            }
        }
        break;
        case 1:
            if ((st & 0x80) != 0)
            {
                v = v - framesThisStep * 0x60;
                if (v < 0)
                {
                    v = 0;
                    state->blinkState = 0;
                    state->blinkTimer = 0;
                }
            }
            else
            {
                v = v + framesThisStep * 0x60;
                if (v > 0x200)
                {
                    if (v - 0x200 < 0)
                    {
                        v = 0;
                        state->blinkState = 0;
                    }
                    else
                    {
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
        characterDoEyeMovements(obj, state, lbl_803DE9A4);
    }
}

void fn_8003B500(GameObject* obj, s16* state, f32 value)
{
    s16* found;

    found = objFindJointVecByKey(obj, 0);
    if (found != NULL)
    {
        if (found[0] != 0)
        {
            found[0] = (s16)(found[0] * 3 / 4);
        }
        fn_80039DF8(obj, state, found, lbl_803DE9A4);
        ((CharacterEyeAnimState*)state)->headTrackMode = (s16)(u16)(u8)((CharacterEyeAnimState*)state)->headTrackMode;
    }
}

void fn_8003B5E0(int a, int b, int c, u8 d)
{
    lbl_803DCC0D = a;
    lbl_803DCC0C = b;
    lbl_803DCC0B = c;
    lbl_803DCC09 = 1;
    lbl_803DCC0A = d;
}


void fn_8003B608(s16 a, s16 b, s16 c)
{
    lbl_803DCC18 = a;
    lbl_803DCC16 = b;
    lbl_803DCC14 = c;
    lbl_803DCC08 = 1;
}

typedef struct
{
    f32 pos[3];
    s16 rot[3];
    s8 joints[6];
} ChildEnt;

#define OBJPRINT_CHILD_TABLE(staff) (*(char**)(*(char**)((staff) + 0x50) + 0x2c))

void staffMtxFn_8003b620(int staffArg, GameObject* objArg, int modelArg, int a, int b, int c)
{
    f32 va[3];
    Vec vb;
    int k;
    char* q;
    Vec* vp;
    int i;
    char* base;
    u8* model;
    int obj;
    char* staff;

    staff = (char*)staffArg;
    obj = (int)objArg;
    model = (u8*)modelArg;

    if (*(u8*)(*(char**)(staff + 0x50) + 0x58) >= 2 && ((GameObject*)staff)->anim.classId == 0x2d)
    {
        int off;
        base = (char*)((GameObject*)staff)->extra;
        i = 0;
        k = 1;
        off = 0x18;
        q = base;
        vp = (Vec*)va;

        while (i < *(s16*)(base + 0xb0))
        {
            if (k < *(u8*)(*(char**)(staff + 0x50) + 0x58))
            {
                MtxPtr jm;
                int joint;
                joint = ((ChildEnt*)(OBJPRINT_CHILD_TABLE(staff) + off))[1].joints[OBJPRINT_ACTIVE_BANK_INDEX(staff)];
                jm = (MtxPtr)ObjModel_GetJointMatrix(model, joint);
                vp->x = ((ChildEnt*)(OBJPRINT_CHILD_TABLE(staff) + off))[1].pos[0];
                va[1] = ((ChildEnt*)(OBJPRINT_CHILD_TABLE(staff) + off))[1].pos[1];
                va[2] = ((ChildEnt*)(OBJPRINT_CHILD_TABLE(staff) + off))[1].pos[2];
                PSMTXMultVec(jm, vp, vp);
                vp->x = vp->x + playerMapOffsetX;
                va[2] = va[2] + playerMapOffsetZ;
                *(f32*)(q + 0x6c) = vp->x;
                *(f32*)(q + 0x74) = va[1];
                *(f32*)(q + 0x7c) = va[2];
            }
            if (k < *(u8*)(*(char**)(staff + 0x50) + 0x58))
            {
                ChildEnt* row = (ChildEnt*)(OBJPRINT_CHILD_TABLE(staff) + off);
                int idx2 = row->joints[OBJPRINT_ACTIVE_BANK_INDEX(staff)];
                MtxPtr mtx2;
                vb.x = row->pos[0];
                mtx2 = (MtxPtr)(*(char**)(model + ((((ObjModel*)model)->bufferFlags & 1) * 4) + 0xc) + idx2 * 0x40);
                vb.y = ((ChildEnt*)(OBJPRINT_CHILD_TABLE(staff) + off))->pos[1];
                vb.z = ((ChildEnt*)(OBJPRINT_CHILD_TABLE(staff) + off))->pos[2];
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
        }

        if (*(s16*)(base + 0xb0) != 0)
        {
            char* r = base + *(s16*)(base + 0xb2) * 4;
            va[0] = *(f32*)(r + 0x6c);
            va[1] = *(f32*)(r + 0x74);
            va[2] = *(f32*)(r + 0x7c);
            (*(void (**)(int, int, Vec*))(*(int*)((GameObject*)staff)->anim.dll + 0x28))((int)staff, obj, &vb);
            va[0] = va[0] - vb.x;
            va[1] = va[1] - vb.y;
            va[2] = va[2] - vb.z;
            ((GameObject*)staff)->anim.rotX = getAngle(va[0], va[2]);
            {
                f32 dx = va[0] * va[0];
                f32 dz = va[2] * va[2];
                ((GameObject*)staff)->anim.rotY = (s16)(-getAngle(va[1], sqrtf(dx + dz)) + 0x4000);
            }
            ((GameObject*)staff)->anim.rotZ = 0;
        }
    }
}


void objRenderShadowIfVisible(GameObject* obj, int wpad0, int wpad1, int wpad2, int wpad3, int wpad4)
{
    void** arr = *(void***)&(obj)->anim.banks;
    s8 idx = (obj)->anim.bankIndex;
    if (arr[idx] != NULL)
    {
        objRenderShadow(obj);
    }
}

int objNormalizeRotationMatrix(f32* matrix, f32* out);

void objRenderModelAndHitVolumes(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale)
{
    int** table = OBJPRINT_BANK_TABLE((int*)obj);
    (void)scale;
    if (table[OBJPRINT_ACTIVE_BANK_INDEX(obj)] != NULL)
    {
        objRenderModel(obj);
        if (obj->anim.hitVolumeTransforms != NULL)
        {
            objRenderFn_80041018((GameObject*)obj);
        }
    }
}


void objSetModelMatrixOverride(f32* matrix)
{
    gObjModelMatrixOverride = matrix;
}


void objRender(int a, int b, int c, int d, GameObject* obj, int flag)
{
    void* sub;
    int walk;
    int i;
    void (*vfn)(int, int, int, int, int, int);

    if ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_FREED) != 0 || ((GameObject*)obj)->ownerObj != NULL)
        return;
    if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
        return;
    sub = *(void**)&((GameObject*)obj)->anim.parent;
    if (sub != NULL && (((GameObject*)sub)->anim.flags & OBJANIM_FLAG_HIDDEN) != 0)
        return;

    doNothing_beforeRenderObject(4);
    ((GameObject*)obj)->objectFlags |= OBJECT_OBJFLAG_RENDERED;
    sub = *(void**)&((GameObject*)obj)->anim.dll;
    if (sub != NULL)
    {
        if ((((GameObject*)obj)->objectFlags & OBJECT_OBJFLAG_HIDDEN) == 0)
        {
            vfn = *(void (**)(int, int, int, int, int, int))(*(int*)sub + 0x10);
            if (vfn != NULL)
            {
                vfn((int)obj, a, b, c, d, flag);
            }
        }
        else if ((s8)flag != 0 && OBJPRINT_ACTIVE_BANK(obj) != NULL)
        {
            objRenderModel(obj);
            if (((GameObject*)obj)->anim.hitVolumeTransforms != NULL)
            {
                objRenderFn_80041018((GameObject*)obj);
            }
        }
    }
    else if ((s8)flag != 0)
    {
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0:
        case 0x1f:
            playerRender((int)obj, a, b, c, d, flag);
            break;
        default:
            if (OBJPRINT_ACTIVE_BANK(obj) != NULL)
            {
                objRenderModel(obj);
                if (((GameObject*)obj)->anim.hitVolumeTransforms != NULL)
                {
                    objRenderFn_80041018((GameObject*)obj);
                }
            }
            break;
        }
    }
    doNothing_afterRenderObject();
    for (i = 0, walk = (int)obj; i < (s32)(u32)((GameObject*)obj)->childCount; i++)
    {
        int staff = *(int*)&((GameObject*)walk)->childObjs[0];
        if (((GameObject*)staff)->anim.classId == 0x2d)
        {
            staffMtxFn_8003b620(staff, obj, (int)OBJPRINT_ACTIVE_BANK(staff), a, b, c);
        }
        walk += 4;
    }
}
int objGetAlphaCompareThreshold(void)
{
    return gObjAlphaCompareThreshold;
}

void objSetAlphaCompareThreshold(u8 x)
{
    gObjAlphaCompareThreshold = x;
}
