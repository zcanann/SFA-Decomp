/* DLL 0x0117 — appleontree / groundAnimator group. TU: 0x8017D818–0x8017E1A0. */
#include "main/audio/sfx_ids.h"
#include "main/dll/appleontreestate_struct.h"
#include "main/dll/groundAnimator.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/objtexture.h"
#include "main/dll/crackanim_state.h"
#include "main/dll/baddie_state.h"
#include "main/sky_interface.h"

extern int randomGetRange(int lo, int hi);
extern u32 ObjMsg_SendToObject();
extern u32 GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern f32 Vec_distance(f32* a, f32* b);

ObjectDescriptor gWM_ColumnObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)wm_column_initialise,
    (ObjectDescriptorCallback)wm_column_release,
    0,
    (ObjectDescriptorCallback)wm_column_init,
    (ObjectDescriptorCallback)wm_column_update,
    (ObjectDescriptorCallback)wm_column_hitDetect,
    (ObjectDescriptorCallback)wm_column_render,
    (ObjectDescriptorCallback)wm_column_free,
    (ObjectDescriptorCallback)wm_column_getObjectTypeId,
    wm_column_getExtraSize,
};

extern void appleontree_init();
extern void appleontree_update();
extern void appleontree_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
extern void appleontree_free(int* obj);
extern int appleontree_getExtraSize(void);
extern void appleontree_setScale(void);
extern u8 appleontree_modelMtxFn(int* obj);

ObjectDescriptor13 gAppleOnTreeObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)appleontree_init,
    (ObjectDescriptorCallback)appleontree_update,
    0,
    (ObjectDescriptorCallback)appleontree_render,
    (ObjectDescriptorCallback)appleontree_free,
    0,
    appleontree_getExtraSize,
    (ObjectDescriptorCallback)appleontree_setScale,
    (ObjectDescriptorCallback)appleontree_func0B,
    (ObjectDescriptorCallback)appleontree_modelMtxFn,
};

u32 jumptable_803214DC[] = {
    (u32)((u8*)appleontree_update + 0x170),
    (u32)((u8*)appleontree_update + 0x274),
    (u32)((u8*)appleontree_update + 0x3C4),
    (u32)((u8*)appleontree_update + 0x4E8),
    (u32)((u8*)appleontree_update + 0x554),
    (u32)((u8*)appleontree_update + 0x6C8),
    (u32)((u8*)appleontree_update + 0x71C),
};

extern f32 Vec_xzDistance(f32* a, f32* b);
extern void itemPickupDoParticleFx(int obj, f32 scale, int p3, int p4);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void Obj_FreeObject(int obj);
extern f32 lbl_803E37C8;
extern f32 lbl_803E37EC;
extern f32 lbl_803E37F0;
extern f32 timeDelta;
extern f32 sqrtf(f32);
extern int fn_80065684(int obj, f32 x, f32 y, f32 z, f32* out, int flag);
extern f32 lbl_803E37D4;
extern f32 lbl_803E37D8;
extern f32 lbl_803E37DC;
extern f32 lbl_803E37E0;
extern f32 lbl_803E37E4;
extern f32 lbl_803E37E8;
extern f32 lbl_803E37F4;
extern f32 lbl_803E37F8;
extern f32 lbl_803E37FC;
extern f32 lbl_803E3800;
extern u32 FUN_80017a78();
extern int ObjHits_GetPriorityHit(int obj, int* outHitObject, int* outSphereIndex, u32* outHitVolume);
extern int ObjMsg_Pop();
extern void itemPickupDoParticleFx(int obj, f32 f1, int p3, int p4);
extern void Obj_SetActiveModelIndex(int obj, int idx);
extern void ObjMsg_AllocQueue(int obj, int capacity);
extern const f32 lbl_803E3828;
extern f32 lbl_803E382C;
extern f32 lbl_803E3830;
extern f32 lbl_803E3834;
extern f32 lbl_803E3838;
extern f32 lbl_803E37CC;
extern f32 lbl_803E37D0;
extern f32 lbl_803E3804;
extern f32 lbl_803E3808;
extern f32 lbl_803E380C;
extern f32 lbl_803E3810;
extern f32 lbl_803E3814;
extern f32 lbl_803E3818;
extern void dll_FC_initialise_nop(void);
extern void dll_FC_release_nop(void);
extern void dll_FC_init(int obj, int objDef);
extern void dll_FC_update(int obj);
extern void dll_FC_hitDetect(int* obj);

void appleontree_func0B(int obj, float* pos)
{
    AppleOnTreeState* state = ((GameObject*)obj)->extra;

    if (state->unk3A == 4)
    {
        return;
    }
    if (state->unk3A == 5)
    {
        return;
    }
    if (state->unk3A == 6)
    {
        return;
    }
    ((GameObject*)obj)->anim.localPosX = pos[0];
    ((GameObject*)obj)->anim.localPosY = pos[1];
    ((GameObject*)obj)->anim.localPosZ = pos[2];
}

/* appleontree_handleCollectableHit: ground-animator collectable hit handler. When player is in
 * range, either send a trigger event (first contact) or apply healing +
 * particle FX + sfx + free-or-disable. */
void appleontree_handleCollectableHit(int obj)
{
    extern void playerAddHealth(int player, u16 amount); /* #57 */
    extern int Obj_GetPlayerObject(void); /* #57 */
    extern u32 ObjHits_DisableObject(); /* #57 */
    int state = *(int*)&((GameObject*)obj)->extra;
    int player = Obj_GetPlayerObject();

    if (!(Vec_xzDistance((float*)(player + 0x18), (float*)(obj + 0x18)) < lbl_803E37EC)) return;
    if (!(Vec_distance((float*)(player + 0x18), (float*)(obj + 0x18)) < lbl_803E37F0)) return;

    if (GameBit_Get(0x90f) == 0)
    {
        (*gObjectTriggerInterface)->setObjects(0x444, 0, 0);
        ((AppleOnTreeState*)state)->unk5C = -1;
        ((AppleOnTreeState*)state)->unk5E = 0;
        ((AppleOnTreeState*)state)->unk60 = lbl_803E37C8;
        ObjMsg_SendToObject(player, 0x7000a, obj, (int*)(state + 0x5c));
        GameBit_Set(0x90f, 1);
        ((AppleOnTreeState*)state)->unk5A = (u8)(((AppleOnTreeState*)state)->unk5A | 4);
    }
    else
    {
        playerAddHealth(player, ((AppleOnTreeState*)state)->healthRestore);
        itemPickupDoParticleFx(obj, lbl_803E37C8, 0xff, 0x28);
        Sfx_PlayFromObject(obj, SFXen_waterblock_stop);
        state = *(int*)&((GameObject*)obj)->extra;
        if ((((GameObject*)obj)->anim.flags & 0x2000) != 0)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            if (((GameObject*)obj)->anim.hitReactState != NULL)
            {
                ObjHits_DisableObject(obj);
            }
            ((AppleOnTreeState*)state)->unk5A = (u8)(((AppleOnTreeState*)state)->unk5A | 2);
        }
    }
}

void appleontree_setScale(void)
{
}

int appleontree_getExtraSize(void) { return 0x64; }

u8 appleontree_modelMtxFn(int* obj) { return ((AppleOnTreeState*)(int*)((GameObject*)obj)->extra)->unk3A; }

void appleontree_free(int* obj)
{
    (*gExpgfxInterface)->freeSource((u32)obj);
}

void appleontree_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    extern void objRenderFn_8003b8f4(int param_1, int param_2, int param_3, int param_4, int param_5, f32 scale); /* #57 */
    AppleOnTreeState* inner = ((GameObject*)obj)->extra;
    if ((inner->unk5A & 2) == 0)
    {
        objRenderFn_8003b8f4(obj, p1, p2, p3, p4, lbl_803E37C8);
    }
}

void fn_8017D854(int obj, int msg)
{
    extern u32 ObjHits_DisableObject(); /* #57 */
    int state = *(int*)&((GameObject*)obj)->extra;
    int v;

    switch (msg)
    {
    case 0:
        v = 2;
        break;
    case 1:
        v = 2;
        break;
    case 2:
        v = 2;
        break;
    default:
        v = 0;
        break;
    }
    ((AppleOnTreeState*)state)->healthRestore = v;
    ((AppleOnTreeState*)state)->unk3A = 4;
    ((AppleOnTreeState*)state)->unk08 = timeDelta;
    ((AppleOnTreeState*)state)->unk0C = timeDelta;
    ((AppleOnTreeState*)state)->rotX = randomGetRange(-0x8000, 0x7fff);
    ((AppleOnTreeState*)state)->rotY = randomGetRange(-0x8000, 0x7fff);
    ((AppleOnTreeState*)state)->rotZ = 0x2000;

    if (fn_80065684(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ,
                    (f32*)(state + 0x30), 0) == 0)
    {
        state = *(int*)&((GameObject*)obj)->extra;
        if ((((GameObject*)obj)->anim.flags & 0x2000) != 0)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            if (((GameObject*)obj)->anim.hitReactState != NULL)
            {
                ObjHits_DisableObject(obj);
            }
            ((AppleOnTreeState*)state)->unk5A = (u8)(((AppleOnTreeState*)state)->unk5A | 2);
        }
    }
    else
    {
        f32 m = ((AppleOnTreeState*)state)->unk40;
        f32 g = lbl_803E37D8 * m;
        f32 q = sqrtf(-(g * ((AppleOnTreeState*)state)->unk30 - lbl_803E37D4));
        f32 t = lbl_803E37DC * m;
        f32 a;
        f32 r;

        if (t >= lbl_803E37D4)
        {
            a = t;
        }
        else
        {
            a = -t;
        }
        if (a <= lbl_803E37E0)
        {
            r = lbl_803E37C8;
        }
        else
        {
            f32 r1 = (lbl_803E37E4 - q) / t;
            f32 r2 = (lbl_803E37E4 + q) / t;
            r = (r1 > 0.0f) ? r1 : r2;
        }
        ((AppleOnTreeState*)state)->unk50 = r;

        if (((AppleOnTreeState*)state)->unk28 < lbl_803E37D4)
        {
            ((AppleOnTreeState*)state)->unk30 = -(lbl_803E37D8 * ((AppleOnTreeState*)state)->unk24 - ((AppleOnTreeState
                *)state)->unk30);
        }
        else
        {
            ((AppleOnTreeState*)state)->unk30 = lbl_803E37E8 * (lbl_803E37D8 * ((AppleOnTreeState*)state)->unk24) + ((
                AppleOnTreeState*)state)->unk30;
        }

        if (((AppleOnTreeState*)state)->unk30 <= lbl_803E37D4)
        {
            state = *(int*)&((GameObject*)obj)->extra;
            if ((((GameObject*)obj)->anim.flags & 0x2000) != 0)
            {
                Obj_FreeObject(obj);
            }
            else
            {
                if (((GameObject*)obj)->anim.hitReactState != NULL)
                {
                    ObjHits_DisableObject(obj);
                }
                ((AppleOnTreeState*)state)->unk5A = (u8)(((AppleOnTreeState*)state)->unk5A | 2);
            }
        }
        else
        {
            ((AppleOnTreeState*)state)->unk2C = ((GameObject*)obj)->anim.localPosY;
            ((AppleOnTreeState*)state)->unk34 = ((GameObject*)obj)->anim.localPosY - ((AppleOnTreeState*)state)->unk30;
            if (((GameObject*)obj)->anim.hitReactState != NULL)
            {
                ObjHits_DisableObject(obj);
            }
            Sfx_PlayFromObject(obj, SFXen_bridge_stops);
        }
    }
}

int fn_8017DCD4(int p, int state, f32 y)
{
    f32 zero = lbl_803E37D4;
    f32 m = ((AppleOnTreeState*)state)->unk40;

    if (zero != m)
    {
        if (((AppleOnTreeState*)state)->unk30 - (((AppleOnTreeState*)state)->unk2C - y) < zero)
        {
            f32 b = ((AppleOnTreeState*)state)->bounceVel;
            if (zero == b)
            {
                f32 g = lbl_803E37D8 * m;
                f32 q = sqrtf(b * b - g * ((AppleOnTreeState*)state)->unk30);
                f32 t = lbl_803E37DC * m;
                f32 a;
                f32 r;

                if (t >= lbl_803E37D4)
                {
                    a = t;
                }
                else
                {
                    a = -t;
                }
                if (a <= lbl_803E37E0)
                {
                    r = lbl_803E37C8;
                }
                else
                {
                    f32 r2;
                    f32 nb;
                    nb = -b;
                    r = (nb - q) / t;
                    r2 = (nb + q) / t;
                    if (r > *(f32*)&lbl_803E37D4)
                    {
                    }
                    else
                    {
                        r = r2;
                    }
                }
                ((AppleOnTreeState*)state)->unk0C = ((AppleOnTreeState*)state)->unk0C - r;
                ((AppleOnTreeState*)state)->unk2C = ((AppleOnTreeState*)state)->unk2C - ((AppleOnTreeState*)state)->
                    unk30;
                ((AppleOnTreeState*)state)->unk30 = lbl_803E37D4;
                ((GameObject*)p)->anim.localPosY = ((AppleOnTreeState*)state)->unk2C;
                ((GameObject*)p)->anim.rotX = ((AppleOnTreeState*)state)->rotX;
                ((GameObject*)p)->anim.rotY = ((AppleOnTreeState*)state)->rotY;
                ((GameObject*)p)->anim.rotZ = ((AppleOnTreeState*)state)->rotZ;
                ((AppleOnTreeState*)state)->bounceVel = -((AppleOnTreeState*)state)->unk28;
                if ((((AppleOnTreeState*)state)->unk5A & 8) == 0)
                {
                    Sfx_PlayFromObject(p, 0x407);
                    ((AppleOnTreeState*)state)->unk5A = (u8)(((AppleOnTreeState*)state)->unk5A | 8);
                }
                return 1;
            }
            else if (b < lbl_803E37F4)
            {
                ((GameObject*)p)->anim.localPosY = ((AppleOnTreeState*)state)->unk2C;
                ((AppleOnTreeState*)state)->unk40 = zero;
                ((AppleOnTreeState*)state)->bounceVel = zero;
                return 1;
            }
            else
            {
                f32 g;
                f32 q;
                f32 t;
                f32 a;
                f32 r;
                m = m + ((AppleOnTreeState*)state)->unk3C;
                g = lbl_803E37D8 * m;
                q = sqrtf(b * b - g * ((AppleOnTreeState*)state)->unk30);
                t = lbl_803E37DC * m;

                if (t >= lbl_803E37D4)
                {
                    a = t;
                }
                else
                {
                    a = -t;
                }
                if (a <= lbl_803E37E0)
                {
                    r = lbl_803E37C8;
                }
                else
                {
                    f32 r2;
                    f32 nb;
                    nb = -b;
                    r = (nb - q) / t;
                    r2 = (nb + q) / t;
                    if (r > *(f32*)&lbl_803E37D4)
                    {
                    }
                    else
                    {
                        r = r2;
                    }
                }
                ((AppleOnTreeState*)state)->unk0C = ((AppleOnTreeState*)state)->unk0C - r;
                ((GameObject*)p)->anim.localPosY = ((AppleOnTreeState*)state)->unk2C;
                ((AppleOnTreeState*)state)->bounceVel = ((AppleOnTreeState*)state)->bounceVel * lbl_803E37F8;
                return 0;
            }
        }
        else
        {
            ((GameObject*)p)->anim.localPosY = y;
            return 1;
        }
    }
    return 1;
}

int fn_8017DF34(int p, int state, f32 y)
{
    if (lbl_803E37D4 == ((AppleOnTreeState*)state)->unk3C)
    {
        if (((AppleOnTreeState*)state)->unk30 - (((AppleOnTreeState*)state)->unk2C - y) <= lbl_803E37D4)
        {
            f32 b;
            f32 m = ((AppleOnTreeState*)state)->unk40;
            f32 g;
            f32 q;
            f32 t;
            f32 a;
            f32 r;
            b = ((AppleOnTreeState*)state)->bounceVel;
            g = lbl_803E37D8 * m;
            q = sqrtf(b * b - g * ((AppleOnTreeState*)state)->unk30);
            t = lbl_803E37DC * m;

            if (t >= lbl_803E37D4)
            {
                a = t;
            }
            else
            {
                a = -t;
            }
            if (a <= lbl_803E37E0)
            {
                r = lbl_803E37C8;
            }
            else
            {
                f32 r2;
                f32 nb;
                nb = -b;
                r = (nb - q) / t;
                r2 = (nb + q) / t;
                r = (r > *(f32*)&lbl_803E37D4) ? r : r2;
            }
            ((AppleOnTreeState*)state)->unk0C = ((AppleOnTreeState*)state)->unk0C - r;
            ((AppleOnTreeState*)state)->unk2C = ((AppleOnTreeState*)state)->unk2C - ((AppleOnTreeState*)state)->unk30;
            ((AppleOnTreeState*)state)->unk30 = lbl_803E37D4;
            ((GameObject*)p)->anim.localPosY = ((AppleOnTreeState*)state)->unk2C;
            ((GameObject*)p)->anim.rotX = ((AppleOnTreeState*)state)->rotX;
            ((GameObject*)p)->anim.rotY = ((AppleOnTreeState*)state)->rotY;
            ((GameObject*)p)->anim.rotZ = ((AppleOnTreeState*)state)->rotZ;
            {
                f32 g2 = lbl_803E37DC * ((AppleOnTreeState*)state)->unk40;
                ((AppleOnTreeState*)state)->bounceVel = g2 * r + ((AppleOnTreeState*)state)->bounceVel;
            }
            ((AppleOnTreeState*)state)->unk3C = ((AppleOnTreeState*)state)->unk28;
            ((WaterfxSpawnSplashBurstAtPointFn)(*gWaterfxInterface)->spawnSplashBurst)(
                (void*)p, ((GameObject*)p)->anim.localPosX, ((AppleOnTreeState*)state)->unk34,
                ((GameObject*)p)->anim.localPosZ);
            return 0;
        }
        else
        {
            ((GameObject*)p)->anim.localPosY = y;
            return 1;
        }
    }
    else if (y - ((AppleOnTreeState*)state)->unk2C >= lbl_803E37D4)
    {
        f32 b;
        f32 m = ((AppleOnTreeState*)state)->unk40 + ((AppleOnTreeState*)state)->unk3C;
        f32 g;
        f32 q;
        f32 t;
        f32 a;
        f32 r;
        b = ((AppleOnTreeState*)state)->bounceVel;
        g = lbl_803E37D8 * m;
        q = sqrtf(b * b - g * ((AppleOnTreeState*)state)->unk30);
        t = lbl_803E37DC * m;

        if (t >= lbl_803E37D4)
        {
            a = t;
        }
        else
        {
            a = -t;
        }
        if (a <= lbl_803E37E0)
        {
            r = lbl_803E37C8;
        }
        else
        {
            f32 r2;
            f32 nb;
            nb = -b;
            r = (nb - q) / t;
            r2 = (nb + q) / t;
            r = (r > *(f32*)&lbl_803E37D4) ? r : r2;
        }
        ((AppleOnTreeState*)state)->unk0C = ((AppleOnTreeState*)state)->unk0C - r;
        ((GameObject*)p)->anim.localPosY = ((AppleOnTreeState*)state)->unk2C;
        ((AppleOnTreeState*)state)->unk3C = lbl_803E37FC;
        ((AppleOnTreeState*)state)->bounceVel = lbl_803E3800;
        return 0;
    }
    else
    {
        ((GameObject*)p)->anim.localPosY = y;
        return 1;
    }
}

/* segment pragma-stack balance (re-split): */

typedef struct AppleontreeObjectDef
{
    u8 pad0[0x18 - 0x0];
    u32 unk18;
    u16 duration;
    u16 elapsed;
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 unk23;
    u8 unk24;
    s8 unk25;
    s16 unk26;
} AppleontreeObjectDef;

void appleontree_update(int objArg)
{
    extern void playerAddHealth(u8* player, int v); /* #57 */
    extern u8* Obj_GetPlayerObject(void); /* #57 */
    extern int FUN_8017e3c0(); /* #57 */
    extern int FUN_8017e15c(); /* #57 */
    extern u32 FUN_8017de58(); /* #57 */
    extern u32 FUN_8017db40(); /* #57 */
    extern u64 ObjHits_DisableObject(); /* #57 */
    float fa;
    u16* obj;
    int val;
    u32* modelIdxPtrW;
    u32 bitVal;
    int* modelIdxPtr;
    int placement;
    int state;
    f32 fc;
    f32 fb;
    f32 fd;
    f32 frac;
    int msg;
    f32 sunTime;

    obj = (u16*)objArg;
    state = *(int*)&((GameObject*)obj)->extra;
    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    msg = 0;
    if ((*(u8*)(state + 0x5a) & 4) != 0)
    {
        while (val = ObjMsg_Pop((int)obj, &msg, 0x0, 0x0), val != 0)
        {
            switch (msg)
            {
            case 0x7000b:
                {
                    playerAddHealth(Obj_GetPlayerObject(), (int)((AppleOnTreeState*)state)->healthRestore);
                    itemPickupDoParticleFx((int)obj, lbl_803E37C8, 0xff, 0x28);
                    Sfx_PlayFromObject((int)obj, SFXen_waterblock_stop);
                    val = *(int*)&((GameObject*)obj)->extra;
                    if (((GameObject*)obj)->anim.flags & 0x2000)
                    {
                        Obj_FreeObject((int)obj);
                    }
                    else
                    {
                        if (*(void**)(obj + 0x2a) != 0)
                        {
                            ObjHits_DisableObject((int)obj);
                        }
                        *(u8*)(val + 0x5a) = *(u8*)(val + 0x5a) | 2;
                    }
                    *(u8*)(state + 0x5a) = *(u8*)(state + 0x5a) & ~4;
                }
            }
        }
        if ((*(u8*)(state + 0x5a) & 4) != 0) goto switchD_8017e864_caseD_7;
    }
    if ((*(u8*)(state + 0x5a) & 2) == 0)
    {
        ((AppleOnTreeState*)state)->unk08 = ((AppleOnTreeState*)state)->unk08 + timeDelta;
        fa = ((AppleOnTreeState*)state)->unk0C;
        ((AppleOnTreeState*)state)->unk0C = fa + timeDelta;
        fb = ((AppleOnTreeState*)state)->unk08;
        frac = fb / *(float*)(state + 4);
        switch (((AppleOnTreeState*)state)->unk3A)
        {
        case 0:
            val = ObjHits_GetPriorityHit((int)obj, 0x0, 0x0, 0x0);
            if ((val != 0) ||
                ((*(short*)(placement + 0x26) != -1 &&
                    (bitVal = GameBit_Get((int)*(short*)(placement + 0x26)), bitVal != 0))))
            {
                state = *(int*)&((GameObject*)obj)->extra;
                placement = 0;
                do
                {
                    (*gPartfxInterface)->spawnObject(obj, 0x55a, NULL, 2, -1, NULL);
                    placement = placement + 1;
                }
                while (placement < 8);
                if (*(void**)(obj + 0x2a) != 0)
                {
                    ObjHits_DisableObject((int)obj);
                }
                *(u8*)(state + 0x5a) = *(u8*)(state + 0x5a) | 2;
                ((AppleOnTreeState*)state)->unk08 = timeDelta;
                ((AppleOnTreeState*)state)->unk3A = 5;
            }
            else
            {
                if (frac > *(float*)(state + 0x10))
                {
                    ((GameObject*)obj)->anim.rootMotionScale = *(float*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4);
                    ((AppleOnTreeState*)state)->unk3A = 1;
                }
                else
                {
                    placement = *(int*)&((GameObject*)obj)->extra;
                    ((GameObject*)obj)->anim.rootMotionScale =
                        (*(float*)(placement + 8) / *(float*)(placement + 4)) *
                        (lbl_803E37C8 / *(float*)(placement + 0x10)) *
                        *(float*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4);
                }
            }
            break;
        case 1:
            val = ObjHits_GetPriorityHit((int)obj, 0x0, 0x0, 0x0);
            if ((val != 0) ||
                ((*(short*)(placement + 0x26) != -1 &&
                    (bitVal = GameBit_Get((int)*(short*)(placement + 0x26)), bitVal != 0))))
            {
                state = *(int*)&((GameObject*)obj)->extra;
                placement = 0;
                do
                {
                    (*gPartfxInterface)->spawnObject(obj, 0x55a, NULL, 2, -1, NULL);
                    placement = placement + 1;
                }
                while (placement < 8);
                if (*(void**)(obj + 0x2a) != 0)
                {
                    ObjHits_DisableObject((int)obj);
                }
                *(u8*)(state + 0x5a) = *(u8*)(state + 0x5a) | 2;
                ((AppleOnTreeState*)state)->unk08 = timeDelta;
                ((AppleOnTreeState*)state)->unk3A = 5;
            }
            else
            {
                if (frac > ((GroundBaddieState*)state)->baddie.posX)
                {
                    placement = 0;
                    do
                    {
                        (*gPartfxInterface)->spawnObject(obj, 0x55a, NULL, 2, -1, NULL);
                        placement = placement + 1;
                    }
                    while (placement < 8);
                    ((AppleOnTreeState*)state)->unk3A = 2;
                }
                else
                {
                    if ((*gSkyInterface)->getSunPosition(&sunTime) != 0)
                    {
                        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E3804, timeDelta, 0);
                    }
                    else
                    {
                        ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)((int)obj, lbl_803E3808, timeDelta, 0);
                    }
                }
            }
            break;
        case 2:
            if (frac > ((GroundBaddieState*)state)->baddie.posY)
            {
                val = *(int*)&((GameObject*)obj)->extra;
                modelIdxPtrW = (u32*)objFindTexture((void*)obj, 0, 0);
                *modelIdxPtrW = 0;
                *(float*)(val + 0x24) = lbl_803E37C8;
                ((GameObject*)obj)->anim.rootMotionScale = *(float*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4);
                FUN_80017a78((int)obj, 1);
                ((AppleOnTreeState*)state)->unk3A = 3;
            }
            else
            {
                val = *(int*)&((GameObject*)obj)->extra;
                fa = *(float*)(val + 8);
                fb = -(*(float*)(val + 4) * *(float*)(val + 0x14) - fa) /
                (*(float*)(val + 4) *
                    (*(float*)(val + 0x18) - *(float*)(val + 0x14)));
                fa = fa * fa * fa * fa;
                state = (int)((fa * fa) / *(float*)(val + 0x54));
                modelIdxPtr = (int*)objFindTexture((void*)obj, 0, 0);
                *modelIdxPtr = 0x100 - state;
                *(float*)(val + 0x24) = lbl_803E37D0 * fb + lbl_803E37CC;
                ((GameObject*)obj)->anim.rootMotionScale = *(float*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4) * *(float*)(val + 0x24);
                FUN_80017a78((int)obj, 1);
            }
            state = ObjHits_GetPriorityHit((int)obj, 0x0, 0x0, 0x0);
            if ((state != 0) ||
                ((*(short*)(placement + 0x26) != -1 &&
                    (bitVal = GameBit_Get((int)*(short*)(placement + 0x26)), bitVal != 0))))
            {
                FUN_8017db40((u32)obj, 1);
            }
            break;
        case 3:
            ((AppleOnTreeState*)state)->unk08 = fb - timeDelta;
            if (frac > ((GroundBaddieState*)state)->baddie.posZ)
            {
                FUN_8017db40((u32)obj, 0);
            }
            else
            {
                state = ObjHits_GetPriorityHit((int)obj, 0x0, 0x0, 0x0);
                if ((state != 0) ||
                    ((*(short*)(placement + 0x26) != -1 &&
                        (bitVal = GameBit_Get((int)*(short*)(placement + 0x26)), bitVal != 0))))
                {
                    FUN_8017db40((u32)obj, 2);
                }
            }
            break;
        case 4:
            if (frac > *(float*)(state + 0x20))
            {
                ((AppleOnTreeState*)state)->unk3A = 6;
                ((AppleOnTreeState*)state)->unk08 = timeDelta;
            }
            else
            {
                placement = 0;
                val = 0;
                fd = lbl_803E37D4;
                do
                {
                    f32 t = ((AppleOnTreeState*)state)->unk0C;
                    if (placement != 0) break;
                    fb = t * (((GroundBaddieState*)state)->baddie.velZ + ((GroundBaddieState*)state)->baddie.velY);
                    fc = t * fb + (((AppleOnTreeState*)state)->bounceVel * t + ((AppleOnTreeState*)state)->unk2C);
                    if (((AppleOnTreeState*)state)->unk28 <= fd)
                    {
                        placement = FUN_8017e15c(fc, obj, state);
                    }
                    else
                    {
                        placement = FUN_8017e3c0(fc, obj, state);
                    }
                    val = val + 1;
                }
                while ((val == 100) || (val != 0x66));
                if (lbl_803E37D4 != ((AppleOnTreeState*)state)->unk30)
                {
                    fb = ((AppleOnTreeState*)state)->unk0C / ((AppleOnTreeState*)state)->unk50;
                    *obj = (f32) * (s16*)(state + 0x48) * fb;
                    obj[1] = (f32) * (s16*)(state + 0x4a) * fb;
                    obj[2] = (f32) * (s16*)(state + 0x4c) * fb;
                }
                modelIdxPtr = (int*)objFindTexture((void*)obj, 0, 0);
                *modelIdxPtr = (int)(lbl_803E380C * frac);
                FUN_8017de58((u32)obj);
            }
            break;
        case 5:
            if (lbl_803E3810 < fb)
            {
                placement = *(int*)&((GameObject*)obj)->extra;
                if (((GameObject*)obj)->anim.flags & 0x2000)
                {
                    Obj_FreeObject((int)obj);
                }
                else
                {
                    if (*(void**)(obj + 0x2a) != 0)
                    {
                        ObjHits_DisableObject((int)obj);
                    }
                    *(u8*)(placement + 0x5a) = *(u8*)(placement + 0x5a) | 2;
                }
            }
            break;
        case 6:
            frac = lbl_803E3814;
            if (fb > frac)
            {
                placement = *(int*)&((GameObject*)obj)->extra;
                if (((GameObject*)obj)->anim.flags & 0x2000)
                {
                    Obj_FreeObject((int)obj);
                }
                else
                {
                    if (*(void**)(obj + 0x2a) != 0)
                    {
                        ObjHits_DisableObject((int)obj);
                    }
                    *(u8*)(placement + 0x5a) = *(u8*)(placement + 0x5a) | 2;
                }
            }
            else
            {
                placement = (int)(lbl_803E3818 * fb / frac);
                ((GameObject*)obj)->anim.alpha = 0xff - placement;
                FUN_8017de58((u32)obj);
            }
        }
    }
switchD_8017e864_caseD_7:
    return;
}

void appleontree_init(int obj, int def)
{
    int state;
    f32 zeroScale;
    f32 timeScale;
    f32 progress;
    int eventBit;
    ObjTextureRuntimeSlot* texture;

    state = *(int*)&((GameObject*)obj)->extra;

    ((CrackAnimState*)state)->unk0 = ((AppleontreeObjectDef*)def)->unk18;
    ((CrackAnimState*)state)->duration = (f32)((AppleontreeObjectDef*)def)->duration;
    ((CrackAnimState*)state)->elapsed = (f32)((AppleontreeObjectDef*)def)->elapsed;
    {
        ((CrackAnimState*)state)->stageEnd0 = (f32)((AppleontreeObjectDef*)def)->unk20 / lbl_803E3828;
        progress = (f32)((AppleontreeObjectDef*)def)->unk21 / lbl_803E3828;
        ((CrackAnimState*)state)->stageEnd1 = progress + ((CrackAnimState*)state)->stageEnd0;
        progress = (f32)((AppleontreeObjectDef*)def)->unk22 / lbl_803E3828;
        ((CrackAnimState*)state)->stageEnd2 = progress + ((CrackAnimState*)state)->stageEnd1;
        progress = (f32)((AppleontreeObjectDef*)def)->unk23 / lbl_803E3828;
        ((CrackAnimState*)state)->stageEnd3 = progress + ((CrackAnimState*)state)->stageEnd2;
        ((CrackAnimState*)state)->unk20 = (f32)((AppleontreeObjectDef*)def)->unk24 / lbl_803E3828;
        ((CrackAnimState*)state)->unk28 = (f32)((AppleontreeObjectDef*)def)->unk25 / lbl_803E3828;
        ((CrackAnimState*)state)->unk28 = ((CrackAnimState*)state)->unk28 * lbl_803E37DC;
        ((CrackAnimState*)state)->unk24 = lbl_803E37C8;
        ((CrackAnimState*)state)->unk38 = 0;
        zeroScale = lbl_803E37D4;
        ((CrackAnimState*)state)->unk3C = zeroScale;
        ((CrackAnimState*)state)->unk40 = lbl_803E382C;
        ((CrackAnimState*)state)->unk44 = zeroScale;

        timeScale = ((CrackAnimState*)state)->duration * ((CrackAnimState*)state)->stageEnd2;
        timeScale *= timeScale;
        timeScale *= timeScale;
        timeScale = timeScale * timeScale;
        ((CrackAnimState*)state)->unk54 = timeScale * lbl_803E3830;

        ((GameObject*)obj)->anim.rotX = randomGetRange(-0x8000, 0x7fff);
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3834;
        Obj_SetActiveModelIndex(obj, 0);

        eventBit = ((AppleontreeObjectDef*)def)->unk26;
        if ((eventBit != -1) && (GameBit_Get(eventBit) != 0))
        {
            ((CrackAnimState*)state)->elapsed = lbl_803E3838;
            ((CrackAnimState*)state)->stage = 6;
        }
        else
        {
            progress = ((CrackAnimState*)state)->elapsed / ((CrackAnimState*)state)->duration;
            if (progress < ((CrackAnimState*)state)->stageEnd0)
            {
                ((CrackAnimState*)state)->stage = 0;
            }
            else if (progress < ((CrackAnimState*)state)->stageEnd1)
            {
                ((GameObject*)obj)->anim.rootMotionScale =
                    ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
                ((CrackAnimState*)state)->stage = 1;
            }
            else if (progress < ((CrackAnimState*)state)->stageEnd2)
            {
                ((CrackAnimState*)state)->stage = 2;
            }
            else
            {
                state = *(int*)&((GameObject*)obj)->extra;
                texture = objFindTexture((void*)obj, 0, 0);
                texture->textureId = 0;
                ((CrackAnimState*)state)->unk24 = lbl_803E37C8;
                ((GameObject*)obj)->anim.rootMotionScale =
                    ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
                Obj_SetActiveModelIndex(obj, 1);
                ((CrackAnimState*)state)->stage = 3;
            }
        }

        ObjMsg_AllocQueue(obj, 2);
    }
}

void dll_FC_free_nop(void);

int dll_FC_getExtraSize_ret_8(void);
int dll_FC_getObjectTypeId(void);

void dll_FC_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dll_FC_hitDetect(int* obj);

ObjectDescriptor gDllFCObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_FC_initialise_nop,
    (ObjectDescriptorCallback)dll_FC_release_nop,
    0,
    (ObjectDescriptorCallback)dll_FC_init,
    (ObjectDescriptorCallback)dll_FC_update,
    (ObjectDescriptorCallback)dll_FC_hitDetect,
    (ObjectDescriptorCallback)dll_FC_render,
    (ObjectDescriptorCallback)dll_FC_free_nop,
    (ObjectDescriptorCallback)dll_FC_getObjectTypeId,
    dll_FC_getExtraSize_ret_8,
};
