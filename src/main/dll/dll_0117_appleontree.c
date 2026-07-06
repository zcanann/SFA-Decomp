/* DLL 0x0117 - appleontree / groundAnimator group. TU: 0x8017D818-0x8017E1A0. */
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
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/dll/dll_00FC_babycloudrunner.h"
#include "main/sfa_extern_decls.h"
#include "main/dll/dll_0117_appleontree.h"
#include "main/audio/sfx_trigger_ids.h"

/* appleontree_update animState machine: an apple's lifecycle from hanging on
 * the tree through falling, resting, being knocked loose, and despawning. */
#define APPLEONTREE_STATE_GROWING 0   /* unripe, hanging; scales up toward ripe */
#define APPLEONTREE_STATE_RIPE 1      /* ripe, swaying; ready to drop */
#define APPLEONTREE_STATE_FALLING 2   /* dropping from branch to ground */
#define APPLEONTREE_STATE_LANDED 3    /* settled on the ground, collectable */
#define APPLEONTREE_STATE_KNOCKED 4   /* knocked loose, bouncing/rolling physics */
#define APPLEONTREE_STATE_BURST 5     /* fx-burst despawn (no fade) */
#define APPLEONTREE_STATE_FADEOUT 6   /* alpha fade-out despawn */

#define APPLEONTREE_MSG_IN_RANGE 0x7000a /* sent to player when grab is offered */
#define APPLEONTREE_MSG_PICKUP   0x7000b /* player collected: restore health + burst */

extern int randomGetRange(int lo, int hi);
extern u32 ObjMsg_SendToObject();
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
extern f32 gAppleOnTreePickupXZRange;
extern f32 gAppleOnTreePickupRange;
extern f32 timeDelta;
extern f32 sqrtf(f32);
extern int fn_80065684(int a, f32 b, f32 val, f32 d, f32* out, int e);
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


void appleontree_func0B(int obj, float* pos)
{
    AppleOnTreeState* state = ((GameObject*)obj)->extra;

    if (state->animState == APPLEONTREE_STATE_KNOCKED)
    {
        return;
    }
    if (state->animState == APPLEONTREE_STATE_BURST)
    {
        return;
    }
    if (state->animState == APPLEONTREE_STATE_FADEOUT)
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
    int state = *(int*)&((GameObject*)obj)->extra;
    int player = Obj_GetPlayerObject();

    if (!(Vec_xzDistance((float*)(player + 0x18), (float*)(obj + 0x18)) < gAppleOnTreePickupXZRange)) return;
    if (!(Vec_distance((float*)(player + 0x18), (float*)(obj + 0x18)) < gAppleOnTreePickupRange)) return;

    if (GameBit_Get(0x90f) == 0)
    {
        (*gObjectTriggerInterface)->setObjects(0x444, 0, 0);
        ((AppleOnTreeState*)state)->unk5C = -1;
        ((AppleOnTreeState*)state)->unk5E = 0;
        ((AppleOnTreeState*)state)->unk60 = lbl_803E37C8;
        ObjMsg_SendToObject(player, APPLEONTREE_MSG_IN_RANGE, obj, (int*)(state + 0x5c));
        GameBit_Set(0x90f, 1);
        ((AppleOnTreeState*)state)->flags = (u8)(((AppleOnTreeState*)state)->flags | 4);
    }
    else
    {
        playerAddHealth(player, ((AppleOnTreeState*)state)->healthRestore);
        itemPickupDoParticleFx(obj, lbl_803E37C8, 0xff, 0x28);
        Sfx_PlayFromObject(obj, SFXen_waterblock_stop);
        state = *(int*)&((GameObject*)obj)->extra;
        if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            if (((GameObject*)obj)->anim.hitReactState != NULL)
            {
                ObjHits_DisableObject(obj);
            }
            ((AppleOnTreeState*)state)->flags = (u8)(((AppleOnTreeState*)state)->flags | 2);
        }
    }
}

void appleontree_setScale(void)
{
}

int appleontree_getExtraSize(void) { return 0x64; }

u8 appleontree_modelMtxFn(int* obj) { return ((AppleOnTreeState*)(int*)((GameObject*)obj)->extra)->animState; }

void appleontree_free(int* obj)
{
    (*gExpgfxInterface)->freeSource((u32)obj);
}

void appleontree_render(int obj, int p1, int p2, int p3, int p4, s8 visible)
{
    extern void objRenderModelAndHitVolumes(int obj, int p1, int p2, int p3, int p4, f32 scale); /* #57 */
    AppleOnTreeState* inner = ((GameObject*)obj)->extra;
    if ((inner->flags & 2) == 0)
    {
        objRenderModelAndHitVolumes(obj, p1, p2, p3, p4, lbl_803E37C8);
    }
}

#pragma opt_lifetimes off
void fn_8017D854(int obj, int msg)
{
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
    ((AppleOnTreeState*)state)->animState = APPLEONTREE_STATE_KNOCKED;
    ((AppleOnTreeState*)state)->elapsedTime = timeDelta;
    ((AppleOnTreeState*)state)->flightTime = timeDelta;
    ((AppleOnTreeState*)state)->rotX = randomGetRange(-0x8000, 0x7fff);
    ((AppleOnTreeState*)state)->rotY = randomGetRange(-0x8000, 0x7fff);
    ((AppleOnTreeState*)state)->rotZ = 0x2000;

    if (fn_80065684(obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.localPosZ,
                    (f32*)(state + 0x30), 0) == 0)
    {
        state = *(int*)&((GameObject*)obj)->extra;
        if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
        {
            Obj_FreeObject(obj);
        }
        else
        {
            if (((GameObject*)obj)->anim.hitReactState != NULL)
            {
                ObjHits_DisableObject(obj);
            }
            ((AppleOnTreeState*)state)->flags = (u8)(((AppleOnTreeState*)state)->flags | 2);
        }
    }
    else
    {
        f32 m = ((AppleOnTreeState*)state)->gravity;
        f32 g = lbl_803E37D8 * m;
        f32 q = sqrtf(-(g * ((AppleOnTreeState*)state)->dropHeight - lbl_803E37D4));
        f32 t = lbl_803E37DC * m;
        f32 r;

        if (t >= lbl_803E37D4)
        {
            r = t;
        }
        else
        {
            r = -t;
        }
        if (r <= lbl_803E37E0)
        {
            r = lbl_803E37C8;
        }
        else
        {
            f32 r2;
            r = (lbl_803E37E4 - q) / t;
            r2 = (lbl_803E37E4 + q) / t;
            r = (r > *(f32*)&lbl_803E37D4) ? r : r2;
        }
        ((AppleOnTreeState*)state)->totalFlightTime = r;

        if (((AppleOnTreeState*)state)->velY < lbl_803E37D4)
        {
            ((AppleOnTreeState*)state)->dropHeight = -(lbl_803E37D8 * ((AppleOnTreeState*)state)->unk24 - ((AppleOnTreeState
                *)state)->dropHeight);
        }
        else
        {
            ((AppleOnTreeState*)state)->dropHeight = lbl_803E37E8 * (lbl_803E37D8 * ((AppleOnTreeState*)state)->unk24) + ((
                AppleOnTreeState*)state)->dropHeight;
        }

        if (((AppleOnTreeState*)state)->dropHeight <= lbl_803E37D4)
        {
            state = *(int*)&((GameObject*)obj)->extra;
            if ((((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA) != 0)
            {
                Obj_FreeObject(obj);
            }
            else
            {
                if (((GameObject*)obj)->anim.hitReactState != NULL)
                {
                    ObjHits_DisableObject(obj);
                }
                ((AppleOnTreeState*)state)->flags = (u8)(((AppleOnTreeState*)state)->flags | 2);
            }
        }
        else
        {
            ((AppleOnTreeState*)state)->posY = ((GameObject*)obj)->anim.localPosY;
            ((AppleOnTreeState*)state)->splashPosY = ((GameObject*)obj)->anim.localPosY - ((AppleOnTreeState*)state)->dropHeight;
            if (((GameObject*)obj)->anim.hitReactState != NULL)
            {
                ObjHits_DisableObject(obj);
            }
            Sfx_PlayFromObject(obj, SFXen_bridge_stops);
        }
    }
}
#pragma opt_lifetimes reset


int fn_8017DCD4(int p, int state, f32 y)
{
    f32 zero = lbl_803E37D4;
    f32 m = ((AppleOnTreeState*)state)->gravity;

    if (zero != m)
    {
        if (((AppleOnTreeState*)state)->dropHeight - (((AppleOnTreeState*)state)->posY - y) < zero)
        {
            f32 b = ((AppleOnTreeState*)state)->bounceVel;
            if (zero == b)
            {
                f32 g = lbl_803E37D8 * m;
                f32 q = sqrtf(b * b - g * ((AppleOnTreeState*)state)->dropHeight);
                f32 t = lbl_803E37DC * m;
                f32 r;

                if (t >= lbl_803E37D4)
                {
                    r = t;
                }
                else
                {
                    r = -t;
                }
                if (r <= lbl_803E37E0)
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
                ((AppleOnTreeState*)state)->flightTime = ((AppleOnTreeState*)state)->flightTime - r;
                ((AppleOnTreeState*)state)->posY = ((AppleOnTreeState*)state)->posY - ((AppleOnTreeState*)state)->
                    dropHeight;
                ((AppleOnTreeState*)state)->dropHeight = lbl_803E37D4;
                ((GameObject*)p)->anim.localPosY = ((AppleOnTreeState*)state)->posY;
                ((GameObject*)p)->anim.rotX = ((AppleOnTreeState*)state)->rotX;
                ((GameObject*)p)->anim.rotY = ((AppleOnTreeState*)state)->rotY;
                ((GameObject*)p)->anim.rotZ = ((AppleOnTreeState*)state)->rotZ;
                ((AppleOnTreeState*)state)->bounceVel = -((AppleOnTreeState*)state)->velY;
                if ((((AppleOnTreeState*)state)->flags & 8) == 0)
                {
                    Sfx_PlayFromObject(p, SFXTRIG_pk_fruit_lands);
                    ((AppleOnTreeState*)state)->flags = (u8)(((AppleOnTreeState*)state)->flags | 8);
                }
                return 1;
            }
            else if (b < lbl_803E37F4)
            {
                ((GameObject*)p)->anim.localPosY = ((AppleOnTreeState*)state)->posY;
                ((AppleOnTreeState*)state)->gravity = zero;
                ((AppleOnTreeState*)state)->bounceVel = zero;
                return 1;
            }
            else
            {
                f32 g;
                f32 q;
                f32 t;
                f32 r;
                m = m + ((AppleOnTreeState*)state)->unk3C;
                g = lbl_803E37D8 * m;
                q = sqrtf(b * b - g * ((AppleOnTreeState*)state)->dropHeight);
                t = lbl_803E37DC * m;

                if (t >= lbl_803E37D4)
                {
                    r = t;
                }
                else
                {
                    r = -t;
                }
                if (r <= lbl_803E37E0)
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
                ((AppleOnTreeState*)state)->flightTime = ((AppleOnTreeState*)state)->flightTime - r;
                ((GameObject*)p)->anim.localPosY = ((AppleOnTreeState*)state)->posY;
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
        if (((AppleOnTreeState*)state)->dropHeight - (((AppleOnTreeState*)state)->posY - y) <= lbl_803E37D4)
        {
            f32 b;
            f32 m = ((AppleOnTreeState*)state)->gravity;
            f32 g;
            f32 q;
            f32 t;
            f32 a;
            f32 r;
            b = ((AppleOnTreeState*)state)->bounceVel;
            g = lbl_803E37D8 * m;
            q = sqrtf(b * b - g * ((AppleOnTreeState*)state)->dropHeight);
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
            ((AppleOnTreeState*)state)->flightTime = ((AppleOnTreeState*)state)->flightTime - r;
            ((AppleOnTreeState*)state)->posY = ((AppleOnTreeState*)state)->posY - ((AppleOnTreeState*)state)->dropHeight;
            ((AppleOnTreeState*)state)->dropHeight = lbl_803E37D4;
            ((GameObject*)p)->anim.localPosY = ((AppleOnTreeState*)state)->posY;
            ((GameObject*)p)->anim.rotX = ((AppleOnTreeState*)state)->rotX;
            ((GameObject*)p)->anim.rotY = ((AppleOnTreeState*)state)->rotY;
            ((GameObject*)p)->anim.rotZ = ((AppleOnTreeState*)state)->rotZ;
            {
                f32 g2 = lbl_803E37DC * ((AppleOnTreeState*)state)->gravity;
                ((AppleOnTreeState*)state)->bounceVel = g2 * r + ((AppleOnTreeState*)state)->bounceVel;
            }
            ((AppleOnTreeState*)state)->unk3C = ((AppleOnTreeState*)state)->velY;
            ((WaterfxSpawnSplashBurstAtPointFn)(*gWaterfxInterface)->spawnSplashBurst)(
                (void*)p, ((GameObject*)p)->anim.localPosX, ((AppleOnTreeState*)state)->splashPosY,
                ((GameObject*)p)->anim.localPosZ);
            return 0;
        }
        else
        {
            ((GameObject*)p)->anim.localPosY = y;
            return 1;
        }
    }
    else if (y - ((AppleOnTreeState*)state)->posY >= lbl_803E37D4)
    {
        f32 b;
        f32 m = ((AppleOnTreeState*)state)->gravity + ((AppleOnTreeState*)state)->unk3C;
        f32 g;
        f32 q;
        f32 t;
        f32 r;
        b = ((AppleOnTreeState*)state)->bounceVel;
        g = lbl_803E37D8 * m;
        q = sqrtf(b * b - g * ((AppleOnTreeState*)state)->dropHeight);
        t = lbl_803E37DC * m;

        if (t >= lbl_803E37D4)
        {
            r = t;
        }
        else
        {
            r = -t;
        }
        if (r <= lbl_803E37E0)
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
        ((AppleOnTreeState*)state)->flightTime = ((AppleOnTreeState*)state)->flightTime - r;
        ((GameObject*)p)->anim.localPosY = ((AppleOnTreeState*)state)->posY;
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
    u8 stage0Frac;
    u8 stage1Frac;
    u8 stage2Frac;
    u8 stage3Frac;
    u8 unk24;
    s8 unk25;
    s16 gameBit;
} AppleontreeObjectDef;

#pragma inline_max_size(1)
void appleontree_update(int objArg)
{
    extern void playerAddHealth(u8* player, int v); /* #57 */
    extern u8* Obj_GetPlayerObject(void); /* #57 */
    extern u64 ObjHits_DisableObject(); /* #57 */
    float fa;
    int obj;
    int val;
    u32* modelIdxPtrW;
    u32 bitVal;
    int* modelIdxPtr;
    int state;
    int placement;
    int i;
    f32 fc;
    f32 fb;
    f32 fd;
    f32 frac;
    f32 sunTime;
    int msg;

    obj = objArg;
    state = *(int*)&((GameObject*)obj)->extra;
    placement = *(int*)&((GameObject*)obj)->anim.placementData;
    msg = 0;
    if ((((AppleOnTreeState*)state)->flags & 4) != 0)
    {
        while (val = ObjMsg_Pop((int)obj, &msg, 0x0, 0x0), val != 0)
        {
            switch (msg)
            {
            case APPLEONTREE_MSG_PICKUP:
                {
                    playerAddHealth(Obj_GetPlayerObject(), (int)((AppleOnTreeState*)state)->healthRestore);
                    itemPickupDoParticleFx((int)obj, lbl_803E37C8, 0xff, 0x28);
                    Sfx_PlayFromObject((int)obj, SFXen_waterblock_stop);
                    val = *(int*)&((GameObject*)obj)->extra;
                    if (((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA)
                    {
                        Obj_FreeObject((int)obj);
                    }
                    else
                    {
                        if (*(void**)((u8*)obj + 0x54) != 0)
                        {
                            ObjHits_DisableObject((int)obj);
                        }
                        ((AppleOnTreeState*)val)->flags = ((AppleOnTreeState*)val)->flags | 2;
                    }
                    ((AppleOnTreeState*)state)->flags = ((AppleOnTreeState*)state)->flags & ~4;
                }
            }
        }
        if ((((AppleOnTreeState*)state)->flags & 4) != 0) goto switchD_8017e864_caseD_7;
    }
    if ((((AppleOnTreeState*)state)->flags & 2) == 0)
    {
        ((AppleOnTreeState*)state)->elapsedTime = ((AppleOnTreeState*)state)->elapsedTime + timeDelta;
        fa = ((AppleOnTreeState*)state)->flightTime;
        ((AppleOnTreeState*)state)->flightTime = fa + timeDelta;
        fb = ((AppleOnTreeState*)state)->elapsedTime;
        frac = fb / ((AppleOnTreeState*)state)->phaseDuration;
        switch (((AppleOnTreeState*)state)->animState)
        {
        case APPLEONTREE_STATE_GROWING:
            val = ObjHits_GetPriorityHit(obj, 0x0, 0x0, 0x0);
            if ((val != 0) ||
                ((((AppleontreeObjectDef*)placement)->gameBit != -1 &&
                    (bitVal = GameBit_Get((int)((AppleontreeObjectDef*)placement)->gameBit), bitVal != 0))))
            {
                state = *(int*)&((GameObject*)obj)->extra;
                i = 0;
                do
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x55a, NULL, 2, -1, NULL);
                    i = i + 1;
                }
                while (i < 8);
                if (*(void**)((u8*)obj + 0x54) != 0)
                {
                    ObjHits_DisableObject(obj);
                }
                ((AppleOnTreeState*)state)->flags = ((AppleOnTreeState*)state)->flags | 2;
                ((AppleOnTreeState*)state)->elapsedTime = timeDelta;
                ((AppleOnTreeState*)state)->animState = APPLEONTREE_STATE_BURST;
            }
            else
            {
                if (frac > ((AppleOnTreeState*)state)->growThreshold)
                {
                    ((GameObject*)obj)->anim.rootMotionScale = *(float*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4);
                    ((AppleOnTreeState*)state)->animState = APPLEONTREE_STATE_RIPE;
                }
                else
                {
                    fb = *(float*)(*(int*)&((GameObject*)obj)->extra + 8) /
                          *(float*)(*(int*)&((GameObject*)obj)->extra + 4);
                    fb = fb * (lbl_803E37C8 / *(float*)(*(int*)&((GameObject*)obj)->extra + 0x10));
                    ((GameObject*)obj)->anim.rootMotionScale =
                        *(float*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4) * fb;
                }
            }
            break;
        case APPLEONTREE_STATE_RIPE:
            val = ObjHits_GetPriorityHit(obj, 0x0, 0x0, 0x0);
            if ((val != 0) ||
                ((((AppleontreeObjectDef*)placement)->gameBit != -1 &&
                    (bitVal = GameBit_Get((int)((AppleontreeObjectDef*)placement)->gameBit), bitVal != 0))))
            {
                state = *(int*)&((GameObject*)obj)->extra;
                i = 0;
                do
                {
                    (*gPartfxInterface)->spawnObject((void*)obj, 0x55a, NULL, 2, -1, NULL);
                    i = i + 1;
                }
                while (i < 8);
                if (*(void**)((u8*)obj + 0x54) != 0)
                {
                    ObjHits_DisableObject(obj);
                }
                ((AppleOnTreeState*)state)->flags = ((AppleOnTreeState*)state)->flags | 2;
                ((AppleOnTreeState*)state)->elapsedTime = timeDelta;
                ((AppleOnTreeState*)state)->animState = APPLEONTREE_STATE_BURST;
            }
            else
            {
                if (frac > ((GroundBaddieState*)state)->baddie.posX)
                {
                    i = 0;
                    do
                    {
                        (*gPartfxInterface)->spawnObject((void*)obj, 0x55a, NULL, 2, -1, NULL);
                        i = i + 1;
                    }
                    while (i < 8);
                    ((AppleOnTreeState*)state)->animState = APPLEONTREE_STATE_FALLING;
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
        case APPLEONTREE_STATE_FALLING:
            if (frac > ((GroundBaddieState*)state)->baddie.posY)
            {
                val = *(int*)&((GameObject*)obj)->extra;
                modelIdxPtrW = (u32*)objFindTexture((void*)obj, 0, 0);
                *modelIdxPtrW = 0;
                *(float*)(val + 0x24) = lbl_803E37C8;
                ((GameObject*)obj)->anim.rootMotionScale = *(float*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4);
                Obj_SetActiveModelIndex((int)obj, 1);
                ((AppleOnTreeState*)state)->animState = APPLEONTREE_STATE_LANDED;
            }
            else
            {
                val = *(int*)&((GameObject*)obj)->extra;
                fb = -(*(float*)(val + 4) * *(float*)(val + 0x14) - *(float*)(val + 8)) /
                (*(float*)(val + 4) *
                    (*(float*)(val + 0x18) - *(float*)(val + 0x14)));
                fa = *(float*)(val + 8);
                fc = fa * fa;
                fc = fc * fc;
                state = 0x100 - (int)((fc * fc) / *(float*)(val + 0x54));
                modelIdxPtr = (int*)objFindTexture((void*)obj, 0, 0);
                *modelIdxPtr = state;
                *(float*)(val + 0x24) = lbl_803E37D0 * fb + lbl_803E37CC;
                ((GameObject*)obj)->anim.rootMotionScale = *(float*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4) * *(float*)(val + 0x24);
                Obj_SetActiveModelIndex((int)obj, 1);
            }
            state = ObjHits_GetPriorityHit((int)obj, 0x0, 0x0, 0x0);
            if ((state != 0) ||
                ((((AppleontreeObjectDef*)placement)->gameBit != -1 &&
                    (bitVal = GameBit_Get((int)((AppleontreeObjectDef*)placement)->gameBit), bitVal != 0))))
            {
                fn_8017D854(obj, 1);
            }
            break;
        case APPLEONTREE_STATE_LANDED:
            ((AppleOnTreeState*)state)->elapsedTime = fb - timeDelta;
            if (frac > ((GroundBaddieState*)state)->baddie.posZ)
            {
                fn_8017D854(obj, 0);
            }
            else
            {
                state = ObjHits_GetPriorityHit((int)obj, 0x0, 0x0, 0x0);
                if ((state != 0) ||
                    ((((AppleontreeObjectDef*)placement)->gameBit != -1 &&
                        (bitVal = GameBit_Get((int)((AppleontreeObjectDef*)placement)->gameBit), bitVal != 0))))
                {
                    fn_8017D854(obj, 2);
                }
            }
            break;
        case APPLEONTREE_STATE_KNOCKED:
            if (frac > ((AppleOnTreeState*)state)->fadeThreshold)
            {
                ((AppleOnTreeState*)state)->animState = APPLEONTREE_STATE_FADEOUT;
                ((AppleOnTreeState*)state)->elapsedTime = timeDelta;
            }
            else
            {
                placement = 0;
                val = 0;
                fd = lbl_803E37D4;
                while (placement == 0)
                {
                    f32 t = ((AppleOnTreeState*)state)->flightTime;
                    fb = t * (((GroundBaddieState*)state)->baddie.velZ + ((GroundBaddieState*)state)->baddie.velY);
                    fc = t * fb + (((AppleOnTreeState*)state)->bounceVel * t + ((AppleOnTreeState*)state)->posY);
                    if (((AppleOnTreeState*)state)->velY > fd)
                    {
                        placement = fn_8017DF34(obj, state, fc);
                    }
                    else
                    {
                        placement = fn_8017DCD4(obj, state, fc);
                    }
                    val = val + 1;
                    if (!((val == 100) || (val != 0x66))) break;
                }
                if (lbl_803E37D4 != ((AppleOnTreeState*)state)->dropHeight)
                {
                    fb = ((AppleOnTreeState*)state)->flightTime / ((AppleOnTreeState*)state)->totalFlightTime;
                    ((u16*)obj)[0] = (f32) * (s16*)(state + 0x48) * fb;
                    ((u16*)obj)[1] = (f32) * (s16*)(state + 0x4a) * fb;
                    ((u16*)obj)[2] = (f32) * (s16*)(state + 0x4c) * fb;
                }
                modelIdxPtr = (int*)objFindTexture((void*)obj, 0, 0);
                *modelIdxPtr = (int)(lbl_803E380C * frac);
                appleontree_handleCollectableHit(obj);
            }
            break;
        case APPLEONTREE_STATE_BURST:
            if (fb > lbl_803E3810)
            {
                placement = *(int*)&((GameObject*)obj)->extra;
                if (((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA)
                {
                    Obj_FreeObject((int)obj);
                }
                else
                {
                    if (*(void**)((u8*)obj + 0x54) != 0)
                    {
                        ObjHits_DisableObject((int)obj);
                    }
                    ((AppleOnTreeState*)placement)->flags = ((AppleOnTreeState*)placement)->flags | 2;
                }
            }
            break;
        case APPLEONTREE_STATE_FADEOUT:
            frac = lbl_803E3814;
            if (fb > frac)
            {
                placement = *(int*)&((GameObject*)obj)->extra;
                if (((GameObject*)obj)->anim.flags & OBJANIM_FLAG_OWNS_PLACEMENT_DATA)
                {
                    Obj_FreeObject((int)obj);
                }
                else
                {
                    if (*(void**)((u8*)obj + 0x54) != 0)
                    {
                        ObjHits_DisableObject((int)obj);
                    }
                    ((AppleOnTreeState*)placement)->flags = ((AppleOnTreeState*)placement)->flags | 2;
                }
            }
            else
            {
                placement = (int)(lbl_803E3818 * fb / frac);
                ((GameObject*)obj)->anim.alpha = 0xff - placement;
                appleontree_handleCollectableHit(obj);
            }
        }
    }
switchD_8017e864_caseD_7:
    return;
}
#pragma inline_max_size reset

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
        ((CrackAnimState*)state)->stageEnd0 = (f32)((AppleontreeObjectDef*)def)->stage0Frac / lbl_803E3828;
        progress = (f32)((AppleontreeObjectDef*)def)->stage1Frac / lbl_803E3828;
        ((CrackAnimState*)state)->stageEnd1 = progress + ((CrackAnimState*)state)->stageEnd0;
        progress = (f32)((AppleontreeObjectDef*)def)->stage2Frac / lbl_803E3828;
        ((CrackAnimState*)state)->stageEnd2 = progress + ((CrackAnimState*)state)->stageEnd1;
        progress = (f32)((AppleontreeObjectDef*)def)->stage3Frac / lbl_803E3828;
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
        zeroScale = timeScale * timeScale;
        ((CrackAnimState*)state)->unk54 = zeroScale * lbl_803E3830;

        ((GameObject*)obj)->anim.rotX = randomGetRange(-0x8000, 0x7fff);
        ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3834;
        Obj_SetActiveModelIndex(obj, 0);

        eventBit = ((AppleontreeObjectDef*)def)->gameBit;
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
                int reread = *(int*)&((GameObject*)obj)->extra;
                texture = objFindTexture((void*)obj, 0, 0);
                texture->textureId = 0;
                ((CrackAnimState*)reread)->unk24 = lbl_803E37C8;
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
