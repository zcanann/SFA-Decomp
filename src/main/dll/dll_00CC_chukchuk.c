/*
 * chukchuk (DLL 0xCC) - the ChukChuk ice-spitter baddie and its IceBall
 * projectile. Idle ChukChuk ramps a glow texture; when index 10 is reached
 * it arms (flags bit 1) and, if the player crosses triggerDistance inside the
 * facing wedge (+/- arcHalfAngle around rotX), rolls attackChance% to spit an
 * IceBall (fn_8015F5B0 spawns object id 1307 aimed at the player + aimHeightY).
 * Taking priority-hit 14 decrements hitsLeft; on depletion it dies: disables
 * hits, hides, sets gameBit, and starts the steam-fade particle. gameBit set
 * at load means already destroyed -> spawn disabled + hidden.
 *
 * This TU also defines fn_8015F5B0 and the ChukChuk ObjectDescriptor.
 */
#include "main/obj_placement.h"
#include "main/dll/chukchukstate_struct.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/scarab.h"
#include "main/objtexture.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"

/* child object id spawned by fn_8015F5B0 (docblock: IceBall aimed at the player) */
#define CHUKCHUK_CHILD_OBJ_ICEBALL 1307

/* sub->flags bits (see chukchukstate_struct.h) */
#define CHUKCHUK_FLAG_PRIMED        0x1
#define CHUKCHUK_FLAG_DEAD          0x2
#define CHUKCHUK_FLAG_FORCED_ATTACK 0x4

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern u32 ObjHits_DisableObject();
extern int ObjHits_GetPriorityHit();

STATIC_ASSERT(sizeof(ChukChukState) == 0x18);
STATIC_ASSERT(offsetof(ChukChukState, flags) == 0x12);

/* glow-texture ramp table */
u8 lbl_8031FF80[] = {0, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 0};

#pragma dont_inline on
#pragma scheduling off
#pragma peephole off
void fn_8015F5B0(short* obj)
{

    extern int Obj_AllocObjectSetup(int size, int id);
    extern void* Obj_SetupObject(int a, int b, int c, int d, int e);
    extern int Obj_GetPlayerObject(void);
    ChukChukState* sub;
    int setup;
    u8* o;
    int pl;
    f32 sc;

    sub = ((GameObject*)obj)->extra;
    if (Obj_IsLoadingLocked() != 0)
    {
        setup = Obj_AllocObjectSetup(36, CHUKCHUK_CHILD_OBJ_ICEBALL);
        ((ObjPlacement*)setup)->posX = ((GameObject*)obj)->anim.localPosX;
        ((ObjPlacement*)setup)->posY = 5.0f + ((GameObject*)obj)->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = ((GameObject*)obj)->anim.localPosZ;
        ((ObjPlacement*)setup)->color[0] = 1;
        ((ObjPlacement*)setup)->color[1] = 4;
        ((ObjPlacement*)setup)->color[3] = 0xff;
        o = Obj_SetupObject(setup, 5, -1, -1, 0);
        if (o != NULL)
        {
            pl = Obj_GetPlayerObject();
            ((GameObject*)o)->anim.velocityX =
                (((GameObject*)pl)->anim.localPosX - ((GameObject*)obj)->anim.localPosX) / (sc = 42.0f);
            ((GameObject*)o)->anim.velocityY =
                (((GameObject*)pl)->anim.localPosY + (f32)(u32)sub->aimHeightY - ((GameObject*)obj)->anim.localPosY) /
                sc;
            ((GameObject*)o)->anim.velocityZ =
                (((GameObject*)pl)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ) / sc;
        }
    }
}
#pragma dont_inline reset

#pragma scheduling on
#pragma peephole on
void ChukChuk_setScale(int obj, int message)
{
    switch ((u8)message)
    {
    case 0x80:
        Sfx_PlayFromObject(obj, SFXTRIG_baddie_rach_bite_26b);
        break;
    }
}

#pragma scheduling off
#pragma peephole off
int ChukChuk_getExtraSize(void)
{
    return sizeof(ChukChukState);
}
int ChukChuk_getObjectTypeId(void)
{
    return 0x0;
}

#pragma scheduling on
#pragma peephole on
void ChukChuk_free(void)
{
}

#pragma scheduling off
#pragma peephole off
void ChukChuk_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

#pragma scheduling on
#pragma peephole on
void ChukChuk_hitDetect(void)
{
}

#pragma scheduling off
#pragma peephole off
#pragma opt_propagation off
void ChukChuk_update(short* obj)
{
    extern void objParticleFn_80099d84(f32, short*, int, f32, int);
    extern int Obj_GetPlayerObject(void);
    extern int getAngle(float y, float x);

    ChukChukState* v;
    u16 di;
    int pl;
    ObjTextureRuntimeSlot* tex;
    int ang;
    int roll;
    f32 lim;
    f32 nv;
    f32 dx;
    f32 dz;
    struct
    {
        int hitVolume;
        int sphereIndex;
        int hitObject;
        f32 toPlayer[3];
    } hit;

    v = ((GameObject*)obj)->extra;
    if (v->steamTimer)
    {
        v->steamTimer -= timeDelta;
        objParticleFn_80099d84(1.0f, obj, 1, v->steamTimer / 60.0f, 0);
        if (v->steamTimer <= 0.0f)
        {
            v->steamTimer = 0.0f;
        }
    }
    if ((v->flags & CHUKCHUK_FLAG_DEAD) == 0)
    {
        tex = objFindTexture((GameObject*)obj, 0, 0);
        if (v->glowPhase < 16.0f)
        {
            if ((int)v->glowPhase == 10)
            {
                v->flags |= CHUKCHUK_FLAG_PRIMED;
            }
            tex->textureId = lbl_8031FF80[(int)v->glowPhase] << 8;
            lim = 16.0f;
            nv = (v->glowPhase += 1.0f);
            if (lim == nv)
            {
                v->glowPhase = (f32)(int)randomGetRange(16, 245);
            }
        }
        else
        {
            if (255.0f - v->glowPhase >= timeDelta)
            {
                v->glowPhase = v->glowPhase + timeDelta;
            }
            else
            {
                v->glowPhase = 0.0f;
            }
            tex->textureId = 0;
        }
        pl = Obj_GetPlayerObject();
        dx = ((GameObject*)pl)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
        dz = ((GameObject*)pl)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
        di = sqrtf(dx * dx + dz * dz);
        if (di < v->triggerDistance)
        {
            if (v->prevDistance >= v->triggerDistance)
            {
                v->flags = CHUKCHUK_FLAG_PRIMED | CHUKCHUK_FLAG_FORCED_ATTACK;
                v->glowPhase = 0.0f;
            }
            if ((v->flags & (CHUKCHUK_FLAG_PRIMED | CHUKCHUK_FLAG_FORCED_ATTACK)) != 0)
            {
                hit.toPlayer[0] = ((GameObject*)pl)->anim.worldPosX - ((GameObject*)obj)->anim.worldPosX;
                hit.toPlayer[1] = ((GameObject*)pl)->anim.worldPosY - ((GameObject*)obj)->anim.worldPosY;
                hit.toPlayer[2] = ((GameObject*)pl)->anim.worldPosZ - ((GameObject*)obj)->anim.worldPosZ;
                ang = getAngle(hit.toPlayer[0], hit.toPlayer[2]) & 0xffff;
                ang -= ((GameObject*)obj)->anim.rotX & 0xffff;
                if (ang > 0x8000)
                {
                    ang -= 0xffff;
                }
                if (ang < -0x8000)
                {
                    ang += 0xffff;
                }
                if (((u32)ang & 0xffff) < v->arcHalfAngle ||
                    ((u32)ang & 0xffff) > ((0xffff - v->arcHalfAngle) & 0xffff))
                {
                    roll = randomGetRange(0, 99);
                    if (roll < v->attackChance || (v->flags & CHUKCHUK_FLAG_FORCED_ATTACK) != 0)
                    {
                        Sfx_PlayFromObject(obj, SFXTRIG_baddie_zyck_lash_268);
                        fn_8015F5B0(obj);
                    }
                    else
                    {
                        Sfx_PlayFromObject(obj, SFXTRIG_baddie_zyck_call02);
                    }
                }
                else
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_baddie_zyck_call02);
                }
            }
        }
        else if ((v->flags & CHUKCHUK_FLAG_PRIMED) != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_zyck_call02);
        }
        v->prevDistance = di;
        if (ObjHits_GetPriorityHit((GameObject*)(obj), &hit.hitObject, &hit.sphereIndex, &hit.hitVolume) == 14)
        {
            v->hitsLeft -= 1;
            if (v->hitsLeft < 1)
            {
                ObjHits_DisableObject(obj);
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                v->flags |= CHUKCHUK_FLAG_DEAD;
                Sfx_PlayFromObject(obj, SFXTRIG_mn_lummy311_26a);
                mainSetBits(v->gameBit, 1);
                v->steamTimer = 60.0f;
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_zyck_lash);
            }
        }
        v->flags &= ~(CHUKCHUK_FLAG_PRIMED | CHUKCHUK_FLAG_FORCED_ATTACK);
    }
}

void ChukChuk_init(u8* obj, u8* params)
{
    ChukChukState* sub = ((GameObject*)obj)->extra;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
        (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    sub->gameBit = *(s16*)(params + 0x18);
    if (sub->gameBit != -1 && mainGetBit(sub->gameBit) != 0)
    {
        ObjHits_DisableObject(obj);
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        sub->flags = (u8)(sub->flags | CHUKCHUK_FLAG_DEAD);
    }
    else
    {
        sub->triggerDistance = (u16)(params[0x29] << 3);
        sub->unk08 = *(s16*)(params + 0x22);
        sub->hitsLeft = params[0x32];
        sub->arcHalfAngle = (u16)((s8)params[0x28] * 0xb6);
        sub->attackChance = params[0x2f];
        sub->aimHeightY = params[0x27];
        ((GameObject*)obj)->anim.rotX = (s16)((s8)params[0x2a] << 8);
    }
}

#pragma opt_propagation reset
#pragma scheduling on
#pragma peephole on
void ChukChuk_release(void)
{
}

void ChukChuk_initialise(void)
{
}

ObjectDescriptor11WithPadding gChukChukObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)ChukChuk_initialise,
        (ObjectDescriptorCallback)ChukChuk_release,
        0,
        (ObjectDescriptorCallback)ChukChuk_init,
        (ObjectDescriptorCallback)ChukChuk_update,
        (ObjectDescriptorCallback)ChukChuk_hitDetect,
        (ObjectDescriptorCallback)ChukChuk_render,
        (ObjectDescriptorCallback)ChukChuk_free,
        (ObjectDescriptorCallback)ChukChuk_getObjectTypeId,
        ChukChuk_getExtraSize,
        (ObjectDescriptorCallback)ChukChuk_setScale,
    },
    0,
};
