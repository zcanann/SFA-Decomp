/*
 * gflevelcon (DLL 0x2BB) - "GalleonForce" level controller object.
 *
 * Its anim-event callback (gf_levelcon_handleScriptEvents) reacts to
 * sequence event opcodes that drive the sky/weather presets (skyFn_*
 * + getEnvfxAct), warp/credits flow at the end of the level, and a
 * countdown-driven on-screen text prompt (gameTextShow 0x476). It also
 * finds the level's linked point-light and scroll objects (by their
 * placement def ids 0x477E3 / 0x4A946 / 0x4A947) and toggles / scrolls
 * them per frame.
 *
 * The fn_8023* helpers (referenced from dll_02BC_andross.c) spawn and
 * aim the Arwing projectile/effect objects used during the boss fight,
 * and fn_8023A3E4 is the hit-reaction handler (three breakable hit
 * zones + texture-state swaps).
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/audio/sfx_trigger_ids.h"

/* sequence event opcodes consumed by gf_levelcon_handleScriptEvents */
#define GFLEVELCON_SEQEV_NONE 0
#define GFLEVELCON_SEQEV_SKY_PRESET_A 1
#define GFLEVELCON_SEQEV_SKY_PRESET_B 2
#define GFLEVELCON_SEQEV_LIGHT_ON 3
#define GFLEVELCON_SEQEV_LIGHT_OFF 4
#define GFLEVELCON_SEQEV_SKY_PRESET_C 5
#define GFLEVELCON_SEQEV_LOAD_MAP 6
#define GFLEVELCON_SEQEV_UNLOCK_LEVELS 7
#define GFLEVELCON_SEQEV_START_PROMPT 8
#define GFLEVELCON_SEQEV_CREDITS 9
#define GFLEVELCON_SEQEV_SKY_PRESET_D 10
#define GFLEVELCON_SEQEV_SKY_PRESET_E 11

/* placement def ids of the linked objects gf_levelcon_findLinkedObjects
   caches into its state (point light + two scrolling textures) */
#define GFLEVELCON_LINK_LIGHT 0x477E3
#define GFLEVELCON_LINK_SCROLL_A 0x4A946
#define GFLEVELCON_LINK_SCROLL_B 0x4A947

/* The next two typedefs are two views over the SAME 0x10-byte obj->extra
   allocation (gf_levelcon_getExtraSize returns 0x10). findLinkedObjects
   caches the three linked object handles as s32 ids (light, scrollA,
   scrollB); handleScriptEvents reads scrollA/scrollB back as
   s16* scroll-offset pointers and promptTimer as the prompt countdown. The split
   into two casts (with differing field types at scrollA/scrollB) is
   matching-required: collapsing to one struct changes the cast keys and
   the codegen. */
/* Spawn-setup buffer for the arwing-projectile children (defNos
 * 0x80d/0x7e4/0x859). Reuses ObjPlacement's pos/color head and adds the
 * class-specific launch fields at 0x18/0x19/0x1a (all u8 stores per asm). */
typedef struct GfProjectileSetup
{
    ObjPlacement head; /* 0x00 */
    u8 roll;        /* 0x18: cleared to 0 */
    u8 pitch;          /* 0x19 */
    u8 yawHi;          /* 0x1a */
} GfProjectileSetup;

typedef struct GfLevelconFindLinkedObjectsState
{
    s32 light;
    s32 scrollA;
    s32 scrollB;
    u8 padC[0x10 - 0xC];
} GfLevelconFindLinkedObjectsState;

typedef struct GfLevelconHandleScriptEventsState
{
    s32 light;
    void* scrollA;
    void* scrollB;
    f32 promptTimer;
} GfLevelconHandleScriptEventsState;

typedef struct GfHitState
{
    u8 pad0[0x88];
    int mode;
    u8 pad1[0x16];
    s16 pitchVel;
    s16 rollVel;
    u8 pad2[8];
    u8 hits[4];
    u8 timer[4];
    u8 pad3[3];
    u8 texState[3];
} GfHitState;

STATIC_ASSERT(offsetof(GfHitState, mode) == 0x88);
STATIC_ASSERT(offsetof(GfHitState, pitchVel) == 0xA2);
STATIC_ASSERT(offsetof(GfHitState, hits[0]) == 0xAE);
STATIC_ASSERT(offsetof(GfHitState, timer[0]) == 0xB2);
STATIC_ASSERT(offsetof(GfHitState, texState[0]) == 0xB9);

int gf_levelcon_handleScriptEvents(int obj, int eventId, ObjAnimUpdateState* animUpdate)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    int i;

    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case GFLEVELCON_SEQEV_NONE:
            break;
        case GFLEVELCON_SEQEV_SKY_PRESET_A:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, 0x96, 0xc8, 0xf0, 0, 0);
            skyFn_800894a8(7, lbl_803E7460, lbl_803E7464, lbl_803E7468);
            getEnvfxAct(obj, obj, 0x21f, 0);
            break;
        case GFLEVELCON_SEQEV_START_PROMPT:
            ((GfLevelconHandleScriptEventsState*)state)->promptTimer = lbl_803E746C;
            break;
        case GFLEVELCON_SEQEV_SKY_PRESET_B:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, lbl_803E7470, lbl_803E7474, lbl_803E7478, 0, 0);
            skyFn_800894a8(7, lbl_803E7464, lbl_803E747C, *(f32*)&lbl_803E7464);
            getEnvfxAct(obj, obj, 0x21d, 0);
            break;
        case GFLEVELCON_SEQEV_LIGHT_ON:
            gf_levelcon_findLinkedObjects(obj);
            if (*(void**)state != NULL)
            {
                pointlight_setEffectState(*(int*)state, 1);
            }
            break;
        case GFLEVELCON_SEQEV_LIGHT_OFF:
            gf_levelcon_findLinkedObjects(obj);
            if (*(void**)state != NULL)
            {
                pointlight_setEffectState(*(int*)state, 0);
            }
            break;
        case GFLEVELCON_SEQEV_SKY_PRESET_C:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, 0x96, 0xc8, 0xf0, 0, 0);
            skyFn_800894a8(7, lbl_803E7480, lbl_803E747C, lbl_803E7464);
            getEnvfxAct(obj, obj, 0x21e, 0);
            break;
        case GFLEVELCON_SEQEV_LOAD_MAP:
            loadMapAndParent(0x29);
            break;
        case GFLEVELCON_SEQEV_UNLOCK_LEVELS:
            unlockLevel(0, 0, 1);
            unlockLevel(0, 1, 1);
            mapUnload(mapGetDirIdx(0xb), 0x20000000);
            break;
        case GFLEVELCON_SEQEV_CREDITS:
            unlockLevel(0, 0, 1);
            loadUiDll(4);
            warpToMap(0x12, 0);
            creditsStart();
            break;
        case GFLEVELCON_SEQEV_SKY_PRESET_D:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, 0x96, 0xc8, 0xf0, 0, 0);
            skyFn_800894a8(7, lbl_803E7484, lbl_803E747C, lbl_803E7464);
            getEnvfxAct(obj, obj, 0x21f, 0);
            break;
        case GFLEVELCON_SEQEV_SKY_PRESET_E:
            skyFn_80089710(7, 1, 0);
            skyFn_800895e0(7, lbl_803E7470, lbl_803E7474, lbl_803E7478, 0, 0);
            skyFn_800894a8(7, lbl_803E7484, lbl_803E747C, lbl_803E7464);
            getEnvfxAct(obj, obj, 0x21d, 0);
            break;
        }
    }

    if (((GfLevelconHandleScriptEventsState*)state)->promptTimer > lbl_803E7488)
    {
        gameTextShow(0x476);
        ((GfLevelconHandleScriptEventsState*)state)->promptTimer -= timeDelta;
        if (((GfLevelconHandleScriptEventsState*)state)->promptTimer < *(f32*)&lbl_803E7488)
        {
            ((GfLevelconHandleScriptEventsState*)state)->promptTimer = lbl_803E7488;
        }
    }

    {
        s16* p = *(s16**)&((GfLevelconHandleScriptEventsState*)state)->scrollA;
        if (p != NULL)
        {
            *p += (s16)(lbl_803E748C * timeDelta);
        }
    }
    {
        s16* p = *(s16**)&((GfLevelconHandleScriptEventsState*)state)->scrollB;
        if (p != NULL)
        {
            *p -= (s16)(lbl_803E748C * timeDelta);
        }
    }
    return 0;
}

int gf_levelcon_getExtraSize(void) { return 0x10; }

int gf_levelcon_getObjectTypeId(void) { return 0; }

void gf_levelcon_hitDetect(void)
{
}

void gf_levelcon_initialise(void)
{
}

void gf_levelcon_release(void)
{
}

void gf_levelcon_free(void)
{
    setIsOvercast(1);
}

void gf_levelcon_update(int obj)
{
    ((GameObject*)obj)->animEventCallback = gf_levelcon_handleScriptEvents;
}

void gf_levelcon_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E7480);
    }
}

void gf_levelcon_init(int obj)
{
    setIsOvercast(0);
    (*gScreenTransitionInterface)->step(0x258, 1);
}

void gf_levelcon_findLinkedObjects(int obj)
{
    int state = *(int*)&((GameObject*)obj)->extra;
    int* objects;
    int objectIndex;
    int objectCount;
    int o;

    ((GfLevelconFindLinkedObjectsState*)state)->light = 0;
    ((GfLevelconFindLinkedObjectsState*)state)->scrollA = 0;
    ((GfLevelconFindLinkedObjectsState*)state)->scrollB = 0;
    objects = ObjList_GetObjects(&objectIndex, &objectCount);
    for (; objectIndex < objectCount; objectIndex++)
    {
        o = objects[objectIndex];
        if ((u32)o != obj && *(void**)(o + 0x4c) != NULL)
        {
            switch (*(int*)(*(int*)(o + 0x4c) + 0x14))
            {
            case GFLEVELCON_LINK_LIGHT:
                ((GfLevelconFindLinkedObjectsState*)state)->light = o;
                break;
            case GFLEVELCON_LINK_SCROLL_A:
                ((GfLevelconFindLinkedObjectsState*)state)->scrollA = o;
                break;
            case GFLEVELCON_LINK_SCROLL_B:
                ((GfLevelconFindLinkedObjectsState*)state)->scrollB = o;
                break;
            }
        }
    }
}

void fn_80239DD8(int obj, int state)
{
    f32 maxDist;
    char* nearObj;
    int newObj;

    maxDist = lbl_803E7490;
    if (Obj_IsLoadingLocked())
    {
        nearObj = (char*)ObjList_FindNearestObjectByDefNo(obj, 0x7e5, &maxDist);
        if (nearObj != NULL)
        {
            newObj = Obj_AllocObjectSetup(0x24, 0x608);
            ((ObjPlacement*)newObj)->posX = ((GameObject*)nearObj)->anim.localPosX;
            ((ObjPlacement*)newObj)->posY = ((GameObject*)nearObj)->anim.localPosY;
            ((ObjPlacement*)newObj)->posZ = ((GameObject*)nearObj)->anim.localPosZ;
            ((ObjPlacement*)newObj)->color[0] = 1;
            ((ObjPlacement*)newObj)->color[1] = 1;
            *(int*)(state + 0x10) = ((int (*)(int, int))loadObjectAtObject)(obj, newObj);
            if (*(void**)(state + 0x10) != NULL)
            {
                ((GameObject*)*(int*)(state + 0x10))->anim.alpha = 0xff;
                *(u8*)(*(int*)(state + 0x10) + 0x37) = 0xff;
                *(int*)(state + 0x90) = 0x12c;
            }
        }
    }
}

void fn_80239EAC(int obj, int state)
{
    f32 dx, dy, dz;
    int* objs;
    int cur;
    int i;
    int count;
    int defNo;

    {
        int* t = ObjGroup_GetObjects(2, &count);
        for (i = 0, objs = t; i < count; i++)
        {
            cur = *objs;
            defNo = *(s16*)(*(int*)&((GameObject*)cur)->anim.placementData);
            if (defNo == 0x80d || defNo == 0x859)
            {
                dy = *(f32*)(state + 0xc4) - ((GameObject*)cur)->anim.localPosY;
                dz = *(f32*)(state + 0xc8) - ((GameObject*)cur)->anim.localPosZ;
                dx = *(f32*)(state + 0xc0) - ((GameObject*)cur)->anim.localPosX;
                ((GameObject*)cur)->anim.rotX = getAngle(dx, dz);
                ((GameObject*)cur)->anim.rotY = -(s16)getAngle(dy, dz);
                arwprojectile_placeForward(cur, (f32)(int)lbl_803DC4E8);
            }
            objs++;
        }
    }
}

void fn_8023A168(int obj, int state)
{
    int proj;
    int yawRnd;
    int pitchRnd;
    int newObj;

    if (Obj_IsLoadingLocked())
    {
        yawRnd = (s16)(randomGetRange(-0x1f40, 0x1f40) - 0x8000);
        pitchRnd = randomGetRange(-0x1f40, 0x1f40) >> 8;
        newObj = Obj_AllocObjectSetup(0x20, 0x80d);
        ((ObjPlacement*)newObj)->posX = *(f32*)(state + 0xc0);
        ((ObjPlacement*)newObj)->posY = *(f32*)(state + 0xc4);
        ((ObjPlacement*)newObj)->posZ = *(f32*)(state + 0xc8);
        ((GfProjectileSetup*)newObj)->yawHi = (*(s16*)obj + yawRnd) >> 8;
        ((GfProjectileSetup*)newObj)->pitch = pitchRnd;
        ((GfProjectileSetup*)newObj)->roll = 0;
        ((ObjPlacement*)newObj)->color[0] = 1;
        ((ObjPlacement*)newObj)->color[1] = 1;
        proj = ((int (*)(int, int))loadObjectAtObject)(obj, newObj);
        if ((void*)proj != NULL)
        {
            ((GameObject*)proj)->anim.rootMotionScale = lbl_803E74B0;
            arwprojectile_setLifetime(proj, 0x6e);
            arwprojectile_placeForward(proj, lbl_803E74AC);
        }
    }
}

void fn_8023A268(int obj, int state, int p3)
{
    f32 dx, dz, dist;
    int yaw;
    int newObj;

    if (Obj_IsLoadingLocked())
    {
        dx = *(f32*)(state + 0xc0) - *(f32*)(*(int*)state + 0xc);
        dz = *(f32*)(state + 0xc8) - *(f32*)(*(int*)state + 0x14);
        dist = sqrtf(dx * dx + dz * dz);
        yaw = (u16)getAngle(dx, dz);
        gGfLevelConProjectilePitch = (u16)getAngle(*(f32*)(state + 0xc4) - *(f32*)(*(int*)state + 0x10), dist) >> 8;
        newObj = Obj_AllocObjectSetup(0x20, 0x7e4);
        ((ObjPlacement*)newObj)->posX = *(f32*)(state + 0xc0);
        ((ObjPlacement*)newObj)->posY = *(f32*)(state + 0xc4);
        ((ObjPlacement*)newObj)->posZ = *(f32*)(state + 0xc8);
        ((GfProjectileSetup*)newObj)->yawHi = (*(s16*)obj + yaw) >> 8;
        ((GfProjectileSetup*)newObj)->pitch = gGfLevelConProjectilePitch;
        ((GfProjectileSetup*)newObj)->roll = 0;
        ((ObjPlacement*)newObj)->color[0] = 1;
        ((ObjPlacement*)newObj)->color[1] = 1;
        obj = ((int (*)(int, int))loadObjectAtObject)(obj, newObj);
        if ((void*)obj != NULL)
        {
            arwprojectile_setLifetime(obj, lbl_803DC4DC);
            arwprojectile_placeForward(obj, (f32)(int)lbl_803DC4D8);
        }
    }
}

void fn_80239FCC(int obj, int state)
{
    f32 ang;
    int rndDur;
    int newObj;
    int proj;
    int yaw;
    s16 rndYaw;

    if (Obj_IsLoadingLocked())
    {
        yaw = gGfLevelConProjectileYaw;
        lbl_803DDDC0 = lbl_803DDDC6;
        rndYaw = randomGetRange(-0x8000, 0x7fff);
        rndDur = randomGetRange(0x64, 0x12c);
        newObj = Obj_AllocObjectSetup(0x20, 0x859);
        ang = lbl_803E74A0 * (f32)(int)rndYaw / lbl_803E74A4;
        ((ObjPlacement*)newObj)->posX = (f32)(int)rndDur * mathSinf(ang) + *(f32*)(*(int*)state + 0xc);
        ((ObjPlacement*)newObj)->posY = (f32)(int)rndDur * mathCosf(ang) + *(f32*)(*(int*)state + 0x10);
        ((ObjPlacement*)newObj)->posZ = *(f32*)(state + 0xc8) - lbl_803E74A8;
        ((GfProjectileSetup*)newObj)->yawHi = (*(s16*)obj + yaw) >> 8;
        ((GfProjectileSetup*)newObj)->pitch = lbl_803DDDC0;
        ((GfProjectileSetup*)newObj)->roll = 0;
        ((ObjPlacement*)newObj)->color[0] = 1;
        ((ObjPlacement*)newObj)->color[1] = 1;
        proj = ((int (*)(int, int))loadObjectAtObject)(obj, newObj);
        if ((u32)proj != 0)
        {
            ((GameObject*)proj)->anim.rootMotionScale = lbl_803DC4E4;
            arwprojectile_setLifetime(proj, lbl_803DC4E0);
            arwprojectile_placeForward(proj, lbl_803E74AC);
        }
    }
}

#pragma optimization_level 1
void fn_8023A3E4(int objArg, int hitState)
{
    u8 i;
    u32 hitVol;
    int hitType;
    int hitObj;
    int got;
    u8* s;
    int obj;
    u8 adjusted;
    int texIdx;
    u8 state;
    ObjTextureRuntimeSlot* tex;

    obj = objArg;
    s = (u8*)hitState;
    got = ObjHits_GetPriorityHit(objArg, &hitObj, &hitType, &hitVol);
    {
        u8 j;
        int off;
        for (j = 0; j < 4; j++)
        {
            int v = s[off = j + 178] - framesThisStep;
            if (v < 0)
                v = 0;
            s[off] = v;
        }
    }
    if (got != 0)
    {
        int ht = hitType;
        switch (ht)
        {
        case 0:
        case 1:
        case 2:
        {
            u8* hp = s + ht;
            if (hp[0xAE] != 0 && hp[0xB2] == 0)
            {
                hp[0xAE] -= 1;
                (s + hitType)[0xB2] = 6;
                if ((s + hitType)[0xAE] != 0)
                    Sfx_PlayFromObject(obj, SFXTRIG_wmap_nameoff);
                else
                    Sfx_PlayFromObject(obj, SFXTRIG_en_barrelblow11);
                switch (hitType)
                {
                case 0:
                    ((GfHitState*)s)->pitchVel = -0xfa;
                    break;
                case 1:
                    ((GfHitState*)s)->pitchVel = 0xfa;
                    break;
                case 2:
                    ((GfHitState*)s)->rollVel = -0xc8;
                    break;
                }
            }
            break;
        }
        case 3:
        {
            if (((GameObject*)hitObj)->anim.seqId == 0x605)
            {
                u8* hp = s + ht;
                if (hp[0xB2] == 0 && hp[0xAE] != 0 && ((GfHitState*)s)->mode == 0xc)
                {
                    Obj_SetModelColorFadeRecursive(obj, 0x19, 0xc8, 0, 0, 1);
                    (s + hitType)[0xAE] -= 1;
                    (s + hitType)[0xB2] = 0xc8;
                }
            }
            break;
        }
        }
    }
    for (i = 0; i < 3; i++)
    {
        int idx = i;
        u8* p = s + idx;
        if (p[0xAE] != 0)
        {
            if (p[0xB2] != 0)
                p[0xB9] = 1;
            else
                p[0xB9] = 0;
        }
        else
        {
            p[0xB9] = 2;
        }
        state = p[0xB9];
        adjusted = state;
        texIdx = (&lbl_803DC4C8)[idx];
        if ((u32)texIdx < 2 && state == 1)
            adjusted = 0;
        tex = objFindTexture((void *)obj, texIdx * 2, 0);
        tex->textureId = adjusted << 8;
        if ((u32)texIdx == 2 && state == 1)
            state = 0;
        tex = objFindTexture((void *)obj, texIdx * 2 + 1, 0);
        tex->textureId = state << 8;
    }
}
