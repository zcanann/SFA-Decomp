#include "main/dll/CF/dll_012C_transporter.h"
#include "main/dll/CF/CFchuckobj.h"
#include "main/dll/CF/warp_pad.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"

extern undefined8 FUN_80006724();
extern undefined8 FUN_80006824();
extern undefined4 FUN_80041ff8();
extern undefined8 FUN_800427c8();
extern undefined8 FUN_80042800();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern int FUN_80044404();
extern undefined4 FUN_80053b3c();
extern undefined8 FUN_80053c98();
extern undefined8 FUN_8005d17c();
extern undefined4 FUN_80080f28();
extern undefined8 FUN_80080f3c();
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();

extern f32 FLOAT_803e4b30;

/*
 * --INFO--
 *
 * Function: Transporter_SeqFn
 * EN v1.0 Address: 0x80190BD4
 * EN v1.0 Size: 4684b
 * EN v1.1 Address: 0x80191150
 * EN v1.1 Size: 2252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Sfx_PlayFromObject(int* obj, int soundId);
extern void unlockLevel(int a, int b, int c);
extern void lockLevel(int dirIdx, int v);
extern int mapGetDirIdx(int mapId);
extern void loadMapAndParent(int mapId);
extern void setLoadedFileFlags_blocks1(void);
extern void clearLoadedFileFlags_blocks1(void);
extern void warpToMap(int warpId, int p2);
extern void getEnvfxActImmediately(int* a, int* b, int id, int p4);
extern void setDrawCloudsAndLights(int v);
extern void skyFn_80088c94(int a, int b);
extern void skyFn_80088e54(int mode, f32 brightness);
extern void timeOfDayFn_80055000(void);
extern f32 lbl_803E3E98;

int Transporter_SeqFn(int* obj, int p2, ObjAnimUpdateState* animUpdate)
{
    extern undefined8 GameBit_Set(int eventId, int value);
    int i;
    WarpPadPlacement* setup = (WarpPadPlacement*)((GameObject*)obj)->anim.placementData;
    WarpPadState* state = ((GameObject*)obj)->extra;
    int id;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 7:
            state->flags = state->flags | 4;
            Sfx_PlayFromObject(obj, 0x420);
            break;
        case 2:
            id = setup->destinationId;
            switch (id)
            {
            case 0x49c33:
                GameBit_Set(0x884, 1);
                (*gMapEventInterface)->setAnimEvent(7, 0, 1);
                (*gMapEventInterface)->setAnimEvent(7, 2, 1);
                (*gMapEventInterface)->setAnimEvent(7, 3, 1);
                (*gMapEventInterface)->setAnimEvent(7, 7, 1);
                (*gMapEventInterface)->setAnimEvent(7, 10, 1);
                (*gMapEventInterface)->setAnimEvent(10, 7, 0);
            /* fallthrough */
            case 0x48506:
            case 0x4977d:
                loadMapAndParent(7);
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(7), 1);
                break;
            case 0x43f83:
                loadMapAndParent(0x21);
                lockLevel(mapGetDirIdx(0x21), 1);
                break;
            case 0x4a533:
                loadMapAndParent(0x28);
                lockLevel(mapGetDirIdx(0x28), 1);
                break;
            case 0xc5d:
                unlockLevel(mapGetDirIdx(0x21), 1, 0);
                break;
            case 0x47064:
                loadMapAndParent(0x1c);
                lockLevel(mapGetDirIdx(0x1c), 1);
                lockLevel(mapGetDirIdx(0x1b), 0);
                break;
            case 0x4800c:
                loadMapAndParent(0x22);
                lockLevel(mapGetDirIdx(0xd), 0);
                lockLevel(mapGetDirIdx(0x22), 1);
                break;
            case 0x48018:
                unlockLevel(mapGetDirIdx(0x22), 1, 0);
                GameBit_Set(0x36a, 0);
                (*gMapEventInterface)->setAnimEvent(0xd, 0, 1);
                (*gMapEventInterface)->setAnimEvent(0xd, 1, 1);
                (*gMapEventInterface)->setAnimEvent(0xd, 5, 1);
                (*gMapEventInterface)->setAnimEvent(0xd, 10, 1);
                (*gMapEventInterface)->setAnimEvent(0xd, 0xb, 1);
                GameBit_Set(0xe05, 0);
                break;
            case 0x45dd6:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(4), 0);
                break;
            case 0x2ba7:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x12), 0);
                lockLevel(mapGetDirIdx(0x1f), 1);
                loadMapAndParent(0x1f);
                break;
            case 0x46a40:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0xe), 0);
                lockLevel(mapGetDirIdx(0x20), 1);
                loadMapAndParent(0x20);
                break;
            case 0x4b666:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(0x32), 0);
                lockLevel(mapGetDirIdx(0x15), 1);
                loadMapAndParent(0x15);
                break;
            case 0x497f4:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(10), 0);
                lockLevel(mapGetDirIdx(0x27), 1);
                loadMapAndParent(0x27);
                break;
            case 0x4cde6:
                unlockLevel(0, 0, 1);
                lockLevel(mapGetDirIdx(10), 0);
                break;
            }
            break;
        case 3:
            switch (setup->destinationId)
            {
            case 0x47064:
                unlockLevel(0, 0, 1);
                break;
            }
            break;
        case 5:
            switch (setup->destinationId)
            {
            case 0x47064:
                setLoadedFileFlags_blocks1();
                break;
            }
            break;
        case 6:
            switch (setup->destinationId)
            {
            case 0x47064:
                clearLoadedFileFlags_blocks1();
                break;
            }
            break;
        case 1:
            switch (setup->destinationId)
            {
            case 0x47064:
                clearLoadedFileFlags_blocks1();
                break;
            }
            warpToMap(setup->warpId, 0);
            break;
        case 8:
            id = setup->destinationId;
            switch (id)
            {
            case 0x43f83:
            case 0x4977d:
                getEnvfxActImmediately(obj, obj, 0x224, 0);
                getEnvfxActImmediately(obj, obj, 0x223, 0);
                getEnvfxActImmediately(obj, obj, 0x22e, 0);
                getEnvfxActImmediately(obj, obj, 0x218, 0);
                setDrawCloudsAndLights(0);
                skyFn_80088c94(1, 1);
                skyFn_80088e54(0, lbl_803E3E98);
                break;
            case 0x48506:
            case 0x4a533:
                getEnvfxActImmediately(obj, obj, 0x217, 0);
                getEnvfxActImmediately(obj, obj, 0x216, 0);
                getEnvfxActImmediately(obj, obj, 0x22e, 0);
                getEnvfxActImmediately(obj, obj, 0x218, 0);
                setDrawCloudsAndLights(1);
                getEnvfxActImmediately(obj, obj, 0x84, 0);
                getEnvfxActImmediately(obj, obj, 0x8a, 0);
                skyFn_80088c94(1, 0);
                skyFn_80088e54(0, lbl_803E3E98);
                break;
            case 0x4b666:
                getEnvfxActImmediately(obj, obj, 0x23a, 0);
                getEnvfxActImmediately(obj, obj, 0x23b, 0);
                break;
            case 0x4b667:
                getEnvfxActImmediately(obj, obj, 0x23a, 0);
                getEnvfxActImmediately(obj, obj, 0x23b, 0);
                (*gMapEventInterface)->setAnimEvent(0x15, 2, 1);
                getEnvfxActImmediately(0, 0, 0x23e, 0);
                skyFn_80088e54(1, lbl_803E3E98);
                break;
            case 0x4670d:
            case 0x4827e:
            case 0x49267:
                getEnvfxActImmediately(obj, obj, 0x247, 0);
                getEnvfxActImmediately(obj, obj, 0x248, 0);
                timeOfDayFn_80055000();
                GameBit_Set(0xef6, 1);
                break;
            case 0x4cb6a:
                getEnvfxActImmediately(obj, obj, 0x238, 0);
                getEnvfxActImmediately(obj, obj, 0x239, 0);
                skyFn_80088c94(1, 1);
                skyFn_80088e54(0, lbl_803E3E98);
            /* fallthrough */
            case 0x4cb84:
                GameBit_Set(0xef6, 0);
                break;
            }
            break;
        }
    }
    warpPadFn_8019042c((int)obj);
    return 0;
}

/*
 * --INFO--
 *
 * Function: transporter_getExtraSize
 * EN v1.0 Address: 0x801914A0
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80191640
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int transporter_getExtraSize(void)
{
    return 0x10;
}

extern void objRenderFn_80041018(int obj);
extern uint GameBit_Get(int eventId);
extern short lbl_803DCEB8;

/*
 * --INFO--
 *
 * Function: transporter_update
 * EN v1.0 Address: 0x80191658
 * EN v1.0 Size: 72b
 */
void transporter_update(int obj)
{
    register int self = obj;
    register WarpPadPlacement* setup = (WarpPadPlacement*)((GameObject*)self)->anim.placementData;
    if ((int)setup->warpId != -1)
    {
        warpPadPlayerStandingOn(self);
    }
    warpPadFn_8019042c(self);
}

/*
 * --INFO--
 *
 * Function: transporter_hitDetect
 * EN v1.0 Address: 0x801914AC
 * EN v1.0 Size: 428b
 */
void transporter_hitDetect(int obj)
{
    register int self = obj;
    register WarpPadPlacement* setup = (WarpPadPlacement*)((GameObject*)self)->anim.placementData;
    register WarpPadState* state = ((GameObject*)self)->extra;

    if ((int)lbl_803DCEB8 > -1)
    {
        *(u8*)&((GameObject*)self)->anim.resetHitboxMode = (u8)(
            (u32) * (u8*)&((GameObject*)self)->anim.resetHitboxMode & 0xffffffe7);
        state->flags = (u8)((u32)state->flags | 1);
        if (*(u32*)(self + 0x74) != 0)
        {
            objRenderFn_80041018(self);
        }
        return;
    }

    if ((int)setup->warpId != -1
        && (state->flags & 0x20) == 0)
    {
        if (state->triggerMode != 0 || state->countdownActive != 0)
        {
            *(u8*)&((GameObject*)self)->anim.resetHitboxMode = (u8)(
                (u32) * (u8*)&((GameObject*)self)->anim.resetHitboxMode | 0x8);
            state->flags = (u8)((u32)state->flags & ~1);
        }
        else if ((int)setup->enableGameBit != -1
            && GameBit_Get((int)setup->enableGameBit) == 0)
        {
            *(u8*)&((GameObject*)self)->anim.resetHitboxMode = (u8)(
                (u32) * (u8*)&((GameObject*)self)->anim.resetHitboxMode & 0xfffffff7);
            *(u8*)&((GameObject*)self)->anim.resetHitboxMode = (u8)(
                (u32) * (u8*)&((GameObject*)self)->anim.resetHitboxMode | 0x10);
            state->flags = (u8)((u32)state->flags & ~1);
        }
        else
        {
            *(u8*)&((GameObject*)self)->anim.resetHitboxMode = (u8)(
                (u32) * (u8*)&((GameObject*)self)->anim.resetHitboxMode & 0xffffffe7);
            state->flags = (u8)((u32)state->flags | 1);
        }
        if (*(u32*)(self + 0x74) != 0)
        {
            objRenderFn_80041018(self);
        }
        return;
    }

    /* Branch C */
    if ((state->flags & 0x40) != 0)
    {
        *(u8*)&((GameObject*)self)->anim.resetHitboxMode = (u8)(
            (u32) * (u8*)&((GameObject*)self)->anim.resetHitboxMode | 0x8);
    }
    else
    {
        *(u8*)&((GameObject*)self)->anim.resetHitboxMode = (u8)(
            (u32) * (u8*)&((GameObject*)self)->anim.resetHitboxMode & 0xfffffff7);
        *(u8*)&((GameObject*)self)->anim.resetHitboxMode = (u8)(
            (u32) * (u8*)&((GameObject*)self)->anim.resetHitboxMode | 0x10);
    }
    state->flags = (u8)((u32)state->flags & ~1);
}

/*
 * --INFO--
 *
 * Function: transporter_render
 * EN v1.0 Address: 0x801914A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80191648
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void transporter_render(void)
{
}

/* === moved from main/dll/mmp_asteroid_re.c [801916A0-80191A70) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/CF/dll_012C_transporter.h"
#include "main/dll/CF/warp_pad.h"
#include "main/game_object.h"

typedef struct CfDoorlightObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    s16 frameStep;
    u8 pad1E[0x20 - 0x1E];
} CfDoorlightObjectDef;


extern undefined4 FUN_800400b0();
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                  int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                  f32 scaleZ, void* args, int arg9);
extern void* objFindTexture(void* obj, int target, int param_3);

extern undefined4 DAT_803ddb38;

typedef struct CfDoorLightState
{
    s32 textureId;
    u8 frameStep;
    u8 pad05[0x8 - 0x5];
    s32 maxFrame;
    s32 resetFrame;
    s32 currentFrame;
    u8 flags;
    u8 pad15[0x18 - 0x15];
} CfDoorLightState;

typedef struct CfDoorLightDef
{
    u8 pad00[0x1e];
    s16 doneEvent;
    s16 triggerEvent;
} CfDoorLightDef;

typedef struct BarrelPadParticleArgs
{
    u8 pad00[0xc];
    f32 offset[3];
} BarrelPadParticleArgs;

/*
 * --INFO--
 *
 * Function: transporter_init
 * EN v1.0 Address: 0x801916A0
 * EN v1.0 Size: 976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 *
 * Recovered: large switch on params[20] (32-bit id) that sets bits in
 * state->flags per map/area id. Six GameBit-guarded cases set bit 0x20 only
 * when any of 3 listed event bits is set; the rest set 0x68, 0x08, 0x30, or
 * 0x10 directly. Tail: if state->flags & 0x40 (which 0x68 includes), set
 * obj->_af |= 8 (redundant with the unconditional prologue store).
 */
void transporter_init(int obj, u8* params)
{
    WarpPadPlacement* placement;
    WarpPadState* state;
    int id;

    placement = (WarpPadPlacement*)params;
    state = ((GameObject*)obj)->extra;
    state->activateDelay = 400;
    state->flags = 0;
    ((GameObject*)obj)->anim.rotX = (s16)((u16)(placement->rotXHigh << 8));
    ((GameObject*)obj)->unkF4 = 0;
    ((GameObject*)obj)->animEventCallback = (void*)Transporter_SeqFn;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);

    id = placement->destinationId;
    switch (id)
    {
    case 0x4670D:
    case 0x4827E:
    case 0x49267:
    case 0x4CB6A:
    case 0x4CB84:
        state->flags = (u8)(state->flags | 0x68);
        break;
    case 0x48506:
    case 0x45753:
    case 0x463C0:
    case 0x45DD6:
    case 0x4977D:
    case 0x49C33:
    case 0x4B666:
    case 0x4B667:
        state->flags = (u8)(state->flags | 0x08);
        break;
    case 0x4C986:
        state->flags = (u8)(state->flags | 0x30);
        break;
    case 0x47064:
        state->flags = (u8)(state->flags | 0x10);
        break;
    case 0x43F83:
        if (GameBit_Get(2984) != 0 || GameBit_Get(790) != 0 || GameBit_Get(1297) != 0)
        {
            state->flags = (u8)(state->flags | 0x20);
        }
        break;
    case 0x2BA7:
        if (GameBit_Get(3069) != 0 || GameBit_Get(666) != 0 || GameBit_Get(667) != 0)
        {
            state->flags = (u8)(state->flags | 0x20);
        }
        break;
    case 0x46A40:
        if (GameBit_Get(255) != 0 || GameBit_Get(2208) != 0 || GameBit_Get(2210) != 0)
        {
            state->flags = (u8)(state->flags | 0x20);
        }
        break;
    case 0x497F4:
        if (GameBit_Get(3182) != 0 || GameBit_Get(3184) != 0 || GameBit_Get(3185) != 0)
        {
            state->flags = (u8)(state->flags | 0x20);
        }
        break;
    case 0x4800C:
        if (GameBit_Get(3205) != 0 || GameBit_Get(3253) != 0 || GameBit_Get(3254) != 0)
        {
            state->flags = (u8)(state->flags | 0x20);
        }
        break;
    case 0x4A533:
        if (GameBit_Get(372) != 0 || GameBit_Get(3255) != 0 || GameBit_Get(3256) != 0)
        {
            state->flags = (u8)(state->flags | 0x20);
        }
        break;
    }

    if ((state->flags & 0x40) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | 8);
    }
}

/*
 * --INFO--
 *
 * Function: FUN_801916e8
 * EN v1.0 Address: 0x801916E8
 * EN v1.0 Size: 72b
 * EN v1.1 Address: 0x80191BD4
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_80191730
 * EN v1.0 Address: 0x80191730
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80191C1C
 * EN v1.1 Size: 976b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/* Trivial 4b 0-arg blr leaves. */














/* 8b "li r3, N; blr" returners. */

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3EE8;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E3F00;
extern f32 lbl_803E3F04;
extern f32 lbl_803E3F08;
extern f32 lbl_803E3F0C;
extern f32 lbl_803E3F10;
extern f32 lbl_803E3F14;
extern f32 lbl_803E3F18;
extern f32 lbl_803E3F1C;
extern f32 lbl_803E3F20;
extern f32 lbl_803E3F24;



extern f32 lbl_803E3EEC;
extern f32 lbl_803E3EF0;



