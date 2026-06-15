#include "main/dll/CF/CFchuckobj.h"
#include "main/dll/CF/warp_pad.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/mapEventTypes.h"

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

extern void objRenderFn_80041018(int obj);
extern short lbl_803DCEB8;

int Transporter_SeqFn(int* obj, int p2, ObjAnimUpdateState* animUpdate)
{
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
            Sfx_PlayFromObject((u32)obj, 0x420);
            break;
        case 2:
            id = setup->destinationId;
            switch (id)
            {
            case 0x49c33:
                GameBit_Set(0x884, 1);
                (*gMapEventInterface)->setObjGroupStatus(7, 0, 1);
                (*gMapEventInterface)->setObjGroupStatus(7, 2, 1);
                (*gMapEventInterface)->setObjGroupStatus(7, 3, 1);
                (*gMapEventInterface)->setObjGroupStatus(7, 7, 1);
                (*gMapEventInterface)->setObjGroupStatus(7, 10, 1);
                (*gMapEventInterface)->setObjGroupStatus(10, 7, 0);
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
                (*gMapEventInterface)->setObjGroupStatus(0xd, 0, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 1, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 5, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 10, 1);
                (*gMapEventInterface)->setObjGroupStatus(0xd, 0xb, 1);
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
                (*gMapEventInterface)->setObjGroupStatus(0x15, 2, 1);
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

int transporter_getExtraSize(void)
{
    return 0x10;
}

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
        if (((GameObject*)self)->anim.hitVolumeTransforms != NULL)
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
        if (((GameObject*)self)->anim.hitVolumeTransforms != NULL)
        {
            objRenderFn_80041018(self);
        }
        return;
    }

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

void transporter_render(void)
{
}

/*
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
