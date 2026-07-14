/* DLL 0x011D - treasurechest (treasure chest interactive object). TU: 0x8018A8BC-0x8018ADB4. */
#include "main/dll/dll_011D_treasurechest.h"
#include "main/shader_api.h"
#include "main/dll/staffflags_struct.h"
#include "main/game_ui_interface.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#define OBJFX_HIT_DETECT_SCALE_FIRST_LEGACY
#include "main/objfx.h"
#include "main/objhits.h"
#include "main/resource.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/obj_group.h"
#include "main/dll/VF/vf_shared.h"

typedef struct ChestHitParams
{
    u32 a;
    u32 b;
    u32 c;
    u32 d;
} ChestHitParams;

typedef struct ChestFlags
{
    u8 open : 1;
    u8 trigger : 1;
} ChestFlags;

typedef struct ChestHitBlock
{
    ChestHitParams params;
    u16 a;
    u16 b;
    u16 c;
    f32 scale;
    f32 x;
    f32 y;
    f32 z[1];
} ChestHitBlock;

STATIC_ASSERT(sizeof(TreasureChestSetup) == 0x24);
STATIC_ASSERT(offsetof(TreasureChestSetup, type) == 0x18);
STATIC_ASSERT(offsetof(TreasureChestSetup, hitboxKind) == 0x19);
STATIC_ASSERT(offsetof(TreasureChestSetup, triggerObjectId) == 0x1a);
STATIC_ASSERT(offsetof(TreasureChestSetup, dialogueId) == 0x1c);
STATIC_ASSERT(offsetof(TreasureChestSetup, openGameBit) == 0x1e);

#define TREASURECHEST_TARGET_OBJGROUP 4

/* anim-sequence event opcodes consumed by TreasureChest_SeqFn */
#define TREASURECHEST_SEQEV_DIALOGUE     1 /* show setup dialogue */
#define TREASURECHEST_SEQEV_STAFFBIT_SET 2 /* set StaffFlags b5 */
#define TREASURECHEST_SEQEV_STAFFBIT_CLR 3 /* clear StaffFlags b5 */
#define TREASURECHEST_SEQEV_OPENED       4 /* hide + disable the chest */

extern f32 lbl_803E3C20;
extern void* lbl_803DDAE0;
extern f32 lbl_803E3C24;
__declspec(section ".rodata") ChestHitParams lbl_802C22B0 = {8, 0xFF, 0xFF, 0x78};
extern int lbl_803DDAE4;
extern f32 lbl_803E3C28;
extern f32 lbl_803E3C2C;

extern void playerPullOutStaff(GameObject* obj, int enabled);

int TreasureChest_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    GameObject* o = (GameObject*)obj;
    int i;
    TreasureChestSetup* setup;
    u8* state;
    u8 eventId;

    setup = (TreasureChestSetup*)o->anim.placementData;
    state = o->extra;
    i = 0;
    while (i < animUpdate->eventCount)
    {
        eventId = animUpdate->eventIds[i];
        switch (eventId)
        {
        case TREASURECHEST_SEQEV_DIALOGUE:
            if (setup->dialogueId != 0)
            {
                (*gGameUIInterface)->showNpcDialogue(setup->dialogueId, 0xc8, 0x8c, 0);
            }
            break;
        case TREASURECHEST_SEQEV_STAFFBIT_SET:
            ((StaffFlags*)state)->b5 = 1;
            break;
        case TREASURECHEST_SEQEV_STAFFBIT_CLR:
            ((StaffFlags*)state)->b5 = 0;
            break;
        case TREASURECHEST_SEQEV_OPENED:
            o->anim.flags = o->anim.flags | OBJANIM_FLAG_HIDDEN;
            ObjHits_DisableObject((u32)o);
            break;
        }
        i++;
    }
    return 0;
}

int TreasureChest_getExtraSize(void)
{
    return 1;
}

int TreasureChest_getObjectTypeId(void)
{
    return 0;
}

void TreasureChest_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E3C20);
}

void TreasureChest_free(void)
{
    Resource_Release(lbl_803DDAE0);
}

void TreasureChest_hitDetect(GameObject* obj)
{
    u8* state;
    TreasureChestSetup* setup;

    setup = (TreasureChestSetup*)((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;
    if (((u32)state[0] >> 5 & 1) != 0)
    {
        hitDetectFn_80097070(lbl_803E3C24, (int)obj, 2, (u8)(setup->hitboxKind + 6), 4, 0);
    }
}

void TreasureChest_update(GameObject* obj)
{

    ChestFlags* flags;
    TreasureChestSetup* setup;
    u32 nearestObject;
    int hitResult;
    ChestHitBlock blk;
    float nearestDist;
    u32 hitVolume;
    int hitPriority;
    int hitObject;

    flags = ((GameObject*)obj)->extra;
    setup = (TreasureChestSetup*)((GameObject*)obj)->anim.placementData;
    nearestDist = lbl_803E3C28;
    if (flags->trigger != 0 && flags->open != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED;
        ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E3C2C, 0);
    }
    if (flags->open == 0)
    {
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED;
            playerPullOutStaff((GameObject*)(Obj_GetPlayerObject()), 1);
            nearestObject = ObjGroup_FindNearestObject(TREASURECHEST_TARGET_OBJGROUP, (int)obj, &nearestDist);
            if (nearestObject != 0)
            {
                (*gObjectTriggerInterface)->setObjects((int)((GameObject*)nearestObject)->anim.seqId, 0, 0);
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, 0xffffffff);
            }
            else
            {
                (*gObjectTriggerInterface)->setObjects(setup->triggerObjectId, 0, 0);
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, 0xffffffff);
            }
            mainSetBits(setup->openGameBit, 1);
            flags->open = 1;
            ObjHits_DisableObject((u32)obj);
        }
        flags->trigger = 0;
        blk.params = lbl_802C22B0;
        hitPriority = 0xffffffff;
        hitResult = ObjHits_GetPriorityHitWithPosition((GameObject*)obj, &hitObject, &hitPriority, &hitVolume, &blk.x,
                                                       &blk.y, blk.z);
        if ((hitResult != 0) && (hitResult != 0xe))
        {
            blk.x = blk.x + playerMapOffsetX;
            blk.z[0] = blk.z[0] + playerMapOffsetZ;
            blk.scale = lbl_803E3C20;
            blk.c = 0;
            blk.b = 0;
            blk.a = 0;
            if (lbl_803DDAE4 == 0)
            {
                (*(void (**)(int, int, u16*, int, int, ChestHitParams*))(*(int*)lbl_803DDAE0 + 4))(
                    0, 1, (u16*)((int)&blk + 16), 0x401, 0xffffffff, &blk.params);
                lbl_803DDAE4 = 0x3c;
            }
        }
        if (lbl_803DDAE4 != 0)
        {
            lbl_803DDAE4 = lbl_803DDAE4 + -1;
        }
    }
    return;
}

void TreasureChest_release(void)
{
}

void TreasureChest_initialise(void)
{
}

void TreasureChest_init(int* obj)
{
    register ChestFlags* state = ((GameObject*)obj)->extra;
    register TreasureChestSetup* cfg = (TreasureChestSetup*)((GameObject*)obj)->anim.placementData;

    ((GameObject*)obj)->animEventCallback = TreasureChest_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)cfg->type << 8);

    if (cfg->openGameBit != -1)
    {
        state->open = mainGetBit(cfg->openGameBit);
    }
    else
    {
        state->open = 0;
    }
    if (state->open != 0)
    {
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ObjHits_DisableObject((u32)obj);
    }
    lbl_803DDAE0 = Resource_Acquire(90, 1);
    state->trigger = 1;
}

ObjectDescriptor gTreasureChestObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)TreasureChest_initialise,
    (ObjectDescriptorCallback)TreasureChest_release,
    0,
    (ObjectDescriptorCallback)TreasureChest_init,
    (ObjectDescriptorCallback)TreasureChest_update,
    (ObjectDescriptorCallback)TreasureChest_hitDetect,
    (ObjectDescriptorCallback)TreasureChest_render,
    (ObjectDescriptorCallback)TreasureChest_free,
    (ObjectDescriptorCallback)TreasureChest_getObjectTypeId,
    TreasureChest_getExtraSize,
};
