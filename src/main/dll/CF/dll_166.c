#include "main/dll/CF/dll_166.h"
#include "main/dll/CF/dll_165.h"
#include "main/game_object.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/objseq.h"
#include "main/resource.h"

extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void* Obj_GetPlayerObject(void);
extern void ObjHits_DisableObject(int obj);
extern int ObjGroup_FindNearestObject(int group, int obj, f32* maxDistance);
extern void fn_802967E0(void* obj, int enabled);
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern void Music_Trigger(s32 triggerId, s32 mode);

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

extern ChestHitParams lbl_802C22B0;
extern void* lbl_803DDAE0;
extern int lbl_803DDAE4;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E3C20;
extern f32 lbl_803E3C28;
extern f32 lbl_803E3C2C;

/*
 * --INFO--
 *
 * Function: treasurechest_update
 * EN v1.0 Address: 0x8018AA60
 * EN v1.0 Size: 632b
 * EN v1.1 Address: 0x8018AA94
 * EN v1.1 Size: 896b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void treasurechest_update(int obj)
{
    ChestFlags* flags;
    TreasureChestSetup* setup;
    uint val;
    int val2;
    ChestHitBlock blk;
    float tmp;
    uint hitVolume;
    int tmp2;
    int hitObject;

    flags = ((GameObject*)obj)->extra;
    setup = (TreasureChestSetup*)((GameObject*)obj)->anim.placementData;
    tmp = lbl_803E3C28;
    if (flags->trigger != 0 && flags->open != 0)
    {
        *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode | 8;
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E3C2C, 0);
    }
    if (flags->open == 0)
    {
        if ((*(byte*)&((GameObject*)obj)->anim.resetHitboxMode & 1) != 0)
        {
            *(byte*)&((GameObject*)obj)->anim.resetHitboxMode = *(byte*)&((GameObject*)obj)->anim.resetHitboxMode | 8;
            fn_802967E0(Obj_GetPlayerObject(), 1);
            val = ObjGroup_FindNearestObject(4, obj, &tmp);
            if (val != 0)
            {
                (*gObjectTriggerInterface)->setObjects((int)*(short*)(val + 0x46), 0, 0);
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, 0xffffffff);
            }
            else
            {
                (*gObjectTriggerInterface)->setObjects(setup->triggerObjectId, 0, 0);
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, 0xffffffff);
            }
            GameBit_Set(setup->openGameBit, 1);
            flags->open = 1;
            ObjHits_DisableObject(obj);
        }
        flags->trigger = 0;
        blk.params = lbl_802C22B0;
        tmp2 = 0xffffffff;
        val2 = ObjHits_GetPriorityHitWithPosition(obj, &hitObject, &tmp2,
                                                   &hitVolume, &blk.x, &blk.y,
                                                   blk.z);
        if ((val2 != 0) && (val2 != 0xe))
        {
            blk.x = blk.x + playerMapOffsetX;
            blk.z[0] = blk.z[0] + playerMapOffsetZ;
            blk.scale = lbl_803E3C20;
            blk.c = 0;
            blk.b = 0;
            blk.a = 0;
            if (lbl_803DDAE4 == 0)
            {
                (*(void (**)(int, int, u16*, int, int, ChestHitParams*))(*(int*)lbl_803DDAE0 + 4))
                    (0, 1, (u16*)((int)&blk + 16), 0x401, 0xffffffff, &blk.params);
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

/*
 * --INFO--
 *
 * Function: treasurechest_release
 * EN v1.0 Address: 0x8018ADB4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018AF9C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void treasurechest_release(void)
{
}

/*
 * --INFO--
 *
 * Function: treasurechest_initialise
 * EN v1.0 Address: 0x8018ADB8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8018AFA0
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void treasurechest_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: magiccavebottom_getExtraSize
 * EN v1.0 Address: 0x8018ADBC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8018AFA4
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int magiccavebottom_getExtraSize(void)
{
    return 1;
}

void magiccavebottom_free(int obj)
{
    (void)obj;
    GameBit_Set(0xefb, 0);
    Music_Trigger(0x2f, 0);
}

void treasurechest_init(int* obj)
{
    register ChestFlags* state = ((GameObject*)obj)->extra;
    register TreasureChestSetup* cfg = (TreasureChestSetup*)((GameObject*)obj)->anim.placementData;

    ((GameObject*)obj)->animEventCallback = (void*)treasurechest_SeqFn;
    *(s16*)obj = (s16)((s32)cfg->type << 8);

    if (cfg->openGameBit != -1)
    {
        state->open = (u8)GameBit_Get(cfg->openGameBit);
    }
    else
    {
        state->open = 0;
    }
    if (state->open != 0)
    {
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ObjHits_DisableObject((int)obj);
    }
    lbl_803DDAE0 = Resource_Acquire(90, 1);
    state->trigger = 1;
}
