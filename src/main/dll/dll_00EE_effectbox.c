/*
 * effectbox (DLL 0x00EE) - an oriented box trigger volume placed in a
 * level. Each frame effectbox_update transforms a candidate object's
 * position into the box's local space (yaw/pitch from the placement) and,
 * if it lies inside the box extents, fires an action on that object.
 *
 * The placement's targetMode selects the candidate set: 0 = the player,
 * 1 = Tricky, 2 = every object in object group 5. The action depends on
 * the same mode (the player gets fn_80295918 with actionArg; group members get
 * a vtable call at slot 0x28). A non-negative placement game bit gates the
 * box: it only runs while the bit's value differs from gameBitValue.
 */
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"
#include "main/objlib.h"
#include "main/dll/VF/vf_shared.h"
extern float mathCosf(float x);
extern float mathSinf(float x);
extern void* getTrickyObject(void);
extern void fn_8002B758(void);
extern void fn_8002B860(int obj);
extern void fn_80295918(int obj, int sel, f32 fval);
extern f32 lbl_803E3508;
extern f32 lbl_803E350C;
extern f32 lbl_803E3510;
extern f32 lbl_803E3514;

typedef struct EffectboxPlacement
{
    ObjPlacement base;
    u8 rotYaw;          /* 0x18: yaw in 1/256 turns */
    u8 rotPitch;        /* 0x19: pitch in 1/256 turns */
    u8 extentX;         /* 0x1A */
    u8 extentY;         /* 0x1B */
    u8 extentZ;         /* 0x1C */
    u8 actionArg;           /* 0x1D: action argument */
    u8 pad1E;
    u8 gameBitValue;    /* 0x1F: gate value compared against the game bit */
    s16 gameBitIndex;          /* 0x20: game bit index */
    u8 targetMode;      /* 0x22: EFFECTBOX_TARGET_* candidate set */
    u8 pad23[0x28 - 0x23];
} EffectboxPlacement;

/* EffectboxPlacement.targetMode values */
#define EFFECTBOX_TARGET_PLAYER 0 /* Obj_GetPlayerObject */
#define EFFECTBOX_TARGET_TRICKY 1 /* getTrickyObject */
#define EFFECTBOX_TARGET_GROUP 2  /* every object in object group 5 */

#define EFFECTBOX_OBJFLAG_HIDDEN 0x4000
#define EFFECTBOX_OBJFLAG_HITDETECT_DISABLED 0x2000

int effectbox_getExtraSize(void) { return 0x0; }
int effectbox_getObjectTypeId(void) { return 0x0; }

void effectbox_free(void)
{
    fn_8002B758();
}

void effectbox_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E3508);
}

void effectbox_hitDetect(void)
{
}

void effectbox_update(int obj)
{
    int* list;
    int def;
    int single;
    int count;
    int i;
    int other;
    f32 cosY;
    f32 sinY;
    f32 cosX;
    f32 sinX;
    f32 negExtX;
    f32 negExtZ;
    f32 extX;
    f32 extY;
    f32 extZ;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 proj;
    int gb;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    gb = ((GameObject*)obj)->unkF8;
    if ((gb <= -1) || (((EffectboxPlacement*)def)->gameBitValue != GameBit_Get(gb)))
    {
        cosY = mathCosf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotYaw << 8)) / lbl_803E3510);
        sinY = mathSinf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotYaw << 8)) / lbl_803E3510);
        cosX = mathCosf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotPitch << 8)) / lbl_803E3510);
        sinX = mathSinf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotPitch << 8)) / lbl_803E3510);
        extX = (f32)((EffectboxPlacement*)def)->extentX;
        extY = (f32)(((EffectboxPlacement*)def)->extentY << 1);
        extZ = (f32)((EffectboxPlacement*)def)->extentZ;
        switch (((EffectboxPlacement*)def)->targetMode)
        {
        case EFFECTBOX_TARGET_PLAYER:
            single = (int)Obj_GetPlayerObject();
            if (single == 0u)
            {
                return;
            }
            list = &single;
            count = 1;
            break;
        case EFFECTBOX_TARGET_TRICKY:
            single = (int)getTrickyObject();
            if (single == 0u)
            {
                return;
            }
            list = &single;
            count = 1;
            break;
        case EFFECTBOX_TARGET_GROUP:
            list = (int*)ObjGroup_GetObjects(5, &count);
            if (list == NULL)
            {
                return;
            }
            break;
        }
        i = 0;
        negExtX = -extX;
        negExtZ = -extZ;
        for (; i < count; i++)
        {
            other = *list;
            dx = ((GameObject*)other)->anim.localPosX;
            dy = ((GameObject*)other)->anim.localPosY;
            dz = ((GameObject*)other)->anim.localPosZ;
            dx = dx - ((GameObject*)obj)->anim.localPosX;
            dy = dy - ((GameObject*)obj)->anim.localPosY;
            dz = dz - ((GameObject*)obj)->anim.localPosZ;
            proj = dx * cosY + dz * sinY;
            if ((proj > negExtX) && (proj < extX))
            {
                proj = (-dx) * sinY + dz * cosY;
                proj = (-dy) * sinX + proj * cosX;
                if ((proj > negExtZ) && (proj < extZ))
                {
                    proj = dy * cosX + proj * sinX;
                    if ((proj >= lbl_803E3514) && (proj < extY))
                    {
                        switch (((EffectboxPlacement*)def)->targetMode)
                        {
                        case EFFECTBOX_TARGET_TRICKY:
                            break;
                        case EFFECTBOX_TARGET_PLAYER:
                            fn_80295918(other, 1, (f32)((EffectboxPlacement*)def)->actionArg);
                            break;
                        case EFFECTBOX_TARGET_GROUP:
                            (*(VtableFn*)(*(int*)(*(int*)&((GameObject*)other)->anim.dll) + 0x28))(other, ((EffectboxPlacement*)def)->actionArg);
                            break;
                        }
                    }
                }
            }
            list++;
        }
    }
}

void effectbox_init(int obj, EffectboxPlacement* def)
{
    s16 gameBit;
    u32 flags;
    if (((GameObject*)obj)->unkF4 == 0)
    {
        fn_8002B860(obj);
    }
    ((GameObject*)obj)->unkF4 = 1;
    gameBit = def->gameBitIndex;
    if (gameBit > -1)
    {
        ((GameObject*)obj)->unkF8 = gameBit;
    }
    else
    {
        ((GameObject*)obj)->unkF8 = -1;
    }
    flags = (u32)((GameObject*)obj)->objectFlags | (EFFECTBOX_OBJFLAG_HIDDEN | EFFECTBOX_OBJFLAG_HITDETECT_DISABLED);
    ((GameObject*)obj)->objectFlags = flags;
}

/* gEffectBoxObjDescriptor (.data 0x80320D10) lives in a separate DLL
 * entry TU; this TU owns only the .text callbacks. */
void effectbox_release(void)
{
}

void effectbox_initialise(void)
{
}

ObjectDescriptor gEffectBoxObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)effectbox_initialise,
    (ObjectDescriptorCallback)effectbox_release,
    0,
    (ObjectDescriptorCallback)effectbox_init,
    (ObjectDescriptorCallback)effectbox_update,
    (ObjectDescriptorCallback)effectbox_hitDetect,
    (ObjectDescriptorCallback)effectbox_render,
    (ObjectDescriptorCallback)effectbox_free,
    (ObjectDescriptorCallback)effectbox_getObjectTypeId,
    effectbox_getExtraSize,
};
