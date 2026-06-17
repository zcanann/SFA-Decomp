/*
 * effectbox (DLL 0x00EE) - an oriented box trigger volume placed in a
 * level. Each frame effectbox_update transforms a candidate object's
 * position into the box's local space (yaw/pitch from the placement) and,
 * if it lies inside the box extents, fires an action on that object.
 *
 * The placement's targetMode selects the candidate set: 0 = Tricky, 1 =
 * the player, 2 = every object in object group 5. The action depends on
 * the same mode (Tricky gets fn_80295918 with unk1D; group members get a
 * vtable call at slot 0x28). A non-negative placement game bit gates the
 * box: it only runs while the bit's value differs from gameBitValue.
 */
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/objlib.h"

extern void objRenderFn_8003b8f4(f32);
extern f32 mathCosf(f32 x);
extern f32 mathSinf(f32 x);
extern u8* Obj_GetPlayerObject(void);
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
    u8 unk1D;           /* 0x1D: action argument */
    u8 pad1E;
    u8 gameBitValue;    /* 0x1F: gate value compared against the game bit */
    s16 unk20;          /* 0x20: game bit index */
    u8 targetMode;      /* 0x22: 0 Tricky, 1 player, 2 object group */
    u8 pad23[0x28 - 0x23];
} EffectboxPlacement;

int effectbox_getExtraSize(void) { return 0x0; }
int effectbox_getObjectTypeId(void) { return 0x0; }

void effectbox_free(void)
{
    fn_8002B758();
}

void effectbox_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) objRenderFn_8003b8f4(lbl_803E3508);
}

void effectbox_hitDetect(void)
{
}

void effectbox_update(int obj)
{
    int def;
    int single;
    int count;
    int* list;
    int i;
    int other;
    f32 cosY;
    f32 sinY;
    f32 cosX;
    f32 sinX;
    f32 extX;
    f32 extY;
    f32 extZ;
    f32 negExtX;
    f32 negExtZ;
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
        case 1:
            single = (int)Obj_GetPlayerObject();
            if (single == 0u)
            {
                return;
            }
            list = &single;
            count = 1;
            break;
        case 0:
            single = (int)getTrickyObject();
            if (single == 0u)
            {
                return;
            }
            list = &single;
            count = 1;
            break;
        case 2:
            list = (int*)ObjGroup_GetObjects(5, &count);
            if (list == NULL)
            {
                return;
            }
            break;
        }
        negExtX = -extX;
        negExtZ = -extZ;
        for (i = 0; i < count; i++)
        {
            other = *list;
            dx = ((GameObject*)other)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
            dy = ((GameObject*)other)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
            dz = ((GameObject*)other)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
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
                        case 1:
                            break;
                        case 0:
                            fn_80295918(other, 1, (f32)((EffectboxPlacement*)def)->unk1D);
                            break;
                        case 2:
                            (*(code*)(*(int*)(*(int*)(other + 0x68)) + 0x28))(other, ((EffectboxPlacement*)def)->unk1D);
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
    gameBit = def->unk20;
    if (gameBit > -1)
    {
        ((GameObject*)obj)->unkF8 = (int)gameBit;
    }
    else
    {
        ((GameObject*)obj)->unkF8 = -1;
    }
    flags = (u32)((GameObject*)obj)->objectFlags | 0x6000;
    ((GameObject*)obj)->objectFlags = (u16)flags;
}

/* gEffectBoxObjDescriptor (.data 0x80320D10) lives in a separate DLL
 * entry TU; this TU owns only the .text callbacks. */
void effectbox_release(void)
{
}

void effectbox_initialise(void)
{
}

