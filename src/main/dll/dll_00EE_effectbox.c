#include "main/dll_000A_expgfx.h"
#include "main/dll/magicduststate_struct.h"
/* This TU contains the COLLECTIBLE/MAGICDUST family; the
 * texframeanimator_* symbols live in MMP_asteroid.c (symbols.txt-verified). */

extern uint GameBit_Get(int eventId);

extern void objRenderFn_8003b8f4(f32);

#include "main/dll/pushable.h"
#include "main/game_object.h"

typedef struct EffectboxPlacement
{
    u8 pad0[0x18 - 0x0];
    u8 rotYaw;
    u8 rotPitch;
    u8 extentX;
    u8 extentY;
    u8 extentZ;
    u8 unk1D;
    u8 pad1E[0x1F - 0x1E];
    u8 gameBitValue;
    s16 unk20;
    u8 targetMode;
    u8 pad23[0x28 - 0x23];
} EffectboxPlacement;

extern f32 mathCosf(f32 x);
extern f32 mathSinf(f32 x);
extern void* ObjGroup_GetObjects();
extern u8* Obj_GetPlayerObject(void);

STATIC_ASSERT(offsetof(MagicDustState, flags27A) == 0x27A);

extern void fn_8002B758(void);

extern void fn_8002B860(int obj);
extern f32 lbl_803E3508;
extern void* getTrickyObject(void);
extern void fn_80295918(f32 amount, int obj, int p3);
extern f32 lbl_803E350C;
extern f32 lbl_803E3510;
extern f32 lbl_803E3514;

void effectbox_free(void)
{
    fn_8002B758();
}

void effectbox_hitDetect(void)
{
}

void effectbox_release(void)
{
}

void effectbox_initialise(void)
{
}

void effectbox_init(int obj, int* def)
{
    s16 bit;
    u32 v;
    if (((GameObject*)obj)->unkF4 == 0)
    {
        fn_8002B860(obj);
    }
    ((GameObject*)obj)->unkF4 = 1;
    bit = *(s16*)((char*)def + 0x20);
    if (bit > -1)
    {
        ((GameObject*)obj)->unkF8 = (int)bit;
    }
    else
    {
        ((GameObject*)obj)->unkF8 = -1;
    }
    v = (u32)((GameObject*)obj)->objectFlags | 0x6000;
    ((GameObject*)obj)->objectFlags = (u16)v;
}

int effectbox_getExtraSize(void) { return 0x0; }
int effectbox_getObjectTypeId(void) { return 0x0; }

void effectbox_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3508);
}

void fn_80174588(int obj, PushableState* p2);

void effectbox_update(int obj)
{
    int def;
    int count;
    int single;
    int* list;
    int i;
    int other;
    f32 sinY;
    f32 cosY;
    f32 sinX;
    f32 cosX;
    f32 extX;
    f32 extYNeg;
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
        sinY = mathCosf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotYaw << 8)) / lbl_803E3510);
        cosY = mathSinf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotYaw << 8)) / lbl_803E3510);
        sinX = mathCosf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotPitch << 8)) / lbl_803E3510);
        cosX = mathSinf((lbl_803E350C * (f32) - (((EffectboxPlacement*)def)->rotPitch << 8)) / lbl_803E3510);
        extX = (f32)((EffectboxPlacement*)def)->extentX;
        extYNeg = (f32) - (((EffectboxPlacement*)def)->extentY << 1);
        extZ = (f32)((EffectboxPlacement*)def)->extentZ;
        switch (((EffectboxPlacement*)def)->targetMode)
        {
        case 1:
            single = (int)Obj_GetPlayerObject();
            if (single == 0)
            {
                return;
            }
            list = &single;
            count = 1;
            break;
        case 0:
            single = (int)getTrickyObject();
            if (single == 0)
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
            proj = dx * sinY + dz * cosY;
            if ((proj > negExtX) && (proj < extX))
            {
                proj = (-dx) * cosY + dz * sinY;
                proj = (-dy) * cosX + proj * sinX;
                if ((proj > negExtZ) && (proj < extZ))
                {
                    proj = dy * sinX + proj * cosX;
                    if ((proj >= lbl_803E3514) && (proj < extYNeg))
                    {
                        switch (((EffectboxPlacement*)def)->targetMode)
                        {
                        case 1:
                            break;
                        case 0:
                            fn_80295918((f32)((EffectboxPlacement*)def)->unk1D, other, 1);
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

int fn_80174438(int obj, PushableState* state);
