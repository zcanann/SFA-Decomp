/* === moved from main/dll/texframeanimator.c [80173224-801732A4) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll_000A_expgfx.h"
/* IDENTITY NOTE: this TU contains the COLLECTIBLE/MAGICDUST family; the
 * real texframeanimator_* symbols live in MMP_asteroid.c (symbols.txt-
 * verified). File rename parked as a repo-owner proposal. */

extern uint GameBit_Get(int eventId);


/*
 * --INFO--
 *
 * Function: collectible_init
 * EN v1.0 Address: 0x80172F14
 * EN v1.0 Size: 1104b
 * EN v1.1 Address: 0x801730D0
 * EN v1.1 Size: 752b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */




/*
 * --INFO--
 *
 * Function: collectible_release
 * EN v1.0 Address: 0x8017321C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80173378
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: collectible_initialise
 * EN v1.0 Address: 0x80173220
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017337C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/* 8b "li r3, N; blr" returners. */

/* render-with-fn(lbl) (no visibility check). */
extern void objRenderFn_8003b8f4(f32);

#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/obj_placement.h"
#include "main/dll/lightning.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/pushable.h"
#include "main/objanim_internal.h"
#include "main/game_object.h"
#include "main/resource.h"

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


/* magicdust extra block (collectible sparkle state; tail of the pickup record). */
typedef struct MagicDustState
{
    u8 unk00[0x6C];
    f32 unk6C;
    u8 unk70[0x25B - 0x70];
    u8 unk25B;
    u8 unk25C[5];
    s8 unk261;
    u8 unk262[6];
    f32 unk268;
    f32 burstTimer; /* counts down to the next 30-particle burst */
    u16 burstEffectId;
    u16 ambientEffectId; /* partfx effect id */
    s16 sfxId; /* collect sfx id */
    s16 unk276;
    s16 ambientTimer;
    u8 flags27A; /* bits 8/0x10/0x40 observed; &0xFA clear on collect */
    u8 bounceCount;
    u8 mode; /* particle color row */
    u8 unk27D[3];
    u16 unk280;
} MagicDustState;

STATIC_ASSERT(offsetof(MagicDustState, flags27A) == 0x27A);

/*
 * --INFO--
 *
 * Function: magicdust_update
 * EN v1.0 Address: 0x801732A4
 * EN v1.0 Size: 2272b
 * EN v1.1 Address: 0x80173750
 * EN v1.1 Size: 2120b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: magicdust_init
 * EN v1.0 Address: 0x80173B84
 * EN v1.0 Size: 1112b
 * EN v1.1 Address: 0x80173F98
 * EN v1.1 Size: 1188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


extern void fn_8002B758(void);

/*
 * --INFO--
 *
 * Function: effectbox_free
 * EN v1.0 Address: 0x80173F90
 * EN v1.0 Size: 32b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void effectbox_free(void)
{
    fn_8002B758();
}


/* Trivial 4b 0-arg blr leaves. */
void effectbox_hitDetect(void)
{
}

void effectbox_release(void)
{
}

void effectbox_initialise(void)
{
}

extern void fn_8002B860(int obj);

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

/* 8b "li r3, N; blr" returners. */
int effectbox_getExtraSize(void) { return 0x0; }
int effectbox_getObjectTypeId(void) { return 0x0; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3508;

void effectbox_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3508);
}

void fn_80174588(int obj, PushableState* p2);

extern void* getTrickyObject(void);
extern void fn_80295918(f32 amount, int obj, int p3);
extern f32 lbl_803E350C;
extern f32 lbl_803E3510;
extern f32 lbl_803E3514;

/*
 * --INFO--
 *
 * Function: effectbox_update
 * EN v1.0 Address: 0x80173FE4
 * EN v1.0 Size: 980b
 */
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
            dx = *(f32*)(other + 0xc) - ((GameObject*)obj)->anim.localPosX;
            dy = *(f32*)(other + 0x10) - ((GameObject*)obj)->anim.localPosY;
            dz = *(f32*)(other + 0x14) - ((GameObject*)obj)->anim.localPosZ;
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

/*
 * --INFO--
 *
 * Function: fn_80174438
 * EN v1.0 Address: 0x80174438
 * EN v1.0 Size: 336b
 */
int fn_80174438(int obj, PushableState* state);

/*
 * --INFO--
 *
 * Function: fn_80174668
 * EN v1.0 Address: 0x80174668
 * EN v1.0 Size: 1048b
 */
