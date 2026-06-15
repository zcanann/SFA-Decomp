#include "main/dll/VF/vf_shared.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

#define VFP_OBJCREATOR_FALLING_MODE 1
#define VFP_OBJCREATOR_PROJECTILE_MODE 6

#define VFP_OBJCREATOR_FALLING_OBJECT_ID 0x263
#define VFP_OBJCREATOR_PROJECTILE_OBJECT_ID 0x549

typedef struct VfpObjCreatorState
{
    s16 gameBit;
    s16 spawnInterval;
    s16 spawnTimer;
    s16 spawnParam;
    s16 spawnRadius;
} VfpObjCreatorState;

typedef struct VfpObjCreatorPlacement
{
    ObjPlacement base;
    s16 gameBit;
    s16 spawnMode;
    s16 spawnInterval;
    s8 yaw;
    s8 spawnParam;
    u8 spawnRadius;
    u8 pad21[3];
} VfpObjCreatorPlacement;

STATIC_ASSERT(sizeof(VfpObjCreatorState) == 0xa);
STATIC_ASSERT(offsetof(VfpObjCreatorPlacement, gameBit) == 0x18);
STATIC_ASSERT(offsetof(VfpObjCreatorPlacement, spawnMode) == 0x1A);
STATIC_ASSERT(offsetof(VfpObjCreatorPlacement, spawnInterval) == 0x1C);
STATIC_ASSERT(offsetof(VfpObjCreatorPlacement, yaw) == 0x1E);
STATIC_ASSERT(offsetof(VfpObjCreatorPlacement, spawnParam) == 0x1F);
STATIC_ASSERT(offsetof(VfpObjCreatorPlacement, spawnRadius) == 0x20);
STATIC_ASSERT(sizeof(VfpObjCreatorPlacement) == 0x24);

/* Obj_AllocObjectSetup buffer filled in vf_objcreator spawn cases.
 * Head is the common ObjPlacement; tail (0x18..0x27) is file-local. */
typedef struct VfpObjCreatorSetup
{
    ObjPlacement base; /* 0x00..0x17 (posX@0x8, unk04@0x4) */
    s16 unk18;         /* 0x18 */
    s16 unk1A;         /* 0x1A */
    s16 unk1C;         /* 0x1C */
    s16 unk1E;         /* 0x1E */
    s16 unk20;         /* 0x20 */
    s16 unk22;         /* 0x22 */
    u8 unk24;          /* 0x24 */
    u8 pad25[3];       /* 0x25 */
} VfpObjCreatorSetup;

STATIC_ASSERT(offsetof(VfpObjCreatorSetup, unk18) == 0x18);
STATIC_ASSERT(offsetof(VfpObjCreatorSetup, unk24) == 0x24);
STATIC_ASSERT(sizeof(VfpObjCreatorSetup) == 0x28);

extern u8 Obj_IsLoadingLocked(void);
extern u8* Obj_AllocObjectSetup(int size, int typeId);
extern char* Obj_SetupObject(u8* setup, int a, int b, int c, int d);
extern void vecRotateZXY(s16 * angles, f32 * vec);
extern f32 lbl_803E6068;
extern f32 lbl_803E606C;
extern f32 lbl_803E6070;
extern f32 lbl_803E6074;
extern f32 lbl_803E6078;

int vfpobjcreator_getExtraSize(void) { return 0xa; }

int vfpobjcreator_getObjectTypeId(void) { return 0x0; }

void vfpobjcreator_free(void)
{
}

void vfpobjcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0) return;
}

void vfpobjcreator_hitDetect(void)
{
}

void vfpobjcreator_release(void)
{
}

void vfpobjcreator_initialise(void)
{
}

void vfpobjcreator_init(int* obj, u8* init)
{
    VfpObjCreatorPlacement* placement = (VfpObjCreatorPlacement*)init;
    VfpObjCreatorState* state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)(placement->yaw << 8);
    state->gameBit = placement->gameBit;
    state->spawnInterval = placement->spawnInterval;
    state->spawnTimer = state->spawnInterval;
    state->spawnParam = placement->spawnParam;
    state->spawnRadius = placement->spawnRadius;
    ((GameObject*)obj)->objectFlags |= 0x2000;
}

/* EN v1.0 0x801F9D78  size: 1068b  Periodically spawns falling-object setups
 * (mode 1) or projectile bursts (mode 6) while loading is locked. */
void vfpobjcreator_update(int* obj)
{
    VfpObjCreatorPlacement* placement =
        (VfpObjCreatorPlacement*)((GameObject*)obj)->anim.placementData;
    VfpObjCreatorState* state = ((GameObject*)obj)->extra;

    if (Obj_IsLoadingLocked() == 0)
    {
        return;
    }
    switch (placement->spawnMode)
    {
    case 0:
        break;
    case VFP_OBJCREATOR_FALLING_MODE:
        if ((u32)GameBit_Get(state->gameBit) == 0 && state->gameBit != -1)
        {
            break;
        }
        state->spawnTimer -= (s16)timeDelta;
        if (state->spawnTimer <= 0)
        {
            u8* o;
            char* n;
            state->spawnTimer = state->spawnInterval;
            o = Obj_AllocObjectSetup(0x28, VFP_OBJCREATOR_FALLING_OBJECT_ID);
            ((VfpObjCreatorSetup*)o)->base.unk04[2] = 0xff;
            ((VfpObjCreatorSetup*)o)->base.unk04[3] = 0xff;
            ((VfpObjCreatorSetup*)o)->base.unk04[0] = 2;
            ((VfpObjCreatorSetup*)o)->base.unk04[1] = 1;
            ((VfpObjCreatorSetup*)o)->base.posX =
                ((GameObject*)obj)->anim.localPosX +
                (f32)(int)
            randomGetRange(-state->spawnRadius, state->spawnRadius);
            ((VfpObjCreatorSetup*)o)->base.posY = ((GameObject*)obj)->anim.localPosY;
            ((VfpObjCreatorSetup*)o)->base.posZ =
                ((GameObject*)obj)->anim.localPosZ +
                (f32)(int)
            randomGetRange(-state->spawnRadius, state->spawnRadius);
            ((VfpObjCreatorSetup*)o)->unk20 = 0x50;
            ((VfpObjCreatorSetup*)o)->unk1E = (s16)(randomGetRange(0, 2) + 0x16a);
            ((VfpObjCreatorSetup*)o)->unk22 = -1;
            ((VfpObjCreatorSetup*)o)->unk18 = (s16)(randomGetRange(-0x1f4, 0x1f4) + 0x5dc);
            ((VfpObjCreatorSetup*)o)->unk1A = (s16)(randomGetRange(-0x1f4, 0x1f4) + 0x5dc);
            ((VfpObjCreatorSetup*)o)->unk1C = (s16)(randomGetRange(-0x1f4, 0x1f4) + 0x5dc);
            ((VfpObjCreatorSetup*)o)->unk24 = 0;
            n = Obj_SetupObject(o, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                *(int*)&((GameObject*)obj)->anim.parent);
            if (n == NULL)
            {
                break;
            }
            ((GameObject*)n)->anim.velocityY =
                lbl_803E606C * (f32)(int)
            randomGetRange(0, 10) + lbl_803E6068;
            ((GameObject*)n)->anim.velocityX = lbl_803E6070 * (f32)(int)
            randomGetRange(-10, 10);
            ((GameObject*)n)->anim.velocityZ = lbl_803E6070 * (f32)(int)
            randomGetRange(-10, 10);
        }
        break;
    case VFP_OBJCREATOR_PROJECTILE_MODE:
        state->spawnTimer -= (s16)timeDelta;
        if (state->spawnTimer <= 0)
        {
            u8* o;
            char* n;
            struct
            {
                s16 ang[3];
                f32 v[4];
            } m;
            state->spawnTimer = state->spawnInterval;
            o = Obj_AllocObjectSetup(0x24, VFP_OBJCREATOR_PROJECTILE_OBJECT_ID);
            ((VfpObjCreatorSetup*)o)->base.posX = placement->base.posX;
            ((VfpObjCreatorSetup*)o)->base.posY = placement->base.posY;
            ((VfpObjCreatorSetup*)o)->base.posZ = placement->base.posZ;
            ((VfpObjCreatorSetup*)o)->base.unk04[0] = placement->base.unk04[0];
            ((VfpObjCreatorSetup*)o)->base.unk04[1] = placement->base.unk04[1];
            ((VfpObjCreatorSetup*)o)->base.unk04[2] = placement->base.unk04[2];
            ((VfpObjCreatorSetup*)o)->base.unk04[3] = placement->base.unk04[3];
            ((VfpObjCreatorSetup*)o)->unk1E = -1;
            ((VfpObjCreatorSetup*)o)->unk20 = -1;
            n = Obj_SetupObject(o, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                *(int*)&((GameObject*)obj)->anim.parent);
            if (n == NULL)
            {
                break;
            }
            ((GameObject*)n)->unkF8 = 0x1f4;
            {
                f32 b;
                f32 a = *(f32*)&lbl_803E6074;
                ((GameObject*)n)->anim.velocityY = a;
                ((GameObject*)n)->anim.velocityX = a;
                b = lbl_803E6078;
                ((GameObject*)n)->anim.velocityZ = b;
                m.v[1] = a;
                m.v[2] = a;
                m.v[3] = a;
                m.v[0] = b;
            }
            m.ang[2] = 0;
            m.ang[1] = 0;
            m.ang[0] = *(s16*)obj;
            vecRotateZXY(m.ang, (f32*)(n + 0x24));
            Sfx_PlayFromObject((int)n, 0x10c);
            (*gPartfxInterface)->spawnObject(n, 0x39a, NULL, 0x10002, -1, NULL);
            (*gPartfxInterface)->spawnObject(n, 0x39b, NULL, 0x10002, -1, NULL);
            (*gPartfxInterface)->spawnObject(n, 0x39c, NULL, 0x10002, -1, NULL);
        }
        break;
    }
}
