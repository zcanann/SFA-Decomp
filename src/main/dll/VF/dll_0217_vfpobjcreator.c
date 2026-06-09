#include "main/dll/VF/vf_shared.h"
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

#define VFP_OBJCREATOR_FALLING_MODE 1
#define VFP_OBJCREATOR_PROJECTILE_MODE 6

#define VFP_OBJCREATOR_FALLING_OBJECT_ID 0x263
#define VFP_OBJCREATOR_PROJECTILE_OBJECT_ID 0x549

typedef struct VfpObjCreatorState {
    s16 gameBit;
    s16 spawnInterval;
    s16 spawnTimer;
    s16 spawnParam;
    s16 spawnRadius;
} VfpObjCreatorState;

typedef struct VfpObjCreatorPlacement {
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

int vfpobjcreator_getExtraSize(void) { return 0xa; }

int vfpobjcreator_getObjectTypeId(void) { return 0x0; }

void vfpobjcreator_free(void) {}

void vfpobjcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) {
    if (visible == 0) return;
}

void vfpobjcreator_hitDetect(void) {}

void vfpobjcreator_release(void) {}

void vfpobjcreator_initialise(void) {}

void vfpobjcreator_init(int *obj, u8 *init) {
    VfpObjCreatorPlacement *placement = (VfpObjCreatorPlacement *)init;
    VfpObjCreatorState *state = ((GameObject *)obj)->extra;
    *(s16 *)obj = (s16)(placement->yaw << 8);
    state->gameBit = placement->gameBit;
    state->spawnInterval = placement->spawnInterval;
    state->spawnTimer = state->spawnInterval;
    state->spawnParam = placement->spawnParam;
    state->spawnRadius = placement->spawnRadius;
    ((GameObject *)obj)->objectFlags |= 0x2000;
}

extern u8 Obj_IsLoadingLocked(void);
extern char *Obj_AllocObjectSetup(int size, int typeId);
extern char *Obj_SetupObject(char *setup, int a, int b, int c, int d);
extern void vecRotateZXY(s16 *angles, f32 *vec);
extern f32 lbl_803E6068;
extern f32 lbl_803E606C;
extern f32 lbl_803E6070;
extern f32 lbl_803E6074;
extern f32 lbl_803E6078;

/* EN v1.0 0x801F9D78  size: 1068b  Periodically spawns falling-object setups
 * (mode 1) or projectile bursts (mode 6) while loading is locked. */
void vfpobjcreator_update(int *obj)
{
    VfpObjCreatorPlacement *placement =
        (VfpObjCreatorPlacement *)((GameObject *)obj)->anim.placementData;
    VfpObjCreatorState *state = ((GameObject *)obj)->extra;

    if (Obj_IsLoadingLocked() == 0) {
        return;
    }
    switch (placement->spawnMode) {
    case 0:
        break;
    case VFP_OBJCREATOR_FALLING_MODE:
        if ((u32)GameBit_Get(state->gameBit) == 0 && state->gameBit != -1) {
            break;
        }
        state->spawnTimer -= (s16)timeDelta;
        if (state->spawnTimer <= 0) {
            char *o;
            char *n;
            state->spawnTimer = state->spawnInterval;
            o = Obj_AllocObjectSetup(0x28, VFP_OBJCREATOR_FALLING_OBJECT_ID);
            *(u8 *)(o + 6) = 0xff;
            *(u8 *)(o + 7) = 0xff;
            o[4] = 2;
            o[5] = 1;
            *(f32 *)(o + 0x8) =
                ((GameObject *)obj)->anim.localPosX +
                (f32)(int)randomGetRange(-state->spawnRadius, state->spawnRadius);
            *(f32 *)(o + 0xc) = ((GameObject *)obj)->anim.localPosY;
            *(f32 *)(o + 0x10) =
                ((GameObject *)obj)->anim.localPosZ +
                (f32)(int)randomGetRange(-state->spawnRadius, state->spawnRadius);
            *(s16 *)(o + 0x20) = 0x50;
            *(s16 *)(o + 0x1e) = (s16)(randomGetRange(0, 2) + 0x16a);
            *(s16 *)(o + 0x22) = -1;
            *(s16 *)(o + 0x18) = (s16)(randomGetRange(-0x1f4, 0x1f4) + 0x5dc);
            *(s16 *)(o + 0x1a) = (s16)(randomGetRange(-0x1f4, 0x1f4) + 0x5dc);
            *(s16 *)(o + 0x1c) = (s16)(randomGetRange(-0x1f4, 0x1f4) + 0x5dc);
            o[0x24] = 0;
            n = Obj_SetupObject(o, 5, *(s8 *)((char *)obj + 0xac), -1,
                                *(int *)&((GameObject *)obj)->anim.parent);
            if (n == NULL) {
                break;
            }
            *(f32 *)(n + 0x28) =
                lbl_803E606C * (f32)(int)randomGetRange(0, 10) + lbl_803E6068;
            *(f32 *)(n + 0x24) = lbl_803E6070 * (f32)(int)randomGetRange(-10, 10);
            *(f32 *)(n + 0x2c) = lbl_803E6070 * (f32)(int)randomGetRange(-10, 10);
        }
        break;
    case VFP_OBJCREATOR_PROJECTILE_MODE:
        state->spawnTimer -= (s16)timeDelta;
        if (state->spawnTimer <= 0) {
            char *o;
            char *n;
            struct {
                s16 ang[3];
                f32 v[4];
            } m;
            state->spawnTimer = state->spawnInterval;
            o = Obj_AllocObjectSetup(0x24, VFP_OBJCREATOR_PROJECTILE_OBJECT_ID);
            *(f32 *)(o + 0x8) = placement->base.posX;
            *(f32 *)(o + 0xc) = placement->base.posY;
            *(f32 *)(o + 0x10) = placement->base.posZ;
            o[4] = placement->base.unk04[0];
            o[5] = placement->base.unk04[1];
            o[6] = placement->base.unk04[2];
            o[7] = placement->base.unk04[3];
            *(s16 *)(o + 0x1e) = -1;
            *(s16 *)(o + 0x20) = -1;
            n = Obj_SetupObject(o, 5, *(s8 *)((char *)obj + 0xac), -1,
                                *(int *)&((GameObject *)obj)->anim.parent);
            if (n == NULL) {
                break;
            }
            *(int *)(n + 0xf8) = 0x1f4;
            {
                f32 a = lbl_803E6074;
                f32 b;
                *(f32 *)(n + 0x28) = a;
                *(f32 *)(n + 0x24) = a;
                b = lbl_803E6078;
                *(f32 *)(n + 0x2c) = b;
                m.v[1] = a;
                m.v[2] = a;
                m.v[3] = a;
                m.v[0] = b;
            }
            m.ang[2] = 0;
            m.ang[1] = 0;
            m.ang[0] = *(s16 *)obj;
            vecRotateZXY(m.ang, (f32 *)(n + 0x24));
            Sfx_PlayFromObject((int)n, 0x10c);
            (*gPartfxInterface)->spawnObject(n, 0x39a, NULL, 0x10002, -1, NULL);
            (*gPartfxInterface)->spawnObject(n, 0x39b, NULL, 0x10002, -1, NULL);
            (*gPartfxInterface)->spawnObject(n, 0x39c, NULL, 0x10002, -1, NULL);
        }
        break;
    }
}
