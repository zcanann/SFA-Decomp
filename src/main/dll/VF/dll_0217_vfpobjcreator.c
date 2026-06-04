#include "main/dll/VF/vf_shared.h"

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
    u8 pad0[0x18];
    s16 gameBit;
    s16 spawnMode;
    s16 spawnInterval;
    s8 yaw;
    s8 spawnParam;
    u8 spawnRadius;
} VfpObjCreatorPlacement;

int vfpobjcreator_getExtraSize(void) { return 0xa; }

int vfpobjcreator_getObjectTypeId(void) { return 0x0; }

void vfpobjcreator_free(void) {}

#pragma peephole off
#pragma scheduling off
void vfpobjcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) {
    if (visible == 0) return;
}
#pragma scheduling reset
#pragma peephole reset

void vfpobjcreator_hitDetect(void) {}

void vfpobjcreator_release(void) {}

void vfpobjcreator_initialise(void) {}

#pragma peephole off
#pragma scheduling off
void vfpobjcreator_init(int *obj, u8 *init) {
    VfpObjCreatorPlacement *placement = (VfpObjCreatorPlacement *)init;
    VfpObjCreatorState *state = *(VfpObjCreatorState **)((char *)obj + 0xb8);
    *(s16 *)obj = (s16)(placement->yaw << 8);
    state->gameBit = placement->gameBit;
    state->spawnInterval = placement->spawnInterval;
    state->spawnTimer = state->spawnInterval;
    state->spawnParam = placement->spawnParam;
    state->spawnRadius = placement->spawnRadius;
    *(u16 *)((char *)obj + 0xb0) |= 0x2000;
}
#pragma scheduling reset
#pragma peephole reset

extern u8 Obj_IsLoadingLocked(void);
extern char *Obj_AllocObjectSetup(int size, int typeId);
extern char *Obj_SetupObject(char *setup, int a, int b, int c, int d);
extern void mathFn_80021ac8(s16 *angles, f32 *vec);
extern f32 lbl_803E6068;
extern f32 lbl_803E606C;
extern f32 lbl_803E6070;
extern f32 lbl_803E6074;
extern f32 lbl_803E6078;

/* EN v1.0 0x801F9D78  size: 1068b  Periodically spawns falling-object setups
 * (mode 1) or projectile bursts (mode 6) while loading is locked. */
#pragma peephole off
#pragma scheduling off
void vfpobjcreator_update(int *obj)
{
    VfpObjCreatorPlacement *placement = *(VfpObjCreatorPlacement **)((char *)obj + 0x4c);
    char *setup = (char *)placement;
    VfpObjCreatorState *state = *(VfpObjCreatorState **)((char *)obj + 0xb8);

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
                *(f32 *)((char *)obj + 0xc) +
                (f32)(int)randomGetRange(-state->spawnRadius, state->spawnRadius);
            *(f32 *)(o + 0xc) = *(f32 *)((char *)obj + 0x10);
            *(f32 *)(o + 0x10) =
                *(f32 *)((char *)obj + 0x14) +
                (f32)(int)randomGetRange(-state->spawnRadius, state->spawnRadius);
            *(s16 *)(o + 0x20) = 0x50;
            *(s16 *)(o + 0x1e) = (s16)(randomGetRange(0, 2) + 0x16a);
            *(s16 *)(o + 0x22) = -1;
            *(s16 *)(o + 0x18) = (s16)(randomGetRange(-0x1f4, 0x1f4) + 0x5dc);
            *(s16 *)(o + 0x1a) = (s16)(randomGetRange(-0x1f4, 0x1f4) + 0x5dc);
            *(s16 *)(o + 0x1c) = (s16)(randomGetRange(-0x1f4, 0x1f4) + 0x5dc);
            o[0x24] = 0;
            n = Obj_SetupObject(o, 5, *(s8 *)((char *)obj + 0xac), -1,
                                *(int *)((char *)obj + 0x30));
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
            *(f32 *)(o + 0x8) = *(f32 *)(setup + 0x8);
            *(f32 *)(o + 0xc) = *(f32 *)(setup + 0xc);
            *(f32 *)(o + 0x10) = *(f32 *)(setup + 0x10);
            o[4] = setup[4];
            o[5] = setup[5];
            o[6] = setup[6];
            o[7] = setup[7];
            *(s16 *)(o + 0x1e) = -1;
            *(s16 *)(o + 0x20) = -1;
            n = Obj_SetupObject(o, 5, *(s8 *)((char *)obj + 0xac), -1,
                                *(int *)((char *)obj + 0x30));
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
            mathFn_80021ac8(m.ang, (f32 *)(n + 0x24));
            Sfx_PlayFromObject((int)n, 0x10c);
            (*(int (*)(char *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(
                n, 0x39a, 0, 0x10002, -1, 0);
            (*(int (*)(char *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(
                n, 0x39b, 0, 0x10002, -1, 0);
            (*(int (*)(char *, int, int, int, int, int))(*(int *)(*gPartfxInterface + 0x8)))(
                n, 0x39c, 0, 0x10002, -1, 0);
        }
        break;
    }
}
#pragma scheduling reset
#pragma peephole reset
