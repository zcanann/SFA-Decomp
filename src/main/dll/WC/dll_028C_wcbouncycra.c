#include "main/dll/dll_80220608_shared.h"

#define WCBLOCK_GRID_OBJECT_OFFSET 0x268
#define WCBLOCK_CELL_X_OFFSET 0x27e
#define WCBLOCK_CELL_Z_OFFSET 0x280
#define WCBLOCK_TILE_INDEX_OFFSET 0x283
#define WCBLOCK_VARIANT_A 1

#define WCBLOCK_GRID_IFACE(state) (*(int *)(*(int *)(*(int *)((state) + WCBLOCK_GRID_OBJECT_OFFSET) + 0x68)))

#define WCBLOCK_METHOD_GET_CELL_WORLD_A 0x20
#define WCBLOCK_METHOD_GET_CELL_XY_A 0x30
#define WCBLOCK_METHOD_GET_CELL_WORLD_B 0x3c
#define WCBLOCK_METHOD_GET_CELL_XY_B 0x4c

#define WCBLOCK_PLAYER_CELL_MARGIN lbl_803E6D50

#define WBOUNCY_EXTRA_SIZE 0xc
#define WBOUNCY_STATE_HOME_Y 0x00
#define WBOUNCY_STATE_COOLDOWN 0x08
#define WBOUNCY_STATE_FLAGS 0x0a
#define WBOUNCY_STATE_BOUNCE_COUNT 0x0b
#define WBOUNCY_FLAG_ACTIVE 1
#define WBOUNCY_TRIGGER_GROUP 3
#define WBOUNCY_RESET_COOLDOWN 0x28
#define WBOUNCY_MAX_BOUNCES 0xa

#define WBOUNCY_HOME_Y(state) (*(f32 *)((state) + WBOUNCY_STATE_HOME_Y))
#define WBOUNCY_COOLDOWN(state) (*(s16 *)((state) + WBOUNCY_STATE_COOLDOWN))
#define WBOUNCY_FLAGS(state) (*(u8 *)((state) + WBOUNCY_STATE_FLAGS))
#define WBOUNCY_BOUNCE_COUNT(state) (*(u8 *)((state) + WBOUNCY_STATE_BOUNCE_COUNT))

#pragma peephole on
#pragma scheduling on
int wcbouncycra_getExtraSize(void) { return WBOUNCY_EXTRA_SIZE; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int wcbouncycra_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcbouncycra_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void wcbouncycra_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6D38);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcbouncycra_hitDetect(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void wcbouncycra_update(int obj)
{
    int state = *(int *)(obj + 0xb8);

    if ((WBOUNCY_FLAGS(state) & WBOUNCY_FLAG_ACTIVE) == 0) {
        int n = (int)((f32)WBOUNCY_COOLDOWN(state) - timeDelta);
        WBOUNCY_COOLDOWN(state) = n;
        if ((s16)n <= 0) {
            f32 v = lbl_803E6D20;
            f32 dist;

            if ((void *)ObjGroup_FindNearestObject(WBOUNCY_TRIGGER_GROUP, obj, &v) == NULL) {
                dist = lbl_803E6D24;
            } else if (v < lbl_803E6D28) {
                dist = lbl_803E6D2C;
            } else if (v > lbl_803E6D30) {
                dist = lbl_803E6D24;
            } else {
                dist = (lbl_803E6D38 - (v - lbl_803E6D28) / lbl_803E6D34) * lbl_803E6D2C;
            }
            *(f32 *)(obj + 0x28) = dist;
            WBOUNCY_FLAGS(state) |= WBOUNCY_FLAG_ACTIVE;
            WBOUNCY_BOUNCE_COUNT(state) = 0;
        }
    } else {
        *(f32 *)(obj + 0x28) = lbl_803E6D3C * timeDelta + *(f32 *)(obj + 0x28);
        *(f32 *)(obj + 0x10) = *(f32 *)(obj + 0x28) * timeDelta + *(f32 *)(obj + 0x10);
        if (*(f32 *)(obj + 0x10) <= WBOUNCY_HOME_Y(state)) {
            *(f32 *)(obj + 0x10) =
                *(f32 *)(obj + 0x10) + (WBOUNCY_HOME_Y(state) - *(f32 *)(obj + 0x10));
            *(f32 *)(obj + 0x28) = lbl_803E6D40 * -*(f32 *)(obj + 0x28);
            WBOUNCY_BOUNCE_COUNT(state) += 1;
            if (WBOUNCY_BOUNCE_COUNT(state) > WBOUNCY_MAX_BOUNCES) {
                WBOUNCY_FLAGS(state) &= ~WBOUNCY_FLAG_ACTIVE;
                WBOUNCY_COOLDOWN(state) = WBOUNCY_RESET_COOLDOWN;
                *(f32 *)(obj + 0x10) = WBOUNCY_HOME_Y(state);
                *(f32 *)(obj + 0x28) = lbl_803E6D24;
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling off
void wcbouncycra_init(int obj, int setup)
{
    int state = *(int *)(obj + 0xb8);

    WBOUNCY_HOME_Y(state) = *(f32 *)(setup + 0xc);
    WBOUNCY_COOLDOWN(state) = WBOUNCY_RESET_COOLDOWN;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcbouncycra_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void wcbouncycra_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int wcblock_isPlayerAwayFromStoredCell(int obj, int state, int player)
{
    f32 cellX;
    f32 cellZ;
    f32 pos;
    f32 min;
    f32 max;
    int iface;

    if ((s8)*(u8 *)(obj + 0xad) == WCBLOCK_VARIANT_A) {
        iface = WCBLOCK_GRID_IFACE(state);
        (*(void (**)(int, int, int, int))(iface + WCBLOCK_METHOD_GET_CELL_XY_A))(
            *(u8 *)(state + WCBLOCK_TILE_INDEX_OFFSET), state + WCBLOCK_CELL_X_OFFSET,
            state + WCBLOCK_CELL_Z_OFFSET, iface);
        iface = WCBLOCK_GRID_IFACE(state);
        (*(void (**)(int, int, int, f32 *, f32 *, int))(iface + WCBLOCK_METHOD_GET_CELL_WORLD_A))(
            obj, *(s16 *)(state + WCBLOCK_CELL_X_OFFSET), *(s16 *)(state + WCBLOCK_CELL_Z_OFFSET), &cellX,
            &cellZ, iface);
    } else {
        iface = WCBLOCK_GRID_IFACE(state);
        (*(void (**)(int, int, int, int))(iface + WCBLOCK_METHOD_GET_CELL_XY_B))(
            *(u8 *)(state + WCBLOCK_TILE_INDEX_OFFSET), state + WCBLOCK_CELL_X_OFFSET,
            state + WCBLOCK_CELL_Z_OFFSET, iface);
        iface = WCBLOCK_GRID_IFACE(state);
        (*(void (**)(int, int, int, f32 *, f32 *, int))(iface + WCBLOCK_METHOD_GET_CELL_WORLD_B))(
            obj, *(s16 *)(state + WCBLOCK_CELL_X_OFFSET), *(s16 *)(state + WCBLOCK_CELL_Z_OFFSET), &cellX,
            &cellZ, iface);
    }

    min = cellX - WCBLOCK_PLAYER_CELL_MARGIN;
    pos = *(f32 *)(player + 0xc);
    max = WCBLOCK_PLAYER_CELL_MARGIN + cellX;
    if (pos > max || pos < min) {
        return 1;
    }

    min = cellZ - WCBLOCK_PLAYER_CELL_MARGIN;
    pos = *(f32 *)(player + 0x14);
    max = WCBLOCK_PLAYER_CELL_MARGIN + cellZ;
    if (pos > max || pos < min) {
        return 1;
    }

    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#undef WCBLOCK_GRID_IFACE
