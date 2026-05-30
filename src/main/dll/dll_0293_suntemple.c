#include "main/dll/dll_80220608_shared.h"
#include "main/mapEventTypes.h"

#pragma peephole on
#pragma scheduling on
int suntemple_getExtraSize(void) { return 2; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
int suntemple_getObjectTypeId(void) { return 0; }
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void suntemple_free(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void suntemple_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0) {
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E6E18);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling on
void suntemple_hitDetect(int obj)
{
    if ((*(u32 *)(*(int *)(obj + 0x50) + 0x44) & 1) != 0 && *(void **)(obj + 0x74) != NULL) {
        objRenderFn_80041018(obj);
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
int suntemple_interactCallback(int obj, int p2, int p3)
{
    int setup = *(int *)(obj + 0x4c);
    int i;
    SunVec3 vec = *(SunVec3 *)lbl_802C25D8;

    *(u8 *)(obj + 0xaf) |= 0x8;
    for (i = 0; i < *(u8 *)(p3 + 0x8b); i++) {
        switch (*(u8 *)(p3 + 0x81 + i)) {
        default:
            if (*(u8 *)(setup + 0x1b) & 0x4) {
                int *tex;
                GameBit_Set(*(s16 *)(setup + 0x1c), 1);
                tex = (int *)objFindTexture(obj, 0, 0);
                if (tex != NULL)
                    *tex = 0x100;
            }
            break;
        case 2:
            if (*(s16 *)(setup + 0x24) != 0)
                (*(void (**)(int))(*gObjectTriggerInterface + 0x58))(p3);
            break;
        case 3:
            if ((s8)*(u8 *)(obj + 0xad) == 1)
                (*(void (**)(void *, int, int, int))(*gMapEventInterface + 0x24))(
                    &vec, -0x4000, getCurMapLayer(), 0);
            break;
        }
    }
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void suntemple_init(u8 *obj, u8 *setup)
{
    u8 *state;

    *(s16 *)(obj + 0) = (s16)(setup[0x18] << 8);
    *(s16 *)(obj + 2) = (s16)(setup[0x19] << 8);
    *(s16 *)(obj + 4) = (s16)(setup[0x1a] << 8);
    *(void **)(obj + 0xbc) = (void *)suntemple_interactCallback;
    obj[0xad] = setup[0x21];
    if (*(s8 *)(obj + 0xad) >= *(s8 *)(*(int *)(obj + 0x50) + 0x55)) {
        obj[0xad] = 0;
    }
    state = *(u8 **)(obj + 0xb8);
    state[0] = (u8)GameBit_Get(*(s16 *)(setup + 0x1c));
    state[1] = ((MapEventInterface *)*gMapEventInterface)->getMode(*(s8 *)(obj + 0xac));
    if ((setup[0x1b] & 1) != 0 && state[0] != 0) {
        obj[0x36] = 0;
    }
    if (state[0] != 0) {
        int *texture = objFindTexture((int)obj, 0, 0);
        if (texture != NULL) {
            *texture = 0x100;
        }
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
void suntemple_update(int obj)
{
    int state;
    int cfg;
    int *texture;
    int flags;

    state = *(int *)(obj + 0xb8);
    cfg = *(int *)(obj + 0x4c);
    *(u8 *)(state + 0) = (u8)GameBit_Get(*(s16 *)(cfg + 0x1c));
    if (*(u8 *)(state + 0) == 0) {
        texture = objFindTexture(obj, 0, 0);
        if (texture != NULL) {
            *texture = 0;
        }
        *(f32 *)(obj + 0xc) = *(f32 *)(cfg + 0x8);
        *(f32 *)(obj + 0x10) = *(f32 *)(cfg + 0xc);
        *(f32 *)(obj + 0x14) = *(f32 *)(cfg + 0x10);
        *(u8 *)(obj + 0xaf) &= ~0x08;

        if (*(s16 *)(cfg + 0x22) == -1) {
            *(u8 *)(obj + 0xaf) &= ~0x10;
        } else if ((u32)GameBit_Get(*(s16 *)(cfg + 0x22)) != 0) {
            *(u8 *)(obj + 0xaf) &= ~0x10;
        } else {
            *(u8 *)(obj + 0xaf) |= 0x10;
            if ((*(u8 *)(cfg + 0x1b) & 0x10) != 0) {
                *(u8 *)(obj + 0xaf) |= 0x08;
            }
        }

        if (*(s16 *)(obj + 0x46) == 0x830 && gameTimerIsRunning() != 0) {
            *(u8 *)(obj + 0xaf) |= 0x10;
        }

        if ((*(u8 *)(obj + 0xaf) & 0x1) != 0) {
            if (*(s16 *)(cfg + 0x1e) == -1 ||
                (*(int (**)(int))(*gGameUIInterface + 0x20))(*(s16 *)(cfg + 0x1e)) != 0) {
                if (*(s8 *)(cfg + 0x20) != -1) {
                    if (*(s16 *)(obj + 0x46) == 0x526) {
                        if (*(u8 *)(state + 1) == 1 &&
                            ((u32)GameBit_Get(0x25a) != 0 || (u32)GameBit_Get(0x25b) != 0)) {
                            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(
                                *(s8 *)(cfg + 0x20) + 2, obj, -1);
                        } else if (*(u8 *)(state + 1) == 2 &&
                                   ((u32)GameBit_Get(0x202) != 0 || (u32)GameBit_Get(0x243) != 0)) {
                            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(
                                *(s8 *)(cfg + 0x20) + 2, obj, -1);
                        } else {
                            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(
                                *(s8 *)(cfg + 0x20), obj, -1);
                        }
                    } else {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(
                            *(s8 *)(cfg + 0x20), obj, -1);
                    }
                }
                if ((*(u8 *)(cfg + 0x1b) & 0x04) == 0) {
                    GameBit_Set(*(s16 *)(cfg + 0x1c), 1);
                    texture = objFindTexture(obj, 0, 0);
                    if (texture != NULL) {
                        *texture = 0x100;
                    }
                }
                if ((*(u8 *)(cfg + 0x1b) & 0x08) != 0) {
                    GameBit_Set(*(s16 *)(cfg + 0x22), 0);
                } else {
                    *(u8 *)(state + 0) = 1;
                    *(int *)(obj + 0xf4) = 1;
                }
                buttonDisable(0, 0x100);
            }
        }
    } else {
        if (*(int *)(obj + 0xf4) == 0 && *(s8 *)(cfg + 0x20) != -1 &&
            *(s16 *)(cfg + 0x24) != 0) {
            (*(void (**)(int))(*gObjectTriggerInterface + 0x54))(obj);
            flags = 1;
            if ((*(u8 *)(cfg + 0x1b) & 0x20) != 0) {
                flags |= 0x2;
            }
            if ((*(u8 *)(cfg + 0x1b) & 0x40) != 0) {
                flags |= 0x3;
            }
            if ((*(u8 *)(cfg + 0x1b) & 0x80) != 0) {
                flags |= 0x4;
            }
            (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(
                *(s8 *)(cfg + 0x20), obj, flags);
        }
        *(u8 *)(obj + 0xaf) |= 0x08;
    }
    *(int *)(obj + 0xf4) = 1;
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void suntemple_release(void) {}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole on
#pragma scheduling on
void suntemple_initialise(void) {}
#pragma scheduling reset
#pragma peephole reset
