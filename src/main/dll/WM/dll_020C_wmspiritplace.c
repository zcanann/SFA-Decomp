#include "main/dll/WM/wm_shared.h"

typedef struct WmSpiritPlaceState {
    f32 heightOffset;
    int unk_04;
    s16 unk_08;
    s16 unk_0A;
    s16 primaryGameBit;
    s16 secondaryGameBit;
    s16 setupParam;
    u8 flags12;
    u8 mapEventState;
    u8 transitionDelay;
    u8 flags15;
    u8 pad16[2];
} WmSpiritPlaceState;

void fn_801F568C(void) {}

int fn_801F5690(int obj, int unused, int actor)
{
    WmSpiritPlaceState *state;
    int i;
    int mapId;
    u8 action;
    u8 fxPos[24];

    state = *(WmSpiritPlaceState **)(obj + 0xb8);
    if ((state->flags12 & 1) != 0) {
        (*(void (**)(int, int, void *, int, int, int))(*gPartfxInterface + 8))(obj, 0x7d8, NULL, 2, -1, 0);
        (*(void (**)(int, int, void *, int, int, int))(*gPartfxInterface + 8))(obj, 0x7d8, fxPos, 2, -1, 0);
    }

    *(u8 *)(actor + 0x56) = 0;
    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xf7);
    *(void **)(actor + 0xe8) = fn_801F568C;

    for (i = 0; i < *(u8 *)(actor + 0x8b); i++) {
        action = *(u8 *)(actor + i + 0x81);
        switch (action) {
            case 1:
                unlockLevel(0, 0, 1);
                break;
            case 3:
                mapId = *(int *)(*(int *)(obj + 0x4c) + 0x14);
                if (mapId == 0x47295 || mapId == 0x49781 || mapId == 0x4a1c0) {
                    warpToMap(0x7e, 0);
                }
                break;
            case 4:
                mapId = *(int *)(*(int *)(obj + 0x4c) + 0x14);
                if (mapId == 0x47295 || mapId == 0x49781 || mapId == 0x4a1c0 ||
                    mapId == 0x4a250 || mapId == 0x4a5e6) {
                    state->transitionDelay = 1;
                }
                break;
            case 5:
                state->flags12 = (u8)(state->flags12 | 1);
                break;
            case 6:
                state->flags12 = (u8)(state->flags12 & ~1);
                break;
            case 7:
                skyFn_80088c94(7, 0);
                setDrawCloudsAndLights(1);
                getEnvfxAct(obj, obj, 0x84, 0);
                getEnvfxAct(obj, obj, 0x8a, 0);
                getEnvfxActImmediately(0, 0, 0x217, 0);
                getEnvfxActImmediately(0, 0, 0x216, 0);
                break;
            case 8:
                Rcp_SetSpiritVisionEnabled(1);
                break;
            case 9:
                Rcp_SetSpiritVisionEnabled(0);
                break;
            case 2:
                mapId = *(int *)(*(int *)(obj + 0x4c) + 0x14);
                if (mapId == 0x2183) {
                    lockLevel(mapGetDirIdx(0x41), 0);
                    lockLevel(mapGetDirIdx(0xb), 1);
                    (*(void (**)(int))(*gMapEventInterface + 0x78))(1);
                } else if (mapId == 0x47295) {
                    loadMapAndParent(0x42);
                    lockLevel(mapGetDirIdx(0x42), 0);
                    lockLevel(mapGetDirIdx(0xb), 1);
                    (*(void (**)(int, int))(*gMapEventInterface + 0x44))(0x42, 3);
                    (*(void (**)(int, int))(*gMapEventInterface + 0x44))(7, 4);
                } else if (mapId == 0x49781) {
                    loadMapAndParent(0x42);
                    lockLevel(mapGetDirIdx(0x42), 0);
                    lockLevel(mapGetDirIdx(0xb), 1);
                    (*(void (**)(int, int))(*gMapEventInterface + 0x44))(0x42, 3);
                    (*(void (**)(int, int))(*gMapEventInterface + 0x44))(7, 5);
                } else if (mapId == 0x4a1c0) {
                    loadMapAndParent(0x42);
                    lockLevel(mapGetDirIdx(0x42), 0);
                    lockLevel(mapGetDirIdx(0xb), 1);
                    (*(void (**)(int, int))(*gMapEventInterface + 0x44))(0x42, 3);
                    (*(void (**)(int, int))(*gMapEventInterface + 0x44))(7, 7);
                }
                break;
        }
    }

    return 0;
}

int wmspiritplace_getExtraSize(void) { return 0x18; }

int wmspiritplace_getObjectTypeId(void) { return 0x0; }

void wmspiritplace_free(void) {}

#pragma peephole off
#pragma scheduling off
void wmspiritplace_render(undefined4 p1, undefined4 p2, undefined4 p3, undefined4 p4, undefined4 p5, s8 visible)
{
    if (visible != 0) {
    }
}
#pragma scheduling reset
#pragma peephole reset

void wmspiritplace_hitDetect(int obj)
{
    if (*(void **)(obj + 0x74) != NULL) {
        objRenderFn_80041018(obj);
    }
}

void wmspiritplace_update(int obj)
{
    WmSpiritPlaceState *state;
    int mapId;

    state = *(WmSpiritPlaceState **)(obj + 0xb8);
    if (state->transitionDelay == 0) {
        state->flags12 = (u8)(state->flags12 & ~1);
        mapId = *(int *)(*(int *)(obj + 0x4c) + 0x14);
        if (mapId == 0x47295) {
            if (state->mapEventState == 2) {
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x10);
                }
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    if (GameBit_Get(state->secondaryGameBit) == 0 || GameBit_Get(0x29b) == 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xf7);
                    } else {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                        GameBit_Set(state->secondaryGameBit, 0);
                        GameBit_Set(0xbfd, 0);
                    }
                } else {
                    if ((*(u8 *)(obj + 0xaf) & 0x10) != 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xef);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                        state->flags15 = (u8)((state->flags15 & 0x7f) | 0x80);
                    }
                }
            } else {
                *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
            }
        } else if (mapId == 0x2183) {
            if (state->mapEventState == 1) {
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x10);
                }
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xf7);
                } else {
                    if ((*(u8 *)(obj + 0xaf) & 0x10) != 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xef);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
                        GameBit_Set(state->secondaryGameBit, 1);
                        GameBit_Set(state->primaryGameBit, 0);
                    }
                }
            } else {
                *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
            }
        } else if (mapId == 0x49781) {
            if (state->mapEventState == 3) {
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x10);
                }
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    if (GameBit_Get(state->secondaryGameBit) == 0 || GameBit_Get(0x8a2) == 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xf7);
                    } else {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                        GameBit_Set(state->secondaryGameBit, 0);
                    }
                } else {
                    if ((*(u8 *)(obj + 0xaf) & 0x10) != 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xef);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                        state->flags15 = (u8)((state->flags15 & 0x7f) | 0x80);
                    }
                }
            } else {
                *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
            }
        } else if (mapId == 0x4a1c0) {
            if (state->mapEventState == 4) {
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x10);
                }
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    if (GameBit_Get(state->secondaryGameBit) == 0 || GameBit_Get(0xc71) == 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xf7);
                    } else {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(1, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                        GameBit_Set(state->secondaryGameBit, 0);
                    }
                } else {
                    if ((*(u8 *)(obj + 0xaf) & 0x10) != 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xef);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                        state->flags15 = (u8)((state->flags15 & 0x7f) | 0x80);
                    }
                }
            } else {
                *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
            }
        } else if (mapId == 0x4a250) {
            if (state->mapEventState == 5) {
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x10);
                }
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    if (GameBit_Get(state->secondaryGameBit) == 0 || GameBit_Get(0xcb6) == 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xf7);
                    } else if (((state->flags15 >> 6) & 1) != 0) {
                        state->flags15 = (u8)(state->flags15 & 0xbf);
                        GameBit_Set(state->primaryGameBit, 0);
                        GameBit_Set(0xd1f, 1);
                        getEnvfxActImmediately(0, 0, 0x217, 0);
                        getEnvfxActImmediately(obj, obj, 0x216, 0);
                        getEnvfxActImmediately(obj, obj, 0x229, 0);
                        getEnvfxActImmediately(obj, obj, 0x22a, 0);
                        (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 4, 1);
                        (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 10, 0);
                        (*(void (**)(int, int, int))(*gMapEventInterface + 0x50))(*(s8 *)(obj + 0xac), 0xb, 1);
                    }
                } else {
                    if ((*(u8 *)(obj + 0xaf) & 0x10) != 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xef);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                        state->flags15 = (u8)((state->flags15 & 0x7f) | 0x80);
                        state->flags15 = (u8)((state->flags15 & 0xbf) | 0x40);
                    }
                }
            } else {
                *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
            }
        } else if (mapId == 0x4a5e6) {
            if (state->mapEventState == 6) {
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 0x10);
                }
                if (GameBit_Get(state->primaryGameBit) == 0) {
                    if (GameBit_Get(state->secondaryGameBit) == 0 || GameBit_Get(0xcb8) == 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xf7);
                    } else {
                        GameBit_Set(state->primaryGameBit, 0);
                        GameBit_Set(state->secondaryGameBit, 1);
                    }
                } else {
                    if ((*(u8 *)(obj + 0xaf) & 0x10) != 0) {
                        *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) & 0xef);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 4) != 0) {
                        setAButtonIcon(0x18);
                    }
                    if ((*(u8 *)(obj + 0xaf) & 1) != 0) {
                        state->flags15 = (u8)((state->flags15 & 0x7f) | 0x80);
                        (*(void (**)(int, int, int))(*gObjectTriggerInterface + 0x48))(0, obj, -1);
                        GameBit_Set(state->primaryGameBit, 0);
                    }
                }
            } else {
                *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
            }
        }
        if ((s8)state->flags15 < 0) {
            *(u8 *)(obj + 0xaf) = (u8)(*(u8 *)(obj + 0xaf) | 8);
        }
    } else {
        state->transitionDelay--;
        if (state->transitionDelay == 0) {
            GameBit_Set(state->secondaryGameBit, 1);
        }
    }
}

void wmspiritplace_init(int obj, int setup)
{
    WmSpiritPlaceState *state;

    state = *(WmSpiritPlaceState **)(obj + 0xb8);
    *(void **)(obj + 0xbc) = fn_801F5690;
    *(s16 *)(obj + 0) = (s16)((s8)*(u8 *)(setup + 0x18) << 8);
    *(s16 *)(obj + 2) = (s16)(*(s16 *)(setup + 0x1a) << 8);
    state->heightOffset = ((f32)(*(s16 *)(setup + 0x1c)) / lbl_803E5EF8) / lbl_803E5EFC;
    state->unk_04 = 0;
    state->unk_08 = 0;
    state->unk_0A = 0;
    state->secondaryGameBit = *(s16 *)(setup + 0x1e);
    state->primaryGameBit = *(s16 *)(setup + 0x20);
    state->setupParam = (s16)*(s8 *)(setup + 0x19);
    state->flags15 = (u8)(state->flags15 & 0x7f);
    *(u16 *)(obj + 0xb0) = (u16)(*(u16 *)(obj + 0xb0) | 0x6000);
    state->mapEventState = (*(u8 (**)(int))(*gMapEventInterface + 0x40))(*(s8 *)(obj + 0xac));

    if (*(int *)(*(int *)(obj + 0x4c) + 0x14) == 0x47295) {
        if (GameBit_Get(0x1fc) != 0 || GameBit_Get(0xeaf) != 0 || state->mapEventState > 2) {
            *(f32 *)(obj + 0xc) = *(f32 *)(obj + 0xc) - lbl_803E5F00;
        }
    } else if (*(int *)(*(int *)(obj + 0x4c) + 0x14) == 0x4a5e6 && state->mapEventState > 5) {
        *(f32 *)(obj + 0xc) = *(f32 *)(obj + 0xc) + lbl_803E5F00;
    }
}

void wmspiritplace_release(void) {}

void wmspiritplace_initialise(void) {}
