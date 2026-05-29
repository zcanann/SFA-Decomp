#include "ghidra_import.h"
#include "main/dll/fx_800944A0_shared.h"

void cloudaction_func08_nop(void) {}

void cloudaction_func09_nop(void) {}

#pragma scheduling off
#pragma peephole off
void cloudaction_free(void) {
    if (*(void **)lbl_8039AB28 != NULL) {
        Obj_FreeObject(*(int *)lbl_8039AB28);
        *(int *)lbl_8039AB28 = 0;
    }
    *(int *)(lbl_8039AB28 + 0xc) = 0;
    if (*(void **)(lbl_8039AB28 + 4) != NULL) {
        Obj_FreeObject(*(int *)(lbl_8039AB28 + 4));
        *(int *)(lbl_8039AB28 + 4) = 0;
    }
    *(int *)(lbl_8039AB28 + 0x10) = 0;
    if (*(void **)(lbl_8039AB28 + 8) != NULL) {
        Obj_FreeObject(*(int *)(lbl_8039AB28 + 8));
        *(int *)(lbl_8039AB28 + 8) = 0;
    }
    *(int *)(lbl_8039AB28 + 0x14) = 0;
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void cloudaction_func05(void) {
    int tex;
    if (*(void **)lbl_8039AB28 != NULL) {
        tex = objFindTexture(*(int *)lbl_8039AB28, 0, 0);
        if (tex != 0) {
            *(s16 *)(tex + 8) = *(s16 *)(tex + 8) - lbl_8039AB28[0x18];
            if (*(s16 *)(tex + 8) < -0x2710) {
                *(s16 *)(tex + 8) = *(s16 *)(tex + 8) + 0x2710;
            }
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void cloudaction_onMapSetup(void) {
    memset(lbl_8039AB28, 0, 0x1c);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void cloudaction_update(int p1, int p2, u8 *state, int p4, int val) {
    CloudEnvTbl *tbl = (CloudEnvTbl *)lbl_8030F7B0;

    saveGameGetEnvState();
    if (state == NULL) {
        return;
    }
    if ((state[0x58] & 2) == 0) {
        return;
    }
    *(s16 *)((char *)tbl + 0xa) = (s16)((s16)*(u16 *)(state + 0x24) - 1);
    if ((state[0x59] & 1) == 0) {
        return;
    }
    lbl_803DB618[0] = lbl_803DB618[1];
    lbl_803DB618[1] = (u16)val;
    lbl_8039AB28[0x18] = (int)(*(f32 *)(state + 8) / lbl_803DF2DC);
    lbl_8039AB28[0x19] = 0;
    if ((state[0x59] & 4) != 0) {
        lbl_8039AB28[0x1a] = 0;
    } else {
        lbl_8039AB28[0x1a] = 1;
    }
    if (state[0x5d] != 0) {
        if (state[0x5d] < 5) {
            if (*(int *)(lbl_8039AB28 + 0xc) != tbl->a[state[0x5d]]) {
                if (*(void **)lbl_8039AB28 != NULL) {
                    Obj_FreeObject(*(int *)lbl_8039AB28);
                }
                *(int *)lbl_8039AB28 = (int)Obj_SetupObject(
                    Obj_AllocObjectSetup(0x20, tbl->a[state[0x5d]]), 4, -1, -1, 0);
                *(int *)(lbl_8039AB28 + 0xc) = tbl->a[state[0x5d]];
            }
        }
    } else {
        if (*(void **)lbl_8039AB28 != NULL) {
            Obj_FreeObject(*(int *)lbl_8039AB28);
            *(int *)lbl_8039AB28 = 0;
        }
        *(int *)(lbl_8039AB28 + 0xc) = 0;
    }
    if (state[0x5b] != 0) {
        if (state[0x5b] < 4) {
            if (*(int *)(lbl_8039AB28 + 0x10) != tbl->b[state[0x5b]]) {
                if (*(void **)(lbl_8039AB28 + 4) != NULL) {
                    Obj_FreeObject(*(int *)(lbl_8039AB28 + 4));
                }
                *(int *)(lbl_8039AB28 + 4) = (int)Obj_SetupObject(
                    Obj_AllocObjectSetup(0x20, tbl->b[state[0x5b]]), 4, -1, -1, 0);
                *(int *)(lbl_8039AB28 + 0x10) = tbl->b[state[0x5b]];
            }
        }
    } else {
        if (*(void **)(lbl_8039AB28 + 4) != NULL) {
            Obj_FreeObject(*(int *)(lbl_8039AB28 + 4));
            *(int *)(lbl_8039AB28 + 4) = 0;
        }
        *(int *)(lbl_8039AB28 + 0x10) = 0;
    }
    if (state[0x5a] != 0) {
        if (state[0x5a] < 5) {
            if (*(int *)(lbl_8039AB28 + 0x14) != tbl->c[state[0x5a]]) {
                if (*(void **)(lbl_8039AB28 + 8) != NULL) {
                    Obj_FreeObject(*(int *)(lbl_8039AB28 + 8));
                }
                *(int *)(lbl_8039AB28 + 8) = (int)Obj_SetupObject(
                    Obj_AllocObjectSetup(0x20, tbl->c[state[0x5a]]), 4, -1, -1, 0);
                *(int *)(lbl_8039AB28 + 0x14) = tbl->c[state[0x5a]];
            }
        }
    } else {
        if (*(void **)(lbl_8039AB28 + 8) != NULL) {
            Obj_FreeObject(*(int *)(lbl_8039AB28 + 8));
            *(int *)(lbl_8039AB28 + 8) = 0;
        }
        *(int *)(lbl_8039AB28 + 0x14) = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset

void cloudaction_release(void) {}

#pragma scheduling off
#pragma peephole off
void cloudaction_initialise(void) {
    lbl_803DB618[0] = -1;
    lbl_803DB618[1] = -1;
    lbl_803DD1F0 = 0;
}
#pragma peephole reset
#pragma scheduling reset

