#include "ghidra_import.h"

extern int *gExpgfxInterface;
extern void ModelLightStruct_free(int model);
extern void Obj_FreeObject(int obj);

int worldobj_getExtraSize(void) { return 0x284; }
int snowclaw_getExtraSize(void) { return 0xb0; }
int snowclaw_getObjectTypeId(void) { return 0x3; }

void worldobj_hitDetect(void) {}
void worldobj_release(void) {}
void worldobj_initialise(void) {}
void worldplanet_release(void) {}
void worldplanet_initialise(void) {}
void snowclaw_release(void) {}
void snowclaw_initialise(void) {}

#pragma scheduling off
#pragma peephole off
int worldobj_getObjectTypeId(int *obj) {
    if (*(s16 *)*(int **)((char *)obj + 0x4c) != 0x5e3) {
        return 0x0;
    }
    return 0x8;
}

void worldobj_free(int obj) {
    int *inner = *(int **)(obj + 0xb8);
    if (*(void **)inner != NULL) {
        ModelLightStruct_free(*inner);
        *inner = 0;
    }
    (*(void (*)(int))(*(int *)(*gExpgfxInterface + 0x14)))(obj);
}

void snowclaw_free(int obj) {
    if (*(void **)(obj + 0xc8) != NULL) {
        Obj_FreeObject(*(int *)(obj + 0xc8));
    }
}
#pragma peephole reset
#pragma scheduling reset

extern u32 GameBit_Get(int id);
extern int GameBit_Set(int id, int value);
extern void loadMapAndParent(int mapId);
extern void unlockLevel(int a, int b, int c);
extern int lockLevel(int mapDir, int flags);
extern int mapGetDirIdx(int mapId);
extern int *gMapEventInterface;
extern int Obj_GetPlayerObject(void);
extern void setMotionBlur(int mode, f32 amount);
extern u32 fn_802972A8(int obj);
extern int ObjGroup_FindNearestObject(int kind, int obj, f32 *maxDistance);
extern f32 lbl_803E6740;
extern f32 lbl_803E6744;

#pragma scheduling off
#pragma peephole off
int crcloudrace_completionCallback(int obj, int arg2, u8 *data) {
    int *inner = *(int **)(obj + 0xb8);
    int i;

    *(u8 *)((char *)inner + 9) |= 1;
    for (i = 0; i < *(u8 *)((char *)data + 0x8b); i++) {
        switch (data[i + 0x81]) {
        case 1:
            GameBit_Set(0xdca, 1);
            GameBit_Set(0x458, 0);
            loadMapAndParent(0xc);
            unlockLevel(0, 0, 1);
            lockLevel(mapGetDirIdx(0xc), 0);
            (*(void (*)(int, int, int))(*(int *)(*gMapEventInterface + 0x50)))(0xc, 1, 1);
            break;
        }
    }
    return 0;
}

void crcloudrace_updateCompletionState(int obj, int *state) {
    f32 dist;
    int player;
    u32 near;

    dist = lbl_803E6740;
    player = Obj_GetPlayerObject();
    if (GameBit_Get(0x499) == 0) {
        if (GameBit_Get(0x2e8) != 0) {
            *(u8 *)((char *)state + 8) = 4;
            setMotionBlur(0, lbl_803E6744);
            GameBit_Set(0x497, 0);
            GameBit_Set(0x49d, 0);
        }
    } else {
        GameBit_Set(0x499, 1);
        setMotionBlur(0, lbl_803E6744);
        if (GameBit_Get(0x4a9) != 0 && fn_802972A8(player) == 0) {
            near = ObjGroup_FindNearestObject(0x1e, obj, &dist);
            if (near != 0) {
                (*(void (*)(int, int))(*(int *)(*(int *)(*(int *)(near + 0x68)) + 0x20)))(near, 1);
            }
            *(u8 *)((char *)state + 8) = 5;
        }
    }
}

extern int padGetStickX(int controller);
extern int padGetStickY(int controller);
extern int getLoadedFileFlags(int file);

void worldplanet_readMapInput(int obj, u8 *outX, u8 *outY) {
    s8 *inner = *(s8 **)(obj + 0xb8);
    int stickX;
    int stickY;
    int resX;
    int resY;

    stickX = padGetStickX(0);
    stickY = padGetStickY(0);
    resX = 0;
    resY = 0;
    if (getLoadedFileFlags(0) == 0) {
        if ((s8)stickX < -0x23 && inner[0xa] >= -0x23) {
            resX = -1;
            inner[0xc] = 0;
        }
        if ((s8)stickX > 0x23 && inner[0xa] <= 0x23) {
            resX = 1;
            inner[0xc] = 0;
        }
        if ((s8)stickY < -0x23 && inner[0xb] >= -0x23) {
            resY = -1;
            inner[0xd] = 0;
        }
        if ((s8)stickY > 0x23 && inner[0xb] <= 0x23) {
            resY = 1;
            inner[0xd] = 0;
        }
        inner[0xb] = stickY;
        if (inner[0xb] < -0x23) {
            inner[0xd]++;
        } else if (inner[0xb] > 0x23) {
            inner[0xd]++;
        } else {
            inner[0xd] = 0;
        }
        if (inner[0xd] > 0x32) {
            inner[0xb] = 0;
            inner[0xd] = 0;
        }
        inner[0xa] = stickX;
        if (inner[0xa] < -0x23) {
            inner[0xc]++;
        } else if (inner[0xa] > 0x23) {
            inner[0xc]++;
        } else {
            inner[0xc] = 0;
        }
        if (inner[0xc] > 0x32) {
            inner[0xa] = 0;
            inner[0xc] = 0;
        }
        *outX = resX;
        *outY = resY;
    } else {
        *outX = 0;
        *outY = 0;
    }
}
#pragma peephole reset
#pragma scheduling reset
