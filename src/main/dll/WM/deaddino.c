#include "ghidra_import.h"
#include "main/dll/WM/deaddino.h"
#include "main/objlib.h"

#define SC_TOTEMPUZZLE_OBJECT_TYPE 0x3c1
#define SC_TOTEMPUZZLE_READY_FLAG 0x2
#define SC_TOTEMPUZZLE_REVERSED_FLAG 0x1
#define SC_TOTEMPUZZLE_FORWARD_STEP 4
#define SC_TOTEMPUZZLE_REVERSE_STEP 3
#define SC_TOTEMPUZZLE_SOLVED_COUNT 5

#define SC_TOTEMPUZZLE_WRONG_SFX 0x487
#define SC_TOTEMPUZZLE_COMPLETE_SFX 0x7e
#define SC_TOTEMPUZZLE_PROGRESS_SFX 0x409

typedef struct SCTotemPuzzleState {
    u8 pad00[0xc];
    f32 angleTarget;
    s16 step;
    s16 flags;
} SCTotemPuzzleState;

typedef struct SCTotemPuzzleObject {
    s16 angle;
    u8 pad02[0x44];
    s16 objectType;
    u8 pad48[0x70];
    SCTotemPuzzleState *state;
} SCTotemPuzzleObject;

typedef struct SCTotemPuzzleParticleBox {
    u8 pad00[8];
    f32 alpha;
    f32 x;
    f32 y;
    f32 z;
} SCTotemPuzzleParticleBox;

extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void objfx_spawnArcedBurst(int obj, int enabled, f32 radius, int particleKind,
                                   int particleId, int lifetime, f32 scaleX, f32 scaleY,
                                   f32 scaleZ, void *args, int arg9);
extern int *objFindTexture(int obj, int textureIndex, int materialIndex);
extern void objRenderFn_8003b8f4(f32);

extern f32 lbl_803E55F0;
extern f32 lbl_803E55F4;
extern f32 lbl_803E55F8;
extern f32 lbl_803E55FC;
extern f32 lbl_803E5600;
extern f32 lbl_803E5604;
extern f32 lbl_803E5608;

#pragma scheduling off
#pragma peephole off
int sc_totempuzzle_checkSolvedSequence(SCTotemPuzzleObject *obj, SCTotemPuzzleState *state)
{
    SCTotemPuzzleParticleBox particleBox;
    int objectIndex;
    int objectCount;
    int *objects;
    int solvedCount;
    u8 solvedThisObject;

    solvedThisObject = 0;
    solvedCount = 0;
    objects = ObjList_GetObjects(&objectIndex, &objectCount);

    while (objectIndex < objectCount) {
        SCTotemPuzzleObject *peer;
        SCTotemPuzzleState *peerState;
        s16 flags;

        peer = (SCTotemPuzzleObject *)objects[objectIndex];
        if (peer->objectType == SC_TOTEMPUZZLE_OBJECT_TYPE) {
            peerState = peer->state;
            flags = peerState->flags;
            if ((flags & SC_TOTEMPUZZLE_READY_FLAG) != 0) {
                if ((flags & SC_TOTEMPUZZLE_REVERSED_FLAG) != 0) {
                    if (peerState->step + 1 == SC_TOTEMPUZZLE_FORWARD_STEP) {
                        solvedCount++;
                        if (peer == obj) {
                            state->angleTarget = lbl_803E55F0 * (f32)(state->step + 1);
                            obj->angle = (s16)(s32)state->angleTarget;
                            solvedThisObject = 1;
                        }
                    } else if (peer == obj) {
                        Sfx_PlayFromObject(0, SC_TOTEMPUZZLE_WRONG_SFX);
                    }
                } else if (peerState->step == SC_TOTEMPUZZLE_FORWARD_STEP) {
                    solvedCount++;
                    if (peer == obj) {
                        state->angleTarget = lbl_803E55F0 * (f32)state->step;
                        obj->angle = (s16)(s32)state->angleTarget;
                        solvedThisObject = 1;
                    }
                } else if (peer == obj) {
                    Sfx_PlayFromObject(0, SC_TOTEMPUZZLE_WRONG_SFX);
                }
            }
        }
        objectIndex++;
    }

    if (solvedThisObject != 0) {
        particleBox.x = lbl_803E55F4;
        particleBox.y = lbl_803E55F8;
        particleBox.z = lbl_803E55F4;
        particleBox.alpha = lbl_803E55FC;

        objectIndex = 20;
        while (objectIndex != 0) {
            objfx_spawnArcedBurst((int)obj, 7, lbl_803E5600, 5, 7, 100, lbl_803E5604,
                                   lbl_803E5604, lbl_803E5608, &particleBox, 0);
            objectIndex--;
        }

        objects = objFindTexture((int)obj, 0, 0);
        if (objects != NULL) {
            *objects = 0x100;
        }
    }

    if (solvedCount == SC_TOTEMPUZZLE_SOLVED_COUNT) {
        if (solvedThisObject != 0) {
            Sfx_PlayFromObject(0, SC_TOTEMPUZZLE_COMPLETE_SFX);
        }
        return 1;
    }

    if (solvedThisObject != 0) {
        Sfx_PlayFromObject(0, SC_TOTEMPUZZLE_PROGRESS_SFX);
    }
    return 0;
}
#pragma peephole reset
#pragma scheduling reset

int sc_totempuzzle_getExtraSize(void)
{
    return 0x14;
}

int sc_totempuzzle_getObjectTypeId(void)
{
    return 0;
}

void sc_totempuzzle_free(void)
{
}

#pragma peephole off
void sc_totempuzzle_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;

    if (v != 0) {
        objRenderFn_8003b8f4(lbl_803E55FC);
    }
}
#pragma peephole reset

void sc_totempuzzle_hitDetect(void)
{
}
