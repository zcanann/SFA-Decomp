#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80284BAC.h"

extern u32 gSalMallocHook[2];
extern void ReverbSTDCallback(int a, int b, int c, void *state);
extern int ReverbSTDCreate(void *state, f32 a, f32 b, f32 c, f32 d, f32 e);

typedef struct ReverbParams {
    int p0;
    int p4;
    int p8;
} ReverbParams;

typedef struct ReverbState {
    u8 unk0[0x13c];
    u8 enabled;
    u8 unk13D[3];
    f32 a;
    f32 c;
    f32 b;
    f32 d;
    f32 e;
} ReverbState;

/*
 * --INFO--
 *
 * Function: salFree
 * EN v1.0 Address: 0x80284B94
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80284BAC
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void salFree(void *ptr)
{
    ((void (*)(void *))gSalMallocHook[1])(ptr);
}

/*
 * --INFO--
 *
 * Function: sndAuxCallbackReverbSTD
 * EN v1.0 Address: 0x80284B98
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80284BC0
 * EN v1.1 Size: 92b
 */
void sndAuxCallbackReverbSTD(u8 mode, ReverbParams *params, ReverbState *state)
{
    switch ((int)mode) {
    case 0:
        if (state->enabled == 0) {
            ReverbSTDCallback(params->p0, params->p4, params->p8, state);
        }
        break;
    case 1:
        break;
    }
}

/*
 * --INFO--
 *
 * Function: sndAuxCallbackUpdateSettingsReverbSTD
 * EN v1.0 Address: 0x80284B9C
 * EN v1.0 Size: 4b (stub)
 * EN v1.1 Address: 0x80284C1C
 * EN v1.1 Size: 60b
 */
void sndAuxCallbackUpdateSettingsReverbSTD(ReverbState *state)
{
    state->enabled = 0;
    ReverbSTDCreate(state, state->a, state->b, state->c, state->d, state->e);
}
