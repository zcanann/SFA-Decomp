#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_8027CAF4.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_802420e0();
extern undefined4 FUN_80242148();
extern undefined4 FUN_80242178();
extern int synthHandleVirtualSampleDone();
extern undefined4 FUN_8027afc4();
extern undefined4 FUN_8027afcc();
extern int FUN_8027afd4();
extern undefined4 FUN_8027c498();
extern undefined4 FUN_8027f2ac();

extern undefined4 DAT_800000f8;
extern undefined DAT_802c2e38;
extern undefined2 DAT_802c2e78;
extern undefined DAT_80330a00;
extern undefined4 DAT_803cce40;
extern undefined4 DAT_803cce88;
extern undefined4 DAT_803def90;
extern undefined2* DAT_803def94;
extern undefined2* DAT_803def98;
extern undefined4 DAT_803def9c;
extern undefined2* DAT_803defa0;
extern undefined2* DAT_803defa4;
extern undefined2* DAT_803defa8;
extern undefined4 DAT_803defac;
extern undefined2* DAT_803defb0;
extern undefined4 DAT_803defb4;
extern undefined4 DAT_803defbc;
extern undefined4* DAT_803defc8;
extern undefined4 DAT_803deffc;
extern undefined4 DAT_803deffe;
extern undefined4 DAT_803defff;

/*
 * --INFO--
 *
 * Function: FUN_8027c48c
 * EN v1.0 Address: 0x8027C48C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8027CAF4
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8027c48c(int param_1,int param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8027c490
 * EN v1.0 Address: 0x8027C490
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8027CBF0
 * EN v1.1 Size: 10828b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8027c490(undefined4 param_1,uint param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8027c494
 * EN v1.0 Address: 0x8027C494
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8027F63C
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_8027c494(int param_1,undefined4 param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8027c49c
 * EN v1.0 Address: 0x8027C49C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8027F680
 * EN v1.1 Size: 164b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8027c49c(int param_1,byte param_2)
{
}

extern u8 lbl_803CC1E0[];
extern u8 salAuxFrame;
extern u8 salMaxStudioNum;
extern void DCFlushRangeNoSync(void *addr, int len);

typedef struct SalVoice {
    u8 pad0[0xc];
    struct SalVoice *next;
    struct SalVoice *prev;
    u8 pad14[0x10];
    u32 flags;
    u8 pad28[0xc4];
    u8 active;
    u8 pendingDeactivate;
    u8 needsUpdate;
    u8 studioIndex;
} SalVoice;

typedef struct SalStudioInputSource {
    u8 volume;
    u8 panning;
    u8 surroundPanning;
    u8 auxBus;
} SalStudioInputSource;

typedef struct SalStudioInput {
    u8 auxBus;
    u8 pad1;
    u16 volume;
    u16 panning;
    u16 surroundPanning;
    SalStudioInputSource *source;
} SalStudioInput;

typedef struct SalStudio {
    u8 pad0[0x48];
    SalVoice *voiceList;
    SalVoice *deferredVoiceList;
    u8 pad50[2];
    u8 inputCount;
    u8 pad53[5];
    SalStudioInput inputs[7];
    u8 padAC[0x10];
} SalStudio;

extern int (*salMessageCallback)(int msg, int arg);
extern void salDeactivateVoice(SalVoice *voice);

int salSynthSendMessage(int synth, int msg) {
    if (salMessageCallback == NULL) {
        return 0;
    }
    return salMessageCallback(msg, *(int *)(synth + 0x18));
}

void salActivateVoice(SalVoice *voice, u8 idx) {
    u8 *st;

    if (voice->active != 0) {
        salDeactivateVoice(voice);
        voice->flags |= 0x20;
    }
    voice->pendingDeactivate = 0;
    st = lbl_803CC1E0 + idx * 0xbc;
    if ((voice->next = *(SalVoice **)(st + 0x48)) != NULL) {
        voice->next->prev = voice;
    }
    voice->prev = NULL;
    *(SalVoice **)(st + 0x48) = voice;
    voice->needsUpdate = 0;
    voice->active = 1;
    voice->studioIndex = idx;
}

void salDeactivateVoice(SalVoice *voice) {
    SalVoice *prev;
    SalVoice *next;

    if (voice->active == 0) {
        return;
    }
    prev = voice->prev;
    if (prev != NULL) {
        prev->next = voice->next;
    } else {
        *(SalVoice **)(lbl_803CC1E0 + voice->studioIndex * 0xbc + 0x48) = voice->next;
    }
    next = voice->next;
    if (next != NULL) {
        next->prev = voice->prev;
    }
    voice->active = 0;
}

int salAddStudioInput(SalStudio *studio, SalStudioInputSource *input) {
    if (studio->inputCount < 7) {
        studio->inputs[studio->inputCount].auxBus = input->auxBus;
        studio->inputs[studio->inputCount].volume = (input->volume << 8) | (input->volume << 1);
        studio->inputs[studio->inputCount].panning = (input->panning << 8) | (input->panning << 1);
        studio->inputs[studio->inputCount].surroundPanning =
            (input->surroundPanning << 8) | (input->surroundPanning << 1);
        studio->inputs[studio->inputCount].source = input;
        studio->inputCount++;
        return 1;
    }
    return 0;
}

int salRemoveStudioInput(SalStudio *studio, SalStudioInputSource *input) {
    int n;
    int idx = 0;
    u8 *p = (u8 *)studio;

    for (n = studio->inputCount; n > 0; n--) {
        if (*(SalStudioInputSource **)(p + 0x60) == input) {
            p = (u8 *)studio + idx * 0xc;
            for (; idx <= studio->inputCount - 2; idx++) {
                *(SalStudioInput *)(p + 0x58) = *(SalStudioInput *)(p + 0x64);
                p += 0xc;
            }
            studio->inputCount--;
            return 1;
        }
        p += 0xc;
        idx++;
    }
    return 0;
}

void salHandleAuxProcessing(void) {
    int i;
    char *studio;
    int buf;
    void *bufs[3];

    studio = (char *)lbl_803CC1E0;
    for (i = 0; (u8)i < salMaxStudioNum; i++, studio += 0xbc) {
        if (*(u8 *)(studio + 0x50) == 1) {
            if (*(void **)(studio + 0xac) != NULL) {
                buf = *(int *)(studio + ((salAuxFrame + 2) % 3) * 4 + 0x30);
                bufs[0] = (void *)buf;
                bufs[1] = (void *)(buf + 0x280);
                bufs[2] = (void *)(buf + 0x500);
                (*(void (*)(int, void *, int))*(int *)(studio + 0xac))(0, bufs, *(int *)(studio + 0xb4));
                DCFlushRangeNoSync((void *)buf, 0x780);
            }
            if (*(int *)(studio + 0x54) == 0 && *(void **)(studio + 0xb0) != NULL) {
                buf = *(int *)(studio + ((salAuxFrame + 2) % 3) * 4 + 0x3c);
                bufs[0] = (void *)buf;
                bufs[1] = (void *)(buf + 0x280);
                bufs[2] = (void *)(buf + 0x500);
                (*(void (*)(int, void *, int))*(int *)(studio + 0xb0))(0, bufs, *(int *)(studio + 0xb8));
                DCFlushRangeNoSync((void *)buf, 0x780);
            }
        }
    }
}
