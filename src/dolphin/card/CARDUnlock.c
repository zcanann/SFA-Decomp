#include <dolphin.h>
#include <dolphin/card.h>

#include "dolphin/card/__card.h"

extern unsigned long int lbl_803DC600;

static u32 CARDUnlockProgram[88] = {
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000021, 0x02FF0021,
    0x13061203, 0x12041305, 0x009200FF, 0x0088FFFF,
    0x0089FFFF, 0x008AFFFF, 0x008BFFFF, 0x8F0002BF,
    0x008816FC, 0xDCD116FD, 0x000016FB, 0x000102BF,
    0x008E25FF, 0x0380FF00, 0x02940027, 0x02BF008E,
    0x1FDF24FF, 0x02400FFF, 0x00980400, 0x009A0010,
    0x00990000, 0x8E0002BF, 0x009402BF, 0x864402BF,
    0x008816FC, 0xDCD116FD, 0x000316FB, 0x00018F00,
    0x02BF008E, 0x0380CDD1, 0x02940048, 0x27FF0380,
    0x00010295, 0x005A0380, 0x00020295, 0x8000029F,
    0x00480021, 0x8E0002BF, 0x008E25FF, 0x02BF008E,
    0x25FF02BF, 0x008E25FF, 0x02BF008E, 0x00C5FFFF,
    0x03400FFF, 0x1C9F02BF, 0x008E00C7, 0xFFFF02BF,
    0x008E00C6, 0xFFFF02BF, 0x008E00C0, 0xFFFF02BF,
    0x008E20FF, 0x03400FFF, 0x1F5F02BF, 0x008E21FF,
    0x02BF008E, 0x23FF1205, 0x1206029F, 0x80B50021,
    0x27FC03C0, 0x8000029D, 0x008802DF, 0x27FE03C0,
    0x8000029C, 0x008E02DF, 0x2ECE2CCF, 0x00F8FFCD,
    0x00F9FFC9, 0x00FAFFCB, 0x26C902C0, 0x0004029D,
    0x009C02DF, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
};

typedef struct DecodeParameters {
    u8* inputAddr;
    u32 inputLength;
    u32 aramAddr;
    u8* outputAddr;
} DecodeParameters;

static void InitCallback(void* task);
static void DoneCallback(void* task);

static inline int CARDRand(void) {
    lbl_803DC600 = lbl_803DC600 * 1103515245 + 12345;
    return (int)((unsigned int)(lbl_803DC600 / 65536) % 32768);
}

static inline void CARDSrand(unsigned int seed) {
    lbl_803DC600 = seed;
}

static inline u32 GetInitVal(void) {
    u32 tmp;
    u32 tick;

    tick = OSGetTick();
    CARDSrand(tick);
    tmp = 0x7fec8000;
    tmp |= CARDRand();
    tmp &= 0xfffff000;
    return tmp;
}

static inline u32 exnor_1st(u32 data, u32 rshift) {
    u32 wk;
    u32 w;
    u32 i;

    w = data;
    for (i = 0; i < rshift; i++) {
        wk = ~(w ^ (w >> 7) ^ (w >> 15) ^ (w >> 23));
        w = (w >> 1) | ((wk << 30) & 0x40000000);
    }
    return w;
}

static inline u32 exnor(u32 data, u32 lshift) {
    u32 wk;
    u32 w;
    u32 i;

    w = data;
    for (i = 0; i < lshift; i++) {
        wk = ~(w ^ (w << 7) ^ (w << 15) ^ (w << 23));
        w = (w << 1) | ((wk >> 30) & 0x00000002);
    }
    return w;
}

static u32 bitrev(u32 data) {
    u32 wk;
    u32 i;
    u32 k = 0;
    u32 j = 1;

    wk = 0;
    for (i = 0; i < 32; i++) {
        if (i > 15) {
            if (i == 31) {
                wk |= (((data & (0x01 << 31)) >> 31) & 0x01);
            } else {
                wk |= ((data & (0x01 << i)) >> j);
                j += 2;
            }
        } else {
            wk |= ((data & (0x01 << i)) << (31 - i - k));
            k++;
        }
    }
    return wk;
}

#define SEC_AD1(x) ((u8)(((x) >> 29) & 0x03))
#define SEC_AD2(x) ((u8)(((x) >> 21) & 0xff))
#define SEC_AD3(x) ((u8)(((x) >> 19) & 0x03))
#define SEC_BA(x) ((u8)(((x) >> 12) & 0x7f))

static s32 ReadArrayUnlock(s32 chan, u32 data, void* rbuf, s32 rlen, s32 mode) {
    CARDControl* card;
    BOOL err;
    u8 cmd[5];

    card = &__CARDBlock[chan];
    if (!EXISelect(chan, 0, 4)) {
        return CARD_RESULT_NOCARD;
    }

    data &= 0xfffff000;
    memset(cmd, 0, 5);
    cmd[0] = 0x52;
    if (mode == 0) {
        cmd[1] = SEC_AD1(data);
        cmd[2] = SEC_AD2(data);
        cmd[3] = SEC_AD3(data);
        cmd[4] = SEC_BA(data);
    } else {
        cmd[1] = (u8)((data & 0xff000000) >> 24);
        cmd[2] = (u8)((data & 0x00ff0000) >> 16);
    }

    err = FALSE;
    err |= !EXIImmEx(chan, cmd, 5, 1);
    err |= !EXIImmEx(chan, (u8*)card->workArea + (u32)sizeof(CARDID), card->latency, 1);
    err |= !EXIImmEx(chan, rbuf, rlen, 0);
    err |= !EXIDeselect(chan);

    return err ? CARD_RESULT_NOCARD : CARD_RESULT_READY;
}

static s32 DummyLen(void) {
    u32 tick;
    u32 wk;
    s32 tmp;
    u32 max;

    wk = 1;
    max = 0;
    tick = OSGetTick();
    CARDSrand(tick);

    tmp = CARDRand();
    tmp &= 0x0000001f;
    tmp += 1;
    while ((tmp < 4) && (max < 10)) {
        tick = OSGetTick();
        tmp = (s32)(tick << wk);
        wk++;
        if (wk > 16) {
            wk = 1;
        }
        CARDSrand((u32)tmp);
        tmp = CARDRand();
        tmp &= 0x0000001f;
        tmp += 1;
        max++;
    }
    if (tmp < 4) {
        tmp = 4;
    }

    return tmp;
}

s32 __CARDUnlock(s32 chan, u8 flashID[12]) {
    u32 init_val;
    u32 data;

    s32 dummy;
    s32 rlen;
    u32 rshift;

    u8 fsts;
    u32 wk, wk1;
    u32 Ans1 = 0;
    u32 Ans2 = 0;
    u32* dp;
    u8 rbuf[64];
    u32 para1A = 0;
    u32 para1B = 0;
    u32 para2A = 0;
    u32 para2B = 0;

    CARDControl* card;
    DSPTaskInfo* task;
    DecodeParameters* param;
    u8* input;
    u8* output;

    card = &__CARDBlock[chan];
    task = &card->task;
    param = (DecodeParameters*)card->workArea;
    input = (u8*)((u8*)param + sizeof(DecodeParameters));
    input = (u8*)OSRoundUp32B(input);
    output = input + 32;

    fsts = 0;
    init_val = GetInitVal();

    dummy = DummyLen();
    rlen = dummy;
    if (ReadArrayUnlock(chan, init_val, rbuf, rlen, 0) < 0) {
        return CARD_RESULT_NOCARD;
    }

    rshift = (u32)(dummy * 8 + 1);
    wk = exnor_1st(init_val, rshift);
    wk1 = ~(wk ^ (wk >> 7) ^ (wk >> 15) ^ (wk >> 23));
    card->scramble = (wk | ((wk1 << 31) & 0x80000000));
    card->scramble = bitrev(card->scramble);
    dummy = DummyLen();
    rlen = 20 + dummy;
    data = 0;
    if (ReadArrayUnlock(chan, data, rbuf, rlen, 1) < 0) {
        return CARD_RESULT_NOCARD;
    }
    dp = (u32*)rbuf;
    para1A = *dp++;
    para1B = *dp++;
    Ans1 = *dp++;
    para2A = *dp++;
    para2B = *dp++;
    para1A = (para1A ^ card->scramble);
    rshift = 32;
    wk = exnor(card->scramble, rshift);
    wk1 = ~(wk ^ (wk << 7) ^ (wk << 15) ^ (wk << 23));
    card->scramble = (wk | ((wk1 >> 31) & 0x00000001));
    para1B = (para1B ^ card->scramble);
    rshift = 32;
    wk = exnor(card->scramble, rshift);
    wk1 = ~(wk ^ (wk << 7) ^ (wk << 15) ^ (wk << 23));
    card->scramble = (wk | ((wk1 >> 31) & 0x00000001));
    Ans1 ^= card->scramble;
    rshift = 32;
    wk = exnor(card->scramble, rshift);
    wk1 = ~(wk ^ (wk << 7) ^ (wk << 15) ^ (wk << 23));
    card->scramble = (wk | ((wk1 >> 31) & 0x00000001));
    para2A = (para2A ^ card->scramble);
    rshift = 32;
    wk = exnor(card->scramble, rshift);
    wk1 = ~(wk ^ (wk << 7) ^ (wk << 15) ^ (wk << 23));
    card->scramble = (wk | ((wk1 >> 31) & 0x00000001));
    para2B = (para2B ^ card->scramble);
    rshift = (u32)(dummy * 8);
    wk = exnor(card->scramble, rshift);
    wk1 = ~(wk ^ (wk << 7) ^ (wk << 15) ^ (wk << 23));
    card->scramble = (wk | ((wk1 >> 31) & 0x00000001));
    rshift = 32 + 1;
    wk = exnor(card->scramble, rshift);
    wk1 = ~(wk ^ (wk << 7) ^ (wk << 15) ^ (wk << 23));
    card->scramble = (wk | ((wk1 >> 31) & 0x00000001));

    *(u32*)&input[0] = para2A;
    *(u32*)&input[4] = para2B;

    param->inputAddr = input;
    param->inputLength = 8;
    param->outputAddr = output;
    param->aramAddr = 0;

    DCFlushRange(input, 8);
    DCInvalidateRange(output, 4);
    DCFlushRange(param, sizeof(DecodeParameters));

    task->priority = 255;
    task->iram_mmem_addr = (u16*)OSPhysicalToCached(CARDUnlockProgram);
    task->iram_length = 0x160;
    task->iram_addr = 0;
    task->dsp_init_vector = 0x10;
    task->init_cb = InitCallback;
    task->res_cb = NULL;
    task->done_cb = DoneCallback;
    task->req_cb = NULL;
    DSPAddTask(task);

    dp = (u32*)flashID;
    *dp++ = para1A;
    *dp++ = para1B;
    *dp = Ans1;

    return CARD_RESULT_READY;
}

static void InitCallback(void* _task) {
    s32 chan;
    CARDControl* card;
    DSPTaskInfo* task;
    DecodeParameters* param;

    task = _task;
    for (chan = 0; chan < 2; ++chan) {
        card = &__CARDBlock[chan];
        if ((DSPTaskInfo*)&card->task == task) {
            break;
        }
    }
    param = (DecodeParameters*)card->workArea;

    DSPSendMailToDSP(0xff000000);
    while (DSPCheckMailToDSP())
        ;

    DSPSendMailToDSP((u32)param);
    while (DSPCheckMailToDSP())
        ;
}

static void DoneCallback(void* _task) {
    u8 rbuf[64];
    u32 data;
    s32 dummy;
    s32 rlen;
    u32 rshift;

    u8 unk;
    u32 wk, wk1;
    u32 Ans2;

    s32 chan;
    CARDControl* card;
    s32 result;
    DSPTaskInfo* task;
    DecodeParameters* param;

    u8* input;
    u8* output;
    task = _task;
    for (chan = 0; chan < 2; ++chan) {
        card = &__CARDBlock[chan];
        if ((DSPTaskInfo*)&card->task == task) {
            break;
        }
    }

    param = (DecodeParameters*)card->workArea;
    input = (u8*)((u8*)param + sizeof(DecodeParameters));
    input = (u8*)OSRoundUp32B(input);
    output = input + 32;

    Ans2 = *(u32*)output;
    dummy = DummyLen();
    rlen = dummy;
    data = ((Ans2 ^ card->scramble) & 0xffff0000);
    if (ReadArrayUnlock(chan, data, rbuf, rlen, 1) < 0) {
        EXIUnlock(chan);
        __CARDMountCallback(chan, CARD_RESULT_NOCARD);
        return;
    }

    rshift = (u32)((dummy + 4 + card->latency) * 8 + 1);
    wk = exnor(card->scramble, rshift);
    wk1 = ~(wk ^ (wk << 7) ^ (wk << 15) ^ (wk << 23));
    card->scramble = (wk | ((wk1 >> 31) & 0x00000001));

    dummy = DummyLen();
    rlen = dummy;
    data = (((Ans2 << 16) ^ card->scramble) & 0xffff0000);
    if (ReadArrayUnlock(chan, data, rbuf, rlen, 1) < 0) {
        EXIUnlock(chan);
        __CARDMountCallback(chan, CARD_RESULT_NOCARD);
        return;
    }
    result = __CARDReadStatus(chan, &unk);
    if (!EXIProbe(chan)) {
        EXIUnlock(chan);
        __CARDMountCallback(chan, CARD_RESULT_NOCARD);
        return;
    }
    if (result == CARD_RESULT_READY && !(unk & 0x40)) {
        EXIUnlock(chan);
        result = CARD_RESULT_IOERROR;
    }
    __CARDMountCallback(chan, result);
}
