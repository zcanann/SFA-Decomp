#include "main/camera_interface.h"
#include "main/game_object.h"
#include "main/objlib.h"
#include "main/objseq.h"
#include "util/carry.h"
#include "string.h"
#include "dolphin/os/OSCache.h"
#include "main/mm.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
extern int randomGetRange(int lo, int hi);
extern u32 FUN_802420b0();
extern u32 FUN_802420e0();
extern int FUN_802640ac();
extern int FUN_80264428();
extern u32 FUN_80264624();
extern u32 DAT_80397560;
extern u32 DAT_803dc360;
extern u32 DAT_803dc364;
extern u32 DAT_803ddcc4;
extern u32 DAT_803ddcd0;
extern u32 DAT_803ddcd4;
extern u32 DAT_803ddd0c;
extern f32 lbl_803DC074;
extern f32 lbl_803DFC20;
extern int lbl_803DD044;

int saveCb_8007e77c(u8 idx, int unused, void* dst)
{
    memcpy(dst, (void*)(lbl_803DD044 + idx * 1772 + 2640), 1772);
    return 0;
}

int FUN_8007eb04(u32 slot)
{
    u32 xorEven;
    u32 xorOdd;
    u32 scratch3;
    u16 i;
    u32 scratch5;
    u32 scratch6;
    u32 scratch7;
    u32 scratch8;
    u32 scratch9;
    u32 scratch10;
    u32 scratch11;
    u32 scratch12;
    int scratch13;
    int sum2;
    u32 scratch15;
    u32 scratch16;
    u32 scratch17;
    u32 scratch18;
    u32 scratch19;
    u32 scratch20;
    u32 scratch21;
    u32 scratch22;
    u32* wp;
    u32 scratch24;
    bool carry;

    scratch7 = DAT_803ddcc4;
    xorOdd = 0;
    xorEven = 0;
    scratch6 = 1;
    scratch13 = 0;
    for (i = 0; i < 0x3f7; i = i + 8)
    {
        wp = (u32*)(DAT_803ddcc4 + (u32)i * 8);
        scratch12 = wp[1];
        carry = addCarryOut32(scratch6, scratch12);
        scratch3 = scratch6 + scratch12;
        scratch15 = wp[3];
        scratch5 = scratch3 + scratch15;
        scratch16 = wp[5];
        scratch24 = scratch5 + scratch16;
        scratch17 = wp[7];
        scratch8 = scratch24 + scratch17;
        scratch18 = wp[9];
        scratch9 = scratch8 + scratch18;
        scratch19 = wp[0xb];
        scratch10 = scratch9 + scratch19;
        scratch20 = wp[0xd];
        scratch11 = scratch10 + scratch20;
        scratch21 = wp[0xf];
        xorOdd = xorOdd ^ scratch12 ^ scratch15 ^ scratch16 ^ scratch17 ^ scratch18 ^ scratch19 ^ scratch20 ^ scratch21;
        xorEven = xorEven ^ *wp ^ wp[2] ^ wp[4] ^ wp[6] ^ wp[8] ^ wp[10] ^
            wp[0xc] ^ wp[0xe];
        scratch6 = scratch11 + scratch21;
        scratch13 = scratch13 + *wp + (u32)carry + wp[2] + (u32)addCarryOut32(scratch3, scratch15) +
            wp[4] + (u32)addCarryOut32(scratch5, scratch16) + wp[6] + (u32)addCarryOut32(scratch24, scratch17) +
            wp[8] + (u32)addCarryOut32(scratch8, scratch18) + wp[10] + (u32)addCarryOut32(scratch9, scratch19) +
            wp[0xc] + (u32)addCarryOut32(scratch10, scratch20) + wp[0xe] + (u32)addCarryOut32(scratch11, scratch21);
    }
    for (; i < 0x3ff; i = i + 1)
    {
        wp = (u32*)(DAT_803ddcc4 + (u32)i * 8);
        scratch3 = *wp;
        scratch5 = wp[1];
        xorOdd = xorOdd ^ scratch5;
        xorEven = xorEven ^ scratch3;
        carry = addCarryOut32(scratch6, scratch5);
        scratch6 = scratch6 + scratch5;
        scratch13 = scratch13 + scratch3 + carry;
    }
    xorOdd = xorOdd ^ scratch6 + 0xd;
    xorEven = xorEven ^ scratch13 + (u32)(0xfffffff2 < scratch6);
    *(u32*)(DAT_803ddcc4 + 0x1ffc) = xorOdd;
    *(u32*)(scratch7 + 0x1ff8) = xorEven;
    FUN_802420e0(DAT_803ddcc4, 0x2000);
    scratch7 = (slot & 0xff) << 0xd;
    scratch13 = FUN_80264428((int*)&DAT_80397560, DAT_803ddcc4, 0x2000, scratch7);
    if (scratch13 == -5)
    {
        FUN_80264624(0, DAT_803dc364);
    }
    scratch6 = DAT_803ddcd0;
    scratch3 = DAT_803ddcd4;
    if (scratch13 == 0)
    {
        FUN_802420b0(DAT_803ddcc4, 0x2000);
        scratch13 = FUN_802640ac((int*)&DAT_80397560, DAT_803ddcc4, 0x2000, scratch7);
        scratch6 = DAT_803ddcd0;
        scratch3 = DAT_803ddcd4;
        if (scratch13 == 0)
        {
            scratch3 = 0;
            scratch6 = 0;
            scratch7 = 1;
            sum2 = 0;
            for (i = 0; i < 0x3f7; i = i + 8)
            {
                wp = (u32*)(DAT_803ddcc4 + (u32)i * 8);
                scratch15 = wp[1];
                carry = addCarryOut32(scratch7, scratch15);
                scratch5 = scratch7 + scratch15;
                scratch16 = wp[3];
                scratch24 = scratch5 + scratch16;
                scratch17 = wp[5];
                scratch8 = scratch24 + scratch17;
                scratch18 = wp[7];
                scratch9 = scratch8 + scratch18;
                scratch19 = wp[9];
                scratch10 = scratch9 + scratch19;
                scratch20 = wp[0xb];
                scratch11 = scratch10 + scratch20;
                scratch21 = wp[0xd];
                scratch12 = scratch11 + scratch21;
                scratch22 = wp[0xf];
                scratch3 = scratch3 ^ scratch15 ^ scratch16 ^ scratch17 ^ scratch18 ^ scratch19 ^ scratch20 ^ scratch21 ^ scratch22;
                scratch6 = scratch6 ^ *wp ^ wp[2] ^ wp[4] ^ wp[6] ^ wp[8] ^ wp[10] ^
                    wp[0xc] ^ wp[0xe];
                scratch7 = scratch12 + scratch22;
                sum2 = sum2 + *wp + (u32)carry + wp[2] + (u32)addCarryOut32(scratch5, scratch16) +
                    wp[4] + (u32)addCarryOut32(scratch24, scratch17) + wp[6] + (u32)addCarryOut32(scratch8, scratch18)
                    + wp[8] + (u32)addCarryOut32(scratch9, scratch19) +
                    wp[10] + (u32)addCarryOut32(scratch10, scratch20) +
                    wp[0xc] + (u32)addCarryOut32(scratch11, scratch21) +
                    wp[0xe] + (u32)addCarryOut32(scratch12, scratch22);
            }
            for (; i < 0x3ff; i = i + 1)
            {
                wp = (u32*)(DAT_803ddcc4 + (u32)i * 8);
                scratch5 = *wp;
                scratch24 = wp[1];
                scratch3 = scratch3 ^ scratch24;
                scratch6 = scratch6 ^ scratch5;
                carry = addCarryOut32(scratch7, scratch24);
                scratch7 = scratch7 + scratch24;
                sum2 = sum2 + scratch5 + carry;
            }
            scratch3 = scratch3 ^ scratch7 + 0xd;
            scratch6 = scratch6 ^ sum2 + (u32)(0xfffffff2 < scratch7);
            if (xorOdd != scratch3 || xorEven != scratch6)
            {
                scratch13 = -0x55;
                DAT_803dc360 = 10;
                scratch6 = DAT_803ddcd0;
                scratch3 = DAT_803ddcd4;
            }
        }
    }
    DAT_803ddcd4 = scratch3;
    DAT_803ddcd0 = scratch6;
    return scratch13;
}

u32
FUN_8007f350(u64 param_1, double param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, char param_9
             , u32 param_10, u32 param_11, u32 param_12, u32 param_13,
             u32 param_14, u32 param_15, u32 param_16)
{
    return 0;
}

int FUN_8007f3c8(int* arr, int count, int target)
{
    int v;
    int idx;

    idx = 0;
    if (0 < count)
    {
        do
        {
            v = *arr;
            arr = arr + 1;
            if (v == target)
            {
                return idx;
            }
            idx = idx + 1;
            count = count + -1;
        }
        while (count != 0);
    }
    return -1;
}

int FUN_8007f56c(int* pairs, int count, int key)
{
    int lo;
    int next;
    int mid;

    if (0x10 < count)
    {
        lo = 0;
        while (true)
        {
            mid = count + lo >> 1;
            next = mid;
            if ((key <= pairs[mid * 2]) &&
                (count = mid, next = lo, key == pairs[mid * 2]))
                break;
            lo = next;
            if (next < count)
            {
                return 0;
            }
        }
        return pairs[mid * 2 + 1];
    }
    if (count != 0)
    {
        do
        {
            if (*pairs == key)
            {
                return pairs[1];
            }
            pairs = pairs + 2;
            count = count + -1;
        }
        while (count != 0);
    }
    return 0;
}

u32 FUN_8007f6c8(float* timer)
{
    return ((u32)(u8)((lbl_803DFC20 == *timer) << 1) << 0x1c) >> 0x1d ^ 1;
}

void FUN_8007f6e4(u32* timer)
{
    *timer = lbl_803DFC20;
    return;
}

void FUN_8007f718(float* out, short val)
{
    *out = (float)((double)(int)val);
    return;
}

u32 FUN_8007f764(float* timer)
{
    float zero;

    zero = lbl_803DFC20;
    if (*timer != lbl_803DFC20)
    {
        *timer = *timer - lbl_803DC074;
        if (*timer <= zero)
        {
            *timer = zero;
            return 1;
        }
    }
    return 0;
}

u8 FUN_8007f7c0(void)
{
    return DAT_803ddd0c;
}

extern u8 curSeqNo;
extern u32 focusedNpc;
extern s16 seqGlobal2;
extern s16 seqGlobal1;
extern u8 seqGlobal3;
u8 getCurSeqNo(void) { return curSeqNo; }
u32 getFocusedNpc(void) { return focusedNpc; }
void ObjSeq_setGlobal2(s16 x) { seqGlobal2 = x; }
s16 ObjSeq_getGlobal2(void) { return seqGlobal2; }
void ObjSeq_setGlobal1(s16 x) { seqGlobal1 = x; }
s16 ObjSeq_getGlobal1(void) { return seqGlobal1; }
void ObjSeq_setGlobal3(u8 x) { seqGlobal3 = x; }
u8 ObjSeq_getGlobal3(void) { return seqGlobal3; }

extern u32 lbl_803DB700;
void cardSetStatusNoCard2(void) { lbl_803DB700 = 0x3; }

void clearCurSeqNo(void) { curSeqNo = 0x0; }

extern f32 lbl_803DEFA0;
void storeZeroToFloatParam(f32* p) { *p = lbl_803DEFA0; }

extern u32 lbl_803DB714;
extern u32 lbl_803DB71C;

void seqClearTaskTexts(void)
{
    u32 v = -0x1;
    lbl_803DB714 = v;
    lbl_803DB71C = v;
}

extern u8 lbl_803DD0F8;
extern f32 lbl_803DD0F4;
extern f32 lbl_803DD0F0;
extern f32 lbl_803DD0EC;
extern s16 lbl_803DD0E8;
extern s16 lbl_803DD0E6;
extern s16 lbl_803DD0E4;
extern f32 lbl_803DD0E0;
extern s16 lbl_8030ECF8[];

int fn_80080150(f32* p) { return lbl_803DEFA0 != *p; }

void fn_8008020C(s16 a, s16 b, s16 c, f32 x, f32 y, f32 z, f32 w)
{
    lbl_803DD0F8 = 1;
    lbl_803DD0F4 = x;
    lbl_803DD0F0 = y;
    lbl_803DD0EC = z;
    lbl_803DD0E8 = a;
    lbl_803DD0E6 = b;
    lbl_803DD0E4 = c;
    lbl_803DD0E0 = w;
}

static inline int maketex_indexOf(int* p, int n, int target)
{
    int i;
    int j;
    i = 0;
    for (j = 0; j < n; j++)
    {
        if (*p++ == target)
        {
            return i;
        }
        i++;
    }
    return -1;
}

int fn_8007FE04(int* arr, int* count_ptr, int target)
{
    int i;
    int n;
    n = *count_ptr;
    i = maketex_indexOf(arr, n, target);
    if (i == -1) return -1;
    arr[i] = arr[n - 1];
    (*count_ptr)--;
    return i;
}

int fn_80080360(int p, int val)
{
    lbl_8030ECF8[(s8) * (u8*)(p + 0x57)] = (s16)val;
    return 1;
}

extern s16 gObjSeqSlotSeqIdTable[];

int animatedObjGetSeqId(int obj)
{
    return gObjSeqSlotSeqIdTable[(s8) * (u8*)(obj + 0x57)] - 1;
}

void ObjSeq_yield(ObjSeqState* seq, int value)
{
    seq->unk74 = value;
    seq->sequenceControlFlags |= OBJSEQ_CONTROL_RESTART_AT_SAVED_FRAME;
}

extern int objSeqObjs;
extern int lbl_803DD07C;
extern u8 lbl_803DD078;

int ObjSeq_SetObjs(int a, int b, int c)
{
    u8 v = (u8)c;
    objSeqObjs = a;
    lbl_803DD07C = b;
    lbl_803DD078 = v;
    return 1;
}

extern u8 lbl_803DD0D9;
f32 objSeqOverridePos[0x259];

int ObjSeq_setOverridePos(f32 x, f32 y, f32 z)
{
    lbl_803DD0D9 = 1;
    objSeqOverridePos[0] = x;
    objSeqOverridePos[1] = y;
    objSeqOverridePos[2] = z;
    return 1;
}

int arrayIndexOf(int* arr, int count, int target)
{
    int idx = 0;
    int i;
    for (i = 0; i < count; i++)
    {
        int v = *arr;
        arr++;
        if (v == target) return idx;
        idx++;
    }
    return -1;
}

int randFn_80080100(int n)
{
    return randomGetRange(0, n * 60 / 60) == 0;
}

extern f32 timeDelta;

int timerCountDown(f32* p)
{
    f32 v = *p;
    f32 zero = lbl_803DEFA0;
    if (v != zero)
    {
        *p = v - timeDelta;
        if (*p <= zero)
        {
            *p = zero;
            return 1;
        }
    }
    return 0;
}

extern u8 AudioStream_IsPreparing(void);
extern void doNothing_8000CF54(int);
extern void gameTextLoadTaskText(int taskId);
extern void subtitleStart(int);
extern u32 lbl_803DB718;

void streamCb_80080384(void)
{
    AudioStream_IsPreparing();
    doNothing_8000CF54(0);
    if ((s32)lbl_803DB71C != -1)
    {
        gameTextLoadTaskText(lbl_803DB71C);
        lbl_803DB71C = -1;
        lbl_803DB714 = -1;
    }
    else if ((s32)lbl_803DB718 != -1)
    {
        subtitleFn_8001b700();
        subtitleStart(lbl_803DB718);
        lbl_803DB718 = -1;
    }
}

void s16toFloat(f32* p, s16 val)
{
    *p = (f32)val;
}

typedef struct
{
    u8 useWorldSpace : 1;
} SeqB4Flags;

extern SeqB4Flags lbl_803DD0B4;

int ObjSeq_func23(int unused, int x)
{
    switch (x)
    {
    case 0:
        lbl_803DD0B4.useWorldSpace = 1;
        break;
    case 1:
        lbl_803DD0B4.useWorldSpace = 0;
        break;
    }
    return 0;
}

int seqStreamLookupFn_8007fff8(int arr[][2], int count, int key)
{
    int lo, mid;
    int i;
    if (count <= 16)
    {
        for (i = 0; i != count; i++)
        {
            if ((*arr)[0] == key) return (*arr)[1];
            arr++;
        }
        return 0;
    }
    lo = 0;
    do
    {
        mid = (count + lo) >> 1;
        if (key > arr[mid][0])
        {
            lo = mid;
        }
        else if (key == arr[mid][0])
        {
            return arr[mid][1];
        }
        else
        {
            count = mid;
        }
    }
    while (count <= lo);
    return 0;
}

extern int objModelGetVecFn_800395d8(int obj, int idx);

void objModelResetVecFn_80080548(int obj)
{
    s16* v = (s16*)objModelGetVecFn_800395d8(obj, 0);
    if (v != NULL)
    {
        v[1] = 0;
        v[0] = 0;
    }
}

extern u8 lbl_803DD124;
extern int gObjSeqPreemptList[][2];

void ObjSeq_preempt(int a, int b)
{
    u8 c = lbl_803DD124;
    int i = (s8)c;
    if (i >= 40) return;
    gObjSeqPreemptList[i][0] = a;
    gObjSeqPreemptList[i][1] = b;
    lbl_803DD124++;
}

void cameraFocusNpc(int param1, u8* obj)
{
    struct
    {
        f32 vec[3];
        u8 tag;
    } buf;
    f32* p;

    if ((*gCameraInterface)->getMode() == 0x4d) return;
    focusedNpc = (u32)obj;
    p = *(f32**)(obj + 0x74);
    if (p == NULL || param1 == 7 || param1 == 6)
    {
        buf.vec[0] = ((GameObject*)obj)->anim.worldPosX;
        buf.vec[1] = ((GameObject*)obj)->anim.worldPosY;
        buf.vec[2] = ((GameObject*)obj)->anim.worldPosZ;
    }
    else
    {
        buf.vec[0] = p[0];
        buf.vec[1] = p[1];
        buf.vec[2] = p[2];
    }
    buf.tag = (u8)param1;
    (*gCameraInterface)->setMode(0x4d, 1, 0, 0x10, buf.vec, 0, 0xff);
}

typedef struct
{
    int key;
    int val;
} SeqSortPair;

/* EN v1.0 0x8007FEAC  size: 332b  Shell sort over (key, val) pairs,
 * ascending by key. */
#pragma dont_inline on
void objSeqInitFn_8007feac(SeqSortPair* arr, int n)
{
    int key;
    int val;
    int i;
    int j;
    int h;

    h = 1;
    while (h <= (n - 1) / 9)
    {
        h = h * 3 + 1;
    }
    for (; h > 0; h /= 3)
    {
        for (i = h + 1; i < n; i++)
        {
            key = arr[i].key;
            val = arr[i].val;
            j = i;
            while (j > h && arr[j - h].key > key)
            {
                arr[j].key = arr[j - h].key;
                arr[j].val = arr[j - h].val;
                j -= h;
            }
            arr[j].key = key;
            arr[j].val = val;
        }
    }
    for (i = 1; i < n; i++)
    {
    }
}
#pragma dont_inline reset

/* EN v1.0 0x80080078  size: 136b  Spin-delay then sort when the pair list
 * is large enough. */
void objSeqInitFn_80080078(SeqSortPair* arr, int n)
{
    int i;
    int j;

    for (i = 0; i < n; i++)
    {
        for (j = 0; j < n; j++)
        {
        }
    }
    if (n > 0x10)
    {
        objSeqInitFn_8007feac(arr, n);
    }
}

extern void debugPrintf(char* fmt, ...);
extern char sEndObjSequenceMaxFreesError[];
extern void AudioStream_CancelPrepared(void);
extern void Obj_FreeObject(int obj);
extern void* lbl_803DD0B8;
extern int lbl_803DB720;
extern int lbl_803DD064;

/* EN v1.0 0x80080C18  size: 464b  Tears down an object sequence: unbinds
 * every object still tagged with the sequence id, runs each freed object's
 * completion callback, frees the collected objects, and resets the global
 * sequence/camera state when this was the active sequence. */
extern s32 CARDWrite(int* fileInfo, void* buf, s32 length, s32 offset);
extern s32 CARDRead(int* fileInfo, void* buf, s32 length, s32 offset);
extern s32 CARDDelete(s32 chan, char* fileName);
extern int lbl_80396900[];
extern char* sMemoryCardFileName;
extern u64 lbl_803DD050;

/* EN v1.0 0x8007E7C0  size: 900b  Checksums the save buffer, writes it to the
 * memory card, then reads it back and verifies the checksum. */
int saveGame_doWrite(int slot)
{
    u64 x[1];
    u16 i[1];
    u64* p;
    u64 a[1];
    u64 chk;
    u64 chk2;
    int result;
    int offset;

    p = (u64*)lbl_803DD044;
    x[0] = 0;
    a[0] = 1;
    for (i[0] = (int)x[0]; (int)i[0] < 0x3ff; i[0]++)
    {
        u64 v = p[i[0]];
        x[0] = x[0] ^ v;
        a[0] = a[0] + v;
    }
    chk = x[0] ^ (a[0] + 13);
    ((u32*)p)[0x7ff] = (u32)chk;
    ((u32*)p)[0x7fe] = (u32)(chk >> 32);
    DCFlushRange((void*)lbl_803DD044, 0x2000);
    result = CARDWrite(lbl_80396900, (void*)lbl_803DD044, 0x2000, offset = (u8)slot << 13);
    if (result == -5)
    {
        CARDDelete(0, sMemoryCardFileName);
    }
    if (result == 0)
    {
        DCInvalidateRange((void*)lbl_803DD044, 0x2000);
        result = CARDRead(lbl_80396900, (void*)lbl_803DD044, 0x2000, offset);
        if (result == 0)
        {
            p = (u64*)lbl_803DD044;
            x[0] = 0;
            a[0] = 1;
            for (i[0] = (int)x[0]; (int)i[0] < 0x3ff; i[0]++)
            {
                u64 v = p[i[0]];
                x[0] = x[0] ^ v;
                a[0] = a[0] + v;
            }
            chk2 = x[0] ^ (a[0] + 13);
            if (chk != chk2)
            {
                result = -0x55;
                lbl_803DB700 = 10;
            }
            else
            {
                lbl_803DD050 = chk2;
            }
        }
    }
    return result;
}

typedef struct
{
    u8 pad[0x3c];
} DVDFileInfoStub;

extern int DVDOpen(char* fileName, DVDFileInfoStub* fi);
extern int DVDClose(DVDFileInfoStub* fi);
extern int DVDRead(void* fileInfo, void* buf, int size, int offset);

extern u8 lbl_803DC968;
extern int gSaveCardImageBuffer;
extern char sMemoryCardFileNameString[];

/* EN v1.0 0x8007F358  size: 1372b  Builds the memory card comment strings
 * (Shift-JIS title on JP cards), loads the banner/icon images from disc, and
 * checksums both halves of the card image buffer. */
void loadMemCardImages(void)
{
    char* names = sMemoryCardFileNameString;
    DVDFileInfoStub fi;
    u64* p;
    u16 i[1];
    u64 x[1];
    u64* q;
    u64 a[1];
    u64 chk;

    if (lbl_803DC968 != 0)
    {
        *(u8*)(gSaveCardImageBuffer + 0x00) = 0x83;
        *(u8*)(gSaveCardImageBuffer + 0x01) = 0x58;
        *(u8*)(gSaveCardImageBuffer + 0x02) = 0x83;
        *(u8*)(gSaveCardImageBuffer + 0x03) = 0x5e;
        *(u8*)(gSaveCardImageBuffer + 0x04) = 0x81;
        *(u8*)(gSaveCardImageBuffer + 0x05) = 0x5b;
        *(u8*)(gSaveCardImageBuffer + 0x06) = 0x83;
        *(u8*)(gSaveCardImageBuffer + 0x07) = 0x74;
        *(u8*)(gSaveCardImageBuffer + 0x08) = 0x83;
        *(u8*)(gSaveCardImageBuffer + 0x09) = 0x48;
        *(u8*)(gSaveCardImageBuffer + 0x0a) = 0x83;
        *(u8*)(gSaveCardImageBuffer + 0x0b) = 0x62;
        *(u8*)(gSaveCardImageBuffer + 0x0c) = 0x83;
        *(u8*)(gSaveCardImageBuffer + 0x0d) = 0x4e;
        *(u8*)(gSaveCardImageBuffer + 0x0e) = 0x83;
        *(u8*)(gSaveCardImageBuffer + 0x0f) = 0x58;
        *(u8*)(gSaveCardImageBuffer + 0x10) = 0x83;
        *(u8*)(gSaveCardImageBuffer + 0x11) = 0x41;
        *(u8*)(gSaveCardImageBuffer + 0x12) = 0x83;
        *(u8*)(gSaveCardImageBuffer + 0x13) = 0x68;
        *(u8*)(gSaveCardImageBuffer + 0x14) = 0x83;
        *(u8*)(gSaveCardImageBuffer + 0x15) = 0x78;
        *(u8*)(gSaveCardImageBuffer + 0x16) = 0x83;
        *(u8*)(gSaveCardImageBuffer + 0x17) = 0x93;
        *(u8*)(gSaveCardImageBuffer + 0x18) = 0x83;
        *(u8*)(gSaveCardImageBuffer + 0x19) = 0x60;
        *(u8*)(gSaveCardImageBuffer + 0x1a) = 0x83;
        *(u8*)(gSaveCardImageBuffer + 0x1b) = 0x83;
        *(u8*)(gSaveCardImageBuffer + 0x1c) = 0x81;
        *(u8*)(gSaveCardImageBuffer + 0x1d) = 0x5b;
        *(u8*)(gSaveCardImageBuffer + 0x1e) = 0x00;
        *(u8*)(gSaveCardImageBuffer + 0x1f) = 0x00;
        sprintf((char*)(gSaveCardImageBuffer + 0x20), names + 0xa0);
    }
    else
    {
        sprintf((char*)gSaveCardImageBuffer, names);
        sprintf((char*)(gSaveCardImageBuffer + 0x20), names + 0xb4);
    }
    if (DVDOpen(names + 0xc4, &fi))
    {
        DVDRead(&fi, (void*)(gSaveCardImageBuffer + 0x40), 0x1800, 0x20);
        DVDClose(&fi);
    }
    if (DVDOpen(names + 0xd0, &fi))
    {
        DVDRead(&fi, (void*)(gSaveCardImageBuffer + 0x1840), 0x400, 0);
        DVDClose(&fi);
    }
    if (DVDOpen(names + 0xe8, &fi))
    {
        DVDRead(&fi, (void*)(gSaveCardImageBuffer + 0x1c40), 0x400, 0);
        DVDClose(&fi);
    }
    if (DVDOpen(names + 0x100, &fi))
    {
        DVDRead(&fi, (void*)(gSaveCardImageBuffer + 0x2040), 0x400, 0);
        DVDClose(&fi);
    }
    if (DVDOpen(names + 0x118, &fi))
    {
        DVDRead(&fi, (void*)(gSaveCardImageBuffer + 0x2440), 0x400, 0);
        DVDClose(&fi);
    }
    if (DVDOpen(names + 0x130, &fi))
    {
        DVDRead(&fi, (void*)(gSaveCardImageBuffer + 0x2840), 0x200, 0);
        DVDClose(&fi);
    }
    p = (u64*)gSaveCardImageBuffer;
    x[0] = 0;
    a[0] = 1;
    for (i[0] = (int)x[0]; (int)i[0] < 0x400; i[0]++)
    {
        u64 v = p[i[0]];
        x[0] = x[0] ^ v;
        a[0] = a[0] + v;
    }
    chk = x[0] ^ (a[0] + 13);
    ((u32*)p)[0xa91] = (u32)chk;
    ((u32*)p)[0xa90] = (u32)(chk >> 32);
    q = (u64*)gSaveCardImageBuffer;
    p = q + 0x400;
    x[0] = 0;
    a[0] = 1;
    for (i[0] = (int)x[0]; (int)i[0] < 0x3ff; i[0]++)
    {
        u64 v = p[i[0]];
        x[0] = x[0] ^ v;
        a[0] = a[0] + v;
    }
    chk = x[0] ^ (a[0] + 13);
    ((u32*)q)[0xfff] = (u32)chk;
    ((u32*)q)[0xffe] = (u32)(chk >> 32);
    DCFlushRange((void*)gSaveCardImageBuffer, 0x4000);
}

typedef struct
{
    char fileName[32];
    u32 length;
    u32 time;
    u8 gameName[4];
    u8 company[2];
    u8 bannerFormat;
    u8 pad;
    u32 iconAddr;
    u16 iconFormat;
    u16 iconSpeed;
    u32 commentAddr;
    u8 pad2[0x30];
} CARDStatStub;

extern int cardProbe(int chan);
extern s32 CARDMount(s32 chan, void* workArea, void (*detachCb)(void));
extern s32 CARDCheck(s32 chan);
extern s32 CARDGetSerialNo(s32 chan, u64* serialNo);
extern s32 CARDOpen(s32 chan, char* fileName, int* fileInfo);
extern s32 CARDClose(int* fileInfo);
extern s32 CARDUnmount(s32 chan);
extern s32 CARDCreate(s32 chan, char* fileName, u32 size, int* fileInfo);
extern s32 CARDGetStatus(s32 chan, s32 fileNo, CARDStatStub* stat);
extern s32 CARDSetStatus(s32 chan, s32 fileNo, CARDStatStub* stat);
extern void* lbl_803DD040;
extern u64 lbl_803DD048;
extern u8 lbl_803DD059;
extern u8 lbl_803DD05A;

#define CARD_RESULT_UNLOCKED 1
#define CARD_RESULT_READY 0
#define CARD_RESULT_NOCARD -3
#define CARD_RESULT_NOFILE -4
#define CARD_RESULT_IOERROR -5
#define CARD_RESULT_BROKEN -6
#define CARD_RESULT_NOENT -8
#define CARD_RESULT_INSSPACE -9
#define CARD_RESULT_ENCODING -13

/* EN v1.0 0x8007F818  size: 1468b  Mounts the memory card, validates its
 * serial number, opens or creates the save file (writing the card image
 * buffer for a fresh file), and maps any CARD error to a status code. */
int saveGame(int writeImages)
{
    u8 created;
    u8 fresh;
    int result;
    int ok;
    int ret;
    u64 serial;
    CARDStatStub stat;
    void* m;

    created = 0;
    fresh = 0;
    if (cardProbe(0) == 0)
    {
        ok = 0;
    }
    else
    {
        if ((lbl_803DD040 = mmAlloc(0xa000, -1, 0)) == NULL)
        {
            lbl_803DB700 = 8;
            ok = 0;
        }
        else
        {
            ok = 1;
        }
    }
    if (ok == 0)
    {
        return 0;
    }
    lbl_803DB700 = 0;
    result = CARDMount(0, lbl_803DD040, cardSetStatusNoCard2);
    if (result == CARD_RESULT_BROKEN)
    {
        result = CARDCheck(0);
    }
    if (result == CARD_RESULT_READY || result == CARD_RESULT_ENCODING)
    {
        int err;
        result = CARDCheck(0);
        err = CARDGetSerialNo(0, &serial);
        if (err == CARD_RESULT_READY)
        {
            if (lbl_803DD059 != 0)
            {
                if (lbl_803DD048 != 0)
                {
                    if (serial != lbl_803DD048)
                    {
                        result = -0x55;
                        lbl_803DB700 = 0xb;
                    }
                }
                else
                {
                    lbl_803DD048 = serial;
                }
            }
            else
            {
                lbl_803DD048 = serial;
            }
        }
        else
        {
            result = err;
        }
    }
    if (result == CARD_RESULT_READY)
    {
        result = CARDOpen(0, sMemoryCardFileName, lbl_80396900);
        if (result == CARD_RESULT_NOFILE && (u8)writeImages == 0)
        {
            created = 1;
            fresh = 1;
        }
        if (result == CARD_RESULT_READY)
        {
            lbl_803DD05A = 1;
        }
    }
    if (result == CARD_RESULT_READY)
    {
        result = CARDGetStatus(0, lbl_80396900[1], &stat);
        if (result == CARD_RESULT_READY)
        {
            if (stat.iconAddr == 0xffffffff || stat.commentAddr == 0xffffffff)
            {
                if ((u8)writeImages != 0)
                {
                    result = CARD_RESULT_NOFILE;
                }
                else
                {
                    fresh = 1;
                }
            }
        }
    }
    if (fresh != 0)
    {
        m = mmAlloc(0x4000, -1, 0);
        gSaveCardImageBuffer = (int)m;
        if (m != NULL)
        {
            memset(m, 0, 0x4000);
            loadMemCardImages();
        }
        else
        {
            lbl_803DB700 = 8;
            CARDUnmount(0);
            mm_free(lbl_803DD040);
            lbl_803DD040 = NULL;
            return 0;
        }
    }
    if (created != 0)
    {
        result = CARDCreate(0, sMemoryCardFileName, 0x6000, lbl_80396900);
    }
    if (fresh != 0)
    {
        if (result == CARD_RESULT_READY)
        {
            result = CARDWrite(lbl_80396900, (void*)gSaveCardImageBuffer, 0x4000, 0);
            if (result == CARD_RESULT_READY)
            {
                result = CARDWrite(lbl_80396900, (void*)(gSaveCardImageBuffer + 0x2000), 0x2000, 0x4000);
            }
            if (result == CARD_RESULT_IOERROR)
            {
                CARDDelete(0, sMemoryCardFileName);
            }
            if (created != 0 && result == CARD_RESULT_READY)
            {
                result = CARDGetStatus(0, lbl_80396900[1], &stat);
            }
            if (result == CARD_RESULT_READY)
            {
                stat.commentAddr = 0;
                stat.bannerFormat = (stat.bannerFormat & ~0x3) | 2;
                stat.iconAddr = 0x40;
                stat.bannerFormat = (stat.bannerFormat & ~0x4) | 4;
                stat.iconFormat = (stat.iconFormat & ~0x3) | 1;
                stat.iconSpeed = (stat.iconSpeed & ~0x3) | 3;
                stat.iconFormat = (stat.iconFormat & ~0xc) | 4;
                stat.iconSpeed = (stat.iconSpeed & ~0xc) | 0xc;
                stat.iconFormat = (stat.iconFormat & ~0x30) | 0x10;
                stat.iconSpeed = (stat.iconSpeed & ~0x30) | 0x30;
                stat.iconFormat = (stat.iconFormat & ~0xc0) | 0x40;
                stat.iconSpeed = (stat.iconSpeed & ~0xc0) | 0xc0;
                stat.iconSpeed = stat.iconSpeed & ~0x300;
                result = CARDSetStatus(0, lbl_80396900[1], &stat);
                if (result == CARD_RESULT_READY)
                {
                    lbl_803DD050 = *(u64*)(gSaveCardImageBuffer + 0x3ff8);
                }
            }
        }
        mm_free((void*)gSaveCardImageBuffer);
    }
    switch (result)
    {
    case CARD_RESULT_READY:
        if (fresh != 0)
        {
            return 1;
        }
        return 2;
    case CARD_RESULT_UNLOCKED:
        lbl_803DB700 = 1;
        ret = 0;
        break;
    case CARD_RESULT_NOCARD:
        if ((int)lbl_803DB700 != 3)
        {
            lbl_803DB700 = 2;
        }
        ret = 0;
        break;
    case CARD_RESULT_NOFILE:
        lbl_803DB700 = 0xc;
        ret = 0;
        break;
    case CARD_RESULT_IOERROR:
        lbl_803DB700 = 4;
        ret = 0;
        break;
    case CARD_RESULT_BROKEN:
        lbl_803DB700 = 5;
        ret = 0;
        break;
    case CARD_RESULT_ENCODING:
        lbl_803DB700 = 6;
        ret = 0;
        break;
    case CARD_RESULT_NOENT:
    case CARD_RESULT_INSSPACE:
        lbl_803DB700 = 9;
        ret = 0;
        break;
    case -0x55:
        ret = 0;
        break;
    default:
        ret = 0;
        break;
    }
    if (lbl_803DD05A != 0)
    {
        lbl_803DD05A = 0;
        CARDClose(lbl_80396900);
    }
    CARDUnmount(0);
    mm_free(lbl_803DD040);
    lbl_803DD040 = NULL;
    return ret;
}

/* EN v1.0 0x8007EB04  size: 1948b  Saves the game: verifies the existing save
 * slots' checksums, rewrites stale slots and card images, then runs the
 * caller's callback and maps the result to a status code. */
int saveGame_prepareAndWrite(int writeImages, int cbA, int cbB, int cbC, int cbD,
                             int (*cb)(int, int, int, int))
{
    u64 x[1];
    u16 i[1];
    u64* p;
    u64 acc[1];
    u64 chk;
    u64 chk2;
    u64 c;
    u64 t;
    int result;
    void* m;

    m = mmAlloc(0x2000, -1, 0);
    lbl_803DD044 = (int)m;
    if (m == NULL)
    {
        lbl_803DB700 = 8;
        return 0;
    }
    if (saveGame(writeImages) == 0)
    {
        mm_free((void*)lbl_803DD044);
        lbl_803DD044 = 0;
        return 0;
    }
    DCInvalidateRange((void*)lbl_803DD044, 0x2000);
    result = CARDRead(lbl_80396900, (void*)lbl_803DD044, 0x2000, 0x2000);
    if (result == 0)
    {
        p = (u64*)lbl_803DD044;
        x[0] = 0;
        acc[0] = 1;
        for (i[0] = (int)x[0]; (int)i[0] < 0x3ff; i[0]++)
        {
            u64 v = p[i[0]];
            x[0] = x[0] ^ v;
            acc[0] = acc[0] + v;
        }
        c = x[0] ^ (acc[0] + 13);
        chk = c;
        if (c != *(u64*)(lbl_803DD044 + 0x1ff8))
        {
            DCInvalidateRange((void*)lbl_803DD044, 0x2000);
            result = CARDRead(lbl_80396900, (void*)lbl_803DD044, 0x2000, 0x4000);
            if (result == 0)
            {
                p = (u64*)lbl_803DD044;
                x[0] = 0;
                acc[0] = 1;
                for (i[0] = (int)x[0]; (int)i[0] < 0x3ff; i[0]++)
                {
                    u64 v = p[i[0]];
                    x[0] = x[0] ^ v;
                    acc[0] = acc[0] + v;
                }
                c = x[0] ^ (acc[0] + 13);
                chk = c;
                if (c == *(u64*)(lbl_803DD044 + 0x1ff8))
                {
                    result = saveGame_doWrite(1);
                }
                else
                {
                    result = -0x55;
                    lbl_803DB700 = 10;
                }
            }
        }
    }
    if (result == 0)
    {
        if (lbl_803DD059 != 0)
        {
            if (lbl_803DD050 != 0)
            {
                if (chk != lbl_803DD050)
                {
                    result = -0x55;
                    lbl_803DB700 = 0xb;
                }
            }
            else
            {
                lbl_803DD050 = chk;
            }
        }
        else
        {
            lbl_803DD050 = chk;
        }
    }
    if (result == 0)
    {
        gSaveCardImageBuffer = (int)(m = mmAlloc(0x4000, -1, 0));
        if (m == NULL)
        {
            if (lbl_803DD05A != 0)
            {
                lbl_803DD05A = 0;
                CARDClose(lbl_80396900);
            }
            CARDUnmount(0);
            mm_free(lbl_803DD040);
            lbl_803DD040 = NULL;
            mm_free((void*)lbl_803DD044);
            lbl_803DD044 = 0;
            lbl_803DB700 = 8;
            return 0;
        }
        result = CARDRead(lbl_80396900, m, 0x2000, 0);
        if (result == 0)
        {
            p = (u64*)gSaveCardImageBuffer;
            x[0] = 0;
            acc[0] = 1;
            for (i[0] = (int)x[0]; (int)i[0] < 0x400; i[0]++)
            {
                u64 v = p[i[0]];
                x[0] = x[0] ^ v;
                acc[0] = acc[0] + v;
            }
            chk2 = x[0] ^ (acc[0] + 13);
            if (chk2 != *(u64*)(lbl_803DD044 + 0xa40))
            {
                if ((u8)writeImages != 0)
                {
                    result = -4;
                    lbl_803DB700 = 0xc;
                }
                else
                {
                    memset((void*)gSaveCardImageBuffer, 0, 0x4000);
                    loadMemCardImages();
                    result = CARDWrite(lbl_80396900, (void*)gSaveCardImageBuffer, 0x2000, 0);
                    if (result == CARD_RESULT_IOERROR)
                    {
                        CARDDelete(0, sMemoryCardFileName);
                    }
                    if (result == 0)
                    {
                        t = *(u64*)(gSaveCardImageBuffer + 0x2a40);
                        if (t != *(u64*)(lbl_803DD044 + 0xa40))
                        {
                            int e;
                            *(u64*)(lbl_803DD044 + 0xa40) = t;
                            e = saveGame_doWrite(2);
                            if (e == 0)
                            {
                                e = saveGame_doWrite(1);
                            }
                            result = e;
                        }
                    }
                }
            }
        }
        mm_free((void*)gSaveCardImageBuffer);
    }
    if (result == 0 && cb != NULL)
    {
        result = cb(cbA, cbB, cbC, cbD);
    }
    if (lbl_803DD05A != 0)
    {
        lbl_803DD05A = 0;
        CARDClose(lbl_80396900);
    }
    CARDUnmount(0);
    mm_free(lbl_803DD040);
    lbl_803DD040 = NULL;
    mm_free((void*)lbl_803DD044);
    lbl_803DD044 = 0;
    switch (result)
    {
    case -5:
        lbl_803DB700 = 4;
        break;
    case 0:
        lbl_803DB700 = 0xd;
        return 1;
    case -4:
        break;
    }
    return 0;
}

extern int Obj_GetPlayerObject(void);
extern int getAngle(float y, float x);
extern f32 sqrtf(f32 x);
extern u8 framesThisStep;

/*
 * Per-object turn-to-face scratch state (carried in GameObject::extra for
 * class-0x10 sequence objects). Only the fields touched by the turn step and
 * the sequence teardown are named; the rest of the region stays padding.
 * Field offsets are pinned to the original raw-buffer layout so member
 * spelling stays byte-neutral.
 */
typedef struct ObjSeqTurnState {
  u8 pad00[0x24];
  f32 turnRate;      /* 0x24: per-frame blend increment */
  u8 pad28[0x40 - 0x28];
  f32 vecX;          /* 0x40 */
  f32 vecY;          /* 0x44 */
  f32 vecZ;          /* 0x48 */
  f32 blend;         /* 0x4c: 0..1 progress */
  s16 turnAmount;    /* 0x50 */
  s16 targetPitch;   /* 0x52 */
  s16 f54;           /* 0x54 */
  u8 mode;           /* 0x56: 4 = start, 5 = advance */
  u8 seqId;          /* 0x57 */
  u8 pad58[0x6E - 0x58];
  s16 flags;         /* 0x6e */
  u8 pad70[0xE8 - 0x70];
  void (*resetVecCb)(int); /* 0xe8 */
  u8 padEC[0x110 - 0xEC];
  int cbArg;         /* 0x110 */
  s16 savedVecY;     /* 0x114 */
  s16 savedVecX;     /* 0x116 */
} ObjSeqTurnState;

/* EN v1.0 0x800805A4  size: 1564b  Object-sequence turn-to-face-player step:
 * starts (mode 4) or advances (mode 5) a smooth turn of the object toward the
 * player, blending the model vector and animation as it goes. */
int ObjSeq_func20(int obj, int state, s16 p3, s16 p4, s16 p5, s16 p6, s16 p7)
{
    int player;
    s16* v;
    int yawd;
    s16 turn;
    int mode;
    f32 out;
    f32 d[3];
    f32 dist;
    f32 rate;
    f32 g;

    player = Obj_GetPlayerObject();
    p4 = (s16)(182.04445f * p4);
    p5 = (s16)(182.04445f * p5);
    p3 = (s16)(182.04445f * p3);
    mode = (s8)((ObjSeqTurnState*)state)->mode;
    if (mode == 4)
    {
        ((ObjSeqTurnState*)state)->flags = ((ObjSeqTurnState*)state)->flags & ~2;
        v = (s16*)objModelGetVecFn_800395d8(obj, 0);
        if (v != NULL)
        {
            ((ObjSeqTurnState*)state)->flags = ((ObjSeqTurnState*)state)->flags & ~8;
        }
        ((ObjSeqTurnState*)state)->resetVecCb = objModelResetVecFn_80080548;
        ((ObjSeqTurnState*)state)->vecX = 0.0f;
        ((ObjSeqTurnState*)state)->vecY = 0.0f;
        ((ObjSeqTurnState*)state)->vecZ = 0.0f;
        yawd = Obj_GetYawDeltaToObject((u16*)obj, player, (float*)0);
        if (((s16)yawd >= 0 ? (s16)yawd : -(s16)yawd) < p4)
        {
            turn = 0;
        }
        else
        {
            turn = (s16)((s16)yawd > 0 ? (s16)yawd - p4 : (s16)yawd + p4);
        }
        ((ObjSeqTurnState*)state)->turnAmount = turn;
        {
            f32* dp = d;
            f32* ovr = *(f32**)(obj + 0x74);
            if (ovr == NULL)
            {
                dp[0] = ((GameObject*)player)->anim.localPosX - ((GameObject*)obj)->anim.localPosX;
                dp[1] = ((GameObject*)player)->anim.localPosY - ((GameObject*)obj)->anim.localPosY;
                dp[2] = ((GameObject*)player)->anim.localPosZ - ((GameObject*)obj)->anim.localPosZ;
            }
            else
            {
                dp[0] = ((GameObject*)player)->anim.localPosX - ovr[0];
                dp[1] = ((GameObject*)player)->anim.localPosY - ovr[1];
                dp[2] = ((GameObject*)player)->anim.localPosZ - ovr[2];
            }
            dp[1] += 30.0f;
            dist = sqrtf(dp[0] * dp[0] + dp[2] * dp[2]);
            ((ObjSeqTurnState*)state)->targetPitch = (s16)getAngle(dp[1], dist);
        }
        ((ObjSeqTurnState*)state)->f54 = 0;
        ((ObjSeqTurnState*)state)->mode = 5;
        ((ObjSeqTurnState*)state)->blend = 0.0f;
        if (turn != 0)
        {
            rate = (f32)p3 / (f32)turn;
            ((ObjSeqTurnState*)state)->turnRate = rate >= 0.0f ? rate : -rate;
        }
        else
        {
            ((ObjSeqTurnState*)state)->turnRate = 1.0f;
        }
        {
            f32 c = ((ObjSeqTurnState*)state)->turnRate;
            ((ObjSeqTurnState*)state)->turnRate = c < 0.0f ? 0.0f : (c > 0.25f ? 0.25f : c);
        }
        if (p6 != -1)
        {
            if (p7 != -1)
            {
                ((ObjSeqTurnState*)state)->flags = ((ObjSeqTurnState*)state)->flags & ~4;
                if (((ObjSeqTurnState*)state)->turnAmount < 0)
                {
                    if (p7 != -1)
                    {
                        ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
                            (obj, p7, 0.0f, 0);
                    }
                }
                else
                {
                    if (p6 != -1)
                    {
                        ((ObjAnimSetCurrentMoveObjectFirstFn)ObjAnim_SetCurrentMove)
                            (obj, p6, 0.0f, 0);
                    }
                }
            }
        }
        ((ObjSeqTurnState*)state)->resetVecCb = objModelResetVecFn_80080548;
        return 1;
    }
    else if (mode == 5)
    {
        ((ObjSeqTurnState*)state)->blend = ((ObjSeqTurnState*)state)->blend + ((ObjSeqTurnState*)state)->turnRate;
        if (((ObjSeqTurnState*)state)->blend > 1.0f)
        {
            ((ObjSeqTurnState*)state)->blend = 1.0001f;
        }
        ((GameObject*)obj)->anim.rotX += (s16)(((ObjSeqTurnState*)state)->turnRate * (f32)((ObjSeqTurnState*)state)->turnAmount);
        v = (s16*)objModelGetVecFn_800395d8(obj, 0);
        if (v != NULL)
        {
            ((ObjSeqTurnState*)state)->flags = ((ObjSeqTurnState*)state)->flags & ~8;
            yawd = Obj_GetYawDeltaToObject((u16*)obj, player, (float*)0);
            g = (f32)(s16)
            yawd;
            {
                f32 cur = (f32)v[1];
                g = cur * (1.0f - ((ObjSeqTurnState*)state)->blend) + g * ((ObjSeqTurnState*)state)->blend;
            }
            g = (g < (f32) - p5) ? (f32) - p5 : ((g > (f32)p5) ? (f32)p5 : g);
            v[1] = g;
            v[0] = (f32)((ObjSeqTurnState*)state)->targetPitch * ((ObjSeqTurnState*)state)->blend;
        }
        if (p6 != -1)
        {
            if (p7 != -1)
            {
                s16 t50 = ((ObjSeqTurnState*)state)->turnAmount;
                f32 fa = (f32)(t50 >= 0 ? t50 : -t50);
                fa = fa * 3.142f / 325767.0f;
                ObjAnim_SampleRootCurvePhase(fa, (ObjAnimComponent*)obj, &out);
                ((ObjAnimAdvanceObjectFirstF32Fn)ObjAnim_AdvanceCurrentMove)
                    (obj, out, (f32)framesThisStep, NULL);
            }
        }
        if (((ObjSeqTurnState*)state)->blend > 1.0f)
        {
            ((ObjSeqTurnState*)state)->mode = 0;
            ((ObjSeqTurnState*)state)->flags = ((ObjSeqTurnState*)state)->flags | 8;
            v = (s16*)objModelGetVecFn_800395d8(obj, 0);
            if (v != NULL)
            {
                ((ObjSeqTurnState*)state)->savedVecY = v[1];
                ((ObjSeqTurnState*)state)->savedVecX = v[0];
            }
            else
            {
                ((ObjSeqTurnState*)state)->savedVecY = 0;
                ((ObjSeqTurnState*)state)->savedVecX = 0;
            }
            if (((ObjSeqTurnState*)state)->blend > 1.0f)
            {
                ((ObjSeqTurnState*)state)->flags = ((ObjSeqTurnState*)state)->flags | 4;
            }
        }
        return 1;
    }
    return 0;
}

extern void AudioStream_StartPrepared(void);
extern int gObjSeqStreamSuppressed;
extern int lbl_803DB728;
extern f32 lbl_803DEFB0;
extern f32 lbl_803DD074;
extern int lbl_803DB724;
extern f32 gObjSeqSlotStreamTimeTable[];

/* EN v1.0 0x8008023C  size: 260b  Starts the prepared audio stream for a
 * sequence slot and records its subtitle timing. */
int seqStreamFn_8008023c(int x)
{
    int seqId = gObjSeqSlotSeqIdTable[x] - 1;
    f32 v;

    if (gObjSeqStreamSuppressed != 0 || AudioStream_IsPreparing() != 0)
    {
        return 0;
    }
    v = gObjSeqSlotStreamTimeTable[x] - (f32)lbl_803DB728;
    lbl_803DD074 = v;
    if (lbl_803DEFB0 != lbl_803DD074)
    {
        lbl_803DB724 = x;
    }
    lbl_803DB728 = -1;
    if (seqId == 0x54b || seqId == 0x550 || seqId == 0x551 || seqId == 0x574 || seqId == 0x579 ||
        seqId == 0x57a)
    {
        lbl_803DD074 = 0.0f;
        lbl_803DB724 = -1;
    }
    lbl_803DB720 = -1;
    AudioStream_StartPrepared();
    return 1;
}

void endObjSequence(int seq)
{
    int j;
    int objCount;
    int objIdx;
    int frees[32];
    int* objs;
    int i;
    int nFree;
    int* ret;

    ret = (int*)ObjList_GetObjects(&objIdx, &objCount);
    nFree = 0;
    i = 0;
    objs = ret;
    for (; i < objCount; i++)
    {
        int obj = *objs;
        if (((GameObject*)obj)->seqIndex == seq)
        {
            ((GameObject*)obj)->seqIndex = -1;
        }
        if (((GameObject*)obj)->anim.classId == 0x10)
        {
            ObjSeqTurnState* st = (ObjSeqTurnState*)*(int*)&((GameObject*)obj)->extra;
            if ((s8)st->seqId == seq)
            {
                if ((void*)obj == lbl_803DD0B8)
                {
                    lbl_803DD0B8 = 0;
                }
                frees[nFree++] = obj;
                if (st->resetVecCb != NULL)
                {
                    (*(void (**)(int, int, int)) & st->resetVecCb)(st->cbArg, obj, (int)st);
                    st->resetVecCb = NULL;
                }
                if (nFree == 0x10)
                {
                    debugPrintf(sEndObjSequenceMaxFreesError);
                }
            }
        }
        objs++;
    }
    if (curSeqNo == seq)
    {
        curSeqNo = 0;
        Pause_ResetMenuFrameCounter();
    }
    if (seq == lbl_803DB720)
    {
        AudioStream_CancelPrepared();
        lbl_803DB720 = -1;
    }
    for (j = 0; j < nFree; j++)
    {
        Obj_FreeObject(frees[j]);
    }
    if (seq == lbl_803DD064)
    {
        if ((*gCameraInterface)->getMode() == 0x4d)
        {
            (*gCameraInterface)->setMode(0x42, 0, 3, 0, NULL, 0, 0);
            lbl_803DD064 = 0;
            curSeqNo = 0;
            Pause_ResetMenuFrameCounter();
        }
    }
    lbl_803DD07C = 0;
    gObjSeqSlotSeqIdTable[seq] = 0;
}
