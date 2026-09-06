#include "dolphin/dvd.h"
#include "dolphin/os/OSCache.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "main/fileio.h"
#include "main/frame_timing.h"
#include "main/maketex.h"
#include "main/maketex_api.h"
#include "main/maketex_random_api.h"
#include "main/maketex_sequence_api.h"
#include "main/maketex_timer_api.h"
#include "main/mm.h"
#include "main/textrender_api.h"
#include "main/vecmath.h"
#include "string.h"
#include "track/intersect_card_api.h"

volatile s32 gSaveCardState = 0xD;
char* sMemoryCardFileName = sMemoryCardFileNameString;
int gSaveCardBackdropColor = 0x404040FF;
int lbl_803DB70C[1] = {0};

typedef struct {
    int key;
    int val;
} SeqSortPair;

static inline int maketex_indexOf(int* p, int n, int target) {
    int i;
    int j;
    i = 0;
    for (j = 0; j < n; j++) {
        if (*p++ == target) {
            return i;
        }
        i++;
    }
    return -1;
}
void loadMemCardImages(void);
static inline u64 saveGame_checksum(u64* p, int count) {
    u64 x;
    u16 i[1];
    u64 acc;

    x = 0;
    acc = 1;
    for (i[0] = (int)x; (int)i[0] < count; i[0]++) {
        x ^= p[i[0]];
        acc += p[i[0]];
    }
    return x ^ (acc + 13);
}

int saveGameReadSlotCb(u8 idx, int unused, void* dst) {
    memcpy(dst, (void*)(gSaveCardIoBuffer + idx * 1772 + 2640), 1772);
    return 0;
}

/* Checksums the save buffer, writes it to the memory card, then reads it
 * back and verifies the checksum. */
int saveGame_doWrite(int slot) {
    u64 x[1];
    u16 i[1];
    u64* p;
    u64 a[1];
    u64 chk;
    u64 chk2;
    int result;
    int offset;

    p = (u64*)gSaveCardIoBuffer;
    x[0] = 0;
    a[0] = 1;
    for (i[0] = (int)x[0]; (int)i[0] < 0x3ff; i[0]++) {
        x[0] = x[0] ^ p[i[0]];
        a[0] = a[0] + p[i[0]];
    }
    chk = x[0] ^ (a[0] + 13);
    p[0x3ff] = chk;
    DCFlushRange((void*)gSaveCardIoBuffer, 0x2000);
    result = CARDWrite(&gSaveCardFileInfo.fileInfo, (void*)gSaveCardIoBuffer, 0x2000, offset = (u8)slot << 13);
    if (result == -5) {
        CARDDelete(0, sMemoryCardFileName);
    }
    if (result == 0) {
        DCInvalidateRange((void*)gSaveCardIoBuffer, 0x2000);
        result = CARDRead(&gSaveCardFileInfo.fileInfo, (void*)gSaveCardIoBuffer, 0x2000, offset);
        if (result == 0) {
            u64 x2[1];
            u64 a2[1];
            p = (u64*)gSaveCardIoBuffer;
            x2[0] = 0;
            a2[0] = 1;
            for (i[0] = (int)x2[0]; (int)i[0] < 0x3ff; i[0]++) {
                x2[0] = x2[0] ^ p[i[0]];
                a2[0] = a2[0] + p[i[0]];
            }
            chk2 = x2[0] ^ (a2[0] + 13);
            if (chk != chk2) {
                result = -0x55;
                gSaveCardState = 10;
            } else {
                *(u64*)&gSaveCardChecksumHi = chk2;
            }
        }
    }
    return result;
}

/* Saves the game: verifies the existing save slots' checksums, rewrites
 * stale slots and card images, then runs the caller's callback and maps the
 * result to a status code. */
int saveGame_prepareAndWrite(int writeImages, int cbA, int cbB, void* cbC, void* cbD, SaveGameCallback cb) {
    u64 chk;
    u64 chk2;
    u64 c;
    u64 t;
    int result;
    void* m;

    m = mmAlloc(0x2000, -1, 0);
    gSaveCardIoBuffer = (char*)m;
    if (m == NULL) {
        gSaveCardState = 8;
        return 0;
    }
    if (saveGame(writeImages) == 0) {
        mm_free((void*)gSaveCardIoBuffer);
        gSaveCardIoBuffer = 0;
        return 0;
    }
    DCInvalidateRange((void*)gSaveCardIoBuffer, 0x2000);
    result = CARDRead(&gSaveCardFileInfo.fileInfo, (void*)gSaveCardIoBuffer, 0x2000, 0x2000);
    if (result == CARD_RESULT_READY) {
        c = saveGame_checksum((u64*)gSaveCardIoBuffer, 0x3ff);
        chk = c;
        if (c != ((u64*)gSaveCardIoBuffer)[0x3ff]) {
            DCInvalidateRange((void*)gSaveCardIoBuffer, 0x2000);
            result = CARDRead(&gSaveCardFileInfo.fileInfo, (void*)gSaveCardIoBuffer, 0x2000, 0x4000);
            if (result == CARD_RESULT_READY) {
                c = saveGame_checksum((u64*)gSaveCardIoBuffer, 0x3ff);
                chk = c;
                if (c == ((u64*)gSaveCardIoBuffer)[0x3ff]) {
                    result = saveGame_doWrite(1);
                } else {
                    result = -0x55;
                    gSaveCardState = 10;
                }
            }
        }
    }
    if (result == 0) {
        if (gSaveCardIdentityCheckEnabled != 0) {
            if (*(u64*)&gSaveCardChecksumHi != 0) {
                if (chk != *(u64*)&gSaveCardChecksumHi) {
                    result = -0x55;
                    gSaveCardState = 0xb;
                }
            } else {
                gSaveCardChecksumLo = (u32)chk;
                gSaveCardChecksumHi = (u32)(chk >> 32);
            }
        } else {
            gSaveCardChecksumLo = (u32)chk;
            gSaveCardChecksumHi = (u32)(chk >> 32);
        }
    }
    if (result == 0) {
        m = gSaveCardImageBuffer = mmAlloc(0x4000, -1, 0);
        if (m == NULL) {
            if (gSaveCardFileOpen != 0) {
                gSaveCardFileOpen = 0;
                CARDClose(&gSaveCardFileInfo.fileInfo);
            }
            CARDUnmount(0);
            mm_free(gSaveCardWorkArea);
            gSaveCardWorkArea = NULL;
            mm_free((void*)gSaveCardIoBuffer);
            gSaveCardIoBuffer = 0;
            gSaveCardState = 8;
            return 0;
        }
        result = CARDRead(&gSaveCardFileInfo.fileInfo, m, 0x2000, 0);
        if (result == CARD_RESULT_READY) {
            chk2 = saveGame_checksum((u64*)gSaveCardImageBuffer, 0x400);
            if (chk2 != *(u64*)(gSaveCardIoBuffer + 0xa40)) {
                if ((u8)writeImages != 0) {
                    result = -4;
                    gSaveCardState = 0xc;
                } else {
                    memset(gSaveCardImageBuffer, 0, 0x4000);
                    loadMemCardImages();
                    result = CARDWrite(&gSaveCardFileInfo.fileInfo, gSaveCardImageBuffer, 0x2000, 0);
                    if (result == CARD_RESULT_IOERROR) {
                        CARDDelete(0, sMemoryCardFileName);
                    }
                    if (result == CARD_RESULT_READY) {
                        t = *(u64*)(gSaveCardImageBuffer + 0x2a40);
                        if (t != *(u64*)(gSaveCardIoBuffer + 0xa40)) {
                            int writeResult;
                            *(u64*)(gSaveCardIoBuffer + 0xa40) = t;
                            writeResult = saveGame_doWrite(2);
                            if (writeResult == 0) {
                                writeResult = saveGame_doWrite(1);
                            }
                            result = writeResult;
                        }
                    }
                }
            }
        }
        mm_free(gSaveCardImageBuffer);
    }
    if (result == 0 && cb != NULL) {
        result = cb(cbA, cbB, cbC, cbD);
    }
    if (gSaveCardFileOpen != 0) {
        gSaveCardFileOpen = 0;
        CARDClose(&gSaveCardFileInfo.fileInfo);
    }
    CARDUnmount(0);
    mm_free(gSaveCardWorkArea);
    gSaveCardWorkArea = NULL;
    mm_free((void*)gSaveCardIoBuffer);
    gSaveCardIoBuffer = 0;
    switch (result) {
    case -5:
        gSaveCardState = 4;
        break;
    case 0:
        gSaveCardState = 0xd;
        return 1;
    case -4:
        break;
    }
    return 0;
}

/* Builds the memory card comment strings (Shift-JIS title on JP cards),
 * loads the banner/icon images from disc, and checksums both halves of the
 * card image buffer. */
void loadMemCardImages(void) {
    char* names = sMemoryCardFileNameString;
    DVDFileInfo fi;
    u64* p;
    u16 i[1];
    u64 x[1];
    u64* q;
    u64 a[1];
    u64 chk;
    u64 x2[1];
    u64 a2[1];

    a[0] = 0;
    if (gGameTextFontIsSjis != 0) {
        gSaveCardImageBuffer[0x00] = 0x83;
        gSaveCardImageBuffer[0x01] = 0x58;
        gSaveCardImageBuffer[0x02] = 0x83;
        gSaveCardImageBuffer[0x03] = 0x5e;
        gSaveCardImageBuffer[0x04] = 0x81;
        gSaveCardImageBuffer[0x05] = 0x5b;
        gSaveCardImageBuffer[0x06] = 0x83;
        gSaveCardImageBuffer[0x07] = 0x74;
        gSaveCardImageBuffer[0x08] = 0x83;
        gSaveCardImageBuffer[0x09] = 0x48;
        gSaveCardImageBuffer[0x0a] = 0x83;
        gSaveCardImageBuffer[0x0b] = 0x62;
        gSaveCardImageBuffer[0x0c] = 0x83;
        gSaveCardImageBuffer[0x0d] = 0x4e;
        gSaveCardImageBuffer[0x0e] = 0x83;
        gSaveCardImageBuffer[0x0f] = 0x58;
        gSaveCardImageBuffer[0x10] = 0x83;
        gSaveCardImageBuffer[0x11] = 0x41;
        gSaveCardImageBuffer[0x12] = 0x83;
        gSaveCardImageBuffer[0x13] = 0x68;
        gSaveCardImageBuffer[0x14] = 0x83;
        gSaveCardImageBuffer[0x15] = 0x78;
        gSaveCardImageBuffer[0x16] = 0x83;
        gSaveCardImageBuffer[0x17] = 0x93;
        gSaveCardImageBuffer[0x18] = 0x83;
        gSaveCardImageBuffer[0x19] = 0x60;
        gSaveCardImageBuffer[0x1a] = 0x83;
        gSaveCardImageBuffer[0x1b] = 0x83;
        gSaveCardImageBuffer[0x1c] = 0x81;
        gSaveCardImageBuffer[0x1d] = 0x5b;
        gSaveCardImageBuffer[0x1e] = 0x00;
        gSaveCardImageBuffer[0x1f] = 0x00;
        sprintf((char*)(gSaveCardImageBuffer + 0x20), names + 0xa0);
    } else {
        sprintf((char*)gSaveCardImageBuffer, names);
        sprintf((char*)(gSaveCardImageBuffer + 0x20), names + 0xb4);
    }
    if (DVDOpen(names + 0xc4, &fi)) {
        DVDRead(&fi, gSaveCardImageBuffer + 0x40, 0x1800, 0x20);
        DVDClose(&fi);
    }
    if (DVDOpen(names + 0xd0, &fi)) {
        DVDRead(&fi, gSaveCardImageBuffer + 0x1840, 0x400, 0);
        DVDClose(&fi);
    }
    if (DVDOpen(names + 0xe8, &fi)) {
        DVDRead(&fi, gSaveCardImageBuffer + 0x1c40, 0x400, 0);
        DVDClose(&fi);
    }
    if (DVDOpen(names + 0x100, &fi)) {
        DVDRead(&fi, gSaveCardImageBuffer + 0x2040, 0x400, 0);
        DVDClose(&fi);
    }
    if (DVDOpen(names + 0x118, &fi)) {
        DVDRead(&fi, gSaveCardImageBuffer + 0x2440, 0x400, 0);
        DVDClose(&fi);
    }
    if (DVDOpen(names + 0x130, &fi)) {
        DVDRead(&fi, gSaveCardImageBuffer + 0x2840, 0x200, 0);
        DVDClose(&fi);
    }
    p = (u64*)gSaveCardImageBuffer;
    x[0] = 0;
    a[0] = 1;
    for (i[0] = (int)x[0]; (int)i[0] < 0x400; i[0]++) {
        x[0] = x[0] ^ p[i[0]];
        a[0] = a[0] + p[i[0]];
    }
    chk = x[0] ^ (a[0] + 13);
    ((u32*)p)[0xa91] = (u32)chk;
    ((u32*)p)[0xa90] = (u32)(chk >> 32);
    q = (u64*)gSaveCardImageBuffer;
    p = q + 0x400;
    x2[0] = 0;
    a2[0] = 1;
    for (i[0] = (int)x2[0]; (int)i[0] < 0x3ff; i[0]++) {
        x2[0] = x2[0] ^ p[i[0]];
        a2[0] = a2[0] + p[i[0]];
    }
    chk = x2[0] ^ (a2[0] + 13);
    ((u32*)q)[0xfff] = (u32)chk;
    ((u32*)q)[0xffe] = (u32)(chk >> 32);
    DCFlushRange(gSaveCardImageBuffer, 0x4000);
}

/* Mounts the memory card, validates its serial number, opens or creates the
 * save file (writing the card image buffer for a fresh file), and maps any
 * CARD error to a status code. */
int saveGame(int writeImages) {
    u8 created;
    u8 fresh;
    int result;
    int ok;
    int ret;
    u64 serial;
    CARDStat stat;
    void* m;

    created = 0;
    fresh = 0;
    if (cardProbe(0) == 0) {
        ok = 0;
    } else {
        if ((gSaveCardWorkArea = mmAlloc(0xa000, -1, 0)) == NULL) {
            gSaveCardState = 8;
            ok = 0;
        } else {
            ok = 1;
        }
    }
    if (ok == 0) {
        return 0;
    }
    gSaveCardState = 0;
    result = CARDMount(0, gSaveCardWorkArea, (CARDCallback)cardSetStatusNoCard2);
    if (result == CARD_RESULT_BROKEN) {
        result = CARDCheck(0);
    }
    if (result == CARD_RESULT_READY || result == CARD_RESULT_ENCODING) {
        int err;
        result = CARDCheck(0);
        err = CARDGetSerialNo(0, &serial);
        if (err == CARD_RESULT_READY) {
            if (gSaveCardIdentityCheckEnabled != 0) {
                if (*(u64*)&gSaveCardSerialHi != 0) {
                    if (serial != *(u64*)&gSaveCardSerialHi) {
                        result = -0x55;
                        gSaveCardState = 0xb;
                    }
                } else {
                    *(u64*)&gSaveCardSerialHi = serial;
                }
            } else {
                *(u64*)&gSaveCardSerialHi = serial;
            }
        } else {
            result = err;
        }
    }
    if (result == CARD_RESULT_READY) {
        result = CARDOpen(0, sMemoryCardFileName, &gSaveCardFileInfo.fileInfo);
        if (result == CARD_RESULT_NOFILE && (u8)writeImages == 0) {
            created = 1;
            fresh = 1;
        }
        if (result == CARD_RESULT_READY) {
            gSaveCardFileOpen = 1;
        }
    }
    if (result == CARD_RESULT_READY) {
        result = CARDGetStatus(0, gSaveCardFileInfo.fileInfo.fileNo, &stat);
        if (result == CARD_RESULT_READY) {
            if (stat.iconAddr == 0xffffffff || stat.commentAddr == 0xffffffff) {
                if ((u8)writeImages != 0) {
                    result = CARD_RESULT_NOFILE;
                } else {
                    fresh = 1;
                }
            }
        }
    }
    if (fresh != 0) {
        m = mmAlloc(0x4000, -1, 0);
        gSaveCardImageBuffer = m;
        if (m != NULL) {
            memset(m, 0, 0x4000);
            loadMemCardImages();
        } else {
            gSaveCardState = 8;
            CARDUnmount(0);
            mm_free(gSaveCardWorkArea);
            gSaveCardWorkArea = NULL;
            return 0;
        }
    }
    if (created != 0) {
        result = CARDCreate(0, sMemoryCardFileName, 0x6000, &gSaveCardFileInfo.fileInfo);
    }
    if (fresh != 0) {
        if (result == CARD_RESULT_READY) {
            result = CARDWrite(&gSaveCardFileInfo.fileInfo, gSaveCardImageBuffer, 0x4000, 0);
            if (result == CARD_RESULT_READY) {
                result = CARDWrite(&gSaveCardFileInfo.fileInfo, gSaveCardImageBuffer + 0x2000, 0x2000, 0x4000);
            }
            if (result == CARD_RESULT_IOERROR) {
                CARDDelete(0, sMemoryCardFileName);
            }
            if (created != 0 && result == CARD_RESULT_READY) {
                result = CARDGetStatus(0, gSaveCardFileInfo.fileInfo.fileNo, &stat);
            }
            if (result == CARD_RESULT_READY) {
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
                result = CARDSetStatus(0, gSaveCardFileInfo.fileInfo.fileNo, &stat);
                if (result == CARD_RESULT_READY) {
                    *(u64*)&gSaveCardChecksumHi = *(u64*)(gSaveCardImageBuffer + 0x3ff8);
                }
            }
        }
        mm_free(gSaveCardImageBuffer);
    }
    switch (result) {
    case CARD_RESULT_READY:
        if (fresh != 0) {
            return 1;
        }
        return 2;
    case CARD_RESULT_UNLOCKED:
        gSaveCardState = 1;
        ret = 0;
        break;
    case CARD_RESULT_NOCARD:
        if ((int)gSaveCardState != 3) {
            gSaveCardState = 2;
        }
        ret = 0;
        break;
    case CARD_RESULT_NOFILE:
        gSaveCardState = 0xc;
        ret = 0;
        break;
    case CARD_RESULT_IOERROR:
        gSaveCardState = 4;
        ret = 0;
        break;
    case CARD_RESULT_BROKEN:
        gSaveCardState = 5;
        ret = 0;
        break;
    case CARD_RESULT_ENCODING:
        gSaveCardState = 6;
        ret = 0;
        break;
    case CARD_RESULT_NOENT:
    case CARD_RESULT_INSSPACE:
        gSaveCardState = 9;
        ret = 0;
        break;
    case -0x55:
        ret = 0;
        break;
    default:
        ret = 0;
        break;
    }
    if (gSaveCardFileOpen != 0) {
        gSaveCardFileOpen = 0;
        CARDClose(&gSaveCardFileInfo.fileInfo);
    }
    CARDUnmount(0);
    mm_free(gSaveCardWorkArea);
    gSaveCardWorkArea = NULL;
    return ret;
}

void cardSetStatusNoCard2(void) {
    gSaveCardState = 0x3;
}

int arrayRemoveUnordered(int* array, int* count, int value) {
    int i;
    int len;
    len = *count;
    i = maketex_indexOf(array, len, value);
    if (i == -1) {
        return -1;
    }
    array[i] = array[len - 1];
    (*count)--;
    return i;
}

int arrayIndexOf(int* arr, int count, int target) {
    int idx = 0;
    int i;
    for (i = 0; i < count; i++) {
        int elem = *arr;
        arr++;
        if (elem == target) {
            return idx;
        }
        idx++;
    }
    return -1;
}

static inline int seqPairKey(SeqSortPair* pair) {
    return pair->key;
}

static inline int seqPairVal(SeqSortPair* pair) {
    return pair->val;
}

void seqPairTableSort(SeqSortPair* arr, int n) {
    int key;
    int val;
    int limit;
    int i;
    int j;
    int gap;

    gap = 1;
    limit = (n - 1) / 9;
    while (gap <= limit) {
        gap = gap * 3 + 1;
    }
    for (; gap > 0; gap /= 3) {
        for (i = gap + 1; i < n; i++) {
            key = seqPairKey(&arr[i]);
            val = seqPairVal(&arr[i]);
            j = i;
            while (j > gap && arr[j - gap].key > key) {
                arr[j].key = arr[j - gap].key;
                arr[j].val = arr[j - gap].val;
                j -= gap;
            }
            arr[j].key = key;
            arr[j].val = val;
        }
    }
    for (i = 1; i < n; i++) {
    }
}

int seqPairTableLookup(void* entries, int count, int key) {
    SeqSortPair* arr = entries;
    int lo, mid;
    int i;
    if (count <= 16) {
        for (i = 0; i != count; i++) {
            if (arr->key == key) {
                return arr->val;
            }
            arr++;
        }
        return 0;
    }
    lo = 0;
    do {
        mid = (count + lo) >> 1;
        if (key > arr[mid].key) {
            lo = mid;
        } else if (key == arr[mid].key) {
            return arr[mid].val;
        } else {
            count = mid;
        }
    } while (count <= lo);
    return 0;
}

/* Spin-delay then sort when the pair list is large enough. */
void seqPairTablePrepare(void* entries, int n) {
    SeqSortPair* arr = entries;
    int i;
    int j;

    for (i = 0; i < n; i++) {
        for (j = 0; j < n; j++) {
        }
    }
    if (n > 0x10) {
        seqPairTableSort(arr, n);
    }
}

int randomChanceOneIn(int n) {
    return randomGetRange(0, n * 60 / 60) == 0;
}

int timerIsActive(const f32* p) {
    return 0.0f != *p;
}

void storeZeroToFloatParam(f32* p) {
    *p = 0.0f;
}

void s16toFloat(f32* p, s16 val) {
    *p = (f32)val;
}

int timerCountDown(f32* p) {
    f32 timer = *p;
    f32 zero = 0.0f;
    if (timer != zero) {
        *p = timer - timeDelta;
        if (*p <= zero) {
            *p = zero;
            return 1;
        }
    }
    return 0;
}

u8 gMemoryCardBannerAssetNames[168] = {
    83,  84,  65,  82,  70,  79,  88,  32,  65,  68,  86,  69,  78,  84,  85,  82,  69,  83,  0,   0,   68,
    105, 110, 111, 115, 97,  117, 114, 32,  80,  108, 97,  110, 101, 116, 0,   111, 112, 101, 110, 105, 110,
    103, 46,  98,  110, 114, 0,   99,  97,  114, 100, 47,  109, 101, 109, 99,  97,  114, 100, 105, 99,  111,
    110, 48,  46,  105, 109, 103, 0,   0,   0,   99,  97,  114, 100, 47,  109, 101, 109, 99,  97,  114, 100,
    105, 99,  111, 110, 49,  46,  105, 109, 103, 0,   0,   0,   99,  97,  114, 100, 47,  109, 101, 109, 99,
    97,  114, 100, 105, 99,  111, 110, 50,  46,  105, 109, 103, 0,   0,   0,   99,  97,  114, 100, 47,  109,
    101, 109, 99,  97,  114, 100, 105, 99,  111, 110, 51,  46,  105, 109, 103, 0,   0,   0,   99,  97,  114,
    100, 47,  109, 101, 109, 99,  97,  114, 100, 105, 99,  111, 110, 48,  46,  112, 97,  108, 0,   0,   0};
