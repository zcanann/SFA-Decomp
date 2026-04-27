#include <dolphin/os.h>
#include <dolphin/exi.h>

#define EXI_TX 0x800400u
#define EXI_MAGIC 0xA5FF005A

extern s32 lbl_803DE098;
extern u32 lbl_803DE09C;
extern u32 lbl_803DE0A0;
extern u32 lbl_803DE0A4;

#define Chan lbl_803DE098
#define Dev lbl_803DE09C
#define Enabled lbl_803DE0A0
#define BarnacleEnabled lbl_803DE0A4

u32 InitializeUART(u32 baudRate) {
    (void)baudRate;

    if (BarnacleEnabled == EXI_MAGIC) {
        return 0;
    }

    if (!(OSGetConsoleType() & OS_CONSOLE_DEVELOPMENT)) {
        Enabled = 0;
        return 2;
    }

    Chan = 0;
    Dev = 1;
    Enabled = EXI_MAGIC;
    return 0;
}

static int QueueLength(void) {
    u32 cmd;

    if (!EXISelect(Chan, Dev, EXI_FREQ_8M)) {
        return -1;
    }

    cmd = EXI_TX << 6;
    EXIImm(Chan, &cmd, 4, EXI_WRITE, NULL);
    EXISync(Chan);

    EXIImm(Chan, &cmd, 1, EXI_READ, NULL);
    EXISync(Chan);
    EXIDeselect(Chan);

    return 16 - (int)((cmd >> 24) & 0xFF);
}

u32 WriteUARTN(const void* buf, u32 len) {
    u32 cmd;
    int qLen;
    long xLen;
    char* ptr;
    BOOL locked;
    u32 error;

    if (Enabled != EXI_MAGIC) {
        return 2;
    }

    locked = EXILock(Chan, Dev, NULL);
    if (!locked) {
        return 0;
    }

    for (ptr = (char*)buf; ptr - (char*)buf < len; ptr++) {
        if (*ptr == '\n') {
            *ptr = '\r';
        }
    }

    error = 0;
    cmd = (EXI_TX | 0x2000000) << 6;
    while (len != 0) {
        qLen = QueueLength();
        if (qLen < 0) {
            error = 3;
            break;
        }

        if (qLen < 12 && qLen < len) {
            continue;
        }

        if (!EXISelect(Chan, Dev, EXI_FREQ_8M)) {
            error = 3;
            break;
        }

        EXIImm(Chan, &cmd, 4, EXI_WRITE, NULL);
        EXISync(Chan);

        while (qLen != 0 && len != 0) {
            if (qLen < 4 && qLen < len) {
                break;
            }

            xLen = len < 4 ? (long)len : 4;
            EXIImm(Chan, (void*)buf, xLen, EXI_WRITE, NULL);
            buf = (u8*)buf + xLen;
            len -= xLen;
            qLen -= xLen;
            EXISync(Chan);
        }

        EXIDeselect(Chan);
    }

    EXIUnlock(Chan);
    return error;
}
