#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/CircleBuffer.h"
#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/MWTrace.h"
#include "OdemuExi2/odemuexi/DebuggerDriver.h"
#include <dolphin/amc/AmcExi2Comm.h>

#define GDEV_ERR_NOT_INITIALIZED (-0x2711)
#define GDEV_ERR_ALREADY_INITIALIZED (-0x2715)
#define GDEV_ERR_READ_ERROR (-0x2719)

#define GDEV_BUF_SIZE (0x500)

typedef struct GdevRecvCB {
    CircleBuffer cb;
    u32 reserved;
} GdevRecvCB;

typedef struct GdevInitFlag {
    BOOL value;
    u32 reserved;
} GdevInitFlag;

static GdevRecvCB gRecvCB ATTRIBUTE_ALIGN(8);
static u8 gRecvBuf[GDEV_BUF_SIZE] ATTRIBUTE_ALIGN(32);
static GdevInitFlag gIsInitialized ATTRIBUTE_ALIGN(8);

static const char gdev_cc_write_not_initialized[] = "cc not initialized\n";
static const char gdev_cc_write_output_data[] = "cc_write : Output data 0x%08x %ld bytes\n";
static const char gdev_cc_write_sending[] = "cc_write sending %ld bytes\n";
static const char gdev_cc_read_expected_packet_size[] = "Expected packet size : 0x%08x (%ld)\n";
static const char gdev_cc_read_error[] = "cc_read : error reading bytes from EXI2 %ld\n";
static const char gdev_cc_initialize_calling_exi2_init[] = "CALLING EXI2_Init\n";
static const char gdev_cc_initialize_done_calling_exi2_init[] = "DONE CALLING EXI2_Init\n";

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
int gdev_cc_initialize(void* inputPendingPtrRef, __OSInterruptHandler monitorCallback)
{
    MWTRACE(1, (char*)gdev_cc_initialize_calling_exi2_init);
    DBInitComm(inputPendingPtrRef, monitorCallback);
    MWTRACE(1, (char*)gdev_cc_initialize_done_calling_exi2_init);
    CircleBufferInitialize(&gRecvCB.cb, gRecvBuf, GDEV_BUF_SIZE);
    return 0;
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
int gdev_cc_shutdown()
{
    return 0;
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
int gdev_cc_open()
{
    if (gIsInitialized.value) {
        return GDEV_ERR_ALREADY_INITIALIZED;
    }

    gIsInitialized.value = TRUE;
    return 0;
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
int gdev_cc_close()
{
    return 0;
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
int gdev_cc_read(u8* data, int size)
{
    u8 buff[GDEV_BUF_SIZE];
    int originalDataSize;
    u32 result;
    int expectedDataSize;
    int poll;

    result = 0;
    if (!gIsInitialized.value) {
        return GDEV_ERR_NOT_INITIALIZED;
    }

    MWTRACE(1, (char*)gdev_cc_read_expected_packet_size, size, size);

    originalDataSize = size;
    expectedDataSize = size;
    while ((u32)CBGetBytesAvailableForRead(&gRecvCB.cb) < expectedDataSize) {
        result = 0;
        poll = DBQueryData();
        if (poll != 0) {
            result = DBRead(buff, expectedDataSize);
            if (result == 0) {
                CircleBufferWriteBytes(&gRecvCB.cb, buff, poll);
            }
        }
    }

    if (result == 0) {
        CircleBufferReadBytes(&gRecvCB.cb, data, originalDataSize);
    } else {
        MWTRACE(8, (char*)gdev_cc_read_error, result);
    }

    return result;
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
int gdev_cc_write(const u8* bytes, int length)
{
    int exi2Len;
    int n_copy;
    u32 hexCopy;

    hexCopy = (u32)bytes;
    n_copy = length;

    if (gIsInitialized.value == FALSE) {
        MWTRACE(8, (char*)gdev_cc_write_not_initialized);
        return GDEV_ERR_NOT_INITIALIZED;
    }

    MWTRACE(8, (char*)gdev_cc_write_output_data, bytes, length);

    while (n_copy > 0) {
        MWTRACE(1, (char*)gdev_cc_write_sending, n_copy);
        exi2Len = DBWrite((const void*)hexCopy, n_copy);
        if (exi2Len == AMC_EXI_NO_ERROR) {
            break;
        }

        hexCopy += exi2Len;
        n_copy -= exi2Len;
    }

    return 0;
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
int gdev_cc_pre_continue()
{
    DBClose();
    return 0;
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
int gdev_cc_post_stop()
{
    DBOpen();
    return 0;
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
int gdev_cc_peek()
{
    int poll;
    u8 buff[GDEV_BUF_SIZE];

    poll = DBQueryData();
    if (poll <= 0) {
        return 0;
    }

    if (DBRead(buff, poll) == 0) {
        CircleBufferWriteBytes(&gRecvCB.cb, buff, poll);
    } else {
        return GDEV_ERR_READ_ERROR;
    }

    return poll;
}

/*
 * --INFO--
 * PAL Address: TODO
 * PAL Size: TODO
 * EN Address: TODO
 * EN Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 */
int gdev_cc_initinterrupts()
{
    DBInitInterrupts();
    return 0;
}
