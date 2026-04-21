#ifndef CIRCLEBUFFER_H
#define CIRCLEBUFFER_H

#include "TRK_MINNOW_DOLPHIN/MetroTRK/Portable/MWCriticalSection_gc.h"
#include "dolphin/types.h"
#include "string.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct CircleBuffer {
    u8* read_ptr;
    u8* write_ptr;
    u8* start_ptr;
    u32 size;
    s32 mBytesToRead;
    u32 mBytesToWrite;
    u32 mCriticalSection;
} CircleBuffer;

static inline u32 CBGetBytesAvailableForRead(CircleBuffer* cb) {
    return cb->mBytesToRead;
}

static inline void CircleBufferInitialize(CircleBuffer* cb, u8* buf, s32 size) {
    cb->start_ptr = buf;
    cb->size = size;
    cb->read_ptr = cb->start_ptr;
    cb->write_ptr = cb->start_ptr;
    cb->mBytesToRead = 0;
    cb->mBytesToWrite = cb->size;
    MWInitializeCriticalSection(&cb->mCriticalSection);
}

static inline int CircleBufferWriteBytes(CircleBuffer* cb, u8* buf, u32 size) {
    int availSize;

    if (size > cb->mBytesToWrite) {
        return -1;
    }
    MWEnterCriticalSection(&cb->mCriticalSection);
    availSize = cb->size - (cb->write_ptr - cb->start_ptr);
    if (availSize >= size) {
        memcpy(cb->write_ptr, buf, size);
        cb->write_ptr += size;
    } else {
        memcpy(cb->write_ptr, buf, availSize);
        memcpy(cb->start_ptr, buf + availSize, size - availSize);
        cb->write_ptr = cb->start_ptr + size - availSize;
    }

    if (cb->size == (cb->write_ptr - cb->start_ptr)) {
        cb->write_ptr = cb->start_ptr;
    }

    cb->mBytesToWrite -= size;
    cb->mBytesToRead += size;
    MWExitCriticalSection(&cb->mCriticalSection);
    return 0;
}

static inline int CircleBufferReadBytes(CircleBuffer* cb, u8* buf, u32 size) {
    int availSize;

    if (size > cb->mBytesToRead) {
        return -1;
    }
    MWEnterCriticalSection(&cb->mCriticalSection);
    availSize = cb->size - (cb->read_ptr - cb->start_ptr);
    if (size < availSize) {
        memcpy(buf, cb->read_ptr, size);
        cb->read_ptr += size;
    } else {
        memcpy(buf, cb->read_ptr, availSize);
        memcpy(buf + availSize, cb->start_ptr, size - availSize);
        cb->read_ptr = cb->start_ptr + size - availSize;
    }

    if (cb->size == (cb->read_ptr - cb->start_ptr)) {
        cb->read_ptr = cb->start_ptr;
    }

    cb->mBytesToWrite += size;
    cb->mBytesToRead -= size;
    MWExitCriticalSection(&cb->mCriticalSection);
    return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* CIRCLEBUFFER_H */
