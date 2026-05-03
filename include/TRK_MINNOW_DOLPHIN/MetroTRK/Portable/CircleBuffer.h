#ifndef CIRCLEBUFFER_H
#define CIRCLEBUFFER_H

#include "dolphin/types.h"

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

int CircleBufferReadBytes(CircleBuffer* cb, u8* buf, u32 size);
int CircleBufferWriteBytes(CircleBuffer* cb, u8* buf, u32 size);
void CircleBufferInitialize(CircleBuffer* cb, u8* buf, s32 size);
u32 CBGetBytesAvailableForRead(CircleBuffer* cb);

#ifdef __cplusplus
}
#endif

#endif /* CIRCLEBUFFER_H */
