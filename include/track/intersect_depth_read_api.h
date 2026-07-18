#ifndef TRACK_INTERSECT_DEPTH_READ_API_H_
#define TRACK_INTERSECT_DEPTH_READ_API_H_

#include "types.h"

typedef struct DepthReadRequest
{
    u16 x;
    u16 y;
    u32 value;
    int key;
} DepthReadRequest;

extern u16 gDepthReadPendingCount;
extern u16 gDepthReadResultCount;
extern DepthReadRequest gDepthReadResults[0x14];
extern DepthReadRequest gDepthReadPendingQueue[0x14];

int depthReadRequestPoll(int x, int y, void* requestKey);

#endif /* TRACK_INTERSECT_DEPTH_READ_API_H_ */
