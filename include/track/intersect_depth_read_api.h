#ifndef TRACK_INTERSECT_DEPTH_READ_API_H_
#define TRACK_INTERSECT_DEPTH_READ_API_H_

int depthReadRequestPoll(int x, int y, int requestKey);

/* Some callers use an object or function address as the opaque request key. */
#define depthReadRequestPollPointerKey(x, y, requestKey)                                                                 \
    ((int (*)(int, int, void*))depthReadRequestPoll)((x), (y), (requestKey))

#endif /* TRACK_INTERSECT_DEPTH_READ_API_H_ */
