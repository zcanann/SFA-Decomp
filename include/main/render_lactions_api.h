#ifndef MAIN_RENDER_LACTIONS_API_H_
#define MAIN_RENDER_LACTIONS_API_H_

#include "types.h"

#if defined(RENDER_LACTIONS_DIRECT_UNPROTOTYPED_CALL)
int getLActions();
#elif defined(RENDER_LACTIONS_DIRECT_VOID6_CALL)
void getLActions(int source, int target, int index, int arg3, int arg4, int arg5);
#else
typedef void (*LActionsVoid6Fn)(int source, int target, int index, int arg3, int arg4, int arg5);
typedef int (*LActionsInt6Fn)(int source, int target, u16 index, int arg3, int arg4, int arg5);

int getLActions(int source, int target, u16 index);

#define getLActionsVoid6(source, target, index, arg3, arg4, arg5) \
    (((LActionsVoid6Fn)getLActions)((int)(source), (int)(target), (index), (arg3), (arg4), (arg5)))
#define getLActionsInt6(source, target, index, arg3, arg4, arg5) \
    (((LActionsInt6Fn)getLActions)((int)(source), (int)(target), (index), (arg3), (arg4), (arg5)))
#endif

#endif /* MAIN_RENDER_LACTIONS_API_H_ */
