#ifndef MAIN_DLL_WC_WCPUSHBLOCK_H_
#define MAIN_DLL_WC_WCPUSHBLOCK_H_

#include "ghidra_import.h"

typedef struct WCPushBlockObject WCPushBlockObject;
typedef struct WCPushBlockState WCPushBlockState;

void fn_801EE0C0(s16 *path);
void fn_801EE248(int obj, WCPushBlockState *state);
void fn_801EE3B4(WCPushBlockObject *obj, WCPushBlockState *state);

#endif /* MAIN_DLL_WC_WCPUSHBLOCK_H_ */
