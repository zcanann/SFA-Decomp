#ifndef MAIN_DLL_WC_WCPUSHBLOCK_H_
#define MAIN_DLL_WC_WCPUSHBLOCK_H_

#include "ghidra_import.h"

typedef struct WCPushBlockObject WCPushBlockObject;
typedef struct WCPushBlockState WCPushBlockState;

void WCPushBlock_SpawnFromPath(s16 *path);
void WCPushBlock_UpdateCloudAction(int obj, WCPushBlockState *state);
void WCPushBlock_UpdateRideTilt(WCPushBlockObject *obj, WCPushBlockState *state);

#endif /* MAIN_DLL_WC_WCPUSHBLOCK_H_ */
