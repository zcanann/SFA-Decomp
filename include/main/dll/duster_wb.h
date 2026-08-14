#ifndef H_MAIN_DLL_DUSTER_WB_H
#define H_MAIN_DLL_DUSTER_WB_H

#include "global.h"

struct GameObject;

void wbUpdateEngaged(struct GameObject* obj, int state);
void wbUpdateIdle(struct GameObject* obj, int state);
void mutatedEbaUpdateEngaged(u32 obj, int state);
void mutatedEbaUpdateIdle(u32 obj, int state);
void mutatedEbaInit(u32 unused, int state);

#endif /* H_MAIN_DLL_DUSTER_WB_H */
