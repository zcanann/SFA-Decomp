#ifndef MAIN_DLL_WC_DLL_0290_WCPUSHBLOCK_H_
#define MAIN_DLL_WC_DLL_0290_WCPUSHBLOCK_H_

#include "global.h"
#include "main/game_object.h"

typedef struct WCPushBlockSetup WCPushBlockSetup;

int wcpushblock_getExtraSize(void);
int wcpushblock_getObjectTypeId(GameObject* obj);
void wcpushblock_free(void);
void wcpushblock_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wcpushblock_hitDetect(void);
void wcpushblock_init(GameObject* obj, WCPushBlockSetup* setup);
void wcpushblock_release(void);
void wcpushblock_initialise(void);
void wcpushblock_update(GameObject* obj);

#endif /* MAIN_DLL_WC_DLL_0290_WCPUSHBLOCK_H_ */
