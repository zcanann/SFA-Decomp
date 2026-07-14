#ifndef MAIN_MAKETEX_API_H_
#define MAIN_MAKETEX_API_H_

#include "main/game_object.h"

void cameraFocusNpc(int param1, GameObject* obj);
GameObject* getFocusedNpc(void);
int arrayIndexOf(int* array, int count, int value);
void cardSetStatusNoCard2(void);

#endif /* MAIN_MAKETEX_API_H_ */
