#ifndef MAIN_MAKETEX_API_H_
#define MAIN_MAKETEX_API_H_

#include "main/game_object.h"

extern char* sMemoryCardFileName;
extern int lbl_803DB708;
extern void* lbl_803DD040;
extern char* lbl_803DD044;

void cameraFocusNpc(int param1, GameObject* obj);
GameObject* getFocusedNpc(void);
int arrayIndexOf(int* array, int count, int value);
void cardSetStatusNoCard2(void);

#endif /* MAIN_MAKETEX_API_H_ */
