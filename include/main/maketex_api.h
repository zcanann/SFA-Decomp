#ifndef MAIN_MAKETEX_API_H_
#define MAIN_MAKETEX_API_H_

#include "main/game_object.h"

extern char* sMemoryCardFileName;
extern int lbl_803DB708;
extern void* lbl_803DD040;
extern char* lbl_803DD044;
extern u8 lbl_803DD05A;

typedef int (*SaveGameCallback)(int arg0, int arg1, int arg2, int arg3);

void cameraFocusNpc(int param1, GameObject* obj);
GameObject* getFocusedNpc(void);
int arrayIndexOf(int* array, int count, int value);
void cardSetStatusNoCard2(void);
int saveGame(int writeImages);
int saveGame_doWrite(int slot);
int saveGame_prepareAndWrite(int writeImages, int cbA, int cbB, int cbC, int cbD, SaveGameCallback callback);
int saveCb_8007e77c(u8 index, int unused, void* dst);

#define saveGamePrepareLegacy(writeImages, cbA, cbB, cbC, cbD, callback) \
    saveGame_prepareAndWrite((writeImages), (cbA), (cbB), (cbC), (cbD), (SaveGameCallback)(callback))

int seqStreamFn_8008023c(int x);
void ObjSeq_preempt(int key, int value);
u8 ObjSeq_getGlobal3(void);
void ObjSeq_setGlobal3(u8 x);
s16 ObjSeq_getGlobal1(void);
void ObjSeq_setGlobal1(s16 x);
s16 ObjSeq_getGlobal2(void);
void ObjSeq_setGlobal2(s16 x);
int ObjSeq_SetObjs(int objs, int arg, int flags);
int ObjSeq_setOverridePos(f32 x, f32 y, f32 z);
int ObjSeq_func23(int unused, int x);

#endif /* MAIN_MAKETEX_API_H_ */
