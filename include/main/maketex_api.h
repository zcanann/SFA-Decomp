#ifndef MAIN_MAKETEX_API_H_
#define MAIN_MAKETEX_API_H_

#include "game/objects/object.h"

struct ObjSeqState;

extern char* sMemoryCardFileName;
extern int gSaveCardBackdropColor;
extern void* gSaveCardWorkArea;
extern char* gSaveCardIoBuffer;
extern u8 gSaveCardFileOpen;

typedef int (*SaveGameCallback)(int arg0, int arg1, void* arg2, void* arg3);

void cameraFocusNpc(int param1, GameObject* obj);
GameObject* getFocusedNpc(void);
int arrayIndexOf(int* array, int count, int value);
void cardSetStatusNoCard2(void);
int saveGame(int writeImages);
int saveGame_doWrite(int slot);
int saveGame_prepareAndWrite(int writeImages, int cbA, int cbB, void* cbC, void* cbD, SaveGameCallback callback);
int saveGameReadSlotCb(u8 index, int unused, void* dst);

int ObjSeq_StartPreparedStream(int slot);
void ObjSeq_preempt(int key, int value);
u8 ObjSeq_getGlobal3(void);
void ObjSeq_setGlobal3(s8 x);
s16 ObjSeq_getGlobal1(void);
void ObjSeq_setGlobal1(s16 x);
s16 ObjSeq_getGlobal2(void);
void ObjSeq_setGlobal2(s16 x);
int ObjSeq_SetObjs(int objs, GameObject* arg, int flags);
int ObjSeq_setOverridePos(f32 x, f32 y, f32 z);
int ObjSeq_SetCoordinateSpace(int unused, int space);
int ObjSeq_TurnToFacePlayer(GameObject* obj, struct ObjSeqState* state, s16 turnDegrees, s16 yawThreshold,
                            s16 maxAngle, s16 animRight, s16 animLeft);

extern char sMemoryCardFileNameString[];
extern u32 gSaveCardChecksumHi;
extern u32 gSaveCardChecksumLo;
extern u8* gSaveCardImageBuffer;
extern u32 gSaveCardSerialHi;
extern u32 gSaveCardSerialLo;
extern u8 gSaveCardIdentityCheckEnabled;
extern volatile s32 gSaveCardState;

#endif /* MAIN_MAKETEX_API_H_ */
