#ifndef MAIN_GAMETEXT_API_H_
#define MAIN_GAMETEXT_API_H_

#include "types.h"

typedef struct TextDisplayState TextDisplayState;
typedef void (*GameTextMeasureS32Fn)(void* str, s32 boxIdx, s32 x, s32 y, s32* outMaxX, s32* outMaxY,
                                     s32* outMinX, s32* outMinY);
typedef void (*GameTextBoundsS32Fn)(int id, int x, int y, s32* outMaxX, s32* outMaxY, s32* outMinX,
                                    s32* outMinY);

void gameTextAppendStr(char* str, int box);
void gameTextFn_80016c18(int textId, int arg);
void gameTextFreePhrase(int* phrase);
void gameTextMeasureFn_800163c4(char* str, int boxIdx, int x, int y, int* outMaxX, int* outMaxY, int* outMinX,
                                int* outMinY);
void gameTextFn_8001628c(int id, int x, int y, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY);

#define gameTextMeasureS32 ((GameTextMeasureS32Fn)gameTextMeasureFn_800163c4)
#define gameTextBoundsS32 ((GameTextBoundsS32Fn)gameTextFn_8001628c)

#endif /* MAIN_GAMETEXT_API_H_ */
