#ifndef MAIN_GAMETEXT_API_H_
#define MAIN_GAMETEXT_API_H_

#include "types.h"

typedef struct TextDisplayState TextDisplayState;

void gameTextAppendStr(char* str, int box);
void gameTextFn_80016c18(int textId, int arg);
void gameTextFreePhrase(int* phrase);
void gameTextMeasureFn_800163c4(char* str, int boxIdx, int x, int y, int* outMaxX, int* outMaxY, int* outMinX,
                                int* outMinY);
void gameTextFn_8001628c(int id, int x, int y, int* outMaxX, int* outMaxY, int* outMinX, int* outMinY);

char** textMeasureFn_80016c9c(char* str, f32 width, f32 height, int* outCount, f32* outLineH);

extern char* sMapDirectoryNameTable[74];

#endif /* MAIN_GAMETEXT_API_H_ */
