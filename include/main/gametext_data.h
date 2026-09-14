#ifndef MAIN_GAMETEXT_DATA_H_
#define MAIN_GAMETEXT_DATA_H_

#include "main/gametext_internal.h"
#include "dolphin/gx/GXStruct.h"

extern char sJpDiscLoadingMessage[];
extern char sDiscLoadingMessage[];
extern char sDiscReadingMessage[];
extern char sDiscInsertPromptLine[];
extern char sDiscInsertGameDiscLine[];
extern char sJpDiscErrorTopSpacerLine[4];
extern char sJpDiscErrorBottomSpacerLine[4];
extern char sJpDiscReadErrorTopSpacerLine[4];
extern char sJpDiscReadingTopSpacerLine[4];
extern char sJpDiscCoverOpenTopSpacerLine[4];
extern char sJpDiscInsertTopSpacerLine[4];
extern char sJpDiscInsertBottomSpacerLine[4];
extern char sJpWrongDiscTopSpacerLine[4];
extern char sJpWrongDiscMiddleSpacerLine[4];
extern char* sJpDiscLoadingMessageLines[1];
extern char sDiscErrorSpacerLine[4];
extern char sDiscReadErrorSpacerLine[4];
extern char* sDiscReadingMessageLines[1];
extern char sDiscCoverOpenSpacerLine[4];
extern char* sDiscInsertMessageLines[2];
extern char sWrongDiscSpacerLine[4];
extern char* sDiscLoadingMessageLines[1];
extern int gGameTextFontTexRowPitch;
extern GXColor gGameTextClearColor;
extern int gGameTextFlagGlyphRaise;
extern char sGameTextBlankFormat[5];
extern int gGameTextSavedDir;
extern u16 gGameTextSjisGlyphTable[256];

#endif /* MAIN_GAMETEXT_DATA_H_ */
