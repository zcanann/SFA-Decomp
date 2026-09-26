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
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
extern char sFrDiscLoadingMessage[];
extern char sFrDiscReadingMessage[];
extern char sFrDiscInsertPromptLine[];
extern char sFrDiscInsertGameDiscLine[];
extern char sDeDiscLoadingMessage[];
extern char sDeDiscReadingMessage[];
extern char sDeDiscInsertPromptLine[];
extern char sDeDiscInsertGameDiscLine[];
extern char sItDiscLoadingMessage[];
extern char sItDiscReadingMessage[];
extern char sItDiscInsertPromptLine[];
extern char sItDiscInsertGameDiscLine[];
extern char sEsDiscLoadingMessage[];
extern char sEsDiscReadingMessage[];
extern char sEsDiscInsertPromptLine[];
extern char sEsDiscInsertGameDiscLine[];
extern char sItDiscErrorOccurredLine[];
extern char sItDiscErrorInstructionBookletLine[];
extern char sFrDiscErrorSpacerLine[4];
extern char sFrDiscReadErrorSpacerLine[4];
extern char* sFrDiscReadingMessageLines[1];
extern char sFrDiscCoverOpenSpacerLine[4];
extern char* sFrDiscInsertMessageLines[2];
extern char sFrWrongDiscSpacerLine[4];
extern char* sFrDiscLoadingMessageLines[1];
extern char sDeDiscErrorSpacerLine[4];
extern char sDeDiscReadErrorSpacerLine[4];
extern char* sDeDiscReadingMessageLines[1];
extern char sDeDiscCoverOpenSpacerLine[4];
extern char* sDeDiscInsertMessageLines[2];
extern char sDeWrongDiscSpacerLine[4];
extern char* sDeDiscLoadingMessageLines[1];
extern char sEsDiscErrorSpacerLine[4];
extern char sEsDiscReadErrorSpacerLine[4];
extern char* sEsDiscReadingMessageLines[1];
extern char sEsDiscCoverOpenSpacerLine[4];
extern char* sEsDiscInsertMessageLines[2];
extern char sEsWrongDiscSpacerLine[4];
extern char* sEsDiscLoadingMessageLines[1];
extern char* sItDiscErrorOccurredMessageLines[2];
extern char sItDiscReadErrorSpacerLine[4];
extern char* sItDiscReadingMessageLines[1];
extern char* sItDiscInsertMessageLines[2];
extern char sItWrongDiscIsNotLine[8];
extern char* sItDiscLoadingMessageLines[1];
#endif
extern int gGameTextFontTexRowPitch;
extern GXColor gGameTextClearColor;
extern int gGameTextFlagGlyphRaise;
extern char sGameTextBlankFormat[5];
extern int gGameTextSavedDir;
extern u16 gGameTextSjisGlyphTable[256];

#endif /* MAIN_GAMETEXT_DATA_H_ */
