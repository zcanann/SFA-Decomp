#ifndef MAIN_OBJPRINT_LOAD_API_H_
#define MAIN_OBJPRINT_LOAD_API_H_

#include "dolphin/dvd.h"

/* Merged-table identity selects capacity; unusedCount is retained for the retail API. */
int mergeTableFiles(void* table, int bankAFileId, int bankBFileId, int unusedCount);
void animCurvReadCb(s32 result, DVDFileInfo* fileInfo);
void animCurvTabReadCb(s32 result, DVDFileInfo* fileInfo);
void voxMapReadCb(s32 result, DVDFileInfo* fileInfo);
void voxMapTabReadCb(s32 result, DVDFileInfo* fileInfo);
void blocksReadCb(s32 result, DVDFileInfo* fileInfo);
void blocksTabReadCb(s32 result, DVDFileInfo* fileInfo);
void tex1ReadCb(s32 result, DVDFileInfo* fileInfo);
void tex1tab1readCb(s32 result, DVDFileInfo* fileInfo);
void tex1tab2readCb(s32 result, DVDFileInfo* fileInfo);
void tex0readCb(s32 result, DVDFileInfo* fileInfo);
void tex0tab1readCb(s32 result, DVDFileInfo* fileInfo);
void tex0tab2readCb(s32 result, DVDFileInfo* fileInfo);
void animReadCb(s32 result, DVDFileInfo* fileInfo);
void animTabReadCb(s32 result, DVDFileInfo* fileInfo);
void modelsReadCb(s32 result, DVDFileInfo* fileInfo);
void modelsTabReadCb(s32 result, DVDFileInfo* fileInfo);
void initLoadFileReadCb(s32 result, DVDFileInfo* fileInfo);
void romListReadCb(s32 result, DVDFileInfo* fileInfo);
s32 ObjLoad_GetDvdCommandBlockStatus(DVDCommandBlock* block);

#endif /* MAIN_OBJPRINT_LOAD_API_H_ */
