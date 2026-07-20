#ifndef MAIN_OBJPRINT_LOAD_API_H_
#define MAIN_OBJPRINT_LOAD_API_H_

#include "dolphin/dvd.h"

int mergeTableFiles(void* table, int id, int idx, int count);
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
void dvdReadCb_80041d30(s32 result, DVDFileInfo* fileInfo);
void romListReadCb(s32 result, DVDFileInfo* fileInfo);
int fn_80041D98(DVDCommandBlock* block);

#endif /* MAIN_OBJPRINT_LOAD_API_H_ */
