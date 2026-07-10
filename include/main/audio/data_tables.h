#ifndef MAIN_AUDIO_DATA_TABLES_H_
#define MAIN_AUDIO_DATA_TABLES_H_

#include "ghidra_import.h"

/* MusyX synthdata.c - see src/main/audio/data_tables.c */

s32 dataInsertLayer(u16 cid, void *layerdata, u16 size);
s32 dataRemoveLayer(u16 sid);
s32 dataInsertCurve(u16 cid, void *curvedata);
s32 dataRemoveCurve(u16 sid);
s32 dataAddSampleReference(u16 sid);
s32 dataRemoveSampleReference(u16 sid);
s32 dataInsertMacro(u16 mid, void *macroaddr);
s32 dataRemoveMacro(u16 mid);
void *dataGetMacro(u16 mid);
void *dataGetCurve(u16 cid);
void *dataGetKeymap(u16 cid);
void *dataGetLayer(u16 cid, u16 *n);
void dataInit(u32 smpBase, u32 smpLength);
int IFFifoAlloc(int addr);

#endif /* MAIN_AUDIO_DATA_TABLES_H_ */
