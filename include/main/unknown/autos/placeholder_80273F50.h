#ifndef MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80273F50_H_
#define MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80273F50_H_

#include "ghidra_import.h"
#include "main/audio/data_ref.h"

int dataInsertLayer(u16 key, void *value, u16 count);
int dataRemoveLayer(s16 key);
int dataInsertCurve(u16 key, void *value);
int dataRemoveCurve(s16 key);
int dataInsertSDir(DataSampleDirEntry *sampleTable, void *baseAddr);
int dataAddSampleReference(s16 sampleId);
int dataRemoveSampleReference(s16 sampleId);
int dataInsertFX(s16 fxId, u8 *samples, u32 count);
int dataInsertMacro(u32 key, void *value);
int dataRemoveMacro(u32 key);
int maccmp(void *a, void *b);
int smpcmp(void *a, void *b);
int dataGetSample(u16 key, u32 *out);
int curvecmp(void *a, void *b);
int layercmp(void *a, void *b);
int fxcmp(void *a, void *b);
void dataInit(u32 unused, void *base);
int IFFifoAlloc(int x);

#endif /* MAIN_UNKNOWN_AUTOS_PLACEHOLDER_80273F50_H_ */
