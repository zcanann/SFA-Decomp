#include "ghidra_import.h"
#include "main/audio/data_ref.h"

extern int hwTransAddr(int x);
extern void sndBegin(void);
extern void sndEnd(void);

/*
 * Insert a scene/sample-list entry, keeping the 12-byte table sorted by id.
 */
extern u8 dataKeymapTable[];
extern u8 dataLayerTable[];
extern u8 dataSmpSDirTable[];
extern u16 dataLayerNum;

int dataInsertLayer(u16 key, void *value, u16 count)
{
    u32 moveCount;
    u32 *entry;
    u32 used;
    u32 batches;
    int index;
    u8 *tableBase;

    tableBase = dataSmpSDirTable;
    sndBegin();
    used = dataLayerNum;
    index = 0;
    for (entry = (u32 *)(tableBase + 0x4e00);
         (index < (int)used) && (*(u16 *)(entry + 1) < key); entry += 3) {
        index++;
    }
    if (index < (int)used) {
        if (key == *(u16 *)(tableBase + 0x4e04 + index * 0xc)) {
            (*(u16 *)(tableBase + 0x4e08 + index * 0xc))++;
            sndEnd();
            return 0;
        }
        if (used > 0xff) {
            sndEnd();
            return 0;
        }
        moveCount = used - index;
        entry = (u32 *)(tableBase + 0x4e00 + (used - 1) * 0xc);
        if (index <= (int)(used - 1)) {
            batches = moveCount >> 3;
            if (batches != 0) {
                do {
                    entry[3] = entry[0];
                    entry[4] = entry[1];
                    entry[5] = entry[2];
                    entry[0] = entry[-3];
                    entry[1] = entry[-2];
                    entry[2] = entry[-1];
                    entry[-3] = entry[-6];
                    entry[-2] = entry[-5];
                    entry[-1] = entry[-4];
                    entry[-6] = entry[-9];
                    entry[-5] = entry[-8];
                    entry[-4] = entry[-7];
                    entry[-9] = entry[-12];
                    entry[-8] = entry[-11];
                    entry[-7] = entry[-10];
                    entry[-12] = entry[-15];
                    entry[-11] = entry[-14];
                    entry[-10] = entry[-13];
                    entry[-15] = entry[-18];
                    entry[-14] = entry[-17];
                    entry[-13] = entry[-16];
                    entry[-18] = entry[-21];
                    entry[-17] = entry[-20];
                    entry[-16] = entry[-19];
                    entry -= 0x18;
                    batches--;
                } while (batches != 0);
                moveCount &= 7;
                if (moveCount == 0) {
                    goto insert;
                }
            }
            do {
                entry[3] = entry[0];
                entry[4] = entry[1];
                entry[5] = entry[2];
                entry -= 3;
                moveCount--;
            } while (moveCount != 0);
        }
    } else if (used > 0xff) {
        sndEnd();
        return 0;
    }

insert:
    dataLayerNum++;
    *(u16 *)(tableBase + 0x4e04 + index * 0xc) = key;
    *(void **)(tableBase + 0x4e00 + index * 0xc) = value;
    *(u16 *)(tableBase + 0x4e06 + index * 0xc) = count;
    *(u16 *)(tableBase + 0x4e08 + index * 0xc) = 1;
    sndEnd();
    return 1;
}

/*
 * Release a scene/sample-list entry, compacting the sorted table.
 */
int dataRemoveLayer(s16 key)
{
    s16 refCount;
    int next;
    u32 *entry;
    u32 moveCount;
    u32 index;
    u32 used;
    u8 *tableBase;

    tableBase = dataSmpSDirTable;
    sndBegin();
    used = dataLayerNum;
    index = 0;
    for (entry = (u32 *)(tableBase + 0x4e00);
         ((int)index < (int)used) && (key != *(s16 *)(entry + 1)); entry += 3) {
        index++;
    }
    if (index == used) {
        sndEnd();
        return 0;
    }
    refCount = *(s16 *)(tableBase + 0x4e08 + index * 0xc);
    *(s16 *)(tableBase + 0x4e08 + index * 0xc) = refCount - 1;
    if ((s16)(refCount - 1) != 0) {
        sndEnd();
        return 0;
    }

    next = index + 1;
    moveCount = used - next;
    entry = (u32 *)(tableBase + 0x4e00 + next * 0xc);
    if (next < (int)used) {
        used = moveCount >> 3;
        if (used != 0) {
            do {
                entry[-3] = entry[0];
                entry[-2] = entry[1];
                entry[-1] = entry[2];
                entry[0] = entry[3];
                entry[1] = entry[4];
                entry[2] = entry[5];
                entry[3] = entry[6];
                entry[4] = entry[7];
                entry[5] = entry[8];
                entry[6] = entry[9];
                entry[7] = entry[10];
                entry[8] = entry[11];
                entry[9] = entry[12];
                entry[10] = entry[13];
                entry[11] = entry[14];
                entry[12] = entry[15];
                entry[13] = entry[16];
                entry[14] = entry[17];
                entry[15] = entry[18];
                entry[16] = entry[19];
                entry[17] = entry[20];
                entry[18] = entry[21];
                entry[19] = entry[22];
                entry[20] = entry[23];
                entry += 0x18;
                used--;
            } while (used != 0);
            moveCount &= 7;
            if (moveCount == 0) {
                goto remove;
            }
        }
        do {
            entry[-3] = entry[0];
            entry[-2] = entry[1];
            entry[-1] = entry[2];
            entry += 3;
            moveCount--;
        } while (moveCount != 0);
    }

remove:
    dataLayerNum--;
    sndEnd();
    return 1;
}

/*
 * Insert a keygroup/sample indirection entry, keeping the table sorted by id.
 */
extern u8 dataCurveTable[];
extern u8 dataSmpSDirTable[];
extern u16 dataCurveNum;
extern void sndBegin(void);
extern void sndEnd(void);

int dataInsertCurve(u16 key, void *value)
{
    u32 moveCount;
    u32 used;
    u32 batches;
    int index;
    u32 *entry;
    u8 *tableBase;

    tableBase = dataSmpSDirTable;
    sndBegin();
    used = dataCurveNum;
    index = 0;
    for (entry = (u32 *)(tableBase + 0x600);
         (index < (int)used) && (*(u16 *)(entry + 1) < key); entry += 2) {
        index++;
    }
    if (index < (int)used) {
        if (key == *(u16 *)(tableBase + 0x604 + index * 8)) {
            sndEnd();
            (*(u16 *)(tableBase + 0x606 + index * 8))++;
            return 0;
        }
        if (used > 0x7ff) {
            sndEnd();
            return 0;
        }
        moveCount = used - index;
        entry = (u32 *)(tableBase + 0x600 + (used - 1) * 8);
        if (index <= (int)(used - 1)) {
            batches = moveCount >> 3;
            if (batches != 0) {
                do {
                    entry[2] = entry[0];
                    entry[3] = entry[1];
                    entry[0] = entry[-2];
                    entry[1] = entry[-1];
                    entry[-2] = entry[-4];
                    entry[-1] = entry[-3];
                    entry[-4] = entry[-6];
                    entry[-3] = entry[-5];
                    entry[-6] = entry[-8];
                    entry[-5] = entry[-7];
                    entry[-8] = entry[-10];
                    entry[-7] = entry[-9];
                    entry[-10] = entry[-12];
                    entry[-9] = entry[-11];
                    entry[-12] = entry[-14];
                    entry[-11] = entry[-13];
                    entry -= 0x10;
                    batches--;
                } while (batches != 0);
                moveCount &= 7;
                if (moveCount == 0) {
                    goto insert;
                }
            }
            do {
                entry[2] = entry[0];
                entry[3] = entry[1];
                entry -= 2;
                moveCount--;
            } while (moveCount != 0);
        }
    } else if (used > 0x7ff) {
        sndEnd();
        return 0;
    }

insert:
    dataCurveNum++;
    *(u16 *)(tableBase + 0x604 + index * 8) = key;
    *(void **)(tableBase + 0x600 + index * 8) = value;
    *(u16 *)(tableBase + 0x606 + index * 8) = 1;
    sndEnd();
    return 1;
}

/*
 * Release a keygroup/sample indirection entry, compacting the sorted table.
 */
int dataRemoveCurve(s16 key)
{
    s16 refCount;
    int next;
    u32 *entry;
    u32 moveCount;
    u32 index;
    u32 used;
    u8 *tableBase;

    tableBase = dataSmpSDirTable;
    sndBegin();
    used = dataCurveNum;
    index = 0;
    for (entry = (u32 *)(tableBase + 0x600);
         ((int)index < (int)used) && (key != *(s16 *)(entry + 1)); entry += 2) {
        index++;
    }
    if (index == used) {
        sndEnd();
        return 0;
    }
    refCount = *(s16 *)(tableBase + 0x606 + index * 8);
    *(s16 *)(tableBase + 0x606 + index * 8) = refCount - 1;
    if ((s16)(refCount - 1) != 0) {
        sndEnd();
        return 0;
    }

    next = index + 1;
    moveCount = used - next;
    entry = (u32 *)(tableBase + 0x600 + next * 8);
    if (next < (int)used) {
        used = moveCount >> 3;
        if (used != 0) {
            do {
                entry[-2] = entry[0];
                entry[-1] = entry[1];
                entry[0] = entry[2];
                entry[1] = entry[3];
                entry[2] = entry[4];
                entry[3] = entry[5];
                entry[4] = entry[6];
                entry[5] = entry[7];
                entry[6] = entry[8];
                entry[7] = entry[9];
                entry[8] = entry[10];
                entry[9] = entry[11];
                entry[10] = entry[12];
                entry[11] = entry[13];
                entry[12] = entry[14];
                entry[13] = entry[15];
                entry += 0x10;
                used--;
            } while (used != 0);
            moveCount &= 7;
            if (moveCount == 0) {
                goto remove;
            }
        }
        do {
            entry[-2] = entry[0];
            entry[-1] = entry[1];
            entry += 2;
            moveCount--;
        } while (moveCount != 0);
    }

remove:
    dataCurveNum--;
    sndEnd();
    return 1;
}

/*
 * Register an SDI sample table and flag entries already present in earlier tables.
 */
extern u8 dataSmpSDirTable[];
extern u16 dataSmpSDirNum;

int dataInsertSDir(DataSampleDirEntry *sampleTable, void *baseAddr)
{
    DataSampleDirBucket *bucket;
    DataSampleDirEntry *entry;
    int result;
    u32 bucketIndex;
    u32 used;
    DataSampleDirEntry *scan;
    u16 tableCount;
    u16 i;
    u16 j;
    u16 k;

    bucketIndex = 0;
    used = dataSmpSDirNum;
    for (bucket = (DataSampleDirBucket *)dataSmpSDirTable;
         ((int)bucketIndex < (int)used) && (bucket->entries != sampleTable); bucket++) {
        bucketIndex++;
    }
    if (bucketIndex == used) {
        if (used < 0x80) {
            tableCount = 0;
            for (entry = sampleTable; entry->sampleId != -1; entry++) {
                tableCount++;
            }
            sndBegin();
            entry = sampleTable;
            for (i = 0; i < tableCount; i++) {
                j = 0;
                bucket = (DataSampleDirBucket *)dataSmpSDirTable;
                for (bucketIndex = dataSmpSDirNum; bucketIndex != 0; bucketIndex--) {
                    scan = bucket->entries;
                    for (k = 0; k < bucket->count; k++) {
                        if (entry->sampleId == scan->sampleId) {
                            goto foundEntry;
                        }
                        scan++;
                    }
                    bucket++;
                    j++;
                }

foundEntry:
                if (j == dataSmpSDirNum) {
                    entry->refCount = 0;
                } else {
                    entry->refCount = -1;
                }
                entry++;
            }
            bucketIndex = dataSmpSDirNum;
            ((DataSampleDirBucket *)dataSmpSDirTable)[bucketIndex].entries = sampleTable;
            ((DataSampleDirBucket *)dataSmpSDirTable)[bucketIndex].count = tableCount;
            ((DataSampleDirBucket *)dataSmpSDirTable)[bucketIndex].baseAddr = baseAddr;
            dataSmpSDirNum++;
            sndEnd();
            result = 1;
        } else {
            result = 0;
        }
    } else {
        result = 1;
    }
    return result;
}

/*
 * Add a reference to a sample table entry, loading it on the first reference.
 */
extern u8 dataSmpSDirTable[];
extern u16 dataSmpSDirNum;
extern void hwSaveSample(void *sampleDescPtr, void *addrOut);

int dataAddSampleReference(s16 sampleId)
{
    u32 remaining;
    u32 bucketIndex;
    DataSampleDirBucket *bucket;
    DataSampleDirEntry *entry;
    u8 *sampleDesc;

    bucket = (DataSampleDirBucket *)dataSmpSDirTable;
    bucketIndex = 0;
    for (remaining = dataSmpSDirNum, entry = 0; remaining != 0; remaining--) {
        for (entry = bucket->entries; entry->sampleId != -1; entry++) {
            if ((entry->sampleId == sampleId) && (entry->refCount != -1)) {
                goto found;
            }
        }
        bucket++;
        bucketIndex++;
    }

found:
    if (entry->refCount == 0) {
        sampleDesc = entry->header;
        entry->loadedAddr = entry->offset + *(u32 *)(dataSmpSDirTable + 4 + bucketIndex * 0xc);
        hwSaveSample(&sampleDesc, &entry->loadedAddr);
    }
    entry->refCount++;
    return 1;
}

/*
 * Release a sample table reference, removing it after the last user.
 */
extern void hwRemoveSample(void *sampleDesc, u32 addr);

int dataRemoveSampleReference(s16 sampleId)
{
    u32 remaining;
    DataSampleDirBucket *bucket;
    DataSampleDirEntry *entry;

    bucket = (DataSampleDirBucket *)dataSmpSDirTable;
    remaining = dataSmpSDirNum;
    do {
        if (remaining == 0) {
            return 0;
        }
        for (entry = bucket->entries; entry->sampleId != -1; entry++) {
            if ((entry->sampleId == sampleId) && (entry->refCount != -1)) {
                entry->refCount--;
                if (entry->refCount == 0) {
                    hwRemoveSample(entry->header, entry->loadedAddr);
                }
                return 1;
            }
        }
        bucket++;
        remaining--;
    } while (1);
}

/*
 * Register an FX sample-list bucket and mark each sample descriptor as resident.
 */
extern u8 dataFXGroupTable[];
extern u16 dataFXGroupNum;
extern void sndBegin(void);
extern void sndEnd(void);

int dataInsertFX(s16 fxId, u8 *samples, u32 count)
{
    u32 i;
    u32 used;
    u32 batchCount;
    u8 *tableBase;
    DataFXGroupRef *groups;

    tableBase = dataSmpSDirTable;
    groups = (DataFXGroupRef *)(tableBase + 0xa200);
    i = 0;
    used = dataFXGroupNum;
    while (((int)i < (int)used) && (fxId != groups[i].groupId)) {
        i++;
    }
    if ((i != used) || (used > 0x7f)) {
        return 0;
    }

    sndBegin();
    used = dataFXGroupNum;
    i = count & 0xffff;
    groups[used].groupId = fxId;
    groups[used].count = count;
    groups[used].samples = samples;
    if (i != 0) {
        batchCount = i >> 3;
        if (batchCount != 0) {
            do {
                samples[9] = 0x1f;
                samples[0x13] = 0x1f;
                samples[0x1d] = 0x1f;
                samples[0x27] = 0x1f;
                samples[0x31] = 0x1f;
                samples[0x3b] = 0x1f;
                samples[0x45] = 0x1f;
                samples[0x4f] = 0x1f;
                samples += 0x50;
                batchCount--;
            } while (batchCount != 0);
            i = count & 7;
            if (i == 0) {
                goto done;
            }
        }
        do {
            samples[9] = 0x1f;
            samples += 10;
            i--;
        } while (i != 0);
    }

done:
    dataFXGroupNum++;
    sndEnd();
    return 1;
}

/*
 * Insert an instrument entry into the bucketed sorted table.
 */
extern u16 dataMacTotal;
extern u8 dataMacroBucketTable[];
extern u8 dataMacroTable[];

int dataInsertMacro(u32 key, void *value)
{
    u32 bucketOffset;
    u32 bucketCount;
    u32 insertIndex;
    u32 bucketIndex;
    DataMacroBucket *bucket;
    u32 *entry;
    int i;
    u32 moveCount;
    u32 batches;

    sndBegin();
    bucketOffset = (key >> 4) & 0xffc;
    bucketCount = *(u16 *)(dataMacroBucketTable + bucketOffset);
    bucketIndex = (key >> 6) & 0x3ff;
    if (bucketCount == 0) {
        bucketCount = dataMacTotal;
        *(u16 *)(dataMacroBucketTable + bucketOffset + 2) = dataMacTotal;
        insertIndex = bucketCount;
    } else {
        insertIndex = *(u16 *)(dataMacroBucketTable + bucketOffset + 2);
        i = 0;
        while ((i < (int)bucketCount) &&
               (((DataRefEntry *)dataMacroTable)[insertIndex + i].key < (key & 0xffff))) {
            i++;
        }
        if (i < (int)bucketCount) {
            bucketCount = insertIndex + i;
            i = bucketCount * 8;
            if ((key & 0xffff) == ((DataRefEntry *)dataMacroTable)[bucketCount].key) {
                ((DataRefEntry *)dataMacroTable)[bucketCount].refCount++;
                sndEnd();
                return 0;
            }
        } else {
            bucketCount = insertIndex + i;
        }
    }
    if (dataMacTotal > 0x7ff) {
        sndEnd();
        return 0;
    }

    i = 0x40;
    bucket = (DataMacroBucket *)dataMacroBucketTable;
    do {
        if (insertIndex < bucket[0].startIndex) {
            bucket[0].startIndex++;
        }
        if (insertIndex < bucket[1].startIndex) {
            bucket[1].startIndex++;
        }
        if (insertIndex < bucket[2].startIndex) {
            bucket[2].startIndex++;
        }
        if (insertIndex < bucket[3].startIndex) {
            bucket[3].startIndex++;
        }
        if (insertIndex < bucket[4].startIndex) {
            bucket[4].startIndex++;
        }
        if (insertIndex < bucket[5].startIndex) {
            bucket[5].startIndex++;
        }
        if (insertIndex < bucket[6].startIndex) {
            bucket[6].startIndex++;
        }
        if (insertIndex < bucket[7].startIndex) {
            bucket[7].startIndex++;
        }
        bucket += 8;
        i--;
    } while (i != 0);

    i = dataMacTotal - 1;
    moveCount = dataMacTotal - bucketCount;
    entry = (u32 *)(dataMacroTable + i * 8);
    if ((int)bucketCount <= i) {
        batches = moveCount >> 3;
        if (batches != 0) {
            do {
                entry[2] = entry[0];
                entry[3] = entry[1];
                entry[0] = entry[-2];
                entry[1] = entry[-1];
                entry[-2] = entry[-4];
                entry[-1] = entry[-3];
                entry[-4] = entry[-6];
                entry[-3] = entry[-5];
                entry[-6] = entry[-8];
                entry[-5] = entry[-7];
                entry[-8] = entry[-10];
                entry[-7] = entry[-9];
                entry[-10] = entry[-12];
                entry[-9] = entry[-11];
                entry[-12] = entry[-14];
                entry[-11] = entry[-13];
                entry -= 0x10;
                batches--;
            } while (batches != 0);
            moveCount &= 7;
            if (moveCount == 0) {
                goto insert;
            }
        }
        do {
            entry[2] = entry[0];
            entry[3] = entry[1];
            entry -= 2;
            moveCount--;
        } while (moveCount != 0);
    }

insert:
    ((DataRefEntry *)dataMacroTable)[bucketCount].key = key;
    ((DataRefEntry *)dataMacroTable)[bucketCount].data = value;
    ((DataRefEntry *)dataMacroTable)[bucketCount].refCount = 1;
    (*(u16 *)(dataMacroBucketTable + bucketIndex * 4))++;
    dataMacTotal++;
    sndEnd();
    return 1;
}

/*
 * Release an instrument entry from the bucketed sorted table.
 */
int dataRemoveMacro(u32 key)
{
    s16 refCount;
    int countOffset;
    u32 bucketOffset;
    u32 moveCount;
    DataMacroBucket *bucket;
    u32 *entry;
    u32 startIndex;
    int scanIndex;
    u32 batches;
    u8 *tableBase;

    sndBegin();
    tableBase = dataSmpSDirTable;
    bucketOffset = (key >> 4) & 0xffc;
    if (*(s16 *)(tableBase + 0x5a00 + bucketOffset) == 0) {
        goto done;
    }
    startIndex = *(u16 *)(tableBase + 0x5a02 + bucketOffset);
    scanIndex = 0;
    while ((scanIndex < (int)(u32)*(u16 *)(tableBase + 0x5a00 + bucketOffset)) &&
           ((key & 0xffff) !=
            *(u16 *)(tableBase + 0x6204 + (startIndex + scanIndex) * 8))) {
        scanIndex++;
    }
    if ((int)(u32)*(u16 *)(tableBase + 0x5a00 + bucketOffset) <= scanIndex) {
        goto done;
    }

    countOffset = (startIndex + scanIndex) * 8;
    refCount = *(s16 *)(tableBase + 0x6206 + countOffset);
    *(s16 *)(tableBase + 0x6206 + countOffset) = refCount - 1;
    if ((s16)(refCount - 1) != 0) {
        goto done;
    }

    scanIndex = startIndex + scanIndex + 1;
    moveCount = dataMacTotal - scanIndex;
    entry = (u32 *)(tableBase + 0x6200 + scanIndex * 8);
    if (scanIndex < (int)(u32)dataMacTotal) {
        batches = moveCount >> 3;
        if (batches != 0) {
            do {
                entry[-2] = entry[0];
                entry[-1] = entry[1];
                entry[0] = entry[2];
                entry[1] = entry[3];
                entry[2] = entry[4];
                entry[3] = entry[5];
                entry[4] = entry[6];
                entry[5] = entry[7];
                entry[6] = entry[8];
                entry[7] = entry[9];
                entry[8] = entry[10];
                entry[9] = entry[11];
                entry[10] = entry[12];
                entry[11] = entry[13];
                entry[12] = entry[14];
                entry[13] = entry[15];
                entry += 0x10;
                batches--;
            } while (batches != 0);
            moveCount &= 7;
            if (moveCount == 0) {
                goto compactBuckets;
            }
        }
        do {
            entry[-2] = entry[0];
            entry[-1] = entry[1];
            entry += 2;
            moveCount--;
        } while (moveCount != 0);
    }

compactBuckets:
    scanIndex = 0x40;
    bucket = (DataMacroBucket *)(tableBase + 0x5a00);
    do {
        if (startIndex < bucket[0].startIndex) {
            bucket[0].startIndex--;
        }
        if (startIndex < bucket[1].startIndex) {
            bucket[1].startIndex--;
        }
        if (startIndex < bucket[2].startIndex) {
            bucket[2].startIndex--;
        }
        if (startIndex < bucket[3].startIndex) {
            bucket[3].startIndex--;
        }
        if (startIndex < bucket[4].startIndex) {
            bucket[4].startIndex--;
        }
        if (startIndex < bucket[5].startIndex) {
            bucket[5].startIndex--;
        }
        if (startIndex < bucket[6].startIndex) {
            bucket[6].startIndex--;
        }
        if (startIndex < bucket[7].startIndex) {
            bucket[7].startIndex--;
        }
        bucket += 8;
        scanIndex--;
    } while (scanIndex != 0);
    (*(s16 *)(tableBase + 0x5a00 + bucketOffset))--;
    dataMacTotal--;

done:
    sndEnd();
    return 0;
}

/*
 * Comparator: return a->key2 - b->key2 (u16 at offset 4).
 *
 */
int maccmp(void *a, void *b)
{
    return (int)*(u16 *)((u8 *)a + 4) - (int)*(u16 *)((u8 *)b + 4);
}

/*
 * Look up an instrument entry through the bucketed table.
 */
extern void *sndBSearch(void *key, void *base, u16 count, u32 stride,
                        int (*cmp)(void *a, void *b));
extern u8 dataMacroBucketTable[];
extern u8 dataMacroTable[];
extern u32 dataGetMacro_main;
extern u32 dataGetMacro_bucket;
extern u8 dataGetMacro_key[8];
extern void *dataGetMacro_result;

void *dataGetMacro(u32 key)
{
    DataMacroBucket *bucketTable;
    void *result;

    bucketTable = (DataMacroBucket *)dataMacroBucketTable;
    dataGetMacro_bucket = (key >> 6) & 0x3ff;
    if (bucketTable[dataGetMacro_bucket].count != 0) {
        dataGetMacro_main = bucketTable[dataGetMacro_bucket].startIndex;
        *(u16 *)(dataGetMacro_key + 4) = key;
        result = sndBSearch(dataGetMacro_key, dataMacroTable + dataGetMacro_main * 8,
                            bucketTable[dataGetMacro_bucket].count, 8, maccmp);
        dataGetMacro_result = result;
        if (result != 0) {
            return ((DataRefEntry *)dataGetMacro_result)->data;
        }
    }
    return 0;
}

/*
 * Comparator: return a->key - b->key (u16 at offset 0).
 *
 */
int smpcmp(void *a, void *b)
{
    return (int)*(u16 *)a - (int)*(u16 *)b;
}

/*
 * Find an SDI sample descriptor and copy its load metadata.
 */
extern u8 dataSmpSDirTable[];
extern u8 dataGetSampleSearchKey[];
extern u16 dataSmpSDirNum;
extern void *dataGetSample_result;
extern u8 *dataGetSample_sheader;

int dataGetSample(u16 key, u32 *out)
{
    u32 i;
    DataSampleDirBucket *bucket;
    DataSampleDirEntry *entry;
    u8 *searchKey;

    i = 0;
    bucket = (DataSampleDirBucket *)dataSmpSDirTable;
    searchKey = dataGetSampleSearchKey;
    *(u16 *)searchKey = key;
    while (i < dataSmpSDirNum) {
        dataGetSample_result = sndBSearch(searchKey, bucket->entries, bucket->count, 0x20,
                                          smpcmp);
        entry = dataGetSample_result;
        if ((entry != 0) && (entry->refCount != -1)) {
            dataGetSample_sheader = entry->header;
            out[0] = *(u32 *)dataGetSample_sheader;
            out[1] = entry->loadedAddr;
            out[3] = 0;
            out[5] = *(u32 *)(dataGetSample_sheader + 8);
            out[4] = *(u32 *)(dataGetSample_sheader + 4) & 0xffffff;
            out[6] = *(u32 *)(dataGetSample_sheader + 0xc);
            *(u8 *)(out + 7) = *(u32 *)(dataGetSample_sheader + 4) >> 0x18;
            if (entry->loopOffset != 0) {
                out[2] = entry->loopOffset + (u32)bucket->entries;
            }
            return 0;
        }
        bucket++;
        i++;
    }
    return -1;
}

/*
 * Comparator: return a->key2 - b->key2 (u16 at offset 4). Same body as
 * maccmp but separate symbol used for a different bsearch table.
 */
int curvecmp(void *a, void *b)
{
    return (int)*(u16 *)((u8 *)a + 4) - (int)*(u16 *)((u8 *)b + 4);
}

/*
 * Look up a keygroup/sample indirection table by id.
 */
extern void *sndBSearch(void *key, void *base, u16 count, u32 stride,
                        int (*cmp)(void *a, void *b));
extern u8 dataCurveTable[];
extern u8 dataKeymapTable[];
extern u8 dataLayerTable[];
extern u8 dataGetLayerSearchKey[];
extern u8 dataFXGroupTable[];
extern u8 dataGetFXSearchKey[];
extern u16 dataCurveNum;
extern u16 dataKeymapNum;
extern u16 dataLayerNum;
extern u16 dataFXGroupNum;
extern u8 dataGetCurve_key[8];
extern void *dataGetCurve_result;
extern u8 dataGetKeymap_key[8];
extern void *dataGetKeymap_result;
extern void *dataGetLayer_result;

void *dataGetCurve(u16 key)
{
    void *result;

    *(u16 *)(dataGetCurve_key + 4) = key;
    result = sndBSearch(dataGetCurve_key, dataCurveTable, dataCurveNum, 8, curvecmp);
    dataGetCurve_result = result;
    if (result == 0) {
        return 0;
    }
    return ((DataRefEntry *)dataGetCurve_result)->data;
}

/*
 * Look up the sample-map table used by nested sample groups.
 */
void *dataGetKeymap(u16 key)
{
    void *result;

    *(u16 *)(dataGetKeymap_key + 4) = key;
    result = sndBSearch(dataGetKeymap_key, dataKeymapTable, dataKeymapNum, 8, curvecmp);
    dataGetKeymap_result = result;
    if (result == 0) {
        return 0;
    }
    return ((DataRefEntry *)dataGetKeymap_result)->data;
}

/*
 * Comparator: return a->key2 - b->key2 (u16 at offset 4). Same body as
 * the others but separate symbol.
 *
 */
int layercmp(void *a, void *b)
{
    return (int)*(u16 *)((u8 *)a + 4) - (int)*(u16 *)((u8 *)b + 4);
}

/*
 * Look up a scene/sample list and return its entry count through outCount.
 */
void *dataGetLayer(u16 key, u16 *outCount)
{
    u8 *searchKey = dataGetLayerSearchKey;
    void *result;

    *(u16 *)(searchKey + 4) = key;
    result = sndBSearch(searchKey, dataLayerTable, dataLayerNum, 0xc, layercmp);
    dataGetLayer_result = result;
    if (result == 0) {
        return 0;
    }
    *outCount = ((DataLayerRef *)dataGetLayer_result)->count;
    return ((DataLayerRef *)dataGetLayer_result)->data;
}

/*
 * Comparator: return a->key - b->key (u16 at offset 0). Same body as
 * smpcmp but separate symbol.
 */
int fxcmp(void *a, void *b)
{
    return (int)*(u16 *)a - (int)*(u16 *)b;
}

/*
 * Search each FX sample-list bucket for the requested FX id.
 */
void *dataGetFX(u16 key)
{
    u32 i;
    DataFXGroupRef *bucket;
    void *entry;
    u8 *searchKey;

    i = 0;
    bucket = (DataFXGroupRef *)dataFXGroupTable;
    searchKey = dataGetFXSearchKey;
    *(u16 *)searchKey = key;
    while (i < dataFXGroupNum) {
        entry = sndBSearch(searchKey, bucket->samples, bucket->count, 10, fxcmp);
        if (entry != 0) {
            return entry;
        }
        bucket++;
        i++;
    }
    return 0;
}

/*
 * Reset the synth sample/instrument lookup counters and bucket table.
 */
extern u16 dataMacTotal;
extern void hwGetStreamPlayBuffer(void);

void dataInit(u32 unused, void *base)
{
    DataMacroBucket *bucketTable;
    int i;

    dataSmpSDirNum = 0;
    dataCurveNum = 0;
    dataKeymapNum = 0;
    dataLayerNum = 0;
    dataFXGroupNum = 0;
    dataMacTotal = 0;

    i = 0x20;
    bucketTable = (DataMacroBucket *)dataMacroBucketTable;
    do {
        bucketTable[0].count = 0;
        bucketTable[0].startIndex = 0;
        bucketTable[1].count = 0;
        bucketTable[1].startIndex = 0;
        bucketTable[2].count = 0;
        bucketTable[2].startIndex = 0;
        bucketTable[3].count = 0;
        bucketTable[3].startIndex = 0;
        bucketTable[4].count = 0;
        bucketTable[4].startIndex = 0;
        bucketTable[5].count = 0;
        bucketTable[5].startIndex = 0;
        bucketTable[6].count = 0;
        bucketTable[6].startIndex = 0;
        bucketTable[7].count = 0;
        bucketTable[7].startIndex = 0;
        bucketTable[8].count = 0;
        bucketTable[8].startIndex = 0;
        bucketTable[9].count = 0;
        bucketTable[9].startIndex = 0;
        bucketTable[10].count = 0;
        bucketTable[10].startIndex = 0;
        bucketTable[11].count = 0;
        bucketTable[11].startIndex = 0;
        bucketTable[12].count = 0;
        bucketTable[12].startIndex = 0;
        bucketTable[13].count = 0;
        bucketTable[13].startIndex = 0;
        bucketTable[14].count = 0;
        bucketTable[14].startIndex = 0;
        bucketTable[15].count = 0;
        bucketTable[15].startIndex = 0;
        bucketTable += 0x10;
        i--;
    } while (i != 0);

    hwGetStreamPlayBuffer();
}

/*
 * Wrapper for hwTransAddr.
 *
 * EN v1.1 Address: 0x80275344, size 32b
 */
int IFFifoAlloc(int x)
{
    return hwTransAddr(x);
}
