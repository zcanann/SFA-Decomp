#include "ghidra_import.h"

extern int hwTransAddr(int x);
extern void sndBegin(void);
extern void sndEnd(void);

/*
 * Insert a scene/sample-list entry, keeping the 12-byte table sorted by id.
 */
extern u8 dataKeymapTable[];
extern u16 dataLayerNum;

int fn_80273D2C(u16 key, void *value, u16 count)
{
    u32 moveCount;
    u32 *entry;
    u32 used;
    u32 batches;
    int index;

    sndBegin();
    used = dataLayerNum;
    index = 0;
    for (entry = (u32 *)(dataKeymapTable + 0x800);
         (index < (int)used) && (*(u16 *)(entry + 1) < key); entry += 3) {
        index++;
    }
    if (index < (int)used) {
        if (key == *(u16 *)(dataKeymapTable + 0x804 + index * 0xc)) {
            (*(u16 *)(dataKeymapTable + 0x808 + index * 0xc))++;
            sndEnd();
            return 0;
        }
        if (used > 0xff) {
            sndEnd();
            return 0;
        }
        moveCount = used - index;
        entry = (u32 *)(dataKeymapTable + 0x800 + (used - 1) * 0xc);
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
    *(u16 *)(dataKeymapTable + 0x804 + index * 0xc) = key;
    *(void **)(dataKeymapTable + 0x800 + index * 0xc) = value;
    *(u16 *)(dataKeymapTable + 0x806 + index * 0xc) = count;
    *(u16 *)(dataKeymapTable + 0x808 + index * 0xc) = 1;
    sndEnd();
    return 1;
}

/*
 * Release a scene/sample-list entry, compacting the sorted table.
 */
int fn_80273F74(s16 key)
{
    s16 refCount;
    int next;
    u32 *entry;
    u32 moveCount;
    u32 index;
    u32 used;

    sndBegin();
    used = dataLayerNum;
    index = 0;
    for (entry = (u32 *)(dataKeymapTable + 0x800);
         ((int)index < (int)used) && (key != *(s16 *)(entry + 1)); entry += 3) {
        index++;
    }
    if (index == used) {
        sndEnd();
        return 0;
    }
    refCount = *(s16 *)(dataKeymapTable + 0x808 + index * 0xc);
    *(s16 *)(dataKeymapTable + 0x808 + index * 0xc) = refCount - 1;
    if ((s16)(refCount - 1) != 0) {
        sndEnd();
        return 0;
    }

    next = index + 1;
    moveCount = used - next;
    entry = (u32 *)(dataKeymapTable + 0x800 + next * 0xc);
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
extern u16 dataCurveNum;
extern void sndBegin(void);
extern void sndEnd(void);

int fn_80274140(u16 key, void *value)
{
    u32 moveCount;
    u32 used;
    u32 batches;
    int index;
    u32 *entry;

    sndBegin();
    used = dataCurveNum;
    index = 0;
    for (entry = (u32 *)dataCurveTable;
         (index < (int)used) && (*(u16 *)(entry + 1) < key); entry += 2) {
        index++;
    }
    if (index < (int)used) {
        if (key == *(u16 *)(dataCurveTable + 4 + index * 8)) {
            sndEnd();
            (*(u16 *)(dataCurveTable + 6 + index * 8))++;
            return 0;
        }
        if (used > 0x7ff) {
            sndEnd();
            return 0;
        }
        moveCount = used - index;
        entry = (u32 *)(dataCurveTable + (used - 1) * 8);
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
    *(u16 *)(dataCurveTable + 4 + index * 8) = key;
    *(void **)(dataCurveTable + index * 8) = value;
    *(u16 *)(dataCurveTable + 6 + index * 8) = 1;
    sndEnd();
    return 1;
}

/*
 * Release a keygroup/sample indirection entry, compacting the sorted table.
 */
int fn_80274338(s16 key)
{
    s16 refCount;
    int next;
    u32 *entry;
    u32 moveCount;
    u32 index;
    u32 used;

    sndBegin();
    used = dataCurveNum;
    index = 0;
    for (entry = (u32 *)dataCurveTable;
         ((int)index < (int)used) && (key != *(s16 *)(entry + 1)); entry += 2) {
        index++;
    }
    if (index == used) {
        sndEnd();
        return 0;
    }
    refCount = *(s16 *)(dataCurveTable + 6 + index * 8);
    *(s16 *)(dataCurveTable + 6 + index * 8) = refCount - 1;
    if ((s16)(refCount - 1) != 0) {
        sndEnd();
        return 0;
    }

    next = index + 1;
    moveCount = used - next;
    entry = (u32 *)(dataCurveTable + next * 8);
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
extern u8 lbl_803BFC78[];
extern u16 dataSmpSDirNum;

int audioLoadSdiFile(s16 *sampleTable, void *baseAddr)
{
    s16 **bucket;
    s16 *entry;
    int result;
    u32 bucketIndex;
    u32 used;
    s16 *scan;
    u16 tableCount;
    u16 i;
    u16 j;
    u16 k;

    bucketIndex = 0;
    used = dataSmpSDirNum;
    for (bucket = (s16 **)lbl_803BFC78;
         ((int)bucketIndex < (int)used) && (*bucket != sampleTable); bucket += 3) {
        bucketIndex++;
    }
    if (bucketIndex == used) {
        if (used < 0x80) {
            tableCount = 0;
            for (entry = sampleTable; *entry != -1; entry += 0x10) {
                tableCount++;
            }
            sndBegin();
            entry = sampleTable;
            for (i = 0; i < tableCount; i++) {
                j = 0;
                bucket = (s16 **)lbl_803BFC78;
                for (bucketIndex = dataSmpSDirNum; bucketIndex != 0; bucketIndex--) {
                    scan = *bucket;
                    for (k = 0; k < *(u16 *)(bucket + 2); k++) {
                        if (*entry == *scan) {
                            goto foundEntry;
                        }
                        scan += 0x10;
                    }
                    bucket += 3;
                    j++;
                }

foundEntry:
                if (j == dataSmpSDirNum) {
                    entry[1] = 0;
                } else {
                    entry[1] = -1;
                }
                entry += 0x10;
            }
            bucketIndex = dataSmpSDirNum;
            *(s16 **)(lbl_803BFC78 + bucketIndex * 0xc) = sampleTable;
            *(u16 *)(lbl_803BFC78 + bucketIndex * 0xc + 8) = tableCount;
            *(void **)(lbl_803BFC78 + bucketIndex * 0xc + 4) = baseAddr;
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
extern u8 lbl_803BFC78[];
extern u16 dataSmpSDirNum;
extern void hwSaveSample(void *sampleDescPtr, void *addrOut);

int fn_80274628(s16 sampleId)
{
    u32 remaining;
    u32 bucketIndex;
    s16 **bucket;
    s16 *entry;
    s16 *sampleDesc;

    bucket = (s16 **)lbl_803BFC78;
    bucketIndex = 0;
    for (remaining = dataSmpSDirNum, entry = 0; remaining != 0; remaining--) {
        for (entry = *bucket; *entry != -1; entry += 0x10) {
            if ((*entry == sampleId) && (entry[1] != -1)) {
                goto found;
            }
        }
        bucket += 3;
        bucketIndex++;
    }

found:
    if (entry[1] == 0) {
        sampleDesc = entry + 6;
        *(int *)(entry + 4) = *(int *)(entry + 2) + *(int *)(lbl_803BFC78 + 4 + bucketIndex * 0xc);
        hwSaveSample(&sampleDesc, entry + 4);
    }
    entry[1]++;
    return 1;
}

/*
 * Release a sample table reference, removing it after the last user.
 */
extern void hwRemoveSample(void *sampleDesc, u32 addr);

int fn_80274700(s16 sampleId)
{
    u32 remaining;
    s16 **bucket;
    s16 *entry;

    bucket = (s16 **)lbl_803BFC78;
    remaining = dataSmpSDirNum;
    do {
        if (remaining == 0) {
            return 0;
        }
        for (entry = *bucket; *entry != -1; entry += 0x10) {
            if ((*entry == sampleId) && (entry[1] != -1)) {
                entry[1]--;
                if (entry[1] == 0) {
                    hwRemoveSample(entry + 6, *(u32 *)(entry + 4));
                }
                return 1;
            }
        }
        bucket += 3;
        remaining--;
    } while (1);
}

/*
 * Register an FX sample-list bucket and mark each sample descriptor as resident.
 */
extern u8 lbl_803C5678[];
extern u16 dataFXGroupNum;
extern void sndBegin(void);
extern void sndEnd(void);

int fn_80274798(s16 fxId, u8 *samples, u32 count)
{
    u32 i;
    u32 used;
    u32 batchCount;

    i = 0;
    used = dataFXGroupNum;
    while (((int)i < (int)used) && (fxId != *(s16 *)(lbl_803C5678 + 0x4800 + i * 8))) {
        i++;
    }
    if ((i != used) || (used > 0x7f)) {
        return 0;
    }

    sndBegin();
    used = dataFXGroupNum;
    i = count & 0xffff;
    *(s16 *)(lbl_803C5678 + 0x4800 + used * 8) = fxId;
    *(s16 *)(lbl_803C5678 + 0x4802 + used * 8) = count;
    *(u8 **)(lbl_803C5678 + 0x4804 + used * 8) = samples;
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

int fn_802748C0(u32 key, void *value)
{
    u32 bucketOffset;
    u32 bucketCount;
    u32 insertIndex;
    u32 bucketIndex;
    u16 *bucket;
    u32 *entry;
    int i;
    u32 moveCount;
    u32 batches;

    sndBegin();
    bucketOffset = (key >> 4) & 0xffc;
    bucketCount = *(u16 *)(lbl_803C5678 + bucketOffset);
    bucketIndex = (key >> 6) & 0x3ff;
    if (bucketCount == 0) {
        bucketCount = dataMacTotal;
        *(u16 *)(lbl_803C5678 + bucketOffset + 2) = dataMacTotal;
        insertIndex = bucketCount;
    } else {
        insertIndex = *(u16 *)(lbl_803C5678 + bucketOffset + 2);
        i = 0;
        while ((i < (int)bucketCount) &&
               (*(u16 *)(lbl_803C5678 + 0x804 + (insertIndex + i) * 8) <
                (key & 0xffff))) {
            i++;
        }
        if (i < (int)bucketCount) {
            bucketCount = insertIndex + i;
            i = bucketCount * 8;
            if ((key & 0xffff) == *(u16 *)(lbl_803C5678 + 0x804 + i)) {
                (*(u16 *)(lbl_803C5678 + 0x806 + i))++;
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
    bucket = (u16 *)lbl_803C5678;
    do {
        if (insertIndex < bucket[1]) {
            bucket[1]++;
        }
        if (insertIndex < bucket[3]) {
            bucket[3]++;
        }
        if (insertIndex < bucket[5]) {
            bucket[5]++;
        }
        if (insertIndex < bucket[7]) {
            bucket[7]++;
        }
        if (insertIndex < bucket[9]) {
            bucket[9]++;
        }
        if (insertIndex < bucket[11]) {
            bucket[11]++;
        }
        if (insertIndex < bucket[13]) {
            bucket[13]++;
        }
        if (insertIndex < bucket[15]) {
            bucket[15]++;
        }
        bucket += 0x10;
        i--;
    } while (i != 0);

    i = dataMacTotal - 1;
    moveCount = dataMacTotal - bucketCount;
    entry = (u32 *)(lbl_803C5678 + 0x800 + i * 8);
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
    i = bucketCount * 8;
    *(u16 *)(lbl_803C5678 + 0x804 + i) = key;
    *(void **)(lbl_803C5678 + 0x800 + i) = value;
    *(u16 *)(lbl_803C5678 + 0x806 + i) = 1;
    (*(u16 *)(lbl_803C5678 + bucketIndex * 4))++;
    dataMacTotal++;
    sndEnd();
    return 1;
}

/*
 * Release an instrument entry from the bucketed sorted table.
 */
int fn_80274BD0(u32 key)
{
    s16 refCount;
    int countOffset;
    u32 bucketOffset;
    u32 moveCount;
    u16 *bucket;
    u32 *entry;
    u32 startIndex;
    int scanIndex;
    u32 batches;

    sndBegin();
    bucketOffset = (key >> 4) & 0xffc;
    if (*(s16 *)(lbl_803C5678 + bucketOffset) == 0) {
        goto done;
    }
    startIndex = *(u16 *)(lbl_803C5678 + bucketOffset + 2);
    scanIndex = 0;
    while ((scanIndex < (int)(u32)*(u16 *)(lbl_803C5678 + bucketOffset)) &&
           ((key & 0xffff) !=
            *(u16 *)(lbl_803C5678 + 0x804 + (startIndex + scanIndex) * 8))) {
        scanIndex++;
    }
    if ((int)(u32)*(u16 *)(lbl_803C5678 + bucketOffset) <= scanIndex) {
        goto done;
    }

    countOffset = (startIndex + scanIndex) * 8;
    refCount = *(s16 *)(lbl_803C5678 + 0x806 + countOffset);
    *(s16 *)(lbl_803C5678 + 0x806 + countOffset) = refCount - 1;
    if ((s16)(refCount - 1) != 0) {
        goto done;
    }

    scanIndex = startIndex + scanIndex + 1;
    moveCount = dataMacTotal - scanIndex;
    entry = (u32 *)(lbl_803C5678 + 0x800 + scanIndex * 8);
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
    bucket = (u16 *)lbl_803C5678;
    do {
        if (startIndex < bucket[1]) {
            bucket[1]--;
        }
        if (startIndex < bucket[3]) {
            bucket[3]--;
        }
        if (startIndex < bucket[5]) {
            bucket[5]--;
        }
        if (startIndex < bucket[7]) {
            bucket[7]--;
        }
        if (startIndex < bucket[9]) {
            bucket[9]--;
        }
        if (startIndex < bucket[11]) {
            bucket[11]--;
        }
        if (startIndex < bucket[13]) {
            bucket[13]--;
        }
        if (startIndex < bucket[15]) {
            bucket[15]--;
        }
        bucket += 0x10;
        scanIndex--;
    } while (scanIndex != 0);
    (*(s16 *)(lbl_803C5678 + bucketOffset))--;
    dataMacTotal--;

done:
    sndEnd();
    return 0;
}

/*
 * Comparator: return a->key2 - b->key2 (u16 at offset 4).
 *
 * EN v1.1 Address: 0x80274E6C, size 16b
 */
int fn_80274E6C(void *a, void *b)
{
    return (int)*(u16 *)((u8 *)a + 4) - (int)*(u16 *)((u8 *)b + 4);
}

/*
 * Look up an instrument entry through the bucketed table.
 */
extern void *sndBSearch(void *key, void *base, u16 count, u32 stride,
                        int (*cmp)(void *a, void *b));
extern u8 lbl_803C5678[];
extern u32 dataGetMacro_main;
extern u32 dataGetMacro_bucket;
extern u8 dataGetMacro_key[];
extern void *dataGetMacro_result;

void *dataGetMacro(u32 key)
{
    u16 *bucketTable;

    bucketTable = (u16 *)lbl_803C5678;
    dataGetMacro_bucket = (key >> 6) & 0x3ff;
    if (bucketTable[dataGetMacro_bucket * 2] != 0) {
        dataGetMacro_main = bucketTable[dataGetMacro_bucket * 2 + 1];
        *(u16 *)(dataGetMacro_key + 4) = key;
        dataGetMacro_result =
            sndBSearch(dataGetMacro_key, lbl_803C5678 + 0x800 + dataGetMacro_main * 8,
                       bucketTable[dataGetMacro_bucket * 2], 8, fn_80274E6C);
        if (dataGetMacro_result != 0) {
            return *(void **)dataGetMacro_result;
        }
    }
    return 0;
}

/*
 * Comparator: return a->key - b->key (u16 at offset 0).
 *
 * EN v1.1 Address: 0x80274F10, size 16b
 */
int fn_80274F10(void *a, void *b)
{
    return (int)*(u16 *)a - (int)*(u16 *)b;
}

/*
 * Find an SDI sample descriptor and copy its load metadata.
 */
extern u8 lbl_803BFC78[];
extern u16 dataSmpSDirNum;
extern void *dataGetSample_result;
extern u8 *dataGetSample_sheader;

int dataGetSample(u16 key, u32 *out)
{
    u32 i;
    u32 *bucket;
    u8 *entry;
    u8 *searchKey;

    i = 0;
    bucket = (u32 *)lbl_803BFC78;
    searchKey = lbl_803C5678 + 0x4c00;
    *(u16 *)searchKey = key;
    while (i < dataSmpSDirNum) {
        dataGetSample_result = sndBSearch(searchKey, (void *)*bucket, *(u16 *)(bucket + 2), 0x20,
                                  fn_80274F10);
        entry = dataGetSample_result;
        if ((entry != 0) && (*(s16 *)(entry + 2) != -1)) {
            dataGetSample_sheader = entry + 0xc;
            out[0] = *(u32 *)dataGetSample_sheader;
            out[1] = *(u32 *)(entry + 8);
            out[3] = 0;
            out[5] = *(u32 *)(dataGetSample_sheader + 8);
            out[4] = *(u32 *)(dataGetSample_sheader + 4) & 0xffffff;
            out[6] = *(u32 *)(dataGetSample_sheader + 0xc);
            *(u8 *)(out + 7) = *(u32 *)(dataGetSample_sheader + 4) >> 0x18;
            if (*(int *)(entry + 0x1c) != 0) {
                out[2] = *(int *)(entry + 0x1c) + *bucket;
            }
            return 0;
        }
        bucket += 3;
        i++;
    }
    return -1;
}

/*
 * Comparator: return a->key2 - b->key2 (u16 at offset 4). Same body as
 * fn_80274E6C but separate symbol used for a different bsearch table.
 *
 * EN v1.1 Address: 0x80275048, size 16b
 */
int audioFindKeymapCb(void *a, void *b)
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
extern u8 lbl_803C5678[];
extern u16 dataCurveNum;
extern u16 dataKeymapNum;
extern u16 dataLayerNum;
extern u16 dataFXGroupNum;
extern u8 dataGetCurve_key[];
extern void *dataGetCurve_result;
extern u8 dataGetKeymap_key[];
extern void *dataGetKeymap_result;
extern void *dataGetLayer_result;

void *dataGetCurve(u16 key)
{
    *(u16 *)(dataGetCurve_key + 4) = key;
    dataGetCurve_result = sndBSearch(dataGetCurve_key, dataCurveTable, dataCurveNum, 8, audioFindKeymapCb);
    if (dataGetCurve_result == 0) {
        return 0;
    }
    return *(void **)dataGetCurve_result;
}

/*
 * Look up the sample-map table used by nested sample groups.
 */
void *dataGetKeymap(u16 key)
{
    *(u16 *)(dataGetKeymap_key + 4) = key;
    dataGetKeymap_result = sndBSearch(dataGetKeymap_key, dataKeymapTable, dataKeymapNum, 8, audioFindKeymapCb);
    if (dataGetKeymap_result == 0) {
        return 0;
    }
    return *(void **)dataGetKeymap_result;
}

/*
 * Comparator: return a->key2 - b->key2 (u16 at offset 4). Same body as
 * the others but separate symbol.
 *
 * EN v1.1 Address: 0x80275118, size 16b
 */
int fn_80275118(void *a, void *b)
{
    return (int)*(u16 *)((u8 *)a + 4) - (int)*(u16 *)((u8 *)b + 4);
}

/*
 * Look up a scene/sample list and return its entry count through outCount.
 */
void *dataGetLayer(u16 key, u16 *outCount)
{
    u8 *searchKey = lbl_803C5678 + 0x4c20;

    *(u16 *)(searchKey + 4) = key;
    dataGetLayer_result =
        sndBSearch(searchKey, dataKeymapTable + 0x800, dataLayerNum, 0xc, fn_80275118);
    if (dataGetLayer_result == 0) {
        return 0;
    }
    *outCount = *(u16 *)((u8 *)dataGetLayer_result + 6);
    return *(void **)dataGetLayer_result;
}

/*
 * Comparator: return a->key - b->key (u16 at offset 0). Same body as
 * fn_80274F10 but separate symbol.
 *
 * EN v1.1 Address: 0x802751A8, size 16b
 */
int audioIdListFindCb_802751a8(void *a, void *b)
{
    return (int)*(u16 *)a - (int)*(u16 *)b;
}

/*
 * Search each FX sample-list bucket for the requested FX id.
 */
void *audioGetSoundEffectById(u16 key)
{
    u32 i;
    u16 *bucket;
    void *entry;
    u8 *searchKey;

    i = 0;
    bucket = (u16 *)(lbl_803C5678 + 0x4800);
    searchKey = lbl_803C5678 + 0x4c2c;
    *(u16 *)searchKey = key;
    while (i < dataFXGroupNum) {
        entry = sndBSearch(searchKey, *(void **)(bucket + 2), bucket[1], 10, audioIdListFindCb_802751a8);
        if (entry != 0) {
            return entry;
        }
        bucket += 4;
        i++;
    }
    return 0;
}

/*
 * Reset the synth sample/instrument lookup counters and bucket table.
 */
extern u16 dataMacTotal;
extern void hwGetStreamPlayBuffer(void);

void fn_80275260(void)
{
    u16 *bucketTable;
    int i;

    dataSmpSDirNum = 0;
    dataCurveNum = 0;
    dataKeymapNum = 0;
    dataLayerNum = 0;
    dataFXGroupNum = 0;
    dataMacTotal = 0;

    i = 0x20;
    bucketTable = (u16 *)lbl_803C5678;
    do {
        bucketTable[0] = 0;
        bucketTable[1] = 0;
        bucketTable[2] = 0;
        bucketTable[3] = 0;
        bucketTable[4] = 0;
        bucketTable[5] = 0;
        bucketTable[6] = 0;
        bucketTable[7] = 0;
        bucketTable[8] = 0;
        bucketTable[9] = 0;
        bucketTable[10] = 0;
        bucketTable[11] = 0;
        bucketTable[12] = 0;
        bucketTable[13] = 0;
        bucketTable[14] = 0;
        bucketTable[15] = 0;
        bucketTable[16] = 0;
        bucketTable[17] = 0;
        bucketTable[18] = 0;
        bucketTable[19] = 0;
        bucketTable[20] = 0;
        bucketTable[21] = 0;
        bucketTable[22] = 0;
        bucketTable[23] = 0;
        bucketTable[24] = 0;
        bucketTable[25] = 0;
        bucketTable[26] = 0;
        bucketTable[27] = 0;
        bucketTable[28] = 0;
        bucketTable[29] = 0;
        bucketTable[30] = 0;
        bucketTable[31] = 0;
        bucketTable += 0x20;
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
