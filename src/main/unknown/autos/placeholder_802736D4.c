#include "ghidra_import.h"
#include "main/audio/data_ref.h"
#include "main/audio/synth_job.h"
#include "main/unknown/autos/placeholder_802736D4.h"

extern undefined4 FUN_802420b0();
extern undefined4 FUN_8028383c();
extern undefined4 FUN_80283d78();
extern undefined4 FUN_80283dfc();
extern undefined4 FUN_80283e00();
extern undefined4 FUN_80283fa0();
extern uint FUN_80284224();
extern undefined4 FUN_80284224();
extern undefined4 FUN_80284228();

extern void sndBegin(void);
extern void sndEnd(void);
extern void voiceBreakAndFree(u32 voice);
extern void hwSetVolume(int slot, undefined4 mode, f32 front, f32 left, f32 right, u32 auxA,
                        undefined4 auxB);

extern u8 lbl_803BD150[];
extern u8 dataSmpSDirTable[];
extern u8 dataKeymapTable[];
extern SynthJob synthJobTable[];
extern u32 synthFlags;
extern u16 dataKeymapNum;

extern undefined4 DAT_803bddb0;
extern undefined4 DAT_803bdfc0;
extern undefined4 DAT_803deee8;
extern undefined4 DAT_803def00;
extern undefined4 DAT_803def01;
extern f64 DOUBLE_803e8478;
extern f32 FLOAT_803e8470;
extern f32 FLOAT_803e8480;
extern f64 lbl_803E77E0;
extern f32 lbl_803E77D8;

/*
 * --INFO--
 *
 * Function: synthUpdateJobTable
 * EN v1.0 Address: 0x80272F70
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802736D4
 * EN v1.1 Size: 2168b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void synthUpdateJobTable(void)
{
}

/* Pattern wrappers. */
void doNothing_802737E8(void) {}

void synthCancelJob(int voice)
{
    SynthJob *job;
    int state;

    job = synthJobTable + voice;
    state = job->state;
    if (state >= 3) {
        goto done;
    }
    if (state >= 1) {
        goto cancel;
    }
    goto done;
cancel:
    if ((u32)state == 2) {
        voiceBreakAndFree(job->voice);
    }
    job->state = 3;
    job->callback(0, 0, 0, 0, job->callbackUser);
done:
    return;
}

void synthRefreshJobVolumes(void)
{
    SynthJob *job;
    u32 i;
    f32 volumeScale;

    sndBegin();
    volumeScale = lbl_803E77D8;
    job = synthJobTable;
    for (i = 0; i < lbl_803BD150[0x210]; i++) {
        if (job->state != 0) {
            job->pan = job->savedPan;
            job->surroundPan = job->savedSurroundPan;
            if ((synthFlags & 1) != 0) {
                job->pan = 0x40;
                job->surroundPan = 0;
            } else if ((synthFlags & 2) == 0) {
                job->surroundPan = 0;
            }
            if (job->state != 3) {
                hwSetVolume(job->voice, 0, volumeScale * job->volume,
                            volumeScale * job->leftVolume, volumeScale * job->rightVolume,
                            job->pan << 0x10, job->surroundPan << 0x10);
            }
        }
        job++;
    }
    sndEnd();
}

int dataInsertKeymap(u16 keymapId, void *data)
{
    DataRefEntry *table;
    DataRefEntry *entry;
    u8 *tableBase;
    u16 count;
    u32 moveCount;
    u32 batches;
    u32 *move;
    int index;
    u16 key;

    tableBase = dataSmpSDirTable;
    sndBegin();
    count = dataKeymapNum;
    table = (DataRefEntry *)(tableBase + 0x4600);
    key = keymapId;
    entry = table;
    index = 0;
    while (index < count && entry->key < key) {
        entry++;
        index++;
    }
    if (index < count) {
        entry = table + index;
        if (key == entry->key) {
            entry->refCount++;
            sndEnd();
            return 0;
        }
        if (count >= 0x100) {
            sndEnd();
            return 0;
        }
        moveCount = count - index;
        move = (u32 *)(table + (count - 1));
        if (index <= (int)(count - 1)) {
            batches = moveCount >> 3;
            if (batches != 0) {
                do {
                    move[2] = move[0];
                    move[3] = move[1];
                    move[0] = move[-2];
                    move[1] = move[-1];
                    move[-2] = move[-4];
                    move[-1] = move[-3];
                    move[-4] = move[-6];
                    move[-3] = move[-5];
                    move[-6] = move[-8];
                    move[-5] = move[-7];
                    move[-8] = move[-10];
                    move[-7] = move[-9];
                    move[-10] = move[-12];
                    move[-9] = move[-11];
                    move[-12] = move[-14];
                    move[-11] = move[-13];
                    move -= 0x10;
                    batches--;
                } while (batches != 0);
                moveCount &= 7;
                if (moveCount == 0) {
                    goto insert;
                }
            }
            do {
                move[2] = move[0];
                move[3] = move[1];
                move -= 2;
                moveCount--;
            } while (moveCount != 0);
        }
insert:
        dataKeymapNum++;
    } else {
        if (count >= 0x100) {
            sndEnd();
            return 0;
        }
        dataKeymapNum++;
    }
    table[index].key = keymapId;
    table[index].data = data;
    table[index].refCount = 1;
    sndEnd();
    return 1;
}

int dataRemoveKeymap(u32 keymapId)
{
    DataRefEntry *table;
    DataRefEntry *entry;
    u16 count;
    int index;
    int moveCount;
    u16 refs;

    sndBegin();
    count = dataKeymapNum;
    table = (DataRefEntry *)dataKeymapTable;
    keymapId &= 0xffff;
    entry = table;
    index = 0;
    while (index < count && entry->key != keymapId) {
        entry++;
        index++;
    }
    if (index != count) {
        entry = table + index;
        refs = entry->refCount - 1;
        entry->refCount = refs;
        if (refs == 0) {
            entry = table + index + 1;
            moveCount = count - (index + 1);
            while (moveCount > 0) {
                entry[-1] = entry[0];
                entry++;
                moveCount--;
            }
            dataKeymapNum--;
            sndEnd();
            return 1;
        }
    }
    sndEnd();
    return 0;
}
