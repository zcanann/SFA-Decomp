#include "ghidra_import.h"
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
extern u8 lbl_803BFC78[];
extern u8 synthJobTable[];
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

typedef struct DataKeymapRef {
    void *data;
    u16 key;
    u16 refCount;
} DataKeymapRef;

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
    u8 *job;
    void (*callback)(u32, u32, u32, u32, u32);

    job = synthJobTable + voice * 0x64;
    if (job[8] < 3 && job[8] >= 1) {
        if (job[8] == 2) {
            voiceBreakAndFree(*(u32 *)(job + 0x48));
        }
        job[8] = 3;
        callback = *(void (**)(u32, u32, u32, u32, u32))(job + 0xc);
        callback(0, 0, 0, 0, *(u32 *)(job + 0x4c));
    }
}

void synthRefreshJobVolumes(void)
{
    u32 i;
    u8 *job;

    sndBegin();
    job = synthJobTable;
    for (i = 0; i < lbl_803BD150[0x210]; i++) {
        if (job[8] != 0) {
            job[0x56] = job[0x5a];
            job[0x57] = job[0x5b];
            if ((synthFlags & 1) != 0) {
                job[0x56] = 0x40;
                job[0x57] = 0;
            } else if ((synthFlags & 2) == 0) {
                job[0x57] = 0;
            }
            if (job[8] != 3) {
                hwSetVolume(*(u32 *)(job + 0x48), 0, lbl_803E77D8 * job[0x55],
                            lbl_803E77D8 * job[0x58], lbl_803E77D8 * job[0x59],
                            job[0x56] << 0x10, job[0x57] << 0x10);
            }
        }
        job += 0x64;
    }
    sndEnd();
}

int dataAddKeymapRef(u32 keymapId, void *data)
{
    DataKeymapRef *table;
    DataKeymapRef *entry;
    u16 count;
    int index;
    int moveIndex;
    u16 key;

    sndBegin();
    count = dataKeymapNum;
    table = (DataKeymapRef *)(lbl_803BFC78 + 0x4600);
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
        moveIndex = count - 1;
        if (moveIndex >= index) {
            do {
                table[moveIndex + 1] = table[moveIndex];
                moveIndex--;
            } while (moveIndex >= index);
        }
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

int dataRemoveKeymapRef(u32 keymapId)
{
    DataKeymapRef *table;
    DataKeymapRef *entry;
    u16 count;
    int index;
    int moveCount;
    u16 refs;

    sndBegin();
    count = dataKeymapNum;
    table = (DataKeymapRef *)(lbl_803BFC78 + 0x4600);
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
