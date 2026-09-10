#ifndef TRACK_INTERSECT_CARD_API_H_
#define TRACK_INTERSECT_CARD_API_H_

#include "dolphin/card.h"
#include "types.h"

typedef union SaveCardFileInfo
{
    CARDFileInfo fileInfo;
    u8 raw[0x18];
} SaveCardFileInfo;

extern SaveCardFileInfo gSaveCardFileInfo;

/*
 * Card init / serial-no validation. Mounts slot 0; if the mount comes back
 * "no card filesystem" (-13) it remembers we need to format. On a check
 * error (-6) it runs CARDCheck; if that also returns -6 it formats. On a
 * clean mount (or after the recovery path) it reads the card serial and
 * compares against the cached pair (gSaveCardSerialHi/Lo). If the cached pair
 * is zero, or doesn't match the live card, the cache is rejected with a
 * "wrong card" error code (-0x55, gSaveCardState = 11). Otherwise CARDFormat
 * if we still owe one, else success: clear the cache, set state 13,
 * unmount, return 1.
 */
int cardFormatMemoryCard(void);
void cardSetIdentityCheckEnabled(u32 enable);
void cardSetStatusNeedInit(void);
s32 saveGameGetStatus(void);
int cardDeleteSaveFile(void);
int _saveGame(int slot, void* save, void* data);
#if defined(VERSION_GSAP01) || defined(VERSION_GSAP01_rev1)
int cardWriteOptions(void* data);
int saveGameWriteOptionsCb(int slot, int unused, void* save, void* data);
#endif
int maybeTryLoadSave(void* data);
int loadSaveGame(int slot, void* save);
int cardCreateSaveFile(u8 retry);
int cardProbe(u8 retry);
void _initCardAndDsp(void);
void cardGetMessage(u32* buttons, u32* texts, u32* count);
void showMemCardError(u8 error);
void cardShowLoadingMsg(u8 kind);
int saveGameWriteSlotCb(u8 slot, int unused, void* save, void* data);
int saveGameReadGlobalsCb(int saveId, int size, void* dst);

#endif /* TRACK_INTERSECT_CARD_API_H_ */
