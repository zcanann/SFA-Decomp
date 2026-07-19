#ifndef TRACK_INTERSECT_CARD_API_H_
#define TRACK_INTERSECT_CARD_API_H_

#include "dolphin/card.h"
#include "types.h"

typedef union SaveCardFileInfo
{
    CARDFileInfo fileInfo;
    u8 raw[0x18];
} SaveCardFileInfo;

extern SaveCardFileInfo lbl_80396900;

int cardLoadFn_8007d72c(void);
void saveFn_8007d960(u32 enable);
void cardSetStatusNeedInit(void);
s32 saveGameGetStatus(void);
int cardDeleteFn_8007d99c(void);
int _saveGame(int slot, void* save, void* data);
int maybeTryLoadSave(void* data);
int loadSaveGame(int slot, void* save);
int memCardFn_8007dd04(u8 retry);
int cardProbe(u8 retry);
void _initCardAndDsp(void);
void cardGetMessage(u32* buttons, u32* texts, u32* count);
void showMemCardError(u8 error);
void cardShowLoadingMsg(u8 kind);
int cardCb_8007e6d4(u8 slot, int unused, void* save, void* data);
int saveCb_8007e748(int saveId, int size, void* dst);

#endif /* TRACK_INTERSECT_CARD_API_H_ */
