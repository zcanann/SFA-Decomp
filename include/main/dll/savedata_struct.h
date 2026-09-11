#ifndef MAIN_DLL_SAVEDATA_STRUCT_H_
#define MAIN_DLL_SAVEDATA_STRUCT_H_

#include "types.h"

#define SAVE_DATA_SIZE 0xE4

/* Stored option order differs from both SRAM and gametext language IDs. */
#define SAVE_LANGUAGE_ENGLISH 0
#define SAVE_LANGUAGE_FRENCH  1
#define SAVE_LANGUAGE_ITALIAN 2
#define SAVE_LANGUAGE_SPANISH 3
#define SAVE_LANGUAGE_GERMAN  4

#define SAVE_SCORE_TABLE_COUNT 5
#define SAVE_SCORE_ENTRY_COUNT 5

typedef struct SaveScoreEntry
{
    u32 score : 31;
    u32 flag : 1;
    u8 initials[4];
} SaveScoreEntry;

typedef struct SaveData
{
    u8 optionsValid;
    u8 languageIndex;
    u8 subtitlesEnabled;
    u8 gameUiSetting;
    u8 cameraSetting;
    u8 pad05;
    u8 widescreenEnabled;
    u8 pad07;
    u8 rumbleEnabled;
    u8 soundMode;
    u8 musicVolume;
    u8 sfxVolume;
    u8 speechVolume;
    u8 pad0D[3];
    u32 unlockedCheats;
    u32 enabledCheats;
    u8 pad18[4];
    SaveScoreEntry scores[SAVE_SCORE_TABLE_COUNT][SAVE_SCORE_ENTRY_COUNT];
} SaveData;

STATIC_ASSERT(sizeof(SaveData) == SAVE_DATA_SIZE);
STATIC_ASSERT(offsetof(SaveData, languageIndex) == 0x01);
STATIC_ASSERT(offsetof(SaveData, subtitlesEnabled) == 0x02);

/* Bit index into unlockedCheats/enabledCheats, aka cheatId. */
enum CheatId
{
    CHEAT_SHOW_CREDITS = 0,
    CHEAT_SEPIA_MODE = 1,
    CHEAT_MUSIC_TEST = 2,
    CHEAT_DINO_LANGUAGE = 3
};

#endif
