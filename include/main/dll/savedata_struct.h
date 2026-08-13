#ifndef MAIN_DLL_SAVEDATA_STRUCT_H_
#define MAIN_DLL_SAVEDATA_STRUCT_H_

#include "types.h"

#define SAVE_DATA_SIZE 0xE4

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
    u8 pad01;
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

/* Bit index into unlockedCheats/enabledCheats, aka cheatId. */
enum CheatId
{
    CHEAT_SHOW_CREDITS = 0,
    CHEAT_SEPIA_MODE = 1,
    CHEAT_MUSIC_TEST = 2,
    CHEAT_DINO_LANGUAGE = 3
};

#endif
