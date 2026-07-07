#ifndef MAIN_DLL_SAVEDATA_STRUCT_H_
#define MAIN_DLL_SAVEDATA_STRUCT_H_

#include "types.h"

typedef struct SaveData
{
    u8 pad00[2];
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
    u32 registeredDebugOptions;
    u32 enabledDebugOptions;
} SaveData;

/* Bit index into registeredDebugOptions/enabledDebugOptions, aka cheatId. */
enum CheatId
{
    CHEAT_SHOW_CREDITS = 0,
    CHEAT_SEPIA_MODE = 1,
    CHEAT_MUSIC_TEST = 2,
    CHEAT_DINO_LANGUAGE = 3
};

#endif
