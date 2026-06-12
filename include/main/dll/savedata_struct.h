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

#endif
