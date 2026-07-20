#ifndef MAIN_DLL_DF_DFCRADLE_H_
#define MAIN_DLL_DF_DFCRADLE_H_

#include "ghidra_import.h"
#include "main/game_object.h"

typedef struct CCriverflowState
{
    u8 active;
} CCriverflowState;

typedef struct CCriverflowModel
{
    u8 pad00[0x04];
    f32 baseHeight;
} CCriverflowModel;

typedef struct CCriverflowMapData
{
    u8 pad00[0x18];
    u8 angleByte;
    u8 heightOffset;
    u8 speedByte;
    u8 pad1B;
    s16 gameBit;
} CCriverflowMapData;

typedef struct CCriverflowObject
{
    s16 angle;
    u8 pad02[0x08 - 0x02];
    f32 height;
    u8 pad0C[0x4C - 0x0C];
    CCriverflowMapData* mapData;
    CCriverflowModel* model;
    u8 pad54[0xB8 - 0x54];
    CCriverflowState* state;
} CCriverflowObject;

#define CCRIVERFLOW_OBJECT_GROUP  0x14
#define CCRIVERFLOW_DEFAULT_SPEED 0xFF

int ccriverflow_getExtraSize(void);
void ccriverflow_free(CCriverflowObject* obj);
void ccriverflow_render(void);
void ccriverflow_update(CCriverflowObject* obj);
void ccriverflow_init(CCriverflowObject* obj, CCriverflowMapData* params);
#endif /* MAIN_DLL_DF_DFCRADLE_H_ */
