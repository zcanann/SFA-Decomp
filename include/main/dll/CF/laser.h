#ifndef MAIN_DLL_CF_LASER_H_
#define MAIN_DLL_CF_LASER_H_

#include "global.h"
#include "game/objects/object.h"
#include "main/game_ui_interface.h"
#include "main/mapEventTypes.h"
#include "dlls/object_descriptor.h"
#include "game/objects/object_setup.h"
#include "main/objseq.h"

#define LASER_UNSUPPORTED_DLL_ID                 0x0236
#define LASER_UNSUPPORTED_OBJECT_CLASS_ID        0x0030
#define LASER_UNSUPPORTED_OBJECT_DEF_DFP_LASERBE 0x0355

typedef struct LaserState {
    s16 completionGameBit;
    s16 activationGameBit;
    u8 completionLatched;
} LaserState;

typedef struct LaserObjectMapData {
    ObjPlacement base;
    s8 yawByte;
    u8 pad19[0x1E - 0x19];
    s16 completionGameBit;
    s16 activationGameBit;
} LaserObjectMapData;

typedef struct LaserReleaseInterface {
    u8 pad00[0x48];
    void (*releaseObject)(int parent, void* object, int flags);
} LaserReleaseInterface;

STATIC_ASSERT(sizeof(LaserState) == 0x06);
STATIC_ASSERT(offsetof(LaserState, completionGameBit) == 0x00);
STATIC_ASSERT(offsetof(LaserState, activationGameBit) == 0x02);
STATIC_ASSERT(offsetof(LaserState, completionLatched) == 0x04);

STATIC_ASSERT(offsetof(LaserObjectMapData, yawByte) == 0x18);
STATIC_ASSERT(offsetof(LaserObjectMapData, completionGameBit) == 0x1E);
STATIC_ASSERT(offsetof(LaserObjectMapData, activationGameBit) == 0x20);
STATIC_ASSERT(sizeof(LaserObjectMapData) == 0x24);

STATIC_ASSERT(offsetof(LaserReleaseInterface, releaseObject) == 0x48);

#define LASEROBJ_MODE_SEQUENCE_A 1
#define LASEROBJ_MODE_SEQUENCE_B 2
#define LASEROBJ_YAW_BYTE_SHIFT  8

#define LASEROBJ_MAIN_SEQUENCE_A_EVENT 0x123
#define LASEROBJ_MAIN_SEQUENCE_B_EVENT 0x83b

extern char sLaserTextBlockInitNoLongerSupported[];
extern char sLaserInitNoLongerSupported[];
extern ObjectDescriptor gLaserUnsupportedObjDescriptor;

int laser_getExtraSize(void);
int laser_getObjectTypeId(void);
void laser_freeUnsupported(void);
void laser_renderUnsupported(void);
void laser_hitDetectUnsupported(void);
void laser_updateUnsupported(void);
void laser_init(void);
void laser_releaseUnsupported(void);
void laser_initialiseUnsupported(void);

#endif /* MAIN_DLL_CF_LASER_H_ */
