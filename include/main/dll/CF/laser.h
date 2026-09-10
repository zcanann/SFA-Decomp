#ifndef MAIN_DLL_CF_LASER_H_
#define MAIN_DLL_CF_LASER_H_

#include "dlls/object_descriptor.h"

#define LASER_UNSUPPORTED_DLL_ID                 0x0236
#define LASER_UNSUPPORTED_OBJECT_CLASS_ID        0x0030
#define LASER_UNSUPPORTED_OBJECT_DEF_DFP_LASERBE 0x0355

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
