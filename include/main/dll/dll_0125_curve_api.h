#ifndef MAIN_DLL_DLL_0125_CURVE_API_H_
#define MAIN_DLL_DLL_0125_CURVE_API_H_

#include "main/dll/dll_0015_curves.h"
#include "main/object_descriptor.h"

extern ObjectDescriptor12 gCurveObjDescriptor;

void curve_free(void);
int curve_func0B(void);
int curve_getExtraSize(void);
int curve_getObjectTypeId(void);
void curve_init(ObjAnimComponent* obj, CurvePlacementParams* params);
void curve_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void curve_setScale(void);

#endif /* MAIN_DLL_DLL_0125_CURVE_API_H_ */
