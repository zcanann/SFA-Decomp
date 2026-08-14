#ifndef MAIN_OBJTYPE_H_
#define MAIN_OBJTYPE_H_

#include "global.h"

struct GameObject;

int objIsObjectType(struct GameObject* obj, int group);
struct GameObject* objGetNearestType(int group, f32* point, f32* maxDistance);
struct GameObject* objGetNearestTypeToExcludingSelf(int group, struct GameObject* obj, f32* maxDistance);
struct GameObject* objGetNearestTypeTo(int group, struct GameObject* obj, f32* maxDistance);
struct GameObject** objGetAllOfType(int group, int* countOut);
void objFreeObjectType(struct GameObject* obj, int group);
int objGetObjectType(struct GameObject* obj);
void objAddObjectType(struct GameObject* obj, int group);
void objTypeInit(void);

#endif /* MAIN_OBJTYPE_H_ */
