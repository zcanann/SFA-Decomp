#ifndef MAIN_TRACK_DOLPHIN_API_H_
#define MAIN_TRACK_DOLPHIN_API_H_

#include "types.h"
#include "main/game_object.h"

typedef struct TrackGroundHit
{
    f32 height;
    f32 normalX;
    f32 normalY;
    f32 normalZ;
    GameObject* object;
    u8 surfaceType;
    u8 pad15[3];
} TrackGroundHit;

STATIC_ASSERT(sizeof(TrackGroundHit) == 0x18);

int objShadowFn_80062498();
int fn_80065640(void);
int hitDetectFn_800658a4(GameObject* obj, f32 x, f32 y, f32 z, f32* outGroundY, int flag);
int hitDetectFn_80065e50(GameObject* obj, f32 x, f32 y, f32 z, TrackGroundHit*** hitsOut, int mode, int submode);
void fn_80065574(int matchValue, GameObject* obj, int flag);
void doNothing_80062A50();
void objHitDetectFn_80062e84(GameObject* obj, GameObject* newParent, int mode);
void playerShadowFn_80062a30(int* obj);
void setShadowFlag_803db658(s32 value);
void mapInitFn_80069990(void);
void trackIntersect(void);

extern int lbl_803DCF34;
extern f32* lbl_803DCF38;

#endif /* MAIN_TRACK_DOLPHIN_API_H_ */
