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

typedef struct TrackQueryBounds
{
    s32 minX;
    s32 minY;
    s32 minZ;
    s32 maxX;
    s32 maxY;
    s32 maxZ;
} TrackQueryBounds;

STATIC_ASSERT(sizeof(TrackQueryBounds) == 0x18);

int objShadowFn_80062498(GameObject* obj, int renderMode, int unused, int frameCount);
int fn_80065640(void);
int fn_80065768(int obj, f32 x, f32 y, f32 z, f32* outGroundY, f32* outNormal, int flag);
int hitDetectFn_800658a4(GameObject* obj, f32 x, f32 y, f32 z, f32* outGroundY, int flag);
int hitDetectFn_80065e50(GameObject* obj, f32 x, f32 y, f32 z, TrackGroundHit*** hitsOut, int mode, int submode);
int hitDetectFn_80067958(GameObject* contactSource, f32* startPoints, f32* endPoints, int pointCount, void* results,
                        int flags);
void hitDetect_calcSweptSphereBounds(TrackQueryBounds* boundsOut, f32* startPoints, f32* endPoints, f32* radii,
                                     int pointCount);
void hitDetectFn_800691c0(GameObject* obj, TrackQueryBounds* bounds, u32 mask, int flags);
void fn_80065574(int matchValue, GameObject* obj, int flag);
void doNothing_80062A50();
void objHitDetectFn_80062e84(GameObject* obj, GameObject* newParent, int mode);
void playerShadowFn_80062a30(GameObject* obj);
void setShadowFlag_803db658(s32 value);
void mapInitFn_80069990(void);
void trackIntersect(void);
void mapBlockRender_setVtxDcrs(int flag, int* obj, int shader, int* blockState);
void initTextures(void);
void fn_80060BB0(void);
void* fn_800606DC(int* obj, int idx);
void* fn_800606FC(int* obj, int idx);
void gxErrorFn_80060b40(void);
void* MapBlock_loadFromFile(int blockId);
void setMapBlockFlag(void);
void objFn_80065604(void);
void setupToRenderMapBlock(int* block, void* posMtx);
void fn_80062894(void);
void fn_80062808(void);
void renderGlows(void);

extern int lbl_803DCF34;
extern f32* lbl_803DCF38;

#endif /* MAIN_TRACK_DOLPHIN_API_H_ */
