#ifndef MAIN_DLL_ARW_DLL_029C_ARWARWINGBO_H
#define MAIN_DLL_ARW_DLL_029C_ARWARWINGBO_H

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

typedef union ArwingBombControl
{
    f32 fuseTimer;
    u8 active;
} ArwingBombControl;

typedef struct ArwingBombState
{
    ArwingBombControl control;
    u8 pad04[4];
    f32 explosionTimer;
} ArwingBombState;

typedef struct ArwingBombSetup
{
    union
    {
        ObjPlacement base;
        ObjPlacement head;
    };
    union
    {
        struct
        {
            u8 rotZ;
            u8 rotY;
            u8 rotX;
        };
        struct
        {
            u8 roll;
            u8 pitch;
            u8 yaw;
        };
    };
} ArwingBombSetup;

STATIC_ASSERT(sizeof(ArwingBombState) == 0x0C);
STATIC_ASSERT(offsetof(ArwingBombState, explosionTimer) == 0x08);
STATIC_ASSERT(offsetof(ArwingBombSetup, rotZ) == 0x18);
STATIC_ASSERT(offsetof(ArwingBombSetup, rotY) == 0x19);
STATIC_ASSERT(offsetof(ArwingBombSetup, rotX) == 0x1A);

extern ObjectDescriptor gARWArwingBoObjDescriptor;
extern f32 lbl_803E7040;
extern f32 lbl_803E7044;
extern f32 lbl_803E7048;
extern f32 lbl_803E704C;

int arwarwingbo_getExtraSize(void);
int arwarwingbo_getObjectTypeId(void);
void arwarwingbo_free(int obj);
void arwarwingbo_hitDetect(void);
void arwarwingbo_render(int obj, int p2, int p3, int p4, int p5, s8 visible);
void arwarwingbo_init(GameObject* obj, ArwingBombSetup* setup);
void arwarwingbo_setActiveVisible(GameObject* obj, u8 active, u8 visible);
void arwarwingbo_release(void);
void arwarwingbo_initialise(void);
void arwarwingbo_update(int obj);

#endif /* MAIN_DLL_ARW_DLL_029C_ARWARWINGBO_H */
