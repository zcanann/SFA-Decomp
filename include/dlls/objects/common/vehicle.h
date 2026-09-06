#ifndef DLLS_OBJECTS_COMMON_VEHICLE_H_
#define DLLS_OBJECTS_COMMON_VEHICLE_H_

#include "game/objects/object.h"

#define VEHICLE_OBJECT_GROUP 10

enum VehicleMountState {
    VEHICLE_NoRider = 0,
    VEHICLE_Mounting = 1,
    VEHICLE_Mounted = 2,
    VEHICLE_Dismounting = 3,
};

/*
 * Shared export table of every rideable object DLL, reached through
 * obj->anim.dll. The layout is the object descriptor from slot02 onwards and
 * is identical across SnowBike, DIMSnowHorn1, DR_EarthWarrior, DR_CloudRunner,
 * SB_CloudRunner, HighTop and DrakorHoverPad.
 */
typedef struct VehicleInterface {
    void* pad00[4];
    void (*render)(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, int visible);
    void* pad14[3];
    int (*canMount)(GameObject* obj, GameObject* player);
    int (*getMountSide)(GameObject* obj);
    void (*getRiderPosition)(GameObject* obj, f32* outX, f32* outY, f32* outZ);
    int (*canDismount)(GameObject* obj, GameObject* player);
    int (*getDismountSide)(GameObject* obj);
    void (*getCameraPosition)(GameObject* obj, f32* outX, f32* outY, f32* outZ);
    int (*getMountState)(GameObject* obj);
    void (*setMountState)(GameObject* obj, int mountState);
    void (*getPlayerAnim)(GameObject* obj, f32* outBlend, int* outAnim);
    f32 (*getNormalizedSpeed)(GameObject* obj, f32* out);
    int (*getRacePosition)(GameObject* obj);
    void (*resetToRomListPosition)(GameObject* obj);
    void (*handleRiderScale)(GameObject* obj, f32 rootMotionScaleBase);
    void (*getLookTargetYaw)(GameObject* obj, int mode, int* out);
} VehicleInterface;

#define VEHICLE_INTERFACE(vehicle) ((VehicleInterface*)*((GameObject*)(vehicle))->anim.dll)

STATIC_ASSERT(offsetof(VehicleInterface, render) == 0x10);
STATIC_ASSERT(offsetof(VehicleInterface, canMount) == 0x20);
STATIC_ASSERT(offsetof(VehicleInterface, getMountSide) == 0x24);
STATIC_ASSERT(offsetof(VehicleInterface, getRiderPosition) == 0x28);
STATIC_ASSERT(offsetof(VehicleInterface, canDismount) == 0x2C);
STATIC_ASSERT(offsetof(VehicleInterface, getDismountSide) == 0x30);
STATIC_ASSERT(offsetof(VehicleInterface, getCameraPosition) == 0x34);
STATIC_ASSERT(offsetof(VehicleInterface, getMountState) == 0x38);
STATIC_ASSERT(offsetof(VehicleInterface, setMountState) == 0x3C);
STATIC_ASSERT(offsetof(VehicleInterface, getPlayerAnim) == 0x40);
STATIC_ASSERT(offsetof(VehicleInterface, getNormalizedSpeed) == 0x44);
STATIC_ASSERT(offsetof(VehicleInterface, getRacePosition) == 0x48);
STATIC_ASSERT(offsetof(VehicleInterface, resetToRomListPosition) == 0x4C);
STATIC_ASSERT(offsetof(VehicleInterface, handleRiderScale) == 0x50);
STATIC_ASSERT(offsetof(VehicleInterface, getLookTargetYaw) == 0x54);
STATIC_ASSERT(sizeof(VehicleInterface) == 0x58);

#endif /* DLLS_OBJECTS_COMMON_VEHICLE_H_ */
