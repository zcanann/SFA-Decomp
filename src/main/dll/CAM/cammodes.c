#include "main/audio/sfx_ids.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/game_object.h"
#include "main/audio/sfx.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "dolphin/os.h"
#include "main/asset_load.h"
#include "main/dll/CAM/dll_0001_camcontrol.h"
#include "main/dll/CAM/dll_0043_unk.h"
#include "main/dll/CAM/dll_0045_camTalk.h"
#include "main/dll/CAM/dll_0047_cameramodeteststrength.h"
#include "main/dll/dll_0042_unk.h"
#include "main/dll/dll_0044_cameramodeviewfinder.h"
#include "main/dll/dll_0046_cameramodedebug.h"
#include "main/dll/dll_0048_cameramodestatic.h"
#include "main/dll/dll_02C0_front_api.h"
#include "main/dll/savegame.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/mm.h"
#include "main/object_transform.h"
#include "main/obj_query.h"
#include "main/pad.h"
#include "main/voxmaps.h"
#include "string.h"
#include "main/dll/dll_0105_largecrate.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/resource.h"

ResourceDescriptorCallbacks12 lbl_80319B58 = {{0x00000000,
                        0x00000000,
                        0x00000000,
                        0x000b0000},
                       {(ResourceDescriptorCallback)CameraModeNormal_initialise,
                        (ResourceDescriptorCallback)CameraModeNormal_release,
                        0x00000000,
                        (ResourceDescriptorCallback)CameraModeNormal_init,
                        (ResourceDescriptorCallback)CameraModeNormal_update,
                        (ResourceDescriptorCallback)CameraModeNormal_free,
                        (ResourceDescriptorCallback)CameraModeNormal_copyToCurrent,
                        (ResourceDescriptorCallback)CameraModeNormal_follow,
                        (ResourceDescriptorCallback)firstperson_updatePitch,
                        (ResourceDescriptorCallback)camslide_update,
                        (ResourceDescriptorCallback)CameraModeNormal_func0A,
                        (ResourceDescriptorCallback)camcontrol_updateVerticalBounds}};
ResourceDescriptorCallbacks8 lbl_80319B98 = {{0x00000000,
                        0x00000000,
                        0x00000000,
                        0x00060000},
                       {(ResourceDescriptorCallback)CameraModeStaffAnim_initialise,
                        (ResourceDescriptorCallback)CameraModeStaffAnim_release,
                        0x00000000,
                        (ResourceDescriptorCallback)CameraModeStaffAnim_init,
                        (ResourceDescriptorCallback)camclimb_update,
                        (ResourceDescriptorCallback)camcontrol_releasePathState,
                        (ResourceDescriptorCallback)CameraModeStaffAnim_copyToCurrent,
                        0x00000000}};
ResourceDescriptorCallbacks8 lbl_80319BC8 = {{0x00000000,
                        0x00000000,
                        0x00000000,
                        0x00060000},
                       {(ResourceDescriptorCallback)CameraModeBike_initialise,
                        (ResourceDescriptorCallback)CameraModeBike_release,
                        0x00000000,
                        (ResourceDescriptorCallback)CameraModeBike_init,
                        (ResourceDescriptorCallback)CameraModeBike_update,
                        (ResourceDescriptorCallback)CameraModeBike_free,
                        (ResourceDescriptorCallback)CameraModeBike_copyToCurrent,
                        0x00000000}};
ResourceDescriptorCallbacks8 lbl_80319BF8 = {{0x00000000,
                        0x00000000,
                        0x00000000,
                        0x00060000},
                       {(ResourceDescriptorCallback)CameraModeViewfinder_initialise,
                        (ResourceDescriptorCallback)CameraModeViewfinder_release,
                        0x00000000,
                        (ResourceDescriptorCallback)CameraModeViewfinder_init,
                        (ResourceDescriptorCallback)CameraModeViewfinder_update,
                        (ResourceDescriptorCallback)CameraModeViewfinder_free,
                        (ResourceDescriptorCallback)CameraModeViewfinder_copyToCurrent,
                        0x00000000}};
ResourceDescriptorCallbacks8 lbl_80319C28 = {{0x00000000,
                        0x00000000,
                        0x00000000,
                        0x00060000},
                       {(ResourceDescriptorCallback)CameraModeDebug_initialise_nop,
                        (ResourceDescriptorCallback)CameraModeDebug_release_nop,
                        0x00000000,
                        (ResourceDescriptorCallback)CameraModeDebug_init,
                        (ResourceDescriptorCallback)CameraModeDebug_update,
                        (ResourceDescriptorCallback)CameraModeDebug_free,
                        (ResourceDescriptorCallback)CameraModeDebug_copyToCurrent_nop,
                        0x00000000}};
ResourceDescriptorCallbacks8 lbl_80319C58 = {{0x00000000,
                        0x00000000,
                        0x00000000,
                        0x00060000},
                       {(ResourceDescriptorCallback)CameraModeStatic_initialise,
                        (ResourceDescriptorCallback)CameraModeStatic_release,
                        0x00000000,
                        (ResourceDescriptorCallback)CameraModeStatic_init,
                        (ResourceDescriptorCallback)CameraModeStatic_update,
                        (ResourceDescriptorCallback)CameraModeStatic_free,
                        (ResourceDescriptorCallback)CameraModeStatic_copyToCurrent,
                        0x00000000}};
ResourceDescriptorCallbacks7 lbl_80319C88 = {{0x00000000,
                        0x00000000,
                        0x00000000,
                        0x00060000},
                       {(ResourceDescriptorCallback)CameraModeTestStrength_initialise,
                        (ResourceDescriptorCallback)CameraModeTestStrength_release,
                        0x00000000,
                        (ResourceDescriptorCallback)CameraModeTestStrength_init,
                        (ResourceDescriptorCallback)CameraModeTestStrength_update,
                        (ResourceDescriptorCallback)CameraModeTestStrength_free,
                        (ResourceDescriptorCallback)CameraModeTestStrength_copyToCurrent}};
