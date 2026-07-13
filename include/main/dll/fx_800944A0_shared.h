#ifndef SFA_DLL_FX_800944A0_SHARED_H
#define SFA_DLL_FX_800944A0_SHARED_H

#include "ghidra_import.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/debug.h"
#include "main/shader_api.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "main/object.h"
#include "main/dll/objfx_api.h"
#include "main/mm.h"
#include "main/cloud_action_runtime.h"
#include "main/cloud_layer_state.h"
#include "main/camera.h"
#include "main/effect_interfaces.h"
#include "main/objtexture.h"
#include "main/texture.h"
#include "main/resource.h"
#include "main/sky_interface.h"
#include "main/frame_timing.h"
#include "main/lightmap_api.h"
#include "main/objfx_hit_emitter_api.h"
#include "main/dll/expgfx_resource_api.h"
#include "main/pad_api.h"
#include "main/dll/waterfx.h"
#include "main/dll/cloudaction.h"
#include "main/dll/objfx.h"
#include "main/dll/ppcwgpipe_struct.h"
#include "main/dll/viewfinder.h"
#include "dolphin/gx/GXLegacyDecls.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "track/intersect_api.h"

/* external symbol declarations */
extern void* memset(void* dst, int c, int n);

#endif
