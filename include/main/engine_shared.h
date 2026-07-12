#ifndef MAIN_ENGINE_SHARED_H_
#define MAIN_ENGINE_SHARED_H_

#include "ghidra_import.h"
#include "main/asset_load.h"
#include "main/audio.h"
#include "main/audio/inp_midi.h"
#include "main/audio/hw_samplemem.h"
#include "main/audio/sfx.h"
#include "main/audio/snd3d.h"
#include "main/audio/snd_core.h"
#include "main/audio/snd_reverb.h"
#include "main/audio/snd_synth_api.h"
#include "main/attract_movie_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/camera.h"
#include "main/curve.h"
#include "main/effect_interfaces.h"
#include "main/fileio.h"
#include "main/frame_timing.h"
#include "main/gametext.h"
#include "main/gamebits.h"
#include "main/gameloop_api.h"
#include "main/lightmap_api.h"
#include "main/model_engine.h"
#include "main/minimap_api.h"
#include "main/mm.h"
#include "main/newclouds.h"
#include "main/object_api.h"
#include "main/pad.h"
#include "main/pause_menu_api.h"
#include "main/pi_dolphin_api.h"
#include "main/resource.h"
#include "main/render.h"
#include "main/shader_api.h"
#include "main/sky_interface.h"
#include "main/table_file.h"
#include "main/voxmaps.h"
#include "main/vecmath.h"
#include "track/intersect_api.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/string.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/ai.h"
#include "dolphin/ar.h"
#include "dolphin/dvd.h"
#include "dolphin/gx/GXLegacy.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSReport.h"
#include "dolphin/os/OSRtc.h"
#include "dolphin/pad.h"

extern int getCurSeqNo(void);
extern void debugPrintf(char *message, ...);
extern void gxSetScissorRect(int p1, int p2, int x, int y, int x2, int y2);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern int lbl_803DC9C8;
extern u8 lbl_8033A540[];
extern void *textureAlloc(int w, int h, int p3, int p4, int p5, int p6, int p7, int p8, int p9);
extern int sndPushGroup(void *project, u16 group, void *sampleBuffer, void *sampleDir, void *pool);


#endif
