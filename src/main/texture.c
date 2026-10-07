#include "main/texture.h"
#include "dolphin/os/OSReport.h"
#include "main/frame_timing.h"
#include "track/intersect_depth_state_api.h"
#include "main/asset_load.h"
#include "main/map_load.h"
#include "main/shader_api.h"
#include "MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/warpvec.h"
#include "main/zlb.h"
#include "main/dll/cloudaction_interface.h"
#include "game/objects/object.h"
#include "main/gameloop_api.h"
#include "sys/objects/lifecycle.h"
#include "main/mapEvent.h"
#include "main/model_light.h"
#include "main/model.h"
#include "main/map_romlist_page.h"
#include "main/map_block.h"
#include "main/shader_init_api.h"
#include "main/newclouds.h"
#include "main/rcp_dolphin.h"
#include "main/rcp_dolphin_api.h"
#include "main/rcp_dolphin_render_api.h"
#include "main/camera.h"
#include "main/loaded_file_flags.h"
#include "main/pi_dolphin.h"
#include "main/screen_transition.h"
#include "main/sky_api.h"
#include "main/sky_interface.h"
#include "main/mm.h"
#include "main/dll/tricky_api.h"
#include "main/dll/dll_0000_gameui_api.h"
#include "main/dll/savegame_env_api.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSInterrupt.h"
#include "dolphin/mtx.h"
#include "dolphin/gx/GXDispList.h"
#include "dolphin/gx/GXFrameBuffer.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXGet.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXManage.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTexture.h"
#include "dolphin/gx/GXTransform.h"
#include "main/dll/modgfx.h"
#include "main/newshadows.h"
#include "main/pi_dolphin_texture_api.h"
#include "main/gx_scissor_api.h"
#include "string.h"

typedef struct LoadedTextureEntry {
    int assetId;
    Texture* texture;
    u8 usesHandle;
    u8 padding[3];
    u32 allocationSize;
} LoadedTextureEntry;

#define LOADED_TEXTURE_CAPACITY 0x2BC

STATIC_ASSERT(offsetof(LoadedTextureEntry, assetId) == 0x0);
STATIC_ASSERT(offsetof(LoadedTextureEntry, texture) == 0x4);
STATIC_ASSERT(offsetof(LoadedTextureEntry, usesHandle) == 0x8);
STATIC_ASSERT(offsetof(LoadedTextureEntry, allocationSize) == 0xC);
STATIC_ASSERT(sizeof(LoadedTextureEntry) == 0x10);

LoadedTextureEntry* gLoadedTextures;
u16* gRcpTexIdRemap;
int gLoadedTextureCount;
int* gRcpTexHeaderBuffer;
u32 lbl_803DCDB4;
u32 lbl_803DCDB0;
u8 gRcpTexAllocFailed;
u32 gRcpRenderFlags;

int* gRcpTexBankTable[3];
int gRcpTexBankCount[3];

u32 gRcpTexAllocTag = 6;
char sDebugIntLineFormat[] = "%d\n";

void textureInitGXTexObj(Texture* texture);

static inline void loadTextureBank(int bank, int fileId);

void* textureAlloc(u16 w, u16 h, int fmt, u8 mip, u8 maxLod, u8 wrapS, u8 wrapT, u8 minFilter, u8 magFilter);

/* Retained N64 RDP state: each preset chooses a combine command by fog
 * state and an other-mode command by (renderFlags & mask) | forcedFlags.
 * The retail pointer graph and command bytes agree with Dinosaur Planet's
 * texture table. These descriptive names are not recovered source symbols. */
typedef struct TextureRdpCommand {
    u32 word0;
    u32 word1;
} TextureRdpCommand;

typedef struct TextureRdpPreset {
    TextureRdpCommand* combineModes;
    TextureRdpCommand* otherModes;
    u32 renderFlagMask;
    u32 forcedRenderFlags;
} TextureRdpPreset;

STATIC_ASSERT(sizeof(TextureRdpCommand) == 8);
STATIC_ASSERT(offsetof(TextureRdpCommand, word1) == 4);
STATIC_ASSERT(sizeof(TextureRdpPreset) == 0x10);
STATIC_ASSERT(offsetof(TextureRdpPreset, combineModes) == 0);
STATIC_ASSERT(offsetof(TextureRdpPreset, otherModes) == 4);
STATIC_ASSERT(offsetof(TextureRdpPreset, renderFlagMask) == 8);
STATIC_ASSERT(offsetof(TextureRdpPreset, forcedRenderFlags) == 0xC);

#define TEXTURE_RDP_ANTIALIAS   0x1u
#define TEXTURE_RDP_Z_COMPARE   0x2u
#define TEXTURE_RDP_TRANSLUCENT 0x4u
#define TEXTURE_RDP_FOG         0x8u
#define TEXTURE_RDP_ALL_FLAGS                                                                                          \
    (TEXTURE_RDP_ANTIALIAS | TEXTURE_RDP_Z_COMPARE | TEXTURE_RDP_TRANSLUCENT | TEXTURE_RDP_FOG)

TextureRdpCommand gRcpTextureCombineCommands[2] = {
    {0xfc121603, 0xfffffff8},
    {0xfc121603, 0xfffffff8},
};

TextureRdpCommand gTextureRdpModesDefault[16] = {
    {0xef182c00, 0x03024000}, {0xef182c00, 0x00112008}, {0xef182c00, 0x00112230}, {0xef182c00, 0x00112038},
    {0xef182c00, 0x00104240}, {0xef182c00, 0x001041c8}, {0xef182c00, 0x00104a50}, {0xef182c00, 0x001049d8},
    {0xef182c00, 0xcb024000}, {0xef182c00, 0xc8112008}, {0xef182c00, 0xc8112230}, {0xef182c00, 0xc8112038},
    {0xef182c00, 0xc8104240}, {0xef182c00, 0xc81041c8}, {0xef182c00, 0xc8104a50}, {0xef182c00, 0xc81049d8},
};

TextureRdpCommand gTextureRdpModesCloud[16] = {
    {0xef182c00, 0x03024000}, {0xef182c00, 0x00112008}, {0xef182c00, 0x00112230}, {0xef182c00, 0x00112038},
    {0xef182c00, 0x00104340}, {0xef182c00, 0x00104340}, {0xef182c00, 0x00104b50}, {0xef182c00, 0x00104b50},
    {0xef182c00, 0xcb024000}, {0xef182c00, 0xc8112008}, {0xef182c00, 0xc8112230}, {0xef182c00, 0xc8112038},
    {0xef182c00, 0xc8104340}, {0xef182c00, 0xc8104340}, {0xef182c00, 0xc8104b50}, {0xef182c00, 0xc8104b50},
};

TextureRdpCommand gTextureRdpCombineShadePrimitive[2] = {
    {0xfc41ffff, 0xfffff638},
    {0xfc41ffff, 0xfffff638},
};

TextureRdpCommand gTextureRdpModesPoint[16] = {
    {0xef180c00, 0x03024000}, {0xef180c00, 0x00112008}, {0xef180c00, 0x00112230}, {0xef180c00, 0x00112038},
    {0xef180c00, 0x00104240}, {0xef180c00, 0x001041c8}, {0xef180c00, 0x00104a50}, {0xef180c00, 0x001049d8},
    {0xef180c00, 0xcb024000}, {0xef180c00, 0xc8112008}, {0xef180c00, 0xc8112230}, {0xef180c00, 0xc8112038},
    {0xef180c00, 0xc8104240}, {0xef180c00, 0xc81041c8}, {0xef180c00, 0xc8104a50}, {0xef180c00, 0xc81049d8},
};

TextureRdpCommand gTextureRdpCombineModulateRgba[2] = {
    {0xfc121803, 0xff0fffff},
    {0xfc121803, 0xff0fffff},
};

TextureRdpCommand gTextureRdpModesTranslucent[16] = {
    {0xef182c00, 0x00104240}, {0xef182c00, 0x001041c8}, {0xef182c00, 0x00104a50}, {0xef182c00, 0x001049d8},
    {0xef182c00, 0x00104240}, {0xef182c00, 0x001041c8}, {0xef182c00, 0x00104a50}, {0xef182c00, 0x001049d8},
    {0xef182c00, 0x00104240}, {0xef182c00, 0x001041c8}, {0xef182c00, 0x00104a50}, {0xef182c00, 0x001049d8},
    {0xef182c00, 0x00104240}, {0xef182c00, 0x001041c8}, {0xef182c00, 0x00104a50}, {0xef182c00, 0x001049d8},
};

TextureRdpCommand gTextureRdpCombineShadePrimitiveRgba[2] = {
    {0xfc41c683, 0xff8fffff},
    {0xfc41c683, 0xff8fffff},
};

TextureRdpCommand gTextureRdpModesPointTranslucent[16] = {
    {0xef080c00, 0x0c184240}, {0xef080c00, 0x005461c8}, {0xef080c00, 0x00546a70}, {0xef080c00, 0x005469f8},
    {0xef080c00, 0x00504240}, {0xef080c00, 0x005041c8}, {0xef080c00, 0x00504a50}, {0xef080c00, 0x005049d8},
    {0xef080c00, 0x0c184240}, {0xef080c00, 0x005461c8}, {0xef080c00, 0x00546a70}, {0xef080c00, 0x005469f8},
    {0xef080c00, 0x00504240}, {0xef080c00, 0x005041c8}, {0xef080c00, 0x00504a50}, {0xef080c00, 0x005049d8},
};

TextureRdpCommand gTextureRdpCombineShadeAlphaFade[2] = {
    {0xfc12160b, 0xfffffff8},
    {0xfc12160b, 0xfffffff8},
};

TextureRdpCommand gTextureRdpModesShadeAlphaFade[8] = {
    {0xef182c00, 0x03024000}, {0xef182c00, 0x00112008}, {0xef182c00, 0x00112230}, {0xef182c00, 0x00112038},
    {0xef182c00, 0x00104240}, {0xef182c00, 0x001041c8}, {0xef182c00, 0x00104a50}, {0xef182c00, 0x001049d8},
};

TextureRdpCommand gTextureRdpCombineUntexturedShadeAlphaFade[2] = {
    {0xfc45ffff, 0xfffff638},
    {0xfc45ffff, 0xfffff638},
};

TextureRdpCommand gTextureRdpModesUntexturedShadeAlphaFade[8] = {
    {0xef180c00, 0x03024000}, {0xef180c00, 0x00112008}, {0xef180c00, 0x00112230}, {0xef180c00, 0x00112038},
    {0xef180c00, 0x00104240}, {0xef180c00, 0x001041c8}, {0xef180c00, 0x00104a50}, {0xef180c00, 0x001049d8},
};

TextureRdpCommand gTextureRdpCombinePrimitiveBlend[2] = {
    {0xfc12166b, 0xf0fffe38},
    {0xfc12166b, 0xf0fffe38},
};

TextureRdpCommand gTextureRdpModesPrimitiveBlend[8] = {
    {0xef182c00, 0x03024000}, {0xef182c00, 0x00112008}, {0xef182c00, 0x00112230}, {0xef182c00, 0x00112038},
    {0xef182c00, 0x00104240}, {0xef182c00, 0x001041c8}, {0xef182c00, 0x00104a50}, {0xef182c00, 0x001049d8},
};

TextureRdpCommand gTextureRdpCombineUntexturedPrimitiveBlend[2] = {
    {0xfc35ffff, 0x4ffc7638},
    {0xfc35ffff, 0x4ffc7638},
};

TextureRdpCommand gTextureRdpModesUntexturedPrimitiveBlend[8] = {
    {0xef180c00, 0x03024000}, {0xef180c00, 0x00112008}, {0xef180c00, 0x00112230}, {0xef180c00, 0x00112038},
    {0xef180c00, 0x00104240}, {0xef180c00, 0x001041c8}, {0xef180c00, 0x00104a50}, {0xef180c00, 0x001049d8},
};

TextureRdpCommand gTextureRdpCombineTrilinear[2] = {
    {0xfc26a04d, 0x11409249},
    {0xfc26a004, 0x1f0c93ff},
};

TextureRdpCommand gTextureRdpModesTrilinear[16] = {
    {0xef192c00, 0x03024000}, {0xef192c00, 0x00112008}, {0xef192c00, 0x00112230}, {0xef192c00, 0x00112038},
    {0xef192c00, 0x00104240}, {0xef192c00, 0x001041c8}, {0xef192c00, 0x00104a50}, {0xef192c00, 0x001049d8},
    {0xef192c00, 0xcb024000}, {0xef192c00, 0xc8112008}, {0xef192c00, 0xc8112230}, {0xef192c00, 0xc8112038},
    {0xef192c00, 0xc8104240}, {0xef192c00, 0xc81041c8}, {0xef192c00, 0xc8104a50}, {0xef192c00, 0xc81049d8},
};

TextureRdpCommand gTextureRdpCombineTextureBlend[2] = {
    {0xfc22aa04, 0x1f0c93ff},
    {0xfc22aa04, 0x1f0c93ff},
};

TextureRdpCommand gTextureRdpModesTextureBlend[16] = {
    {0xef182c00, 0x03024000}, {0xef182c00, 0x00112008}, {0xef182c00, 0x00112230}, {0xef182c00, 0x00112038},
    {0xef182c00, 0x00104240}, {0xef182c00, 0x001041c8}, {0xef182c00, 0x00104a50}, {0xef182c00, 0x001049d8},
    {0xef182c00, 0xcb024000}, {0xef182c00, 0xc8112008}, {0xef182c00, 0xc8112230}, {0xef182c00, 0xc8112038},
    {0xef182c00, 0xc8104240}, {0xef182c00, 0xc81041c8}, {0xef182c00, 0xc8104a50}, {0xef182c00, 0xc81049d8},
};

TextureRdpCommand gTextureRdpCombineTextureBlendShade[2] = {
    {0xfc22aa04, 0x1f1093ff},
    {0xfc22aa04, 0x1f1093ff},
};

TextureRdpCommand gTextureRdpCombineTextureBlendShadeAlpha[2] = {
    {0xfc25a804, 0x1f0c93ff},
    {0xfc25a804, 0x1f0c93ff},
};

TextureRdpCommand gTextureRdpCombineTextureBlendPrimitive[2] = {
    {0xfc25a803, 0x1f0c93ff},
    {0xfc25a803, 0x1f0c93ff},
};

TextureRdpCommand gTextureRdpCombinePrimitiveEnvironmentFog[2] = {
    {0xfc119623, 0xff2fffff},
    {0xfc1196ac, 0xf0fffe38},
};

TextureRdpCommand gTextureRdpCombinePrimitiveEnvironmentBlend[2] = {
    {0xfc367ea0, 0x5f0ef3ff},
    {0xfc367ea0, 0x5f0ef3ff},
};

TextureRdpCommand gTextureRdpModesPrimitiveEnvironmentFog[16] = {
    {0xef082c00, 0x00504240}, {0xef082c00, 0x005041c8}, {0xef082c00, 0x00553078}, {0xef082c00, 0x005045d8},
    {0xef082c00, 0x00504240}, {0xef082c00, 0x005041c8}, {0xef082c00, 0x00553078}, {0xef082c00, 0x005045d8},
    {0xef182c00, 0xc8104240}, {0xef182c00, 0xc81041c8}, {0xef182c00, 0xc8113078}, {0xef182c00, 0xc81045d8},
    {0xef182c00, 0xc8104240}, {0xef182c00, 0xc81041c8}, {0xef182c00, 0xc81045f8}, {0xef182c00, 0xc81045d8},
};

TextureRdpCommand gTextureRdpModesPrimitiveEnvironmentFogPoint[16] = {
    {0xef080c00, 0x00504240}, {0xef080c00, 0x005041c8}, {0xef080c00, 0x00553078}, {0xef080c00, 0x005045d8},
    {0xef080c00, 0x00504240}, {0xef080c00, 0x005041c8}, {0xef080c00, 0x00553078}, {0xef080c00, 0x005045d8},
    {0xef180c00, 0xc8104240}, {0xef180c00, 0xc81041c8}, {0xef180c00, 0xc8113078}, {0xef180c00, 0xc81045d8},
    {0xef180c00, 0xc8104240}, {0xef180c00, 0xc81041c8}, {0xef180c00, 0xc81045f8}, {0xef180c00, 0xc81045d8},
};

TextureRdpCommand gTextureRdpModesPrimitiveEnvironmentBlendNoise[16] = {
    {0xef082c80, 0x00504240}, {0xef082c80, 0x005041c8}, {0xef082c80, 0x00553078}, {0xef082c80, 0x00504b50},
    {0xef082c80, 0x00504240}, {0xef082c80, 0x005041c8}, {0xef082c80, 0x00553078}, {0xef082c80, 0x00504b50},
    {0xef182c80, 0xc8104240}, {0xef182c80, 0xc81041c8}, {0xef182c80, 0xc8113078}, {0xef182c80, 0xc8104b50},
    {0xef182c80, 0xc8104240}, {0xef182c80, 0xc81041c8}, {0xef182c80, 0xc81045f8}, {0xef182c80, 0xc8104b50},
};

TextureRdpCommand gTextureRdpCombineTextureBlend2[2] = {
    {0xfc22aa04, 0x1f0c93ff},
    {0xfc22aa04, 0x1f0c93ff},
};

TextureRdpCommand gTextureRdpModesTextureBlend2[16] = {
    {0xef182c00, 0x00104240}, {0xef182c00, 0x001041c8}, {0xef182c00, 0x00113078}, {0xef182c00, 0x001045d8},
    {0xef182c00, 0x00104240}, {0xef182c00, 0x001041c8}, {0xef182c00, 0x001045f8}, {0xef182c00, 0x001045d8},
    {0xef182c00, 0xc8104240}, {0xef182c00, 0xc81041c8}, {0xef182c00, 0xc8113078}, {0xef182c00, 0xc81045d8},
    {0xef182c00, 0xc8104240}, {0xef182c00, 0xc81041c8}, {0xef182c00, 0xc81045f8}, {0xef182c00, 0xc81045d8},
};

TextureRdpCommand gTextureRdpModesTextureBlend2Point[16] = {
    {0xef180c00, 0x00104240}, {0xef180c00, 0x001041c8}, {0xef180c00, 0x00113078}, {0xef180c00, 0x001045d8},
    {0xef180c00, 0x00104240}, {0xef180c00, 0x001041c8}, {0xef180c00, 0x001045f8}, {0xef180c00, 0x001045d8},
    {0xef180c00, 0xc8104240}, {0xef180c00, 0xc81041c8}, {0xef180c00, 0xc8113078}, {0xef180c00, 0xc81045d8},
    {0xef180c00, 0xc8104240}, {0xef180c00, 0xc81041c8}, {0xef180c00, 0xc81045f8}, {0xef180c00, 0xc81045d8},
};

TextureRdpCommand gTextureRdpCombineDecal[2] = {
    {0xfc121603, 0xfffffff8},
    {0xfc121603, 0xfffffff8},
};

TextureRdpCommand gTextureRdpModesDecal[16] = {
    {0xef182c00, 0x00112e10}, {0xef182c00, 0x00112d18}, {0xef182c00, 0x00112e10}, {0xef182c00, 0x00112d18},
    {0xef182c00, 0x00104e50}, {0xef182c00, 0x00104dd8}, {0xef182c00, 0x00104e50}, {0xef182c00, 0x00104dd8},
    {0xef182c00, 0xc8112e10}, {0xef182c00, 0xc8112d18}, {0xef182c00, 0xc8112e10}, {0xef182c00, 0xc8112d18},
    {0xef182c00, 0xc8104e50}, {0xef182c00, 0xc8104dd8}, {0xef182c00, 0xc8104e50}, {0xef182c00, 0xc8104dd8},
};

TextureRdpCommand gTextureRdpCombineCutout[2] = {
    {0xfc121603, 0xfffffff8},
    {0xfc121603, 0xfffffff8},
};

TextureRdpCommand gTextureRdpModesCutout[16] = {
    {0xef182c00, 0x00104240}, {0xef182c00, 0x001041c8}, {0xef182c00, 0x00111338}, {0xef182c00, 0x00111038},
    {0xef182c00, 0x00104240}, {0xef182c00, 0x001041c8}, {0xef182c00, 0x00111338}, {0xef182c00, 0x00111038},
    {0xef182c00, 0xc8104240}, {0xef182c00, 0xc81041c8}, {0xef182c00, 0xc8111338}, {0xef182c00, 0xc8111038},
    {0xef182c00, 0xc8104240}, {0xef182c00, 0xc81041c8}, {0xef182c00, 0xc8111338}, {0xef182c00, 0xc8111038},
};

TextureRdpCommand gTextureRdpModesFoggedCutoutBlend[8] = {
    {0xef182c00, 0xc8104240}, {0xef182c00, 0xc81041c8}, {0xef182c00, 0xc8113078}, {0xef182c00, 0xc8105858},
    {0xef182c00, 0xc8104240}, {0xef182c00, 0xc81041c8}, {0xef182c00, 0xc8113078}, {0xef182c00, 0xc8105858},
};

TextureRdpCommand gTextureRdpCombineDecalSimple[2] = {
    {0xfc121803, 0xff0fffff},
    {0xfc121803, 0xff0fffff},
};

TextureRdpCommand gTextureRdpModesDecalSimple[16] = {
    {0xef182c00, 0x00104e50}, {0xef182c00, 0x00104dd8}, {0xef182c00, 0x00104e50}, {0xef182c00, 0x00104dd8},
    {0xef182c00, 0x00104b50}, {0xef182c00, 0x00104b50}, {0xef182c00, 0x00104b50}, {0xef182c00, 0x00104b50},
    {0xef182c00, 0x00104e50}, {0xef182c00, 0x00104dd8}, {0xef182c00, 0x00104e50}, {0xef182c00, 0x00104dd8},
    {0xef182c00, 0x00104b50}, {0xef182c00, 0x00104b50}, {0xef182c00, 0x00104b50}, {0xef182c00, 0x00104b50},
};

TextureRdpCommand gTextureRdpCombineTrilinearDecal[2] = {
    {0xfc26a004, 0x1f1093ff},
    {0xfc26a004, 0x1f1093ff},
};

TextureRdpCommand gTextureRdpModesTrilinearDecal[16] = {
    {0xef192c00, 0x00104e50}, {0xef192c00, 0x00104dd8}, {0xef192c00, 0x00104e50}, {0xef192c00, 0x00104dd8},
    {0xef192c00, 0x00104a50}, {0xef192c00, 0x001049d8}, {0xef192c00, 0x00104a50}, {0xef192c00, 0x001049d8},
    {0xef192c00, 0x00104e50}, {0xef192c00, 0x00104dd8}, {0xef192c00, 0x00104e50}, {0xef192c00, 0x00104dd8},
    {0xef192c00, 0x00104a50}, {0xef192c00, 0x001049d8}, {0xef192c00, 0x00104a50}, {0xef192c00, 0x001049d8},
};

TextureRdpCommand gTextureRdpCombineSubsurface[2] = {
    {0xfc121603, 0xff0fffff},
    {0xfc121603, 0xff0fffff},
};

TextureRdpCommand gTextureRdpModesSubsurface[16] = {
    {0xef182c00, 0x03024000}, {0xef182c00, 0x00112248}, {0xef182c00, 0x00112230}, {0xef182c00, 0x00112278},
    {0xef182c00, 0x00104240}, {0xef182c00, 0x001041c8}, {0xef182c00, 0x00104a50}, {0xef182c00, 0x001049d8},
    {0xef182c00, 0xcb024000}, {0xef182c00, 0xc8112248}, {0xef182c00, 0xc8112230}, {0xef182c00, 0xc8112278},
    {0xef182c00, 0xc8104240}, {0xef182c00, 0xc81041c8}, {0xef182c00, 0xc8104a50}, {0xef182c00, 0xc81049d8},
};

TextureRdpCommand gTextureRdpCombineTrilinearSubsurface[2] = {
    {0xfc26a004, 0x1f0c93ff},
    {0xfc26a004, 0x1f0c93ff},
};

TextureRdpCommand gTextureRdpModesTrilinearSubsurface[16] = {
    {0xef192c00, 0x03024000}, {0xef192c00, 0x00112248}, {0xef192c00, 0x00112230}, {0xef192c00, 0x00112278},
    {0xef192c00, 0x00104240}, {0xef192c00, 0x001041c8}, {0xef192c00, 0x00104a50}, {0xef192c00, 0x001049d8},
    {0xef192c00, 0xcb024000}, {0xef192c00, 0xc8112248}, {0xef192c00, 0xc8112230}, {0xef192c00, 0xc8112278},
    {0xef192c00, 0xc8104240}, {0xef192c00, 0xc81041c8}, {0xef192c00, 0xc8104a50}, {0xef192c00, 0xc81049d8},
};

TextureRdpCommand gTextureRdpCombineEnvironmentFadeOpaque[2] = {
    {0xfc55fe04, 0x1ffcfdfe},
    {0xfc55fe04, 0x1ffcfdfe},
};

TextureRdpCommand gTextureRdpModesEnvironmentFadeOpaque[16] = {
    {0xef182c00, 0x03024000}, {0xef182c00, 0x00112008}, {0xef182c00, 0x00112230}, {0xef182c00, 0x00112038},
    {0xef182c00, 0x00104240}, {0xef182c00, 0x001041c8}, {0xef182c00, 0x00104a50}, {0xef182c00, 0x001049d8},
    {0xef182c00, 0x03024000}, {0xef182c00, 0x00112008}, {0xef182c00, 0x00112230}, {0xef182c00, 0x00112038},
    {0xef182c00, 0x00104240}, {0xef182c00, 0x001041c8}, {0xef182c00, 0x00104a50}, {0xef182c00, 0x001049d8},
};

TextureRdpPreset gTextureRdpPresets[52] = {
    {gRcpTextureCombineCommands, gTextureRdpModesDefault, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineModulateRgba, gTextureRdpModesTranslucent, TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG,
     TEXTURE_RDP_TRANSLUCENT},
    {gTextureRdpCombineShadeAlphaFade, gTextureRdpModesShadeAlphaFade, TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG, 0},
    {gTextureRdpCombinePrimitiveBlend, gTextureRdpModesPrimitiveBlend, TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG, 0},
    {gTextureRdpCombineTextureBlend, gTextureRdpModesTextureBlend, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineTextureBlendShade, gTextureRdpModesTextureBlend, TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG,
     TEXTURE_RDP_TRANSLUCENT},
    {gTextureRdpCombineTextureBlendShadeAlpha, gTextureRdpModesTextureBlend, TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG,
     0},
    {gTextureRdpCombineTextureBlendPrimitive, gTextureRdpModesTextureBlend, TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG,
     0},
    {gTextureRdpCombineDecal, gTextureRdpModesDecal, TEXTURE_RDP_ALL_FLAGS, TEXTURE_RDP_Z_COMPARE},
    {gTextureRdpCombineDecal, gTextureRdpModesDecal, TEXTURE_RDP_ALL_FLAGS, TEXTURE_RDP_Z_COMPARE},
    {gTextureRdpCombineDecal, gTextureRdpModesDecal, TEXTURE_RDP_ALL_FLAGS, TEXTURE_RDP_Z_COMPARE},
    {gTextureRdpCombineDecal, gTextureRdpModesDecal, TEXTURE_RDP_ALL_FLAGS, TEXTURE_RDP_Z_COMPARE},
    {gTextureRdpCombineTextureBlend, gTextureRdpModesDecal, TEXTURE_RDP_ALL_FLAGS, TEXTURE_RDP_Z_COMPARE},
    {gTextureRdpCombineTextureBlendShade, gTextureRdpModesDecal, TEXTURE_RDP_ALL_FLAGS,
     TEXTURE_RDP_Z_COMPARE | TEXTURE_RDP_TRANSLUCENT},
    {gTextureRdpCombineTextureBlendShadeAlpha, gTextureRdpModesDecal, TEXTURE_RDP_ALL_FLAGS, TEXTURE_RDP_Z_COMPARE},
    {gTextureRdpCombineTextureBlendPrimitive, gTextureRdpModesDecal, TEXTURE_RDP_ALL_FLAGS, TEXTURE_RDP_Z_COMPARE},
    {gTextureRdpCombineCutout, gTextureRdpModesCutout, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineCutout, gTextureRdpModesCutout, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineCutout, gTextureRdpModesCutout, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineCutout, gTextureRdpModesCutout, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineTextureBlend, gTextureRdpModesFoggedCutoutBlend, TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG, 0},
    {gTextureRdpCombineTextureBlendShade, gTextureRdpModesFoggedCutoutBlend, TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG,
     TEXTURE_RDP_TRANSLUCENT},
    {gTextureRdpCombineTextureBlendShadeAlpha, gTextureRdpModesFoggedCutoutBlend,
     TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG, 0},
    {gTextureRdpCombineTextureBlendPrimitive, gTextureRdpModesFoggedCutoutBlend,
     TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG, 0},
    {gTextureRdpCombineSubsurface, gTextureRdpModesSubsurface, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineModulateRgba, gTextureRdpModesSubsurface, TEXTURE_RDP_ALL_FLAGS, TEXTURE_RDP_TRANSLUCENT},
    {gTextureRdpCombineShadeAlphaFade, gTextureRdpModesSubsurface, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombinePrimitiveBlend, gTextureRdpModesSubsurface, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineTextureBlend, gTextureRdpModesSubsurface, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineTextureBlendShade, gTextureRdpModesSubsurface, TEXTURE_RDP_ALL_FLAGS, TEXTURE_RDP_TRANSLUCENT},
    {gTextureRdpCombineTextureBlendShadeAlpha, gTextureRdpModesSubsurface, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineTextureBlendPrimitive, gTextureRdpModesSubsurface, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineTrilinear, gTextureRdpModesTrilinear, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineTrilinearSubsurface, gTextureRdpModesTrilinearSubsurface,
     TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG, 0},
    {gTextureRdpCombineDecalSimple, gTextureRdpModesDecalSimple, TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG,
     TEXTURE_RDP_Z_COMPARE},
    {gTextureRdpCombineTrilinearDecal, gTextureRdpModesTrilinearDecal, TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG,
     TEXTURE_RDP_Z_COMPARE},
    {gTextureRdpCombineEnvironmentFadeOpaque, gTextureRdpModesEnvironmentFadeOpaque,
     TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_TRANSLUCENT, 0},
    {gRcpTextureCombineCommands, gTextureRdpModesCloud, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineShadePrimitive, gTextureRdpModesPoint, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineShadePrimitiveRgba, gTextureRdpModesPointTranslucent, TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG,
     TEXTURE_RDP_TRANSLUCENT},
    {gTextureRdpCombineUntexturedShadeAlphaFade, gTextureRdpModesUntexturedShadeAlphaFade,
     TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG, 0},
    {gTextureRdpCombineUntexturedPrimitiveBlend, gTextureRdpModesUntexturedPrimitiveBlend,
     TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG, 0},
    {gTextureRdpCombineShadePrimitive, gTextureRdpModesPoint, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineShadePrimitiveRgba, gTextureRdpModesPointTranslucent, TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG,
     TEXTURE_RDP_TRANSLUCENT},
    {gTextureRdpCombineUntexturedShadeAlphaFade, gTextureRdpModesUntexturedShadeAlphaFade,
     TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG, 0},
    {gTextureRdpCombineUntexturedPrimitiveBlend, gTextureRdpModesUntexturedPrimitiveBlend,
     TEXTURE_RDP_ALL_FLAGS & ~TEXTURE_RDP_FOG, 0},
    {gTextureRdpCombinePrimitiveEnvironmentFog, gTextureRdpModesPrimitiveEnvironmentFog, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineTextureBlend2, gTextureRdpModesTextureBlend2, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombinePrimitiveEnvironmentFog, gTextureRdpModesPrimitiveEnvironmentFogPoint, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombineTextureBlend2, gTextureRdpModesTextureBlend2Point, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombinePrimitiveEnvironmentBlend, gTextureRdpModesPrimitiveEnvironmentFog, TEXTURE_RDP_ALL_FLAGS, 0},
    {gTextureRdpCombinePrimitiveEnvironmentBlend, gTextureRdpModesPrimitiveEnvironmentBlendNoise, TEXTURE_RDP_ALL_FLAGS,
     0},
};

/* Seven retained tile setups, eight RDP commands in each. */
TextureRdpCommand gTextureRdpMipmapTiles[7][8] = {
    {
        {0xf5101000, 0x00014050},
        {0xf2000000, 0x0007c07c},
        {0xf5100900, 0x01010441},
        {0xf2000000, 0x0103c03c},
        {0xf5100540, 0x0200c832},
        {0xf2000000, 0x0201c01c},
        {0xf5100350, 0x03008c23},
        {0xf2000000, 0x0300c00c},
    },
    {
        {0xf5101000, 0x00080050},
        {0xf2000000, 0x0007c07c},
        {0xf5100900, 0x01080441},
        {0xf2000000, 0x0103c03c},
        {0xf5100540, 0x02080832},
        {0xf2000000, 0x0201c01c},
        {0xf5100350, 0x03080c23},
        {0xf2000000, 0x0300c00c},
    },
    {
        {0xf5101000, 0x00014200},
        {0xf2000000, 0x0007c07c},
        {0xf5100900, 0x01010601},
        {0xf2000000, 0x0103c03c},
        {0xf5100540, 0x0200ca02},
        {0xf2000000, 0x0201c01c},
        {0xf5100350, 0x03008e03},
        {0xf2000000, 0x0300c00c},
    },
    {
        {0xf5100400, 0x00018050},
        {0xf2000000, 0x0007c07c},
        {0xf5100280, 0x01414441},
        {0xf2000000, 0x0103c03c},
        {0xf51002a0, 0x02810832},
        {0xf2000000, 0x0201c01c},
        {0xf51002a8, 0x03c0cc23},
        {0xf2000000, 0x0300c00c},
    },
    {
        {0xf5100400, 0x00080050},
        {0xf2000000, 0x0007c07c},
        {0xf5100280, 0x01480441},
        {0xf2000000, 0x0103c03c},
        {0xf51002a0, 0x02880832},
        {0xf2000000, 0x0201c01c},
        {0xf51002a8, 0x03c80c23},
        {0xf2000000, 0x0300c00c},
    },
    {
        {0xf5100400, 0x00018200},
        {0xf2000000, 0x0007c07c},
        {0xf5100280, 0x01414601},
        {0xf2000000, 0x0103c03c},
        {0xf51002a0, 0x02810a02},
        {0xf2000000, 0x0201c01c},
        {0xf51002a8, 0x03c0ce03},
        {0xf2000000, 0x0300c00c},
    },
    {
        {0xf5180800, 0x00010040},
        {0xf5180440, 0x0100c431},
        {0xf5180250, 0x02008822},
        {0xf5180254, 0x03008822},
        {0xf2000000, 0x0003c03c},
        {0xf2000000, 0x0001c01c},
        {0xf2000000, 0x0000c00c},
        {0xf2000000, 0x0000c00c},
    },
};

char sTexRestructAllocFailedMessage[] = "Failed to allocate memory->forcing texture free\n";
char sTexRestructRunningBanner[] = "^^^^^^^^^^^^^^^^  Restruct textures Running\n";
char sTexRestructReRegionBanner[] = "^^^^^^^^^^^^^^^^  REREGION \n";
char sTexRestructReRegionNoSpaceFormat[] = "texRestructRefs  No Space to ReRegion from 0x%x size %d!!!!\n";
char sTexRestructReRegionOptimalFormat[] = "texRestructRefs   Optimal ReRegion from 0x%x to 0x%x size %d!!!!\n";
char sTexRestructAfterReRegionBanner[] = "^^^^^^^^^^^^^^^^  AFTER REREGION \n";
char sTexRestructNoSpaceFormat[] = "texRestructRefs  No Space to Restructure from 0x%x size %d!!!!\n";
char sTexRestructWrongRegionFormat[] = "texRestructRefs Wrong region from 0x%x to 0x%x size %d!!!!\n";
char sTexRestructSubOptimalFormat[] = "texRestructRefs   SubOptimal Restructure from 0x%x to 0x%x size %d!!!!\n";
char sTexRestructOptimalFormat[] = "texRestructRefs   Optimal Restructure from 0x%x to 0x%x size %d!!!!\n";
char sTexRestructReRegionedStuckFormat[] =
    "texRestructRefs ReRegioned alloc can't get back into region 0 from 0x%x to 0x%x size %d!!!!\n";
char sTexRestructReRegionedOptimalFormat[] =
    "texRestructRefs   ReRegioned alloc Optimal Restructure from 0x%x to 0x%x size %d!!!!\n";
char sTexRestructFinishedFormat[] = "^^^^^^^^^^^^^^^^  Restruct textures Finished passes %d\n";

void loadTextureFiles(void) {
    int* bankEntry;
    int bank;
    int count;

    gLoadedTextures = mmAlloc(LOADED_TEXTURE_CAPACITY * sizeof(LoadedTextureEntry), 6, 0);
    gLoadedTextureCount = 0;
    loadTextureBank(0, MLDF_FILEID_TEX0_TAB_A);
    loadTextureBank(1, MLDF_FILEID_TEX1_TAB_A);
    count = 0;
    bankEntry = getCurrentDataFile(MLDF_FILEID_TEXPRE_TAB);
    gRcpTexBankTable[2] = bankEntry;
    while (bankEntry[count] != -1) {
        count++;
    }
    gRcpTexBankCount[2] = count - 1;
    loadAssetFileById(&gRcpTexIdRemap, MLDF_FILEID_TEXTABLE_BIN);
    for (bank = 0; bank < 2; bank++) {
        for (count = 0; gRcpTexBankTable[bank][count] != -1; count++) {
        }
        gRcpTexBankCount[bank] = count - 1;
    }
    gRcpTexHeaderBuffer = mmAlloc(0x120, 6, 0);
    textureLoad(0, 0);
}

void* textureLoadAsset(int asset) {
    void* out = NULL;
    if (getLoadedFileFlags(0) & LOADED_FILE_FLAG_PI_LOCKED) {
        return NULL;
    }
    loadTextureFile(&out, asset);
    return out;
}

void* textureAlloc(u16 w, u16 h, int fmt, u8 mip, u8 maxLod, u8 wrapS, u8 wrapT, u8 minFilter, u8 magFilter) {
    Texture* obj;
    u32 size = GXGetTexBufferSize(w, h, fmt, mip, maxLod) + (u32)sizeof(Texture);
    obj = mmAlloc(size, 6, 0);
    if (obj == NULL) {
        return NULL;
    }
    memset(obj, 0, sizeof(Texture) + 4);
    obj->format = fmt;
    obj->width = w;
    obj->height = h;
    obj->animationFrameCountFixed = 1;
    obj->refCount = 0;
    obj->wrapS = wrapS;
    obj->wrapT = wrapT;
    obj->minFilter = minFilter;
    obj->magFilter = magFilter;
    obj->imageOffset = 0;
    textureInitGXTexObj(obj);
    return obj;
}

Texture* textureGetAnimationFrame(Texture* texture, int frameFixed) {
    int limit = texture->animationFrameCountFixed;
    int i;
    if (frameFixed >= limit) {
        frameFixed = limit - 1;
    }
    frameFixed >>= 8;
    for (i = 0; i < frameFixed; i++) {
        texture = texture->nextAnimationFrame;
    }
    return texture;
}

void* textureLoad(int texId, u8 useHandle) {
    int fileId;
    int bank;
    int bankIndex;
    u32 size;
    Texture* buf;
    Texture* firstTex;
    Texture* prevTex;
    int slot;
    Texture* walk;
    u32 bankWord;
    int bankWordHeld;
    int bankWordSaved;
    BOOL interruptState;
    int origTexId;
    int frameCountFixed;
    u16 remapped;
    int dataByteOffset;
    int frameCount;
    int frameIndex;
    int storedSize;
    int n;
    int decompressedSize;
    int compressedSize;
    BOOL interruptsDisabled;

    interruptState = TRUE;
    interruptsDisabled = FALSE;
    if (texId < 0) {
        n = -texId;
        if (n & 0x8000) {
            slot = n & 0x7fff;
            if (slot == 0x82e) {
                OSReport(sDebugIntLineFormat, slot);
            }
        }
    }
    for (n = 0; n < gLoadedTextureCount; n++) {
        if (texId == gLoadedTextures[n].assetId) {
            buf = gLoadedTextures[n].texture;
            buf->refCount += 1;
            if (useHandle != 0 && gLoadedTextures[n].usesHandle != 0) {
                return (void*)(n + 1);
            }
            return buf;
        }
    }
    if (getLoadedFileFlags(0) != 0) {
        interruptState = OSDisableInterrupts();
        interruptsDisabled = TRUE;
    }
    origTexId = texId;
    if (texId < 0) {
        texId = -texId;
    } else if (texId >= 0xbb8 && (remapped = gRcpTexIdRemap[texId]) != 0) {
        texId = remapped + 1;
    } else {
        texId = gRcpTexIdRemap[texId];
    }
    bankIndex = texId & 0xffff;
    if (texId & 0x8000) {
        bank = 1;
        fileId = 0x20;
        bankIndex &= 0x7fff;
    } else if (origTexId >= 0xbb8) {
        bank = 2;
        fileId = 0x4f;
    } else {
        bank = 0;
        fileId = 0x23;
    }
    if (bankIndex >= gRcpTexBankCount[bank] || bankIndex < 0) {
        bankIndex = 0;
    }
    loadTextureBank(0, MLDF_FILEID_TEX0_TAB_A);
    loadTextureBank(1, MLDF_FILEID_TEX1_TAB_A);
    bankWord = gRcpTexBankTable[bank][bankIndex];
    frameCount = (bankWord >> TEX_TAB_FRAME_COUNT_SHIFT) & TEX_TAB_FRAME_COUNT_MASK;
    bankWordSaved = bankWord;
    if (frameCount == 1) {
        if (bank == 0) {
            tex0GetFrame(bankWord, bankIndex, &decompressedSize, &compressedSize, frameCount, 0,
                         TEXTURE_FRAME_QUERY_HEADER);
        } else if (bank == 2) {
            texPreGetFrame(bankWord, bankIndex, &decompressedSize, &compressedSize, frameCount, 0,
                           TEXTURE_FRAME_QUERY_HEADER);
        } else {
            tex1GetFrame(bankWord, bankIndex, &decompressedSize, &compressedSize, frameCount, 0,
                         TEXTURE_FRAME_QUERY_HEADER);
        }
        gRcpTexHeaderBuffer[0] = 0;
        gRcpTexHeaderBuffer[1] = decompressedSize;
        if (compressedSize == -1) {
            gRcpTexHeaderBuffer[2] = decompressedSize;
        } else {
            gRcpTexHeaderBuffer[2] = compressedSize;
        }
    } else if (bank == 0) {
        tex0GetFrame(bankWord, bankIndex, &decompressedSize, &compressedSize, frameCount, gRcpTexHeaderBuffer,
                     TEXTURE_FRAME_QUERY_OFFSETS);
    } else if (bank == 2) {
        texPreGetFrame(bankWord, bankIndex, &decompressedSize, &compressedSize, frameCount, gRcpTexHeaderBuffer,
                       TEXTURE_FRAME_QUERY_OFFSETS);
    } else {
        tex1GetFrame(bankWord, bankIndex, &decompressedSize, &compressedSize, frameCount, gRcpTexHeaderBuffer,
                     TEXTURE_FRAME_QUERY_OFFSETS);
    }
    firstTex = NULL;
    prevTex = NULL;
    frameIndex = 0;
    bankWordHeld = bankWordSaved;
    frameCountFixed = frameCount << 8;
    dataByteOffset = bankWordSaved = (bankWordSaved & 0xffffff) << 1;
    for (; frameIndex < frameCount; frameIndex++) {
        if (frameCount > 1) {
            if (bank == 0) {
                tex0GetFrame(bankWordHeld, bankIndex, &decompressedSize, &compressedSize, frameIndex,
                             gRcpTexHeaderBuffer, TEXTURE_FRAME_QUERY_INDEXED_HEADER);
            } else if (bank == 2) {
                texPreGetFrame(bankWordHeld, bankIndex, &decompressedSize, &compressedSize, frameIndex,
                               gRcpTexHeaderBuffer, TEXTURE_FRAME_QUERY_INDEXED_HEADER);
            } else {
                tex1GetFrame(bankWordHeld, bankIndex, &decompressedSize, &compressedSize, frameIndex,
                             gRcpTexHeaderBuffer, TEXTURE_FRAME_QUERY_INDEXED_HEADER);
            }
        }
        size = decompressedSize;
        if (compressedSize == -1) {
            storedSize = decompressedSize;
        } else {
            storedSize = compressedSize;
            mmSetTextureAllocationState(1);
            buf = mmAlloc(size, gRcpTexAllocTag, 0);
            mmSetTextureAllocationState(0);
            if (buf == NULL) {
                gRcpTexAllocFailed = 1;
                if (getLoadedFileFlags(0) != 0 && interruptsDisabled == TRUE) {
                    OSRestoreInterrupts(interruptState);
                } else if (interruptsDisabled == TRUE) {
                    OSRestoreInterrupts(interruptState);
                }
                if (useHandle != 0) {
                    return (void*)1;
                }
                return gLoadedTextures[0].texture;
            }
        }
        if (compressedSize != -1 && buf == NULL) {
            if (frameIndex == 0) {
                gRcpTexAllocFailed = 1;
                if (getLoadedFileFlags(0) != 0 && interruptsDisabled == TRUE) {
                    OSRestoreInterrupts(interruptState);
                } else if (interruptsDisabled == TRUE) {
                    OSRestoreInterrupts(interruptState);
                }
                if (useHandle != 0) {
                    return (void*)1;
                }
                return gLoadedTextures[0].texture;
            } else {
                firstTex->animationFrameCountFixed = frameCountFixed;
                frameIndex = frameCount;
                continue;
            }
        }
        if (compressedSize == -1) {
            buf = loadAndDecompressDataFile(fileId, 0, dataByteOffset + gRcpTexHeaderBuffer[frameIndex], storedSize, 0,
                                            bankIndex, 0);
            buf->cached = 1;
            if (useHandle != 0) {
                useHandle = 0;
            }
            buf->refCount = 1;
        } else {
            loadAndDecompressDataFile(fileId, buf, dataByteOffset + gRcpTexHeaderBuffer[frameIndex], storedSize, 0,
                                      bankIndex, 0);
        }
        if (compressedSize != -1) {
            DCStoreRange(buf, size);
        }
        buf->nextAnimationFrame = NULL;
        if (prevTex != NULL) {
            prevTex->nextAnimationFrame = buf;
        }
        prevTex = buf;
        if (frameIndex == 0) {
            firstTex = buf;
            buf->animationFrameCountFixed = frameCountFixed;
        } else {
            buf->animationFrameCountFixed = 1;
        }
    }
    walk = firstTex;
    firstTex->loadedSize = size;
    for (slot = 0; slot < gLoadedTextureCount; slot++) {
        if (gLoadedTextures[slot].assetId == -1) {
            break;
        }
    }
    if (slot == gLoadedTextureCount) {
        gLoadedTextureCount += 1;
    }
    gLoadedTextures[slot].assetId = origTexId;
    gLoadedTextures[slot].texture = firstTex;
    gLoadedTextures[slot].usesHandle = useHandle;
    gLoadedTextures[slot].allocationSize = getHeapItemSize(gLoadedTextures[slot].texture);
    if (gLoadedTextureCount > LOADED_TEXTURE_CAPACITY) {
        if (getLoadedFileFlags(0) != 0 && interruptsDisabled == TRUE) {
            OSRestoreInterrupts(interruptState);
        } else if (interruptsDisabled == TRUE) {
            OSRestoreInterrupts(interruptState);
        }
        if (useHandle != 0) {
            return (void*)1;
        }
        return gLoadedTextures[0].texture;
    }
    while (walk != NULL) {
        textureInitGXTexObj(walk);
        walk = walk->nextAnimationFrame;
    }
    if (getLoadedFileFlags(0) != 0 && interruptsDisabled == TRUE) {
        OSRestoreInterrupts(interruptState);
    } else if (interruptsDisabled == TRUE) {
        OSRestoreInterrupts(interruptState);
    }
    if (useHandle != 0) {
        return (void*)(slot + 1);
    }
    return firstTex;
}

static inline void loadTextureBank(int bank, int fileId) {
    int n = 0;

    gRcpTexBankTable[bank] = getCurrentDataFile(fileId);
    if (gRcpTexBankTable == NULL) {
        return;
    }
    while (gRcpTexBankTable[bank][n] != -1) {
        n++;
    }
    gRcpTexBankCount[bank] = n - 1;
}

void textureFree(Texture* tex) {
    Texture* iter;
    Texture* next;
    if (tex == gLoadedTextures[0].texture) {
        return;
    }
    if (tex == NULL) {
        ((Texture*)tex)->evictTimer = 10;
        return;
    }
    if (((Texture*)tex)->refCount == 0) {
        ((Texture*)tex)->evictTimer = 10;
        return;
    }
    if (((Texture*)tex)->cached != 0 && ((Texture*)tex)->refCount <= 1) {
        ((Texture*)tex)->evictTimer = 10;
    }
    (((Texture*)tex)->refCount)--;
    if (((Texture*)tex)->refCount != 0) {
        return;
    }
    {
        int i;
        for (i = 0; i < gLoadedTextureCount; i++) {
            if (gLoadedTextures[i].texture == tex) {
                iter = tex->nextAnimationFrame;
                while (iter != NULL) {
                    if ((u32)iter < 0x80000000 || (u32)iter > 0x81800000) {
                        iter = NULL;
                    }
                    if ((u32)iter < 0x80000000 || (u32)iter >= 0xa0000000) {
                        iter = NULL;
                        continue;
                    }
                    if (iter == NULL) {
                        continue;
                    }
                    next = iter->nextAnimationFrame;
                    if (iter->preloaded != 0) {
                        newshadows_releaseTextureEntry((void*)iter->tmemAddr);
                    }
                    if (iter->cached == 0) {
                        mm_free(iter);
                    }
                    iter = next;
                }
                if (((Texture*)tex)->preloaded != 0) {
                    newshadows_releaseTextureEntry((void*)((Texture*)tex)->tmemAddr);
                }
                if (((Texture*)tex)->cached == 0) {
                    mm_free(tex);
                }
                gLoadedTextures[i].assetId = -1;
                gLoadedTextures[i].texture = NULL;
                return;
            }
        }
    }
}

void Rcp_ResetRenderState(void) {
    gRcpRenderFlags = 0;
    lbl_803DCDB4 = 0;
    lbl_803DCDB0 = 0;
}

void textureSelectAnimationFramePair(void* context, Texture* texture, Texture* forcedTexture, int flags,
                                     int packedFrame, int unused0, int unused1) {
    int i;
    int idx, count;
    Texture* node;
    Texture* current;
    Texture* result;
    Texture* walk;
    u16 animationFrameCountFixed;

    if (texture == NULL) {
        return;
    }
    idx = packedFrame >> 16;
    animationFrameCountFixed = texture->animationFrameCountFixed;
    if (animationFrameCountFixed != 0) {
        count = animationFrameCountFixed >> 8;
    } else {
        count = 0;
    }
    current = texture;
    result = texture;
    if (count > 1 && idx < count) {
        node = texture;
        for (i = 0; i < idx && node != NULL; i++) {
            node = node->nextAnimationFrame;
        }
        if (node != NULL) {
            current = node;
        }
        if (flags & TEXTURE_ANIM_SELECT_NEXT) {
            if (flags & TEXTURE_ANIM_REVERSE) {
                idx--;
                if (idx < 0) {
                    if (flags & TEXTURE_ANIM_PING_PONG) {
                        idx += 2;
                    } else {
                        idx = 0;
                    }
                }
            } else {
                idx++;
                if (idx >= count) {
                    if (flags & TEXTURE_ANIM_PING_PONG) {
                        idx -= 2;
                    } else {
                        idx = count - 1;
                    }
                }
            }
            walk = texture;
            for (i = 0; i < idx && walk != NULL; i++) {
                walk = walk->nextAnimationFrame;
            }
            if (walk != NULL) {
                result = walk;
            }
        } else {
            result = current;
        }
    }
    if (forcedTexture != NULL) {
        result = forcedTexture;
    }
    selectTexture(current, 0);
    selectTexture(result, 1);
}

void textureSetAnimationFrameStep(Texture* texture, u16 frameStep) {
    texture->animationFrameStep = frameStep;
}

void textureUpdateAnimationFrame(const Texture* texture, u32* animationFlags, s32* frameFixed) {
    u32 reverse, pingPong, randomStart;
    u32 flags;
    int roll;
    int reflected;

    flags = *animationFlags;
    reverse = flags & TEXTURE_ANIM_REVERSE;
    pingPong = flags & TEXTURE_ANIM_PING_PONG;
    randomStart = flags & TEXTURE_ANIM_RANDOM_START;
    if (randomStart != 0) {
        if (pingPong == 0) {
            roll = randomGetRange(0, 0x3e8);
            if (roll > 0x3d9) {
                *animationFlags &= ~TEXTURE_ANIM_REVERSE;
                *animationFlags |= TEXTURE_ANIM_PING_PONG;
            }
        } else if (reverse == 0) {
            *frameFixed += texture->animationFrameStep * framesThisStep;
            if (*frameFixed >= texture->animationFrameCountFixed) {
                *frameFixed = texture->animationFrameCountFixed * 2 - 1 - *frameFixed;
                if (*frameFixed < 0) {
                    *frameFixed = 0;
                    *animationFlags &= ~(TEXTURE_ANIM_REVERSE | TEXTURE_ANIM_PING_PONG);
                } else {
                    *animationFlags |= TEXTURE_ANIM_REVERSE;
                }
            }
        } else {
            *frameFixed -= texture->animationFrameStep * framesThisStep;
            if (*frameFixed < 0) {
                *frameFixed = 0;
                *animationFlags &= ~(TEXTURE_ANIM_REVERSE | TEXTURE_ANIM_PING_PONG);
            }
        }
    } else if (pingPong != 0) {
        if (reverse == 0) {
            *frameFixed += texture->animationFrameStep * framesThisStep;
        } else {
            *frameFixed -= texture->animationFrameStep * framesThisStep;
        }
        do {
            reflected = 0;
            if (*frameFixed < 0) {
                *frameFixed = -*frameFixed;
                *animationFlags &= ~TEXTURE_ANIM_REVERSE;
                reflected = 1;
            }
            if (*frameFixed >= texture->animationFrameCountFixed) {
                *frameFixed = texture->animationFrameCountFixed * 2 - 1 - *frameFixed;
                *animationFlags |= TEXTURE_ANIM_REVERSE;
                reflected = 1;
            }
        } while (reflected != 0);
    } else if (reverse == 0) {
        *frameFixed += texture->animationFrameStep * framesThisStep;
        while (*frameFixed >= texture->animationFrameCountFixed) {
            *frameFixed -= texture->animationFrameCountFixed;
        }
    } else {
        *frameFixed -= texture->animationFrameStep * framesThisStep;
        while (*frameFixed < 0) {
            *frameFixed += texture->animationFrameCountFixed;
        }
    }
}

void* getLoadedTexture(int assetId) {
    LoadedTextureEntry* base;
    int i;

    i = 0;
    base = gLoadedTextures;
    for (; i < gLoadedTextureCount; i++) {
        if (assetId == base[i].assetId) {
            return base[i].texture;
        }
    }
    return NULL;
}

void Rcp_SetRenderFlags(u32 bits) {
    gRcpRenderFlags |= bits;
}

void Rcp_ClearRenderFlags(u32 bits) {
    gRcpRenderFlags &= ~(u64)bits;
}

static inline GXBool textureHasMipmaps(Texture* texture, GXBool hasMipmaps) {
    if (texture->maxLod - texture->minLod > 0) {
        hasMipmaps = TRUE;
    }
    return hasMipmaps;
}

void textureInitGXTexObj(Texture* texture) {
    GXBool hasMipmaps = FALSE;
    GXTexObj* gxTexObj;
    u16 width;
    u16 height;
    GXTexFmt format;
    texture->tmemAddr = NULL;
    texture->preloaded = hasMipmaps;
    gxTexObj = textureGetGXTexObj(texture);
    hasMipmaps = textureHasMipmaps(texture, hasMipmaps);
    GXInitTexObj(gxTexObj, textureGetImageData(texture), texture->width, texture->height, texture->format,
                 texture->wrapS, texture->wrapT, hasMipmaps);
    if (hasMipmaps != 0) {
        GXInitTexObjLOD(gxTexObj, texture->minFilter, texture->magFilter, (f32)(u32)texture->minLod,
                        (f32)(s32)texture->maxLod, -2.0f, 0, 0, 0);
    } else {
        GXInitTexObjLOD(gxTexObj, texture->minFilter, texture->magFilter, 0.0f, 0.0f, 0.0f, 0, 0, 0);
    }
    GXInitTexObjUserData(gxTexObj, texture);
    format = GXGetTexObjFmt(gxTexObj);
    width = GXGetTexObjWidth(gxTexObj);
    height = GXGetTexObjHeight(gxTexObj);
    texture->dataSize = GXGetTexBufferSize(width, height, format, 0, 0);
}

void textureInitSecondaryGXTexObj(Texture* tex, GXTexObj* obj) {
    u8 mipmap;
    if ((int)tex->maxLod - (int)tex->minLod > 0) {
        mipmap = 1;
    } else {
        mipmap = 0;
    }
    GXInitTexObj(obj, (u8*)tex + tex->imageOffset + sizeof(Texture), tex->width, tex->height, GX_TF_I4, tex->wrapS,
                 tex->wrapT, mipmap);
    if (mipmap != 0) {
        GXInitTexObjLOD(obj, tex->minFilter, tex->magFilter, (f32)(u32)tex->minLod, (f32)(s32)tex->maxLod, -2.0f, 0, 0,
                        0);
    } else {
        GXInitTexObjLOD(obj, ((Texture*)tex)->minFilter, ((Texture*)tex)->magFilter, 0.0f, 0.0f, 0.0f, 0, 0, 0);
    }
}

/* Keep the explicit successful-allocation checks: plain else branches change MWCC codegen. */
void texRestructRefs(int mode) {
    Texture* replacement;
    int slot;
    int stable;
    int passIndex;
    Texture* texture;
    u32 allocationSize;
    int previousFreeDelay;

    stable = 0;
    passIndex = 0;
    mmSetTextureAllocationState(2);
    OSReport(sTexRestructRunningBanner);
    printHeapStats(1);
    OSReport(sTexRestructReRegionBanner);
    mmSetForceHeaps1and2Only(1);
    for (slot = 0; slot < gLoadedTextureCount; slot++) {
        texture = gLoadedTextures[slot].texture;
        if (texture != NULL && gLoadedTextures[slot].usesHandle != 0 && texture->cached == 0 &&
            (int)gLoadedTextures[slot].allocationSize != -1 && mmGetRegionForPtr((u8*)texture) == 0 &&
            texture->nextAnimationFrame == NULL) {
            allocationSize = gLoadedTextures[slot].allocationSize;
            replacement = mmAlloc(allocationSize, 0xa0a0a0a0, 0);
            if (replacement == NULL) {
                OSReport(sTexRestructReRegionNoSpaceFormat, texture, getHeapItemSize(texture));
            } else if (replacement != NULL) {
                OSReport(sTexRestructReRegionOptimalFormat, texture, replacement, getHeapItemSize(texture));
                stable = 0;
                memcpy(replacement, texture, allocationSize);
                DCStoreRange(replacement, allocationSize);
                textureInitGXTexObj(replacement);
                previousFreeDelay = mmSetFreeDelay(0);
                mm_free(gLoadedTextures[slot].texture);
                mmSetFreeDelay(previousFreeDelay);
                gLoadedTextures[slot].texture = replacement;
            }
        }
    }
    mmSetForceHeaps1and2Only(-1);
    OSReport(sTexRestructAfterReRegionBanner);
    printHeapStats(1);
    defragMemory(2);
    while (stable == 0 && passIndex < 4) {
        stable = 1;
        for (slot = 0; slot < gLoadedTextureCount; slot++) {
            texture = gLoadedTextures[slot].texture;
            if (texture != NULL && gLoadedTextures[slot].usesHandle != 0 && texture->cached == 0 &&
                (int)gLoadedTextures[slot].allocationSize != -1) {
                if (mmGetRegionForPtr((u8*)texture) == 0 && texture->nextAnimationFrame == NULL) {
                    allocationSize = gLoadedTextures[slot].allocationSize;
                    replacement = mmAlloc(allocationSize, 0xa0a0a0a0, 0);
                    if (replacement == NULL) {
                        OSReport(sTexRestructNoSpaceFormat, texture, getHeapItemSize(texture));
                    } else if (mmGetRegionForPtr((u8*)replacement) != 0) {
                        OSReport(sTexRestructWrongRegionFormat, texture, replacement, getHeapItemSize(texture));
                        previousFreeDelay = mmSetFreeDelay(0);
                        mm_free(replacement);
                        mmSetFreeDelay(previousFreeDelay);
                    } else if ((size_t)replacement < (size_t)texture) {
                        OSReport(sTexRestructSubOptimalFormat, texture, replacement, getHeapItemSize(texture));
                        previousFreeDelay = mmSetFreeDelay(0);
                        mm_free(replacement);
                        mmSetFreeDelay(previousFreeDelay);
                    } else if (replacement != NULL) {
                        OSReport(sTexRestructOptimalFormat, texture, replacement, getHeapItemSize(texture));
                        stable = 0;
                        memcpy(replacement, texture, allocationSize);
                        DCStoreRange(replacement, allocationSize);
                        textureInitGXTexObj(replacement);
                        previousFreeDelay = mmSetFreeDelay(0);
                        mm_free(gLoadedTextures[slot].texture);
                        mmSetFreeDelay(previousFreeDelay);
                        gLoadedTextures[slot].texture = replacement;
                    }
                } else if (mode == 0) {
                    if (mmGetRegionForPtr((u8*)texture) == 1 || mmGetRegionForPtr((u8*)texture) == 2) {
                        if (texture->nextAnimationFrame == NULL && getHeapItemSize(texture) >= 0x3000) {
                            allocationSize = gLoadedTextures[slot].allocationSize;
                            replacement = mmAlloc(allocationSize, 0xa0a0a0a0, 0);
                            if (replacement == NULL) {
                                OSReport(sTexRestructNoSpaceFormat, texture, getHeapItemSize(texture));
                            } else if (mmGetRegionForPtr((u8*)replacement) != 0) {
                                OSReport(sTexRestructReRegionedStuckFormat, texture, replacement,
                                         getHeapItemSize(texture));
                                previousFreeDelay = mmSetFreeDelay(0);
                                mm_free(replacement);
                                mmSetFreeDelay(previousFreeDelay);
                            } else if (replacement != NULL) {
                                OSReport(sTexRestructReRegionedOptimalFormat, texture, replacement,
                                         getHeapItemSize(texture));
                                stable = 0;
                                memcpy(replacement, texture, allocationSize);
                                DCStoreRange(replacement, allocationSize);
                                textureInitGXTexObj(replacement);
                                previousFreeDelay = mmSetFreeDelay(0);
                                mm_free(gLoadedTextures[slot].texture);
                                mmSetFreeDelay(previousFreeDelay);
                                gLoadedTextures[slot].texture = replacement;
                            }
                        }
                    }
                }
            }
        }
        printHeapStats(1);
        passIndex++;
    }
    OSReport(sTexRestructFinishedFormat, passIndex);
    mmSetTextureAllocationState(0);
}

Texture* textureIdxToPtr(TextureReference reference) {
    int slot;
    /* Retail addresses have bit 31 set; retain any higher native address bits. */
    if (reference & ~(TextureReference)0x7fffffff) {
        return (Texture*)reference;
    }
    slot = (int)reference - 1;
    if (slot < 0 || slot >= gLoadedTextureCount) {
        return NULL;
    }
    return gLoadedTextures[slot].texture;
}