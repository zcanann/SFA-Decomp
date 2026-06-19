#ifndef MAIN_DLL_MMP_MMP_MOONROCK_H_
#define MAIN_DLL_MMP_MMP_MOONROCK_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

#define MMP_LIGHTNING_OBJGROUP 0x48

#define WATERFALLSPRAY_ALT_SFX_DEF_MIN 0x4BE5C
#define WATERFALLSPRAY_ALT_SFX_DEF_END 0x4BE5E
#define WATERFALLSPRAY_DEFAULT_SFX_A 0x2AF
#define WATERFALLSPRAY_DEFAULT_SFX_B 0x2B2
#define WATERFALLSPRAY_ALT_SFX_A 0x489
#define WATERFALLSPRAY_ALT_SFX_B 0x48A

#define SFXPLAYER_OBJECT_FLAGS 0x6000
#define SFXPLAYER_MODE_GAMEBIT 0
#define SFXPLAYER_MODE_LOOPED 1
#define SFXPLAYER_MODE_RANDOM_DELAY 2
#define SFXPLAYER_RUNTIME_ACTIVE_FLAG 0x01

extern ObjectDescriptor gWaterFallSprayObjDescriptor;
extern ObjectDescriptor gLightningObjDescriptor;
extern ObjectDescriptor gSfxPlayerObjDescriptor;

void lightning_free(u8 *obj, int p2);
void lightning_render(u8 *obj);
void lightning_update(u8 *obj);
void lightning_init(u8 *obj, u8 *data);
void WaterFallSpray_free(u8 *obj);
void WaterFallSpray_init(u8 *obj, u8 *data);
void WaterFallSpray_render(void);
void WaterFallSpray_update(int *obj);
int WaterFallSpray_getExtraSize(void);
int WaterFallSpray_SeqFn(int *obj);
void sfxplayerObj_init(u8 *obj, u8 *data);
void sfxplayerObj_free(u8 *obj);
void sfxplayerObj_update(u8 *obj);
int sfxplayerObj_getExtraSize(void);
void fn_80198A00(u8 *obj, int seqArg);
int fn_80198B68(u8 *obj, f32 *point);
void fn_80198DE8(u8 *obj, int seqArg);

void FUN_80197960(int param_1);
void FUN_80197990(int param_1);
void FUN_80197c38(int param_1,int param_2);
void FUN_80197e14(int param_1);
void FUN_80197e54(int param_1);
void FUN_80197e84(void);
void FUN_80198230(int param_1,int param_2);
u32 FUN_80198348(u32 param_1);
void FUN_8019836c(int obj);
void FUN_801983a0(u32 param_1);
void FUN_80198634(int param_1);
void FUN_801986d4(u32 param_1);
void FUN_80198d58(int param_1,int param_2);
void FUN_80198e08(void);

#endif /* MAIN_DLL_MMP_MMP_MOONROCK_H_ */
