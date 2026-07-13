#ifndef MAIN_DLL_DLL_0133_SFXPLAYER_H_
#define MAIN_DLL_DLL_0133_SFXPLAYER_H_

#include "ghidra_import.h"
#include "main/object_descriptor.h"

#define SFXPLAYER_OBJECT_FLAGS 0x6000
#define SFXPLAYER_MODE_GAMEBIT 0
#define SFXPLAYER_MODE_LOOPED 1
#define SFXPLAYER_MODE_RANDOM_DELAY 2
#define SFXPLAYER_RUNTIME_ACTIVE_FLAG 0x01

extern ObjectDescriptor gSfxPlayerObjDescriptor;

void sfxplayerObj_init(u8 *obj, u8 *data);
void sfxplayerObj_free(u8 *obj);
void sfxplayerObj_update(u8 *obj);
int sfxplayerObj_getExtraSize(void);

#endif /* MAIN_DLL_DLL_0133_SFXPLAYER_H_ */
