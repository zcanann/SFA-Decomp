#ifndef H_MAIN_DLL_WISPBADDIESEQ_EXT_H
#define H_MAIN_DLL_WISPBADDIESEQ_EXT_H

#include "global.h"
#include "game/objects/object.h"

u32 wispBaddieProcessAnimEvent(GameObject* obj, u8* state, u32 allowNewEvent);
void wispBaddiePlayMoveEventSfx(GameObject* obj, void* state);
void wispBaddieQueueNextEvent(GameObject* obj, int delta);

#endif /* H_MAIN_DLL_WISPBADDIESEQ_EXT_H */
