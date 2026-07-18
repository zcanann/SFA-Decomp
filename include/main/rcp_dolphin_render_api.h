#ifndef MAIN_RCP_DOLPHIN_RENDER_API_H_
#define MAIN_RCP_DOLPHIN_RENDER_API_H_

#include "types.h"

struct Texture;
struct _GXTexObj;
typedef struct GameObject GameObject;

int objShouldUnload(GameObject* obj);
void fn_80053C40(struct Texture* texture, struct _GXTexObj* obj);
void Rcp_SetColorFilterEnabled(u32 x);

#endif /* MAIN_RCP_DOLPHIN_RENDER_API_H_ */
